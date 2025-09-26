package db

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/utils"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query/primitives"
)

type DBStore struct {
	ds            sqlutil.DataSource
	lggr          logger.Logger
	rwMutex       sync.RWMutex
	schemaEnsured bool
}

func NewDBStore(ds sqlutil.DataSource, logger logger.Logger) *DBStore {
	return &DBStore{
		ds:   ds,
		lggr: logger,
	}
}

type EventRecord struct {
	ID                  uint64
	EventAccountAddress string
	EventHandle         string
	EventFieldName      string
	EventOffset         uint64
	TxVersion           uint64
	BlockHeight         string
	BlockHash           []byte
	BlockTimestamp      uint64
	Data                map[string]any
}

func (s *DBStore) InsertEvents(ctx context.Context, records []EventRecord) error {
	if len(records) == 0 {
		return nil
	}

	insertSQL := `
INSERT INTO aptos.events (
    event_account_address,
    event_handle,
    event_field_name,
    event_offset,
    tx_version,
    block_height,
    block_hash,
    block_timestamp,
    data
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (event_account_address, event_handle, event_field_name, event_offset, tx_version)
DO NOTHING;
`

	var allErrors []error
	for _, record := range records {
		data, err := json.Marshal(record.Data)
		if err != nil {
			errMsg := fmt.Errorf("failed to marshal event data for handle %s: %w", record.EventHandle, err)
			s.lggr.Errorw("Event marshaling failed",
				"error", errMsg,
				"handle", record.EventHandle,
				"fieldName", record.EventFieldName,
				"offset", record.EventOffset)
			allErrors = append(allErrors, errMsg)
			continue
		}

		s.rwMutex.Lock()
		_, err = s.ds.ExecContext(ctx, insertSQL,
			record.EventAccountAddress,
			record.EventHandle,
			record.EventFieldName,
			record.EventOffset,
			record.TxVersion,
			record.BlockHeight,
			record.BlockHash,
			record.BlockTimestamp,
			data,
		)
		s.rwMutex.Unlock()

		if err != nil {
			errMsg := fmt.Errorf("failed to insert event (handle: %s, field_name: %s, offset: %v): %w",
				record.EventHandle, record.EventFieldName, record.EventOffset, err)
			s.lggr.Errorw("Event insertion failed",
				"error", errMsg,
				"account", record.EventAccountAddress,
				"handle", record.EventHandle,
				"fieldName", record.EventFieldName,
				"txVersion", record.TxVersion)
			allErrors = append(allErrors, errMsg)
			continue
		}
	}

	if len(allErrors) > 0 {
		return fmt.Errorf("failed to insert %d events: %v", len(allErrors), allErrors)
	}

	return nil
}

func (s *DBStore) QueryEvents(ctx context.Context, eventAccountAddress, eventHandle, eventFieldName string, expressions []query.Expression, limitAndSort query.LimitAndSort) ([]EventRecord, error) {
	baseSQL := `
SELECT id, event_account_address, event_handle, event_field_name, event_offset, tx_version, block_height, block_hash, block_timestamp, data
FROM aptos.events
WHERE event_account_address = $1 AND event_handle = $2 AND event_field_name = $3
`

	args := []interface{}{eventAccountAddress, eventHandle, eventFieldName}
	argCount := 4

	s.lggr.Debugw("Building SQL query from expressions",
		"event", eventAccountAddress+"/"+eventHandle+"/"+eventFieldName,
		"expressionCount", len(expressions),
		"expressions", expressions)

	if len(expressions) > 0 {
		var conditions []string
		for _, expr := range expressions {
			sqlCondition, err := s.buildSQLCondition(expr, &args, &argCount)
			if err != nil {
				return nil, fmt.Errorf("failed to build SQL condition: %w", err)
			}
			conditions = append(conditions, sqlCondition)
		}

		if len(conditions) > 0 {
			baseSQL += " AND " + strings.Join(conditions, " AND ")
		}
	}

	if len(limitAndSort.SortBy) > 0 {
		direction := "ASC"
		if sortDir, ok := limitAndSort.SortBy[0].(query.SortBySequence); ok && sortDir.GetDirection() == query.Desc {
			direction = "DESC"
		}
		baseSQL += " ORDER BY (tx_version, event_offset) " + direction
	}

	var maxLimit uint64 = 2000
	limitCount := limitAndSort.Limit.Count
	if limitCount > maxLimit {
		s.lggr.Warnw("Requested limit exceeds maximum allowed, capping limit",
			"requestedLimit", limitCount,
			"maxLimit", maxLimit)
		limitCount = maxLimit
	} else if limitCount <= 0 {
		// Default limit if none provided
		limitCount = maxLimit
	}

	baseSQL += fmt.Sprintf(" LIMIT %d", limitCount)

	s.lggr.Debugw("Executing SQL query",
		"sql", baseSQL,
		"paramCount", len(args),
		"params", args,
		"limitCount", limitAndSort.Limit.Count)

	s.rwMutex.RLock()
	rows, err := s.ds.QueryContext(ctx, baseSQL, args...)
	s.rwMutex.RUnlock()

	if err != nil {
		return nil, fmt.Errorf("query events failed: %w", err)
	}
	defer rows.Close()

	var records []EventRecord
	for rows.Next() {
		var record EventRecord
		var dataBytes []byte
		err := rows.Scan(&record.ID, &record.EventAccountAddress, &record.EventHandle, &record.EventFieldName, &record.EventOffset, &record.TxVersion, &record.BlockHeight, &record.BlockHash, &record.BlockTimestamp, &dataBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to scan event record: %w", err)
		}

		var data map[string]any
		decoder := json.NewDecoder(bytes.NewReader(dataBytes))
		decoder.UseNumber()
		if err := decoder.Decode(&data); err != nil {
			return nil, fmt.Errorf("failed to unmarshal event data: %w", err)
		}

		record.Data = data
		records = append(records, record)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error during row iteration: %w", err)
	}

	return records, nil
}

func (s *DBStore) GetLatestOffset(ctx context.Context, eventAccountAddress, eventHandle, eventFieldName string) (uint64, error) {
	querySQL := `
SELECT COALESCE(MAX(event_offset) + 1, 0) FROM aptos.events
WHERE event_account_address = $1 AND event_handle = $2 AND event_field_name = $3
`

	s.rwMutex.RLock()
	row := s.ds.QueryRowxContext(ctx, querySQL, eventAccountAddress, eventHandle, eventFieldName)
	s.rwMutex.RUnlock()

	var offset uint64
	err := row.Scan(&offset)
	if err != nil {
		return 0, fmt.Errorf("failed to get latest offset: %w", err)
	}

	return offset, nil
}

func (s *DBStore) GetTxVersionByID(ctx context.Context, id uint64) (uint64, error) {
	querySQL := `
SELECT tx_version FROM aptos.events
WHERE id = $1
`

	s.rwMutex.RLock()
	row := s.ds.QueryRowxContext(ctx, querySQL, id)
	s.rwMutex.RUnlock()

	var txVersion uint64
	err := row.Scan(&txVersion)
	if err != nil {
		return 0, fmt.Errorf("failed to fetch tx_version for id %d: %w", id, err)
	}

	return txVersion, nil
}

func (s *DBStore) GetTransmitterSequenceNum(ctx context.Context, transmitterAddress string) (uint64, error) {
	querySQL := `
SELECT COALESCE(
  (SELECT ts.sequence_number FROM aptos.transmitter_sequence_nums ts WHERE ts.transmitter_address = $1), 0
)
 `

	s.rwMutex.RLock()
	row := s.ds.QueryRowxContext(ctx, querySQL, transmitterAddress)
	s.rwMutex.RUnlock()

	var sequenceNumber uint64
	err := row.Scan(&sequenceNumber)
	if err != nil {
		return 0, fmt.Errorf("failed to get transmitter sequence: %w", err)
	}

	return sequenceNumber, nil
}

func (s *DBStore) UpdateTransmitterSequence(ctx context.Context, transmitterAddress string, sequenceNumber uint64) error {
	upsertSQL := `
INSERT INTO aptos.transmitter_sequence_nums (transmitter_address, sequence_number, updated_at)
VALUES ($1, $2, NOW())
ON CONFLICT (transmitter_address) DO UPDATE
SET sequence_number = EXCLUDED.sequence_number, updated_at = NOW()
WHERE aptos.transmitter_sequence_nums.sequence_number < EXCLUDED.sequence_number
`

	s.rwMutex.Lock()
	_, err := s.ds.ExecContext(ctx, upsertSQL, transmitterAddress, sequenceNumber)
	s.rwMutex.Unlock()

	if err != nil {
		return fmt.Errorf("failed to update transmitter sequence: %w", err)
	}

	return nil
}

func (s *DBStore) buildSQLCondition(expr query.Expression, args *[]any, argCount *int) (string, error) {
	if expr.IsPrimitive() {
		switch v := expr.Primitive.(type) {
		case *primitives.Comparator:
			conditions := []string{}
			for _, valueCmp := range v.ValueComparators {
				jsonPath, err := utils.BuildJsonPathExpr("data", v.Name)
				if err != nil {
					return "", fmt.Errorf("invalid field name %s: %w", v.Name, err)
				}

				var condition string
				if utils.IsNumeric(valueCmp.Value) {
					condition = fmt.Sprintf("CAST(%s AS numeric) %s $%d", jsonPath, operatorSQL(valueCmp.Operator), *argCount)
				} else {
					condition = fmt.Sprintf("%s %s $%d", jsonPath, operatorSQL(valueCmp.Operator), *argCount)
				}

				*args = append(*args, valueCmp.Value)
				*argCount++
				conditions = append(conditions, condition)
			}
			return "(" + strings.Join(conditions, " AND ") + ")", nil

		case *primitives.Timestamp:
			condition := fmt.Sprintf("block_timestamp %s $%d", operatorSQL(v.Operator), *argCount)
			*args = append(*args, v.Timestamp)
			*argCount++
			return condition, nil

		case *primitives.Confidence:
			// Confidence filter isn't applicable in the context of Aptos
			return "TRUE", nil

		default:
			return "", fmt.Errorf("unsupported primitive type: %T", expr.Primitive)
		}
	} else {
		if len(expr.BoolExpression.Expressions) < 2 {
			return "", fmt.Errorf("boolean expression must have at least 2 expressions")
		}

		var subConditions []string
		for _, subExpr := range expr.BoolExpression.Expressions {
			subCond, err := s.buildSQLCondition(subExpr, args, argCount)
			if err != nil {
				return "", err
			}
			subConditions = append(subConditions, subCond)
		}

		operator := " AND "
		if expr.BoolExpression.BoolOperator == query.OR {
			operator = " OR "
		}

		return "(" + strings.Join(subConditions, operator) + ")", nil
	}
}

func operatorSQL(op primitives.ComparisonOperator) string {
	switch op {
	case primitives.Eq:
		return "="
	case primitives.Neq:
		return "!="
	case primitives.Gt:
		return ">"
	case primitives.Gte:
		return ">="
	case primitives.Lt:
		return "<"
	case primitives.Lte:
		return "<="
	default:
		// Default to equality if unknown
		return "="
	}
}
