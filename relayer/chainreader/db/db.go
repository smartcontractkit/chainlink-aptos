package db

import (
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

func (s *DBStore) EnsureSchema(ctx context.Context) error {
	if s.schemaEnsured {
		return nil
	}

	s.rwMutex.Lock()
	defer s.rwMutex.Unlock()

	dropSchemaSQL := `
DROP SCHEMA IF EXISTS aptos CASCADE;
`
	_, err := s.ds.ExecContext(ctx, dropSchemaSQL)
	if err != nil {
		return fmt.Errorf("failed to drop aptos schema: %w", err)
	}

	schemaSQL := `
CREATE SCHEMA IF NOT EXISTS aptos;
`
	_, err = s.ds.ExecContext(ctx, schemaSQL)
	if err != nil {
		return fmt.Errorf("failed to create aptos schema: %w", err)
	}

	createTableSQL := `
CREATE TABLE IF NOT EXISTS aptos.events (
		id BIGSERIAL PRIMARY KEY,
    event_account_address TEXT NOT NULL,
    event_handle TEXT NOT NULL,
		event_field_name TEXT NOT NULL,
    event_offset BIGINT,
    tx_version BIGINT NOT NULL,
    block_height TEXT NOT NULL,
    block_hash BYTEA NOT NULL,
    block_timestamp BIGINT NOT NULL,
    data JSONB NOT NULL,
		UNIQUE (event_account_address, event_handle, event_field_name, tx_version)
);
`
	_, err = s.ds.ExecContext(ctx, createTableSQL)
	if err != nil {
		return fmt.Errorf("failed to create aptos.events table: %w", err)
	}

	indexSQL := `
CREATE INDEX IF NOT EXISTS idx_events_account_handle_offset
ON aptos.events(event_account_address, event_handle, event_field_name, event_offset);
`
	_, err = s.ds.ExecContext(ctx, indexSQL)
	if err != nil {
		return fmt.Errorf("failed to create index on aptos.events: %w", err)
	}

	s.schemaEnsured = true
	return nil
}

type EventRecord struct {
	ID                  uint64
	EventAccountAddress string
	EventHandle         string
	EventFieldName      string
	EventOffset         *uint64
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

	s.rwMutex.Lock()
	defer s.rwMutex.Unlock()

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
ON CONFLICT (event_account_address, event_handle, event_field_name, tx_version)
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
	s.rwMutex.RLock()
	defer s.rwMutex.RUnlock()

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
		baseSQL += " ORDER BY tx_version " + direction
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

	rows, err := s.ds.QueryContext(ctx, baseSQL, args...)
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
		if err := json.Unmarshal(dataBytes, &data); err != nil {
			return nil, fmt.Errorf("failed to unmarshal event data: %w", err)
		}
		record.Data = data
		records = append(records, record)
	}

	return records, nil
}

func (s *DBStore) GetLatestOffset(ctx context.Context, eventAccountAddress, eventHandle, eventFieldName string) (uint64, error) {
	s.rwMutex.RLock()
	defer s.rwMutex.RUnlock()

	querySQL := `
SELECT COALESCE(MAX(event_offset), 0) FROM aptos.events
WHERE event_account_address = $1 AND event_handle = $2 AND event_field_name = $3
`

	var offset uint64
	err := s.ds.QueryRowxContext(ctx, querySQL, eventAccountAddress, eventHandle, eventFieldName).Scan(&offset)
	if err != nil {
		return 0, fmt.Errorf("failed to get latest offset: %w", err)
	}

	return offset, nil
}

func (s *DBStore) GetTxVersionByID(ctx context.Context, id uint64) (uint64, error) {
	s.rwMutex.RLock()
	defer s.rwMutex.RUnlock()

	querySQL := `
SELECT tx_version FROM aptos.events
WHERE id = $1
`

	var txVersion uint64
	err := s.ds.QueryRowxContext(ctx, querySQL, id).Scan(&txVersion)
	if err != nil {
		return 0, fmt.Errorf("failed to fetch tx_version for id %d: %w", id, err)
	}

	return txVersion, nil
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
