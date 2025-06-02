package chainreader

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query/primitives"
)

type DBStore struct {
	ds            sqlutil.DataSource
	rwMutex       sync.RWMutex
	schemaEnsured bool
}

func NewDBStore(ds sqlutil.DataSource) *DBStore {
	return &DBStore{ds: ds}
}

func (s *DBStore) EnsureSchema(ctx context.Context) error {
	if s.schemaEnsured {
		return nil
	}

	s.rwMutex.Lock()
	defer s.rwMutex.Unlock()

	schemaSQL := `
CREATE SCHEMA IF NOT EXISTS aptos;
`
	_, err := s.ds.ExecContext(ctx, schemaSQL)
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

	for _, record := range records {
		data, err := json.Marshal(record.Data)
		if err != nil {
			return fmt.Errorf("failed to marshal event data for handle %s: %w", record.EventHandle, err)
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
			return fmt.Errorf("failed to insert event (handle: %s, field_name: %s, offset: %v): %w", record.EventHandle, record.EventFieldName, record.EventOffset, err)
		}
	}

	return nil
}

func (s *DBStore) QueryEvents(ctx context.Context, eventAccountAddress, eventHandle, eventFieldName string, expressions []query.Expression, limitAndSort query.LimitAndSort) ([]EventRecord, error) {
	s.rwMutex.Lock()
	defer s.rwMutex.Unlock()

	baseSQL := `
SELECT id, event_account_address, event_handle, event_field_name, event_offset, tx_version, block_height, block_hash, block_timestamp, data
FROM aptos.events
WHERE event_account_address = $1 AND event_handle = $2 AND event_field_name = $3
`

	args := []interface{}{eventAccountAddress, eventHandle, eventFieldName}
	argCount := 4

	tsFilter, hasTSFilter := extractTimestampFilter(expressions)
	if hasTSFilter {
		baseSQL += fmt.Sprintf(" AND block_timestamp >= $%d", argCount)
		args = append(args, tsFilter)
		argCount++
	}

	for _, expr := range expressions {
		if expr.IsPrimitive() {
			switch v := expr.Primitive.(type) {
			case *primitives.Comparator:
				for _, valueCmp := range v.ValueComparators {
					jsonPath := buildJsonPathExpr("data", v.Name)

					var condition string
					if isNumeric(valueCmp.Value) {
						condition = fmt.Sprintf("CAST(%s AS numeric) %s $%d", jsonPath, operatorSQL(valueCmp.Operator), argCount)
					} else {
						condition = fmt.Sprintf("%s %s $%d", jsonPath, operatorSQL(valueCmp.Operator), argCount)
					}

					baseSQL += " AND " + condition
					args = append(args, valueCmp.Value)
					argCount++
				}
			}
		}
	}

	if len(limitAndSort.SortBy) > 0 {
		direction := "ASC"
		if sortDir, ok := limitAndSort.SortBy[0].(query.SortBySequence); ok && sortDir.GetDirection() == query.Desc {
			direction = "DESC"
		}
		baseSQL += " ORDER BY tx_version " + direction
	}

	if limitAndSort.Limit.Count > 0 {
		baseSQL += fmt.Sprintf(" LIMIT %d", limitAndSort.Limit.Count)
	}

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
	s.rwMutex.Lock()
	defer s.rwMutex.Unlock()

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
	s.rwMutex.Lock()
	defer s.rwMutex.Unlock()

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
