package write_target

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// version | workflow_execution_id | timestamp | don_id | config_version | ...
type Report struct {
	Version             uint8
	WorkflowExecutionID string
	Timestamp           uint32
	DONID               uint32
	ConfigVersion       uint32
	ReportID            uint16
	Metadata            []byte
	Data                []byte
}

func decodeReport(rawReport []byte) (*Report, error) {
	if len(rawReport) < 109 {
		return nil, fmt.Errorf("invalid report length")
	}

	report := &Report{}
	buf := bytes.NewReader(rawReport)

	// Decode version
	var versionByte byte
	if err := binary.Read(buf, binary.BigEndian, &versionByte); err != nil {
		return nil, err
	}
	report.Version = uint8(versionByte)

	// Decode workflow_execution_id
	var workflowExecutionIDBytes [32]byte
	if _, err := buf.Read(workflowExecutionIDBytes[:]); err != nil {
		return nil, err
	}
	report.WorkflowExecutionID = hex.EncodeToString(workflowExecutionIDBytes[:])

	// Decode timestamp
	var timestampBytes [4]byte
	if _, err := buf.Read(timestampBytes[:]); err != nil {
		return nil, err
	}
	report.Timestamp = binary.BigEndian.Uint32(timestampBytes[:])

	// Decode don_id
	var donIDBytes [4]byte
	if _, err := buf.Read(donIDBytes[:]); err != nil {
		return nil, err
	}
	report.DONID = binary.BigEndian.Uint32(donIDBytes[:])

	// Decode config_version
	var configVersionBytes [4]byte
	if _, err := buf.Read(configVersionBytes[:]); err != nil {
		return nil, err
	}
	report.ConfigVersion = binary.BigEndian.Uint32(configVersionBytes[:])

	// Decode report_id
	var reportIDBytes [2]byte
	if _, err := buf.Read(reportIDBytes[:]); err != nil {
		return nil, err
	}
	report.ReportID = binary.BigEndian.Uint16(reportIDBytes[:])

	// Decode metadata
	report.Metadata = make([]byte, 64)
	if _, err := buf.Read(report.Metadata); err != nil {
		return nil, err
	}

	// Decode data
	report.Data = make([]byte, buf.Len())
	if _, err := buf.Read(report.Data); err != nil {
		return nil, err
	}

	return report, nil
}
