package deploy

type AccountTransaction struct {
	Version                 string    `json:"version"`
	Hash                    string    `json:"hash"`
	StateChangeHash         string    `json:"state_change_hash"`
	EventRootHash           string    `json:"event_root_hash"`
	StateCheckpointHash     *string   `json:"state_checkpoint_hash"` // Nullable
	GasUsed                 string    `json:"gas_used"`
	Success                 bool      `json:"success"`
	VMStatus                string    `json:"vm_status"`
	AccumulatorRootHash     string    `json:"accumulator_root_hash"`
	Changes                 []Change  `json:"changes"`
	Sender                  string    `json:"sender"`
	SequenceNumber          string    `json:"sequence_number"`
	MaxGasAmount            string    `json:"max_gas_amount"`
	GasUnitPrice            string    `json:"gas_unit_price"`
	ExpirationTimestampSecs string    `json:"expiration_timestamp_secs"`
	Payload                 Payload   `json:"payload"`
	Signature               Signature `json:"signature"`
	Events                  []Event   `json:"events"`
	Timestamp               string    `json:"timestamp"`
	Type                    string    `json:"type"`
}

type TransactionByHash struct {
	AccountTransaction
}

type Change struct {
	Address      string `json:"address,omitempty"`
	StateKeyHash string `json:"state_key_hash"`
	Data         Data   `json:"data,omitempty"`
	Handle       string `json:"handle,omitempty"`
	Key          string `json:"key,omitempty"`
	Value        string `json:"value,omitempty"`
	Type         string `json:"type"`
}

type Data struct {
	Type      string      `json:"type"`
	Data      interface{} `json:"data"`
	Key       string      `json:"key,omitempty"`
	KeyType   string      `json:"key_type,omitempty"`
	Value     interface{} `json:"value,omitempty"`
	ValueType string      `json:"value_type,omitempty"`
}

type Payload struct {
	Function      string        `json:"function"`
	TypeArguments []interface{} `json:"type_arguments"`
	Arguments     []interface{} `json:"arguments"`
	Type          string        `json:"type"`
}

type Signature struct {
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
	Type      string `json:"type"`
}

type Event struct {
	GUID           GUID      `json:"guid"`
	SequenceNumber string    `json:"sequence_number"`
	Type           string    `json:"type"`
	Data           EventData `json:"data"`
}

type GUID struct {
	CreationNumber string `json:"creation_number"`
	AccountAddress string `json:"account_address"`
}

type EventData struct {
	Benchmark           string `json:"benchmark,omitempty"`
	FeedId              string `json:"feed_id,omitempty"`
	Report              string `json:"report,omitempty"`
	Receiver            string `json:"receiver,omitempty"`
	ReportId            int    `json:"report_id,omitempty"`
	WorkflowExecutionId string `json:"workflow_execution_id,omitempty"`
}
