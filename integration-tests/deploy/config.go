package deploy

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

var (
	GETH_ACC_KEY        = "348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8709"
	GETH_ACC_ADDRESS    = "0xb8CE9ab6943e0eCED004cDe8e3bBed6568B2Fa01"
	DEVNET_ACC          = "0xa337b42bd0eecf8fb59ee5929ea4541904b3c35a642040223f3d26ab57f59d6e"
	DEVNET_ACC_PRIV_KEY = "0xd477c65f88ed9e6d4ec6e2014755c3cfa3e0c44e521d0111a02868c5f04c41d4"
)

type CoreConfigToml struct {
	Log       CoreLogTomlConfig       `toml:"Log"`
	Feature   CoreFeatureTomlConfig   `toml:"Feature"`
	OCR2      CoreOCR2TomlConfig      `toml:"OCR2"`
	P2P       CoreP2PTomlConfig       `toml:"P2P"`
	WebServer CoreWebServerTomlConfig `toml:"WebServer"`
	Aptos     []CoreAptosTomlConfig   `toml:"Aptos"`
	EVM       []CoreEVMTomlConfig     `toml:"EVM"`
}

type CoreLogTomlConfig struct {
	Level string `toml:"Level"`
}

type CoreFeatureTomlConfig struct {
	FeedsManager bool `toml:"FeedsManager"`
	LogPoller    bool `toml:"LogPoller"`
	UICSAKeys    bool `toml:"UICSAKeys"`
}

type CoreOCR2TomlConfig struct {
	Enabled bool `toml:"Enabled"`
}

type CoreP2PTomlConfig struct {
	V2 CoreP2PV2TomlConfig `toml:"V2"`
}

type CoreP2PV2TomlConfig struct {
	Enabled         bool     `toml:"Enabled"`
	DeltaDial       string   `toml:"DeltaDial"`
	DeltaReconcile  string   `toml:"DeltaReconcile"`
	ListenAddresses []string `toml:"ListenAddresses"`
}

type CoreWebServerTomlConfig struct {
	HTTPPort     int               `toml:"HTTPPort"`
	TLS          CoreTLSTomlConfig `toml:"TLS"`
	AllowOrigins string            `toml:"AllowOrigins"`
}

type CoreTLSTomlConfig struct {
	HTTPSPort int `toml:"HTTPSPort"`
}

type CoreAptosTomlConfig struct {
	Enabled  bool                      `toml:"Enabled"`
	ChainID  string                    `toml:"ChainID"`
	Workflow CoreWorkflowTomlConfig    `toml:"Workflow"`
	Nodes    []CoreAptosNodeTomlConfig `toml:"Nodes"`
}

type CoreWorkflowTomlConfig struct {
	ForwarderAddress string `toml:"ForwarderAddress"`
	PublicKey        string `toml:"PublicKey"`
}

type CoreAptosNodeTomlConfig struct {
	Name string `toml:"Name"`
	URL  string `toml:"URL"`
}

type CoreEVMTomlConfig struct {
	ChainID            string                  `toml:"ChainID"`
	MinContractPayment string                  `toml:"MinContractPayment"`
	Enabled            bool                    `toml:"Enabled"`
	Nodes              []CoreEVMNodeTomlConfig `toml:"Nodes"`
}

type CoreEVMNodeTomlConfig struct {
	Name    string `toml:"Name"`
	WSURL   string `toml:"WSURL"`
	HTTPURL string `toml:"HTTPURL"`
}

type CoreConfig struct {
	Env           map[string]string
	Image         string
	Ports         []string
	Name          string
	Email         string
	Password      string
	Toml          CoreConfigToml
	CoreNodeCount int
	CoreP2PPort   int
}

type PostgresConfig struct {
	Env   map[string]string
	Image string
	Ports []string
	Name  string
}

type GethConfig struct {
	Env     map[string]string
	Image   string
	Ports   []string
	Name    string
	WSRPC   string
	HTTPRPC string
	ChainId string
}

type DevnetConfig struct {
	Env       map[string]string
	Image     string
	Ports     []string
	Name      string
	FaucetRPC string
	HTTPRPC   string
	ChainId   string
}

func ValidatePostgres() (*PostgresConfig, error) {
	var errs []string
	envVars := make(map[string]string)

	pgImage, ok := os.LookupEnv("POSTGRES_IMAGE")
	if !ok {
		errs = append(errs, "POSTGRES_IMAGE is required")
	}

	pgPort, ok := os.LookupEnv("POSTGRES_PORT")
	if !ok {
		errs = append(errs, "POSTGRES_PORT is required")
	}

	pgUser, ok := os.LookupEnv("POSTGRES_USER")
	if !ok {
		errs = append(errs, "POSTGRES_USER is required")
	}
	envVars["POSTGRES_USER"] = pgUser

	pgPassword, ok := os.LookupEnv("POSTGRES_PASSWORD")
	if !ok {
		errs = append(errs, "POSTGRES_PASSWORD is required")
	}
	envVars["POSTGRES_PASSWORD"] = pgPassword

	pgDB, ok := os.LookupEnv("POSTGRES_DB")
	if !ok {
		errs = append(errs, "POSTGRES_DB is required")
	}
	envVars["POSTGRES_DB"] = pgDB

	if len(errs) == 0 {
		return &PostgresConfig{
			Env:   envVars,
			Image: pgImage,
			Ports: []string{pgPort},
			Name:  "chainlink.postgres",
		}, nil
	}

	return nil, errors.New(strings.Join(errs, "; "))
}

func ValidateGeth() (*GethConfig, error) {
	var errs []string
	name := "chainlink-geth"

	gethImage, ok := os.LookupEnv("GETH_IMAGE")
	if !ok {
		errs = append(errs, "GETH_IMAGE is required")
	}

	gethWsPort, ok := os.LookupEnv("GETH_WS_PORT")
	if !ok {
		errs = append(errs, "GETH_WS_PORT is required")
	}

	gethHttpPort, ok := os.LookupEnv("GETH_HTTP_PORT")
	if !ok {
		errs = append(errs, "GETH_HTTP_PORT is required")
	}

	chainId, ok := os.LookupEnv("GETH_CHAIN_ID")
	if !ok {
		errs = append(errs, "GETH_CHAIN_ID is required")
	}

	if len(errs) == 0 {
		return &GethConfig{
			Image:   gethImage,
			Ports:   []string{gethWsPort, gethHttpPort},
			Name:    name,
			WSRPC:   fmt.Sprintf("ws://%s:%s", name, gethWsPort),
			HTTPRPC: fmt.Sprintf("http://%s:%s", name, gethHttpPort),
			ChainId: chainId,
		}, nil
	}

	return nil, errors.New(strings.Join(errs, "; "))
}

func ValidateDevnet() (*DevnetConfig, error) {
	var errs []string
	name := "chainlink-aptos.devnet"

	devnetImage, ok := os.LookupEnv("DEVNET_IMAGE")

	if !ok {
		errs = append(errs, "DEVNET_IMAGE is required")
	}

	devnetFaucetPort, ok := os.LookupEnv("DEVNET_FAUCET_PORT")
	if !ok {
		errs = append(errs, "DEVNET_FAUCET_PORT is required")
	}

	devnetHttpPort, ok := os.LookupEnv("DEVNET_HTTP_PORT")
	if !ok {
		errs = append(errs, "DEVNET_HTTP_PORT is required")
	}

	chainId, ok := os.LookupEnv("DEVNET_CHAIN_ID")
	if !ok {
		errs = append(errs, "DEVNET_CHAIN_ID is required")
	}

	if len(errs) == 0 {
		return &DevnetConfig{
			Image:     devnetImage,
			Ports:     []string{devnetFaucetPort, devnetHttpPort},
			Name:      name,
			FaucetRPC: fmt.Sprintf("http://%s:%s", name, devnetFaucetPort),
			HTTPRPC:   fmt.Sprintf("http://%s:%s/v1", name, devnetHttpPort),
			ChainId:   chainId,
		}, nil
	}

	return nil, errors.New(strings.Join(errs, "; "))
}

func ValidateCore() (*CoreConfig, error) {
	var errs []string
	name := "chainlink.core"

	coreImage, ok := os.LookupEnv("CORE_IMAGE")

	if !ok {
		errs = append(errs, "CORE_IMAGE is required")
	}

	coreVersion, ok := os.LookupEnv("CORE_VERSION")

	if !ok {
		errs = append(errs, "CORE_VERSION is required")
	}

	imageArg := fmt.Sprintf("%s:%s", coreImage, coreVersion)

	if coreVersion == "" || coreVersion == "none" {
		imageArg = coreImage
	}

	coreHttpPort, ok := os.LookupEnv("CORE_HTTP_PORT")
	if !ok {
		errs = append(errs, "CORE_HTTP_PORT is required")
	}

	coreP2PPort, ok := os.LookupEnv("CORE_P2P_PORT")

	if !ok {
		errs = append(errs, "CORE_P2P_PORT is required")
	}

	coreP2PPortParsed, err := strconv.Atoi(coreP2PPort)
	if err != nil {
		errs = append(errs, "CORE_P2P_PORT must be an integer")
	}

	coreNodeCount, ok := os.LookupEnv("CORE_NODE_COUNT")
	if !ok {
		errs = append(errs, "CORE_NODE_COUNT is required")
	}

	coreNodeCountParsed, err := strconv.Atoi(coreNodeCount)
	if err != nil {
		errs = append(errs, "CORE_NODE_COUNT must be an integer")
	}

	if len(errs) != 0 {
		return nil, errors.New(strings.Join(errs, "; "))
	}

	return &CoreConfig{
		Image:         imageArg,
		Ports:         []string{coreHttpPort},
		Name:          name,
		Email:         "notreal@fakeemail.ch",
		Password:      "fj293fbBnlQ!f9vNs",
		CoreNodeCount: coreNodeCountParsed,
		CoreP2PPort:   coreP2PPortParsed,
	}, nil

}
