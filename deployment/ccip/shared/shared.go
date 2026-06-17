package shared

import (
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
)

type TokenSymbol string

func (ts TokenSymbol) String() string {
	return string(ts)
}

const (
	LinkSymbol TokenSymbol = "LINK"
	APTSymbol  TokenSymbol = "APT"

	AptosAPTAddress = "0xa"
)

var (
	AptosMCMSType               cldf.ContractType = "AptosManyChainMultisig"
	AptosCurseMCMSType          cldf.ContractType = "AptosCurseMCMS"
	AptosCCIPType               cldf.ContractType = "AptosCCIP"
	AptosReceiverType           cldf.ContractType = "AptosReceiver"
	AptosManagedTokenPoolType   cldf.ContractType = "AptosManagedTokenPool"
	AptosRegulatedTokenPoolType cldf.ContractType = "AptosRegulatedTokenPool"
	AptosManagedTokenType       cldf.ContractType = "AptosManagedTokenType"
	AptosRegulatedTokenType     cldf.ContractType = "AptosRegulatedTokenType"
	AptosTestTokenType          cldf.ContractType = "AptosTestToken"
	BurnMintTokenPool           cldf.ContractType = "BurnMintTokenPool"
	BurnFromMintTokenPool       cldf.ContractType = "BurnFromMintTokenPool"
	LockReleaseTokenPool        cldf.ContractType = "LockReleaseTokenPool"
)
