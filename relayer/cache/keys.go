package cache

import (
	"fmt"

	"github.com/aptos-labs/aptos-go-sdk"
)

type AccountResourceCacheKey struct {
	Address      aptos.AccountAddress
	ResourceType string
}

func (a AccountResourceCacheKey) String() string {
	return fmt.Sprintf("%s::%s", a.Address.String(), a.ResourceType)
}
