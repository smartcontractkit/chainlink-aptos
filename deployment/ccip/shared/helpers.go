package shared

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
)

func PopulateDataStore(addressBook cldf.AddressBook) (*datastore.MemoryDataStore, error) {
	addrs, err := addressBook.Addresses()
	if err != nil {
		return nil, err
	}

	ds := datastore.NewMemoryDataStore()
	for chainselector, chainAddresses := range addrs {
		for addr, typever := range chainAddresses {
			ref := datastore.AddressRef{
				ChainSelector: chainselector,
				Address:       addr,
				Type:          datastore.ContractType(typever.Type),
				Version:       &typever.Version,
				Qualifier:     fmt.Sprintf("%s-%s", addr, typever.Type),
			}

			if !typever.Labels.IsEmpty() {
				ref.Labels = datastore.NewLabelSet(typever.Labels.List()...)
			}

			if err = ds.Addresses().Add(ref); err != nil {
				return nil, err
			}
		}
	}

	return ds, nil
}
