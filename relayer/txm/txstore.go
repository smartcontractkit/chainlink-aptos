package txm

type AccountStore struct{}

func newAccountStore() *AccountStore {
	return &AccountStore{}
}

func (a *AccountStore) GetTotalInflightCount() int {
	return 0
}
