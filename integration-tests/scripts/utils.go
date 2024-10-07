package scripts

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"path/filepath"
	"runtime"

	"github.com/joho/godotenv"
)

var (
	_, b, _, _ = runtime.Caller(0)
	// ProjectRoot Root folder of this project
	ProjectRoot = filepath.Join(filepath.Dir(b), "/../..")
	Contracts   = fmt.Sprintf("%s/contracts", ProjectRoot)
	Templates   = fmt.Sprintf("%s/integration-tests/templates", ProjectRoot)
	Cache       = fmt.Sprintf("%s/integration-tests/.cache", ProjectRoot)
	Logs        = fmt.Sprintf("%s/integration-tests/logs", ProjectRoot)
)

func LoadEnv() error {
	err := godotenv.Load(fmt.Sprintf("%s/.env", ProjectRoot))
	if err != nil {
		return err
	}

	return nil
}

func GetRandomName(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	buff := make([]byte, length)
	for i := range buff {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			panic(err)
		}
		buff[i] = charset[num.Int64()]
	}
	return string(buff)
}
