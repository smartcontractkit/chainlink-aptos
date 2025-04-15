package utils

import (
	"encoding/hex"
)

func DecodeHexRelaxed(hexStr string) ([]byte, error) {
	if len(hexStr) >= 2 && hexStr[0:2] == "0x" {
		hexStr = hexStr[2:]
	}
	if len(hexStr) == 0 {
		return []byte{}, nil
	}
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}
	return hex.DecodeString(hexStr)
}
