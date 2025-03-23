package bind

import (
	"encoding/json"
)

type FunctionInfo struct {
	Package    string              `json:"package"`
	Module     string              `json:"module"`
	Name       string              `json:"name"`
	Parameters []FunctionParameter `json:"parameters"`
}

type FunctionParameter struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

func ParseFunctionInfo(info ...string) ([]FunctionInfo, error) {
	var result []FunctionInfo
	for _, s := range info {
		var temp []FunctionInfo
		if err := json.Unmarshal([]byte(s), &temp); err != nil {
			return nil, err
		}
		result = append(result, temp...)
	}
	return result, nil
}

func MustParseFunctionInfo(info ...string) []FunctionInfo {
	result, err := ParseFunctionInfo(info...)
	if err != nil {
		panic(err)
	}
	return result
}
