package bind

import (
	"encoding/json"
)

type FunctionParameter struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type FunctionInfo struct {
	Package    string              `json:"package"`
	Module     string              `json:"module"`
	Name       string              `json:"name"`
	Parameters []FunctionParameter `json:"parameters"`
}

func (f FunctionInfo) String() string {
	out, err := json.Marshal(f)
	if err != nil {
		panic(err)
	}
	return string(out)
}

type FunctionInfos []FunctionInfo

func (f FunctionInfos) String() string {
	out, err := json.Marshal(f)
	if err != nil {
		panic(err)
	}
	return string(out)
}

func ParseFunctionInfo(info ...string) (FunctionInfos, error) {
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

func MustParseFunctionInfo(info ...string) FunctionInfos {
	infos, err := ParseFunctionInfo(info...)
	if err != nil {
		panic(err)
	}
	return infos
}

func CombineFunctionInfos(infos ...FunctionInfos) FunctionInfos {
	var result []FunctionInfo
	for _, info := range infos {
		result = append(result, info...)
	}
	return result
}
