package codec

import (
	"fmt"
)

func EncodeFunctionParams(argMap map[string]interface{}, params []AptosFunctionParam) ([]string, []any, error) {
	types := make([]string, len(params))
	values := make([]any, len(params))

	for i, paramConfig := range params {
		argValue, ok := argMap[paramConfig.Name]
		if !ok {
			if paramConfig.Required {
				return nil, nil, fmt.Errorf("missing argument: %s", paramConfig.Name)
			}
			argValue = paramConfig.DefaultValue
		}

		types[i] = paramConfig.Type
		values[i] = argValue
	}

	return types, values, nil
}
