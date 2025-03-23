package template

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"go/format"
	"log"
	"slices"
	"strings"
	"text/template"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/cmd/bindgen/parse"
)

//go:embed go.tmpl
var tmpl string

type tmplData struct {
	Package      string
	Module       string
	FunctionInfo string
	Structs      []*tmplStruct
	ViewFuncs    []*tmplFunc
	EntryFuncs   []*tmplFunc
	OtherFuncs   []*tmplFunc
}

type tmplStruct struct {
	Name   string
	Fields []*tmplField
}

type tmplOption struct {
	UnderlyingGoType string
}

type tmplType struct {
	GoType   string
	MoveType string

	Option *tmplOption
}

type tmplField struct {
	Name string
	Type tmplType
}

type tmplFunc struct {
	Name     string
	MoveName string
	Params   []*tmplField
	Returns  []tmplType
}

func Convert(pkg, mod string, structs []parse.Struct, functions []parse.Func) (tmplData, error) {
	data := tmplData{
		Package: pkg,
		Module:  mod,
	}
	structMap := make(map[string]*parse.Struct)
	for _, s := range structs {
		out := &tmplStruct{
			Name:   s.Name,
			Fields: nil,
		}
		structMap[s.Name] = &s
		data.Structs = append(data.Structs, out)
	}
	for i, s := range data.Structs {
		parsedStruct := structMap[s.Name]
		for _, field := range parsedStruct.Fields {
			goType, err := createGoTypeFromMove(field.Type, structMap)
			if err != nil {
				log.Printf("WARNING: Ignoring unknown type of struct %q: %v\n", s.Name, field.Type)
				continue
			}
			data.Structs[i].Fields = append(data.Structs[i].Fields, &tmplField{
				Type: goType,
				Name: ToUpperCamelCase(field.Name),
			})
		}
	}

	var functionInfos []bind.FunctionInfo

	for _, f := range functions {
		if f.Name == "init_module" {
			continue
		}
		out := &tmplFunc{
			Name:     ToUpperCamelCase(f.Name),
			MoveName: f.Name,
			Params:   nil,
			Returns:  nil,
		}
		functionInfo := bind.FunctionInfo{
			Package:    pkg,
			Module:     mod,
			Name:       f.Name,
			Parameters: nil,
		}
		skip := false
		for _, param := range f.Params {
			if param.Type == "&signer" {
				// Ignore the signer parameter
				continue
			}
			typ, err := createGoTypeFromMove(param.Type, structMap)
			if err != nil {
				if f.IsEntry {
					panic(fmt.Sprintf("Function %v has unsupported parameter %v, type %v", f.Name, param.Name, param.Type))
				} else {
					log.Printf("WARNING: Ignoring function %v due to unknown parameter type %v: %v\n", f.Name, param.Name, param.Type)
					skip = true
					break
				}
			}
			if typ.Option != nil {
				if f.IsEntry {
					panic(fmt.Sprintf("Function %v has unsupported option::Option parameter %q: %v", f.Name, param.Name, typ.MoveType))
				} else {
					log.Printf("WARNING: Ignoring function %v due to unsupported option::Option parameter %q: %v", f.Name, param.Name, typ.MoveType)
					skip = true
					break
				}
			}
			out.Params = append(out.Params, &tmplField{
				Type: typ,
				Name: ToLowerCamelCase(param.Name),
			})
			functionInfo.Parameters = append(functionInfo.Parameters, bind.FunctionParameter{
				Name: param.Name,
				Type: typ.MoveType,
			})
		}
		for _, returnType := range f.ReturnTypes {
			typ, err := createGoTypeFromMove(returnType, structMap)
			if err != nil {
				if f.IsEntry {
					panic(fmt.Sprintf("Function %v has an unknown return type: %v: %v", f.Name, returnType, err))
				} else {
					log.Printf("WARNING: Ignoring function %v due to unknown return type: %v", f.Name, returnType)
					skip = true
					break
				}
			}
			out.Returns = append(out.Returns, typ)
		}
		if skip {
			continue
		}
		if f.IsView {
			data.ViewFuncs = append(data.ViewFuncs, out)
		} else if f.IsEntry {
			data.EntryFuncs = append(data.EntryFuncs, out)
			functionInfos = append(functionInfos, functionInfo)
		} else {
			data.OtherFuncs = append(data.OtherFuncs, out)
			functionInfos = append(functionInfos, functionInfo)
		}
	}
	slices.SortFunc(functionInfos, func(a, b bind.FunctionInfo) int {
		return strings.Compare(a.Name, b.Name)
	})
	marshalledInfo, err := json.Marshal(functionInfos)
	if err != nil {
		return tmplData{}, err
	}
	data.FunctionInfo = string(marshalledInfo)
	return data, nil
}

func Generate(data tmplData) (string, error) {
	funcs := template.FuncMap{
		"toLowerCamel": ToLowerCamelCase,
		"toUpperCamel": ToUpperCamelCase,
	}

	tpl := template.Must(template.New("").Funcs(funcs).Parse(tmpl))
	buffer := new(bytes.Buffer)
	if err := tpl.Execute(buffer, data); err != nil {
		return "", err
	}
	bb := buffer.Bytes()
	formatted, err := format.Source(bb)
	if err == nil {
		return string(formatted), nil
	}
	return string(bb), nil
}

var UppercaseWords []string

// ToUpperCamelCase converts an under-score string to a camel-case string
func ToUpperCamelCase(input string) string {
	parts := strings.Split(input, "_")
	for i, s := range parts {
		if len(s) > 0 {
			for _, word := range UppercaseWords {
				if strings.EqualFold(word, s) {
					s = word
				}
			}
			parts[i] = strings.ToUpper(s[:1]) + s[1:]
		}
	}
	return strings.Join(parts, "")
}

func ToLowerCamelCase(input string) string {
	parts := strings.Split(input, "_")
	for i, s := range parts {
		if len(s) > 0 {
			if i != 0 {
				for _, word := range UppercaseWords {
					if strings.EqualFold(word, s) {
						s = word
					}
				}
				parts[i] = strings.ToUpper(s[:1]) + s[1:]
			}
		}
	}
	return strings.Join(parts, "")
}
