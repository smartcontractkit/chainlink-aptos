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
	Consts       []*tmplConst
	ViewFuncs    []*tmplFunc
	EntryFuncs   []*tmplFunc
	OtherFuncs   []*tmplFunc
	Imports      []*tmplImport
}

type tmplStruct struct {
	Name   string
	Fields []*tmplField
}

type tmplConst struct {
	Name  string
	Type  tmplType
	Value string
}

type tmplOption struct {
	UnderlyingGoType string
}

type tmplImport struct {
	Path        string // The import path, e.g. github.com/smartcontractkit/chainlink-aptos/path/etc
	PackageName string // The package name to import this import with, e.g. module_ocr3_base
}

type tmplType struct {
	GoType          string
	GoInternalType  string
	MoveType        string
	MoveInteralType string

	Import *tmplImport // Optional go import to add for this type

	// Special types

	StdOption *tmplOption
	StdObject bool
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

func Convert(pkg, mod string, structs []parse.Struct, functions []parse.Func, consts []parse.Const, externalStructs []parse.ExternalStruct) (tmplData, error) {
	data := tmplData{
		Package: pkg,
		Module:  mod,
	}
	structMap := make(map[string]parse.Struct)
	importMap := make(map[string]*tmplImport)
	for _, s := range structs {
		out := &tmplStruct{
			Name:   s.Name,
			Fields: nil,
		}
		structMap[s.Name] = s
		data.Structs = append(data.Structs, out)
	}
	for i, s := range data.Structs {
		parsedStruct := structMap[s.Name]
		for _, field := range parsedStruct.Fields {
			goType, err := createGoTypeFromMove(field.Type, structMap, externalStructs)
			if err != nil {
				log.Printf("WARNING: Ignoring unknown type of struct %q: %v\n", s.Name, field.Type)
				continue
			}
			data.Structs[i].Fields = append(data.Structs[i].Fields, &tmplField{
				Type: goType,
				Name: ToUpperCamelCase(field.Name),
			})
			if goType.Import != nil {
				importMap[goType.Import.Path] = goType.Import
			}
		}
	}

	// Constants
	for _, c := range consts {
		out := &tmplConst{
			Name:  c.Name,
			Type:  tmplType{},
			Value: c.Value,
		}
		typ, err := createGoTypeFromMove(c.Type, nil, nil)
		if err != nil {
			panic(fmt.Sprintf("Failed to parse const %v: %v", c.Name, err))
		}
		if !typ.IsGoConstant() {
			// Skip constants that cannot be expressed as Go constants
			continue
		}
		out.Type = typ
		data.Consts = append(data.Consts, out)
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
			// external types aren't supported as parameters, therefore passing no externalStructs
			typ, err := createGoTypeFromMove(param.Type, structMap, nil)
			if err != nil {
				if f.IsEntry {
					panic(fmt.Sprintf("Function %v has unsupported parameter %v, type %v", f.Name, param.Name, param.Type))
				} else {
					log.Printf("WARNING: Ignoring function %v due to unknown parameter type %v: %v\n", f.Name, param.Name, param.Type)
					skip = true
					break
				}
			}
			if typ.StdOption != nil {
				if f.IsEntry {
					// 0x1::option::Option parameters in entry functions will be represented by pointers to the underlying type.
					//  0x1::option::Option<u32>                 -> *uint32
					//  0x1::option::Option<0x1::string::String> -> *string
					//  0x1::option::Option<u256>                -> **big.Int
					// Note the double pointer on e.g. **big.Int - this is due to the bcs utils automatically dereferencing the pointer if it is set,
					// which would lead to big.Int trying to be being serialized, which is currently unsupported.
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
			typ, err := createGoTypeFromMove(returnType, structMap, externalStructs)
			if err != nil {
				if f.IsView {
					// If the function is a view function and has an unknown return type, panic
					panic(fmt.Sprintf("Function %v has an unknown return type: %v: %v", f.Name, returnType, err))
				} else {
					log.Printf("WARNING: Ignoring function %v due to unknown return type: %v", f.Name, returnType)
					skip = true
					break
				}
			}
			out.Returns = append(out.Returns, typ)
			if typ.Import != nil {
				importMap[typ.Import.Path] = typ.Import
			}
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
	for _, v := range importMap {
		data.Imports = append(data.Imports, v)
	}
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
