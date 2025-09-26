package main

import (
	_ "embed"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/smartcontractkit/chainlink-aptos/cmd/bindgen/parse"
	"github.com/smartcontractkit/chainlink-aptos/cmd/bindgen/template"
)

func main() {
	inputFile := flag.String("input", "", "path to aptos file to parse")
	outputFolder := flag.String("output", "", "path to output directory")
	uppercase := flag.String("uppercase", "CCIP,MCMS,RMN,USDC", "list of words to convert to uppercase")
	externalStructs := flag.String("externalStructs", "", "comma-separated list of struct names, usage: --externalStructs ccip::ocr3_base::OCRConfig=github.com/smartcontractkit/chainlink-aptos/bindings/ccip/ocr3_base")

	flag.Parse()

	log.Printf("Generating bindings for %s", *inputFile)

	if *uppercase != "" {
		for _, w := range strings.Split(*uppercase, ",") {
			template.UppercaseWords = append(template.UppercaseWords, strings.ToUpper(w))
		}
		log.Printf("Capitalizing %v words: %v", len(template.UppercaseWords), strings.Join(template.UppercaseWords, ", "))
	}

	// Parse external structs
	var extStructs []parse.ExternalStruct
	if *externalStructs != "" {
		for _, s := range strings.Split(*externalStructs, ",") {
			// package::module::Struct=github.com/smartcontractkit/chainlink-aptos/bindings/path
			split := strings.Split(s, "=")
			if len(split) != 2 {
				log.Fatalf("Invalid external stucture definition: %v", s)
			}
			from := strings.Split(split[0], "::")
			if len(from) != 3 {
				log.Fatalf("Invalid external stucture definition: %v", s)
			}
			packageName := from[0]
			moduleName := from[1]
			structName := from[2]
			importPath := split[1]

			log.Printf("Importing struct %v::%v::%v from %v", packageName, moduleName, structName, importPath)
			extStructs = append(extStructs, parse.ExternalStruct{
				ImportPath: importPath,
				Package:    packageName,
				Module:     moduleName,
				Name:       structName,
			})
		}
	}

	file, err := os.Open(*inputFile)
	if err != nil {
		log.Fatal(err)
	}
	fileBytes, err := io.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}

	pkg, mod, moduleContent, err := parse.PackageModule(fileBytes)
	if err != nil {
		panic(err)
	}

	funcs, err := parse.Functions([]byte(moduleContent))
	if err != nil {
		panic(err)
	}
	log.Println("Parsed functions:")
	for i, viewFunc := range funcs {
		log.Println(i, viewFunc)
	}
	log.Println("----")
	structs, err := parse.Structs([]byte(moduleContent))
	if err != nil {
		panic(err)
	}
	log.Println("Parsed structs:")
	for i, structt := range structs {
		log.Println(i, structt)
	}
	log.Println("----")
	consts, err := parse.Consts([]byte(moduleContent))
	if err != nil {
		panic(err)
	}
	log.Println("Parsed consts:")
	for i, constt := range consts {
		log.Println(i, constt)
	}
	log.Println("----")

	data, err := template.Convert(pkg, mod, structs, funcs, consts, extStructs)
	if err != nil {
		log.Fatal(err)
	}
	t, err := template.Generate(data)
	if err != nil {
		log.Fatal(err)
	}

	outputFile := filepath.Join(*outputFolder, fmt.Sprintf("%s.go", data.Module))

	log.Printf("Writing output to %s", outputFile)
	_ = os.MkdirAll(filepath.Dir(outputFile), os.ModePerm)
	if err := os.WriteFile(outputFile, []byte(t), 0600); err != nil {
		panic(err)
	}
}
