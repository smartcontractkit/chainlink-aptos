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
	uppercase := flag.String("uppercase", "", "list of words to convert to uppercase")

	flag.Parse()

	log.Printf("Generating bindings for %s", *inputFile)

	if *uppercase != "" {
		for _, w := range strings.Split(*uppercase, ",") {
			template.UppercaseWords = append(template.UppercaseWords, strings.ToUpper(w))
		}
		log.Printf("Capitalizing %v words: %v", len(template.UppercaseWords), strings.Join(template.UppercaseWords, ", "))
	}

	file, err := os.Open(*inputFile)
	if err != nil {
		log.Fatal(err)
	}
	fileBytes, err := io.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}

	pkg, mod, err := parse.PackageModule(fileBytes)
	if err != nil {
		panic(err)
	}

	funcs, err := parse.Functions(fileBytes)
	if err != nil {
		panic(err)
	}
	log.Println("Parsed functions:")
	for i, viewFunc := range funcs {
		log.Println(i, viewFunc)
	}
	log.Println("----")
	structs, err := parse.Structs(fileBytes)
	if err != nil {
		panic(err)
	}
	log.Println("Parsed structs:")
	for i, structt := range structs {
		log.Println(i, structt)
	}

	log.Println("----")
	data, err := template.Convert(pkg, mod, structs, funcs)
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
