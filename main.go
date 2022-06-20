package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func main() {
	path := flag.String("path", EmptyString, PathUsage)
	target := flag.String("target", All, TargetUsage)
	severity := flag.String("severity", All, SeverityUsage)
	metadata := flag.Bool("metadata", false, MetadataUsage)
	flag.Parse()

	if *path == EmptyString {
		fmt.Println(NoPath)
		os.Exit(1)
	}

	data, err := os.ReadFile(*path)
	check(err)

	trivyData := TrivyData{}
	err = json.Unmarshal(data, &trivyData)
	check(err)

	vulnerabilities := make([]VulnerabilityData, 0)
	vulnerabilities = fetch(target, severity, &trivyData, vulnerabilities)

	output, err := pretty(vulnerabilities)
	check(err)

	if *metadata {
		metadataOutput, err := pretty(trivyData.Metadata)
		check(err)
		fmt.Println(metadataOutput)
	}
	fmt.Println(output)
}
