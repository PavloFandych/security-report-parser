package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func main() {
	path := flag.String("path", EmptyString, "path to JSON trivy report")
	target := flag.String("target", All, "vulnerability target: [Java, Node.js, other]")
	severity := flag.String("severity", All, "severity level: [ALL, CRITICAL, HIGH, MEDIUM, LOW]")
	metadata := flag.Bool("metadata", false, "print metadata: [true, false]")
	flag.Parse()

	if *path == EmptyString {
		fmt.Println("No path to JSON trivy report")
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
