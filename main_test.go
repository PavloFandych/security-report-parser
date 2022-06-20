package main

import (
	"encoding/json"
	"os"
	"testing"
)

const inputPath = "./resources/trivy.json"

func BenchmarkFetch(b *testing.B) {
	data, err := os.ReadFile(inputPath)
	check(err)

	trivyData := TrivyData{}
	err = json.Unmarshal(data, &trivyData)
	check(err)

	target := Java
	severity := Critical
	var vulnerabilities []VulnerabilityData
	for i := 0; i < b.N; i++ {
		fetch(&target, &severity, &trivyData, vulnerabilities)
	}
}
