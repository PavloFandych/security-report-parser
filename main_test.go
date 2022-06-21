package main

import (
	"encoding/json"
	"os"
	"testing"
)

func BenchmarkFetch(b *testing.B) {
	inputPath := "./resources/trivy.json"

	data, err := os.ReadFile(inputPath)
	check(err)

	trivyData := TrivyData{}
	err = json.Unmarshal(data, &trivyData)
	check(err)

	target := Java
	severity := Critical
	metadata := true

	for i := 0; i < b.N; i++ {
		fetch(&UserConfig{Path: &inputPath, Target: &target, Severity: &severity, Metadata: &metadata}, &trivyData)
	}
}
