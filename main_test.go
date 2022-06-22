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
	prettyPrint := false

	for i := 0; i < b.N; i++ {
		_, _ = trivyData.fetch(&UserConfig{
			Path:        &inputPath,
			Target:      &target,
			Severity:    &severity,
			PrettyPrint: &prettyPrint})
	}
}
