package main

import (
	"encoding/json"
	"os"
	"testing"
)

func BenchmarkFetch(b *testing.B) {
	data, err := os.ReadFile("/media/total/Data/GolandProjects/security-report-parser/resources/trivy.json")
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
