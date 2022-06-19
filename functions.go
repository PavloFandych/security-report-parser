package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func check(e error) {
	if e != nil {
		fmt.Println(e)
		os.Exit(1)
	}
}

func filter(results []ResultsData, byTarget func(string) bool, bySeverity func(string) bool,
	result []VulnerabilityData) []VulnerabilityData {
	for _, v := range results {
		if byTarget(v.Target) {
			for _, value := range v.Vulnerabilities {
				if bySeverity(value.Severity) {
					result = append(result, value)
				}
			}
		}
	}
	return result
}

func pretty[T any](t T) (string, error) {
	val, err := json.MarshalIndent(t, EmptyString, "  ")
	if err != nil {
		return EmptyString, err
	}
	return string(val), nil
}

func java(target string) bool {
	return Java == target
}

func nodeJs(target string) bool {
	return NodeJs == target
}

func defaultFunc(target string) bool {
	return NodeJs != target && Java != target
}

func all[T any](input T) bool {
	return true
}

func critical(severity string) bool {
	return Critical == severity
}

func high(severity string) bool {
	return Critical == severity || High == severity
}

func medium(severity string) bool {
	return Critical == severity || High == severity || Medium == severity
}

func unknownSeverityProcess() {
	fmt.Println("Unknown severity level")
	os.Exit(1)
}

func fetch(target *string, severity *string, td *TrivyData, result []VulnerabilityData) []VulnerabilityData {
	switch *target {
	case All:
		switch *severity {
		case All:
			result = filter(td.Results, all[string], all[string], result)
		case Critical:
			result = filter(td.Results, all[string], critical, result)
		case High:
			result = filter(td.Results, all[string], high, result)
		case Medium:
			result = filter(td.Results, all[string], medium, result)
		case Low:
			result = filter(td.Results, all[string], all[string], result)
		default:
			unknownSeverityProcess()
		}
	case Java:
		switch *severity {
		case All:
			result = filter(td.Results, java, all[string], result)
		case Critical:
			result = filter(td.Results, java, critical, result)
		case High:
			result = filter(td.Results, java, high, result)
		case Medium:
			result = filter(td.Results, java, medium, result)
		case Low:
			result = filter(td.Results, java, all[string], result)
		default:
			unknownSeverityProcess()
		}
	case NodeJs:
		switch *severity {
		case All:
			result = filter(td.Results, nodeJs, all[string], result)
		case Critical:
			result = filter(td.Results, nodeJs, critical, result)
		case High:
			result = filter(td.Results, nodeJs, high, result)
		case Medium:
			result = filter(td.Results, nodeJs, medium, result)
		case Low:
			result = filter(td.Results, nodeJs, all[string], result)
		default:
			unknownSeverityProcess()
		}
	default:
		switch *severity {
		case All:
			result = filter(td.Results, defaultFunc, all[string], result)
		case Critical:
			result = filter(td.Results, defaultFunc, critical, result)
		case High:
			result = filter(td.Results, defaultFunc, high, result)
		case Medium:
			result = filter(td.Results, defaultFunc, medium, result)
		case Low:
			result = filter(td.Results, defaultFunc, all[string], result)
		default:
			unknownSeverityProcess()
		}
	}
	return result
}
