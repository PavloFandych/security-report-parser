package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
)

func initUserConfig() *UserConfig {
	path := flag.String("path", EmptyString, PathUsage)
	target := flag.String("target", All, TargetUsage)
	severity := flag.String("severity", All, SeverityUsage)
	metadata := flag.Bool("metadata", false, MetadataUsage)
	flag.Parse()
	return &UserConfig{Path: path, Target: target, Severity: severity, Metadata: metadata}
}

func check(e error) {
	if e != nil {
		fmt.Println(e)
		os.Exit(1)
	}
}

func fetch(uc *UserConfig, td *TrivyData) ([]VulnerabilityData, error) {
	switch *uc.Target {
	case All:
		switch *uc.Severity {
		case All, Low:
			return filter(td.Results, all[string], all[string]), nil
		case Critical:
			return filter(td.Results, all[string], critical), nil
		case High:
			return filter(td.Results, all[string], high), nil
		case Medium:
			return filter(td.Results, all[string], medium), nil
		default:
			return nil, errors.New(UnknownSeverityLevel)
		}
	case Java:
		switch *uc.Severity {
		case All, Low:
			return filter(td.Results, java, all[string]), nil
		case Critical:
			return filter(td.Results, java, critical), nil
		case High:
			return filter(td.Results, java, high), nil
		case Medium:
			return filter(td.Results, java, medium), nil
		default:
			return nil, errors.New(UnknownSeverityLevel)
		}
	case NodeJs:
		switch *uc.Severity {
		case All, Low:
			return filter(td.Results, nodeJs, all[string]), nil
		case Critical:
			return filter(td.Results, nodeJs, critical), nil
		case High:
			return filter(td.Results, nodeJs, high), nil
		case Medium:
			return filter(td.Results, nodeJs, medium), nil
		default:
			return nil, errors.New(UnknownSeverityLevel)
		}
	default:
		switch *uc.Severity {
		case All, Low:
			return filter(td.Results, defaultFunc, all[string]), nil
		case Critical:
			return filter(td.Results, defaultFunc, critical), nil
		case High:
			return filter(td.Results, defaultFunc, high), nil
		case Medium:
			return filter(td.Results, defaultFunc, medium), nil
		default:
			return nil, errors.New(UnknownSeverityLevel)
		}
	}
}

func filter(results []ResultsData, byTarget func(string) bool, bySeverity func(string) bool) []VulnerabilityData {
	result := make([]VulnerabilityData, 0)
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
	val, err := json.MarshalIndent(t, EmptyString, Ident)
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

func printOut(uc *UserConfig, td *TrivyData, vulnerabilities []VulnerabilityData) {
	output, err := pretty(vulnerabilities)
	check(err)
	if *uc.Metadata {
		metadataOutput, err := pretty(td.Metadata)
		check(err)
		fmt.Println(metadataOutput)
	}
	fmt.Println(output)
}
