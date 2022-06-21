package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
)

func userConfig() (*UserConfig, error) {
	path := flag.String("path", EmptyString, PathUsage)
	target := flag.String("target", All, TargetUsage)
	severity := flag.String("severity", All, SeverityUsage)
	metadata := flag.Bool("metadata", false, MetadataUsage)
	flag.Parse()
	if *path == EmptyString {
		return nil, errors.New(NoPath)
	}
	return &UserConfig{Path: path, Target: target, Severity: severity, Metadata: metadata}, nil
}

func check(e error) {
	if e != nil {
		fmt.Println(e)
		os.Exit(1)
	}
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
