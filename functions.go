package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

func userConfig() (*UserConfig, error) {
	path := flag.String("path", EmptyString, PathUsage)
	target := flag.String("target", All, TargetUsage)
	severity := flag.String("severity", All, SeverityUsage)
	prettyPrint := flag.Bool("pretty", false, PrettyPrintUsage)
	flag.Parse()
	if *path == EmptyString {
		return nil, errors.New(NoPath)
	}
	return &UserConfig{Path: path, Target: target, Severity: severity, PrettyPrint: prettyPrint}, nil
}

func check(e error) {
	if e != nil {
		fmt.Println(e)
		os.Exit(1)
	}
}

func java(target *string) bool {
	return Java == *target
}

func nodeJs(target *string) bool {
	return NodeJs == *target
}

func defaultFunc(target *string) bool {
	value := *target
	return NodeJs != value && Java != value
}

func all[T any](input *T) bool {
	return true
}

func critical(severity *string) bool {
	return Critical == *severity
}

func high(severity *string) bool {
	value := *severity
	return Critical == value || High == value
}

func medium(severity *string) bool {
	value := *severity
	return Critical == value || High == value || Medium == value
}
