package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	defer func() {
		if err := recover(); err != nil {
			fmt.Println("Error: ", err)
		}
	}()

	userConfig := initUserConfig()
	if *userConfig.Path == EmptyString {
		fmt.Println(NoPath)
		os.Exit(1)
	}

	data, err := os.ReadFile(*userConfig.Path)
	check(err)

	trivyData := TrivyData{}
	err = json.Unmarshal(data, &trivyData)
	check(err)

	vulnerabilities, err := fetch(userConfig, &trivyData)
	check(err)

	printOut(userConfig, &trivyData, vulnerabilities)
}
