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

	uc, err := userConfig()
	check(err)

	data, err := os.ReadFile(*uc.Path)
	check(err)

	td := TrivyData{}
	err = json.Unmarshal(data, &td)
	check(err)

	td.printOut(uc)
}
