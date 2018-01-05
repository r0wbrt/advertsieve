package main

import (
	"os"
	"strings"
	"bufio"
	"fmt"
)

func main() {
	hostFile := strings.Join(os.Args[1:], " ")
	file, err := os.Open(hostFile)
	if err != nil {
		return
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		
		if len(line) <= 0 {
			continue
		}
		
		if line[0] == '#' {
			continue
		}
		
		pieces := strings.Split(line, " ")
		
		if len(pieces) != 2 {
			continue
		}
		
		fmt.Println(pieces[1])
		
	}
}
