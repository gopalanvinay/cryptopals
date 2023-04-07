package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	crypto "github.com/gopalavinay/cryptopals"
)

func main() {
	filePath := os.Args[1]
	readFile, err := os.Open(filePath)

	if err != nil {
		fmt.Println(err)
	}
	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)
	var fileLines []string

	for fileScanner.Scan() {
		fileLines = append(fileLines, fileScanner.Text())
	}

	readFile.Close()

	for _, line := range fileLines {
		plaintext, key, asciiIdx, err := crypto.DecodeCaesar(line)
		if err != nil && strings.Contains(err.Error(), "probably gibberish") {
			continue
		}

		fmt.Printf("Plaintext: %s\n", plaintext)
		fmt.Printf("Key: %s\n", key)
		fmt.Printf("Key 8bit value: %d\n\n", asciiIdx)

	}
}
