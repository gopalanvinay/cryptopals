package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/gopalavinay/cryptopals"
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

	var largestIdenticalBlocksCount int
	var candidateLine string
	var idx int
	for i, line := range fileLines {
		data, err := hex.DecodeString(line)
		if err != nil {
			log.Fatal(err)
		}

		isLikelyECBCandidate, dist, err := cryptopals.DetectAESECB(data)
		if isLikelyECBCandidate {
			if dist > largestIdenticalBlocksCount {
				largestIdenticalBlocksCount = dist
				candidateLine = line
				idx = i
			}
		}
	}

	fmt.Printf("The likely AES ECB encrypted line is at #%d\n", idx)
	fmt.Printf("The likely AES ECB encrypted line is: %s\n", candidateLine)
	fmt.Printf("The largest identical block count in this line is %d\n", largestIdenticalBlocksCount)
}
