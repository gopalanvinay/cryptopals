package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/gopalavinay/cryptopals"
)

func main() {
	fileName := os.Args[1]
	key := os.Args[2]
	fileContent, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Fatal(err)
	}

	// Convert []byte to string
	text := string(fileContent)
	cipher, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		log.Fatal(err)
	}

	plaintext := cryptopals.DecryptAES_ECB(cipher, []byte(key), false)
	fmt.Printf("Plaintext: %s\n", plaintext)
}
