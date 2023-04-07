package cryptopals

import (
	"encoding/hex"
	"fmt"
)

func DecodeCaesar(inputHex string) (string, string, int, error) {
	ciphertext, err := hex.DecodeString(inputHex)
	if err != nil {
		return "", "", 0, err
	}

	var possibleKey string
	var possiblePlaintext string
	var bestRatioSoFar float64
	var index int

	bestRatioSoFar = 0

	for i := 0; i <= 255; i++ {
		char := byte(i)
		keystream := make([]byte, len(ciphertext))
		for j := range ciphertext {
			keystream[j] = char
		}

		msg, err := xor([]byte(ciphertext), keystream)
		if err != nil {
			return "", "", 0, err
		}

		msgLetterRatio := letterRatio(msg)

		if msgLetterRatio > bestRatioSoFar {
			index = i
			possibleKey = string(keystream)
			possiblePlaintext = string(msg)
			bestRatioSoFar = msgLetterRatio
		}
	}

	if !gibberishCheck(possiblePlaintext) {
		return "", "", 0, fmt.Errorf("probably gibberish; failed check")
	}

	if bestRatioSoFar < 0.75 {
		return "", "", 0, fmt.Errorf("probably gibberish; ratio=%f", bestRatioSoFar)
	}

	return possiblePlaintext, possibleKey, index, nil
}

func isAlphabet(n int) bool {
	return (n >= 65 && n <= 90) || (n >= 97 && n <= 122) || n == 32
}

func isASCII(n int) bool {
	return n >= 0 && n <= 127

}

func letterRatio(chars []byte) float64 {
	c := 0
	for i := range chars {
		if isAlphabet(int(chars[i])) {
			c += 1
		}
	}

	return float64(c) / float64(len(chars))
}

func gibberishCheck(txt string) bool {
	chars := []byte(txt)
	for i := range chars {
		if !isASCII(int(chars[i])) {
			return false
		}
	}

	return true
}
