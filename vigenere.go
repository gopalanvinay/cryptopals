package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
)

func VigenereEncrypt(msg, key []byte) string {
	keyLength := len(key)
	var idx int

	cipher := make([]byte, len(msg))

	for i := range msg {
		cipher[i] = msg[i] ^ key[idx]

		idx += 1
		if idx == keyLength {
			idx = 0
		}
	}

	return hex.EncodeToString(cipher)
}

func GetVigenereKeySize(ciphertext string) (int, error) {

	// largest possible normalized value
	minNormalizedDistance := 1.0
	var bestKeySize int
	b, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return 0, err
	}

	for keySize := 2; keySize <= 40; keySize++ {
		// Get two slices between every jump size
		// average the total hamming distances for all
		// possible slices
		// normalize the final value
		jumpSize := 4 * keySize
		numTotalJumps := (len(b) / jumpSize) - 1

		s := 0
		var dist int
		for blockNum := 0; blockNum < numTotalJumps; blockNum++ {
			firstSlice := b[(blockNum * jumpSize):(blockNum*jumpSize + keySize)]
			secondSlice := b[(blockNum*jumpSize + keySize):(blockNum*jumpSize + 2*keySize)]
			dist, err = hamming(firstSlice, secondSlice)
			if err != nil {
				return 0, err
			}

			s += dist
		}

		// divide by keysize and total number of bits
		normalized := float64(s) / (float64(keySize) * float64(numTotalJumps) * 8.0)

		if normalized < minNormalizedDistance {
			minNormalizedDistance = normalized
			bestKeySize = keySize
		}
	}

	return bestKeySize, nil
}

func sliceBlocksByKeyLength(b []byte, keyLength int) [][]byte {
	numSlices := len(b) / keyLength
	numRemainingBytes := len(b) % keyLength
	// there can be an extra slice that has remaining bytes
	var sliceLength int
	if numRemainingBytes > 0 {
		sliceLength = numSlices + 1
	} else {
		sliceLength = numSlices
	}
	slices := make([][]byte, sliceLength)
	for i := 0; i < numSlices; i++ {
		slice := b[(i * keyLength):(i*keyLength + keyLength)]
		slices[i] = slice
	}

	if numRemainingBytes > 0 {
		dataLength := len(b)
		extraSlice := make([]byte, keyLength)
		for idx := numRemainingBytes; idx >= 0; idx-- {
			extraSlice[numRemainingBytes-idx] = b[(dataLength - idx - 1)]
		}
		slices[numSlices] = extraSlice
	}
	return slices
}

func transposeBlocks(slices [][]byte, keyLength int) [][]byte {
	caesarBlocks := make([][]byte, keyLength)

	for i := 0; i < keyLength; i++ {
		currentBlock := make([]byte, len(slices))
		for j := 0; j < len(slices); j++ {
			currentBlock[j] = slices[j][i]
		}
		caesarBlocks[i] = currentBlock
	}

	return caesarBlocks
}

func getVigenereData(transposed [][]byte) ([]string, string, error) {
	keys := make([]string, len(transposed))
	texts := make([]string, len(transposed))

	for i, block := range transposed {
		s := hex.EncodeToString(block)

		plainText, _, idx, err := DecodeCaesar(s)
		if err != nil {
			return nil, "", err
		}

		keys[i] = string(byte(idx))
		texts[i] = plainText
	}

	return texts, strings.Join(keys, ""), nil
}

func rebuildMessage(plainTexts []string, keyLength int, key string) (string, error) {
	blocks := make([][]byte, keyLength)
	for i, text := range plainTexts {
		block := []byte(text)
		blocks[i] = block
	}

	// all blocks are of equal lengths
	minBlockLength := len(blocks[0])
	slices := make([][]byte, minBlockLength)

	for i := 0; i < minBlockLength; i++ {
		slice := make([]byte, keyLength)
		for j := 0; j < keyLength; j++ {
			slice[j] = blocks[j][i]
		}

		slices[i] = slice
	}

	messageSlices := make([]string, len(slices))
	for i, byteSlice := range slices {
		if i == len(slices)-1 {
			byteSlice, _ = xor(byteSlice, []byte(key))
		} else {
			messageSlices[i] = string(byteSlice)
		}
	}

	return strings.Join(messageSlices, ""), nil
}

func DecodeVigenere(ciphertext string) (string, string, error) {
	keyLength, err := GetVigenereKeySize(ciphertext)
	if err != nil {
		return "", "", err
	}

	b, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", "", err
	}

	slices := sliceBlocksByKeyLength(b, keyLength)

	transposed := transposeBlocks(slices, keyLength)
	transposedPlaintexts, key, err := getVigenereData(transposed)
	if err != nil {
		return "", "", err
	}

	plaintext, err := rebuildMessage(transposedPlaintexts, keyLength, key)
	if err != nil {
		return "", "", err

	}

	return plaintext, key, nil

}
