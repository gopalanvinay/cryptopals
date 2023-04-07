package cryptopals

import (
	"fmt"
	"testing"
)

func TestSingleXORCipher(t *testing.T) {

	testcases := []struct {
		name              string
		input             string
		expectedPlaintext string
		expectedKey       string
	}{
		{
			name:              "basic",
			input:             "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
			expectedPlaintext: "Cooking MC's like a pound of bacon",
			expectedKey:       "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			s, b, _, err := DecodeCaesar(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			t.Logf("received %s, %s", s, b)
		})
	}
}

func TestLetterRatio(t *testing.T) {
	testcases := []struct {
		name           string
		input          string
		expectedOutput float64
	}{
		{
			name:           "basic",
			input:          "Cooking MC's like a pound of bacon",
			expectedOutput: 0.97,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			ratio := letterRatio([]byte(tt.input))

			if fmt.Sprintf("%.2f", ratio) != fmt.Sprintf("%.2f", tt.expectedOutput) {
				t.Fatalf("expected %f got %f", tt.expectedOutput, ratio)
			}
		})
	}
}
