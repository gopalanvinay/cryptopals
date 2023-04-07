package cryptopals

import (
	"encoding/base64"
	"testing"
)

func TestVigenereEncrypt(t *testing.T) {
	testcases := []struct {
		name           string
		input          string
		key            string
		expectedOutput string
	}{
		{
			name:           "basic",
			input:          "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
			key:            "ICE",
			expectedOutput: "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			msg := []byte(tt.input)
			key := []byte(tt.key)
			cipher := VigenereEncrypt(msg, key)

			if string(cipher) != tt.expectedOutput {
				t.Fatalf("expected %s got %s", tt.expectedOutput, cipher)
			}
		})
	}
}

func TestDecodeKeySize(t *testing.T) {

	testcases := []struct {
		name            string
		ciphertext      string
		expectedKeySize int
	}{
		{
			name: "8-length",
			ciphertext: base64.StdEncoding.EncodeToString([]byte(VigenereEncrypt([]byte("On insensible possession oh particular attachment at excellence in. The books arose but miles happy she. It building contempt or interest children mistress of unlocked no. Offending she contained mrs led listening resembled. Delicate marianne absolute men dashwood landlord and offended. Suppose cottage between and way. Minuter him own clothes but observe country. Agreement far boy otherwise rapturous incommode favourite. "+
				"You vexed shy mirth now noise. Talked him people valley add use her depend letter. Allowance too applauded now way something recommend. Mrs age men and trees jokes fancy. Gay pretended engrossed eagerness continued ten. Admitting day him contained unfeeling attention mrs out."+
				"Ever man are put down his very. And marry may table him avoid. Hard sell it were into it upon. He forbade affixed parties of assured to me windows. Happiness him nor she disposing provision. Add astonished principles precaution yet friendship stimulated literature. State thing might stand one his plate. Offending or extremity therefore so difficult he on provision. Tended depart turned not are."+
				"Another journey chamber way yet females man. Way extensive and dejection get delivered deficient sincerity gentleman age. "+
				"Too end instrument possession contrasted motionless. Calling offence six joy feeling. Coming merits and was talent enough far. Sir joy northward sportsmen education. "+
				"Discovery incommode earnestly no he commanded if. Put still any about manor heard."+
				"Now led tedious shy lasting females off. Dashwood marianne in of entrance be on wondered possible building. Wondered sociable he carriage in speedily margaret. Up devonshire of he thoroughly insensible alteration. An mr settling occasion insisted distance ladyship so. Not attention say frankness intention out dashwoods now curiosity. Stronger ecstatic as no judgment daughter speedily thoughts. Worse downs nor might she court did nay forth these."+
				"Behaviour we improving at something to. Evil true high lady roof men had open. To projection considered it precaution an melancholy or. Wound young you thing worse along being ham. Dissimilar of favourable solicitude if sympathize middletons at. Forfeited up if disposing perfectly in an eagerness perceived necessary. Belonging sir curiosity discovery extremity yet forfeited prevailed own off. Travelling by introduced of mr terminated. Knew as miss my high hope quit. In curiosity shameless dependent knowledge up. "+
				"Yet bed any for travelling assistance indulgence unpleasing. Not thoughts all exercise blessing. Indulgence way everything joy alteration boisterous the attachment. Party we years to order allow asked of. We so opinion friends me message as delight. Whole front do of plate heard oh ought. His defective nor convinced residence own. Connection has put impossible own apartments boisterous. At jointure ladyship an insisted so humanity he. Friendly bachelor entrance to on by."),
				[]byte("FASTLANE")))),
			expectedKeySize: 8,
		},
		{
			name: "15-length",
			ciphertext: base64.StdEncoding.EncodeToString([]byte(VigenereEncrypt([]byte("On insensible possession oh particular attachment at excellence in. The books arose but miles happy she. It building contempt or interest children mistress of unlocked no. Offending she contained mrs led listening resembled. Delicate marianne absolute men dashwood landlord and offended. Suppose cottage between and way. Minuter him own clothes but observe country. Agreement far boy otherwise rapturous incommode favourite. "+
				"You vexed shy mirth now noise. Talked him people valley add use her depend letter. Allowance too applauded now way something recommend. Mrs age men and trees jokes fancy. Gay pretended engrossed eagerness continued ten. Admitting day him contained unfeeling attention mrs out."+
				"Ever man are put down his very. And marry may table him avoid. Hard sell it were into it upon. He forbade affixed parties of assured to me windows. Happiness him nor she disposing provision. Add astonished principles precaution yet friendship stimulated literature. State thing might stand one his plate. Offending or extremity therefore so difficult he on provision. Tended depart turned not are."+
				"Another journey chamber way yet females man. Way extensive and dejection get delivered deficient sincerity gentleman age. "+
				"Too end instrument possession contrasted motionless. Calling offence six joy feeling. Coming merits and was talent enough far. Sir joy northward sportsmen education. "+
				"Discovery incommode earnestly no he commanded if. Put still any about manor heard."+
				"Now led tedious shy lasting females off. Dashwood marianne in of entrance be on wondered possible building. Wondered sociable he carriage in speedily margaret. Up devonshire of he thoroughly insensible alteration. An mr settling occasion insisted distance ladyship so. Not attention say frankness intention out dashwoods now curiosity. Stronger ecstatic as no judgment daughter speedily thoughts. Worse downs nor might she court did nay forth these."+
				"Behaviour we improving at something to. Evil true high lady roof men had open. To projection considered it precaution an melancholy or. Wound young you thing worse along being ham. Dissimilar of favourable solicitude if sympathize middletons at. Forfeited up if disposing perfectly in an eagerness perceived necessary. Belonging sir curiosity discovery extremity yet forfeited prevailed own off. Travelling by introduced of mr terminated. Knew as miss my high hope quit. In curiosity shameless dependent knowledge up. "+
				"Yet bed any for travelling assistance indulgence unpleasing. Not thoughts all exercise blessing. Indulgence way everything joy alteration boisterous the attachment. Party we years to order allow asked of. We so opinion friends me message as delight. Whole front do of plate heard oh ought. His defective nor convinced residence own. Connection has put impossible own apartments boisterous. At jointure ladyship an insisted so humanity he. Friendly bachelor entrance to on by."),
				[]byte("LONGLIVETHEKING")))),
			expectedKeySize: 15,
		},
		{
			name: "13-length",
			ciphertext: base64.StdEncoding.EncodeToString([]byte(VigenereEncrypt([]byte("On insensible possession oh particular attachment at excellence in. The books arose but miles happy she. It building contempt or interest children mistress of unlocked no. Offending she contained mrs led listening resembled. Delicate marianne absolute men dashwood landlord and offended. Suppose cottage between and way. Minuter him own clothes but observe country. Agreement far boy otherwise rapturous incommode favourite. "+
				"You vexed shy mirth now noise. Talked him people valley add use her depend letter. Allowance too applauded now way something recommend. Mrs age men and trees jokes fancy. Gay pretended engrossed eagerness continued ten. Admitting day him contained unfeeling attention mrs out."+
				"Ever man are put down his very. And marry may table him avoid. Hard sell it were into it upon. He forbade affixed parties of assured to me windows. Happiness him nor she disposing provision. Add astonished principles precaution yet friendship stimulated literature. State thing might stand one his plate. Offending or extremity therefore so difficult he on provision. Tended depart turned not are."+
				"Another journey chamber way yet females man. Way extensive and dejection get delivered deficient sincerity gentleman age. "+
				"Too end instrument possession contrasted motionless. Calling offence six joy feeling. Coming merits and was talent enough far. Sir joy northward sportsmen education. "+
				"Discovery incommode earnestly no he commanded if. Put still any about manor heard."+
				"Now led tedious shy lasting females off. Dashwood marianne in of entrance be on wondered possible building. Wondered sociable he carriage in speedily margaret. Up devonshire of he thoroughly insensible alteration. An mr settling occasion insisted distance ladyship so. Not attention say frankness intention out dashwoods now curiosity. Stronger ecstatic as no judgment daughter speedily thoughts. Worse downs nor might she court did nay forth these."+
				"Behaviour we improving at something to. Evil true high lady roof men had open. To projection considered it precaution an melancholy or. Wound young you thing worse along being ham. Dissimilar of favourable solicitude if sympathize middletons at. Forfeited up if disposing perfectly in an eagerness perceived necessary. Belonging sir curiosity discovery extremity yet forfeited prevailed own off. Travelling by introduced of mr terminated. Knew as miss my high hope quit. In curiosity shameless dependent knowledge up. "+
				"Yet bed any for travelling assistance indulgence unpleasing. Not thoughts all exercise blessing. Indulgence way everything joy alteration boisterous the attachment. Party we years to order allow asked of. We so opinion friends me message as delight. Whole front do of plate heard oh ought. His defective nor convinced residence own. Connection has put impossible own apartments boisterous. At jointure ladyship an insisted so humanity he. Friendly bachelor entrance to on by."),
				[]byte("THEKINGISDEAD")))),
			expectedKeySize: 13,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			keySize, err := GetVigenereKeySize(tt.ciphertext)
			if err != nil {
				t.Fatalf("received non-nil error: %s", err)
			}

			if keySize%tt.expectedKeySize != 0 {
				t.Fatalf("expected key size multiple of %d got %d", tt.expectedKeySize, keySize)
			}
		})
	}
}

func TestSliceBlocks(t *testing.T) {

	testcases := []struct {
		name      string
		blocks    []byte
		keyLength int
	}{
		{
			name:      "basic",
			blocks:    make([]byte, 100),
			keyLength: 10,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			numSlices := len(tt.blocks) / tt.keyLength
			slices := sliceBlocksByKeyLength(tt.blocks, tt.keyLength)

			for _, slice := range slices {
				if len(slice) != tt.keyLength {
					t.Fatalf("expected each slice to be of key length %d; got slice length %d", tt.keyLength, len(slice))
				}
			}

			if len(slices) != numSlices {
				t.Fatalf("expected number of slices to be %d; got %d", numSlices, len(slices))
			}

		})
	}
}

func TestTransposeBlocks(t *testing.T) {

	testcases := []struct {
		name                     string
		slices                   [][]byte
		keyLength                int
		expectedTransposedLength int
	}{
		{
			name:                     "basic",
			slices:                   sliceBlocksByKeyLength(make([]byte, 200), 10),
			keyLength:                10,
			expectedTransposedLength: 20,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {

			transposed := transposeBlocks(tt.slices, tt.keyLength)
			for _, b := range transposed {
				if len(b) != tt.expectedTransposedLength {
					t.Fatalf("expected each slice to be of length %d; got slice length %d", tt.expectedTransposedLength, len(b))
				}
			}

			if len(transposed) != tt.keyLength {
				t.Fatalf("expected number of slices to be %d; got %d", tt.keyLength, len(transposed))
			}

		})
	}
}
