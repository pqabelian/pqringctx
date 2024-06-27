package internal

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"golang.org/x/crypto/sha3"
	mrand "math/rand"
	"reflect"
	"testing"
)

// RandomBytes returns a byte array with given length from crypto/rand.Reader
func RandomBytes(length int) []byte {
	res := make([]byte, 0, length)

	neededLen := length
	var tmp []byte
	for neededLen > 0 {
		tmp = make([]byte, neededLen)
		// n == len(b) if and only if err == nil.
		n, err := rand.Read(tmp)
		if err != nil {
			continue
		}
		res = append(res, tmp[:n]...)
		neededLen -= n
	}
	return res
}
func TestKMAC128(t *testing.T) {
	type fields struct {
		key    string
		data   string
		custom string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "KMAC Tests (From NIST) Sample #1",
			fields: fields{
				key:    "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
				data:   "00010203",
				custom: "",
			},
			want: "E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E",
		},
		{
			name: "KMAC Tests (From NIST) Sample #2",
			fields: fields{
				key:    "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
				data:   "00010203",
				custom: "My Tagged Application",
			},
			want: "3B1FBA963CD8B0B59E8C1A6D71888B7143651AF8BA0A7070C0979E2811324AA5",
		},
		{
			name: "KMAC Tests (From NIST) Sample #3",
			fields: fields{
				key:    "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
				data:   "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7",
				custom: "My Tagged Application",
			},
			want: "1F5B4E6CCA02209E0DCB5CA635B89A15E271ECC760071DFD805FAA38F9729230",
		},
	}
	// Above test cases from NIST
	// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMAC_samples.pdf
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := hex.DecodeString(tt.fields.data)
			key, _ := hex.DecodeString(tt.fields.key)
			expected, _ := hex.DecodeString(tt.want)

			kmac128 := NewKMAC128(key, 32, []byte(tt.fields.custom))
			kmac128.Write(data)
			result := kmac128.Sum(nil)

			if !reflect.DeepEqual(result, expected) {
				t.Errorf("newKMAC128() expected %s, got %s", hex.EncodeToString(expected), hex.EncodeToString(result))
			}
		})
	}
}

func TestKMAC256(t *testing.T) {
	type fields struct {
		key    string
		data   string
		custom string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "KMAC Tests (From NIST) Sample #4",
			fields: fields{
				key:    "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
				data:   "00010203",
				custom: "My Tagged Application",
			},
			want: "20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD",
		},
		{
			name: "KMAC Tests (From NIST) Sample #5",
			fields: fields{
				key:    "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
				data:   "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7",
				custom: "",
			},
			want: "75358CF39E41494E949707927CEE0AF20A3FF553904C86B08F21CC414BCFD691589D27CF5E15369CBBFF8B9A4C2EB17800855D0235FF635DA82533EC6B759B69",
		},
		{
			name: "KMAC Tests (From NIST) Sample #6",
			fields: fields{
				key:    "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
				data:   "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7",
				custom: "My Tagged Application",
			},
			want: "B58618F71F92E1D56C1B8C55DDD7CD188B97B4CA4D99831EB2699A837DA2E4D970FBACFDE50033AEA585F1A2708510C32D07880801BD182898FE476876FC8965",
		},
	}
	// Above test cases from NIST
	// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMAC_samples.pdf
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := hex.DecodeString(tt.fields.data)
			key, _ := hex.DecodeString(tt.fields.key)
			expected, _ := hex.DecodeString(tt.want)

			kmac256 := NewKMAC256(key, 64, []byte(tt.fields.custom))
			kmac256.Write(data)
			result := kmac256.Sum(nil)

			if !reflect.DeepEqual(result, expected) {
				t.Errorf("newKMAC128() expected %s, got %s", hex.EncodeToString(expected), hex.EncodeToString(result))
			}
		})
	}
}

func TestKMAC256_ORIGIN(t *testing.T) {
	data, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7")
	key, _ := hex.DecodeString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F")

	data = []byte("Hello, world!")
	key = []byte("hellohellohellohellohellohellooo")

	shake256 := sha3.NewShake256()
	shake256.Write(data)
	result := shake256.Sum(nil)
	t.Logf("SHAKE256 Result:\n %08b \n %s", result, hex.EncodeToString(result))

	cshake256 := sha3.NewCShake256(
		[]byte{'K', 'M', 'A', 'C'},
		[]byte{'P', 'Q', 'R', 'I', 'N', 'G', 'C', 'T'},
	)
	cshake256.Write(data)
	result = cshake256.Sum(nil)
	t.Logf("cSHAKE256 Result:\n %08b \n %s", result, hex.EncodeToString(result))

	cshake256ForKMAC := sha3.NewCShake256(
		[]byte{'K', 'M', 'A', 'C'},
		[]byte{'P', 'Q', 'R', 'I', 'N', 'G', 'C', 'T'},
	)
	initBlock2 := make([]byte, 0, 9+len(key))
	initBlock2 = append(initBlock2, leftEncode(uint64(len(key)*8))...)
	initBlock2 = append(initBlock2, key...)
	cshake256ForKMAC.Write(bytepad(initBlock2, cshake256ForKMAC.BlockSize()))
	cshake256ForKMAC.Write(data)
	cshake256ForKMAC.Write(rightEncode(uint64(cshake256ForKMAC.Size() * 8)))
	result = cshake256ForKMAC.Sum(nil)
	t.Logf("KMAC based on cSHAKE256 Result:\n %08b \n %s", result, hex.EncodeToString(result))

	kmac256 := NewKMAC256(key, 64, []byte{'P', 'Q', 'R', 'I', 'N', 'G', 'C', 'T'})
	kmac256.Write(data)
	result = kmac256.Sum(nil)
	t.Logf("KMAC Result\n %08b \n %s", result, hex.EncodeToString(result))

	kmac256 = NewKMAC256(key, 64, []byte("PQRINGCT"))
	kmac256.Write(data)
	result = kmac256.Sum(nil)
	t.Logf("KMAC Result\n %08b \n %s", result, hex.EncodeToString(result))
}
func Test_kmac_Clone(t *testing.T) {
	type fields struct {
		outputLen int
		initBlock []byte
	}
	tests := []struct {
		name   string
		fields fields
		want   sha3.ShakeHash
	}{
		{
			name: "clone",
			fields: fields{
				outputLen: 64,
				initBlock: RandomBytes(256),
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &kmac{
				outputLen: tt.fields.outputLen,
				initBlock: tt.fields.initBlock,
			}
			k.ShakeHash = sha3.NewCShake128(RandomBytes(64), RandomBytes(64))

			expected := k.Sum(nil)

			cloned := k.Clone()

			if !reflect.DeepEqual(expected, cloned.Sum(nil)) {
				t.Errorf("Clone() fail")
			}

			k.ShakeHash = sha3.NewCShake256(RandomBytes(64), RandomBytes(64))

			expected = k.Sum(nil)

			cloned = k.Clone()

			if !reflect.DeepEqual(expected, cloned.Sum(nil)) {
				t.Errorf("Clone() fail")
			}

		})
	}
}

func TestKMAC(t *testing.T) {
	key := []byte("hellohellohellohellohellohellooo")
	customization := []byte("PQRINGCT")
	data := []byte("Hello, world!")

	c := sha3.NewCShake256([]byte(functionName), customization)
	mac := newKMAC(key, 64, c)

	mac.Write(data)
	sum := mac.Sum(nil)

	t.Logf("%x", sum)

	kmac256 := NewKMAC256(key, 64, customization)
	kmac256.Write(data)
	result := kmac256.Sum(nil)
	t.Logf("KMAC Result:\n %08b \n %s", result, hex.EncodeToString(result))
}

var testKMac = map[string]struct {
	constructor  func(key []byte, outputLen int, S []byte) sha3.ShakeHash
	defAlgoName  string
	defCustomStr string
	outputLen    int
}{
	// NewCShake without customization produces same result as SHAKE
	"KMAC128": {NewKMAC128, "KMAC", "CustomStrign", 32},
	"KMAC256": {NewKMAC256, "KMAC", "CustomStrign", 64},
}
var key = []byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
}

// sequentialBytes produces a buffer of size consecutive bytes 0x00, 0x01, ..., used for testing.
//
// The alignment of each slice is intentionally randomized to detect alignment
// issues in the implementation. See https://golang.org/issue/37644.
// Ideally, the compiler should fuzz the alignment itself.
// (See https://golang.org/issue/35128.)
func sequentialBytes(size int) []byte {
	alignmentOffset := mrand.Intn(8)
	result := make([]byte, size+alignmentOffset)[alignmentOffset:]
	for i := range result {
		result[i] = byte(i)
	}
	return result
}

func TestReset(t *testing.T) {
	for _, v := range testKMac {
		out1 := make([]byte, v.outputLen)
		out2 := make([]byte, v.outputLen)
		// Calculate hash for the first time
		c := v.constructor(key, v.outputLen, []byte{0x99, 0x98})
		c.Write(sequentialBytes(0x100))
		c.Read(out1)

		// Calculate hash again
		c.Reset()
		c.Write(sequentialBytes(0x100))
		c.Read(out2)

		if !bytes.Equal(out1, out2) {
			t.Error("\nExpected:\n", out1, "\ngot:\n", out2)
		}
	}
}

func TestClone(t *testing.T) {

	for _, size := range []int{0x1, 0x100} {
		in := sequentialBytes(size)
		for _, v := range testKMac {
			out1 := make([]byte, v.outputLen)
			out2 := make([]byte, v.outputLen)
			// Calculate hash for the first time
			h1 := v.constructor(key, v.outputLen, []byte{0x99, 0x98})
			h1.Write([]byte{0x01})

			h2 := h1.Clone()

			h1.Write(in)
			h1.Read(out1)

			h2.Write(in)
			h2.Read(out2)

			if !bytes.Equal(out1, out2) {
				t.Error("\nExpected:\n", hex.EncodeToString(out1), "\ngot:\n", hex.EncodeToString(out2))
			}
		}
	}
}
