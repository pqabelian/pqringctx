package pqringctx

import (
	"bytes"
	"crypto/hmac"
	"golang.org/x/crypto/sha3"
	"strconv"
	"testing"
)

func TestMACGen(t *testing.T) {
	tests := []struct {
		name    string
		message []byte
	}{}
	for i := 0; i < 10; i++ {
		tests = append(tests,
			struct {
				name    string
				message []byte
			}{
				name:    strconv.Itoa(i),
				message: RandomBytes(i),
			},
		)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := RandomBytes(MACKeyBytesLen)
			gotMessageMac, err := MACGen(key, tt.message)
			if err != nil {
				t.Errorf("error happen when calling MacGen: %v", err)
			}
			if MACVerify(key, tt.message, gotMessageMac) != nil {
				t.Errorf("MACGen() = %v, want %v", gotMessageMac, tt.message)
			}
		})
	}

	message := RandomBytes(1000)
	mac := hmac.New(sha3.New512, RandomBytes(MACKeyBytesLen))
	mac.Write(message)
	res1 := mac.Sum(nil)

	mac2 := hmac.New(sha3.New512, RandomBytes(MACKeyBytesLen))
	res2 := mac2.Sum(message)
	if !bytes.Equal(res1, res2) {
		t.Fatal("Fail")
	}
}
