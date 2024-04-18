package internal

import (
	"crypto/rand"
	"golang.org/x/crypto/sha3"
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

		})
	}
}
