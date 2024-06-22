package pqringctx

import (
	"bytes"
	"errors"
)

// ValueCommitment
// moved from pqringctx.go on 2024.06.21
// reviewed by Alice, 2024.06.22
type ValueCommitment struct {
	b *PolyCNTTVec //	binding vector with length PublicParameter.paramKC
	c *PolyCNTT    //	commitment
}

// ValueCommitmentSerializeSize
// moved from serialization.go on 2024.06.21
// reviewed by Alice, 2024.06.22
func (pp *PublicParameter) ValueCommitmentSerializeSize() int {
	//	return pp.PolyCNTTVecSerializeSize(v.b) + pp.PolyCNTTSerializeSize()
	return (pp.paramKC + 1) * pp.PolyCNTTSerializeSize()
}

// SerializeValueCommitment
// moved from serialization.go on 2024.06.21
// reviewed by Alice, 2024.06.22
func (pp *PublicParameter) SerializeValueCommitment(vcmt *ValueCommitment) ([]byte, error) {
	var err error
	if vcmt == nil || vcmt.b == nil || vcmt.c == nil {
		return nil, errors.New("SerializeValueCommitment: there is nil pointer in ValueCommitment")
	}
	if len(vcmt.b.polyCNTTs) != pp.paramKC {
		return nil, errors.New("SerializeValueCommitment: the format of ValueCommitment does not match the design")
	}

	length := pp.ValueCommitmentSerializeSize()
	w := bytes.NewBuffer(make([]byte, 0, length))
	for i := 0; i < pp.paramKC; i++ {
		err = pp.writePolyCNTT(w, vcmt.b.polyCNTTs[i])
		if err != nil {
			return nil, err
		}
	}
	err = pp.writePolyCNTT(w, vcmt.c)
	if err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// DeserializeValueCommitment
// moved from serialization.go on 2024.06.21
// reviewed by Alice, 2024.06.22
func (pp *PublicParameter) DeserializeValueCommitment(serializedValueCommitment []byte) (*ValueCommitment, error) {
	var err error
	r := bytes.NewReader(serializedValueCommitment)

	b := pp.NewPolyCNTTVec(pp.paramKC)
	var c *PolyCNTT

	for i := 0; i < pp.paramKC; i++ {
		b.polyCNTTs[i], err = pp.readPolyCNTT(r)
		if err != nil {
			return nil, err
		}
	}
	c, err = pp.readPolyCNTT(r)
	if err != nil {
		return nil, err
	}

	return &ValueCommitment{b, c}, nil
}

// TxoValueBytesLen returns 7 (bytes) to encode the value in [0, 2^{51}-1].
// reviewed by Alice, 2024.06.22
func (pp *PublicParameter) TxoValueBytesLen() int {
	//	N = 51, v \in [0, 2^{51}-1]
	return 7
}

// reviewed by Alice, 2024.06.22
func (pp *PublicParameter) encodeTxoValueToBytes(value uint64) ([]byte, error) {
	//	N = 51, v \in [0, 2^{51}-1]
	if value < 0 || value > (1<<51)-1 {
		return nil, errors.New("encodeTxoValueToBytes: value is not in the scope [0, 2^N-1] for N= 51")
	}

	rst := make([]byte, 7)
	for i := 0; i < 7; i++ {
		rst[0] = byte(value >> 0)
		rst[1] = byte(value >> 8)
		rst[2] = byte(value >> 16)
		rst[3] = byte(value >> 24)
		rst[4] = byte(value >> 32)
		rst[5] = byte(value >> 40)
		rst[6] = byte(value >> 48)
	}
	return rst, nil
}

// reviewed by Alice, 2024.06.22
func (pp *PublicParameter) decodeTxoValueFromBytes(serializedValue []byte) (uint64, error) {
	//	N = 51, v \in [0, 2^{51}-1]
	if len(serializedValue) != 7 {
		return 0, errors.New("decodeTxoValueFromBytes: serializedValue's length is not 7")
	}
	var res uint64
	res = uint64(serializedValue[0]) << 0
	res |= uint64(serializedValue[1]) << 8
	res |= uint64(serializedValue[2]) << 16
	res |= uint64(serializedValue[3]) << 24
	res |= uint64(serializedValue[4]) << 32
	res |= uint64(serializedValue[5]) << 40
	res |= uint64(serializedValue[6]&0x07) << 48

	return res, nil
}
