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

	if !pp.ValueCommitmentSanityCheck(vcmt) {
		return nil, errors.New("SerializeValueCommitment: the input ValueCommitment is not well-form")
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

// encodeTxoValueToBytes
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

// decodeTxoValueFromBytes
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

// ValueCommitmentSanityCheck checks whether the input ValueCommitment is well-form:
// (1) cmt is not nil
// (2) cmt.b != nil AND is well-form
// (3) cmt.c is well-form
// added and reviewed by Alice, 2024.06.25
// todo: review, by 2024.06
func (pp *PublicParameter) ValueCommitmentSanityCheck(cmt *ValueCommitment) bool {
	if cmt == nil {
		return false
	}

	if cmt.b == nil {
		return false
	}
	if len(cmt.b.polyCNTTs) != pp.paramKC {
		return false
	}
	for i := 0; i < pp.paramKC; i++ {
		if !pp.PolyCNTTSanityCheck(cmt.b.polyCNTTs[i]) {
			return false
		}
	}

	if !pp.PolyCNTTSanityCheck(cmt.c) {
		return false
	}

	return true
}

// ValueCommitmentRandomnessSanityCheck checks whether the input PolyCVec is in the random space for the value commitment.
// (1) not nil
// (2) has the correct length paramLC
// (3) each PolyC is well-form and has the right normal, say in {-1, 0, 1}^{d_c}
// added and reviewed by Alice, 2024.06.27
// todo: review, by 2024.06
func (pp *PublicParameter) ValueCommitmentRandomnessSanityCheck(r *PolyCVec) bool {

	if r == nil {
		return false
	}

	if len(r.polyCs) != pp.paramLC {
		return false
	}
	for i := 0; i < pp.paramLC; i++ {
		if !pp.PolyCSanityCheck(r.polyCs[i]) {
			return false
		}

		if r.polyCs[i].infNorm() > 1 {
			// the randomness for value commitment should come from the space {-1, 0, 1}^{d_c}
			return false
		}
	}

	return true
}

// ValueCommitmentRandomnessNTTSanityCheck checks whether the input rNTT *PolyCNTTVec is the NTT form of a valid randomness in the random space for the value commitment.
// As this function is somewhat redundant (complementing ValueCommitmentRandomnessSanityCheck), it provide an efficient way for the NTT form randomness.
// (1) rNTT is not nil
// (2) rNTT.polyCNTTs has the correct length paramLC
// (3) each PolyCNTT in rNTT.polyCNTTs is well-form and its poly form has the right normal, say in {-1, 0, 1}^{d_c}
// added and reviewed by Alice, 2024.07.01
// todo: review, by 2024.07
func (pp *PublicParameter) ValueCommitmentRandomnessNTTSanityCheck(rNTT *PolyCNTTVec) bool {

	if rNTT == nil {
		return false
	}

	if len(rNTT.polyCNTTs) != pp.paramLC {
		return false
	}

	for i := 0; i < pp.paramLC; i++ {
		if !pp.PolyCNTTSanityCheck(rNTT.polyCNTTs[i]) {
			return false
		}

		polyC := pp.NTTInvPolyC(rNTT.polyCNTTs[i])

		if polyC.infNorm() > 1 {
			// the randomness for value commitment should come from the space {-1, 0, 1}^{d_c}
			return false
		}
	}

	return true
}

// ValueCommitmentOpen checks whether the input (msgNTT, randNTT) is a valid opening for the input cmt.
// Note that here all the inputs are in the NTT form.
// As the binding matrix in the public key is pp.paramMatrixB, the hiding vector could be different vectors in pp.paramMatrixH,
// the parameter vecHIdx uint8 is used to specify the hiding vector.
// added and reviewed by Alice, 2024.06.27
// todo: review, by 2024.06
func (pp *PublicParameter) ValueCommitmentOpen(cmt *ValueCommitment, msgNTT *PolyCNTT, randNTT *PolyCNTTVec, vecHIdx uint8) bool {
	if !pp.ValueCommitmentSanityCheck(cmt) {
		return false
	}

	if !pp.PolyCNTTSanityCheck(msgNTT) {
		return false
	}

	if !pp.ValueCommitmentRandomnessNTTSanityCheck(randNTT) {
		return false
	}

	if int(vecHIdx) >= len(pp.paramMatrixH) {
		return false
	}

	// Note that the matrix is always paramMatrixB, but the vec for the hiding part could be one row of paramMatrixH.
	b := pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, randNTT, pp.paramKC, pp.paramLC)
	c := pp.PolyCNTTAdd(
		pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[vecHIdx], randNTT, pp.paramLC),
		msgNTT,
	)

	if !pp.PolyCNTTVecEqualCheck(b, cmt.b) || !pp.PolyCNTTEqualCheck(c, cmt.c) {
		return false
	}

	return true
}
