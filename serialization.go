package pqringctx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/pqabelian/pqringctx/pqringctxkem"
	"io"
)

const (
	ErrInvalidLength = "invalid length"
	ErrNilPointer    = "there are nil pointer"
)

// PolyANTTSerializeSize
// For PolyANTT, each coefficient lies in the scope [-(q_a-1)/2, (q_a-1)/2].
// Note that q_a = 8522826353 = 2^32+2^31+2^30+2^29+2^28+2^27+2^26+2^9+2^6+2^5+2^4+1 is a 33-bit number.
// We use 33-bit to encode/serialize a coefficient in [-(q_a-1)/2, (q_a-1)/2], say 32-bit for absolute and 1 bit for signal.
// reviewed by Alice, 2024.06.20
func (pp *PublicParameter) PolyANTTSerializeSize() int {
	return pp.paramDA*4 + pp.paramDA/8 //	pp.paramDA is 2^n, at this moment pp.paramDA=256
}

// writePolyANTT
// reviewed by Alice, 2024.06.20
func (pp *PublicParameter) writePolyANTT(w io.Writer, a *PolyANTT) error {
	if a == nil {
		return errors.New("writePolyANTT: attempting to serialize a nil PolyANTT")
	}
	if len(a.coeffs) != pp.paramDA {
		return errors.New("writePolyANTT: coeffs of the input PolyANTT has an invalid length")
	}

	signalBytes := make([]byte, pp.paramDA/8)
	for i := 0; i < pp.paramDA/8; i++ {
		signalBytes[i] = 0
	}

	var coeff int64
	tmp := make([]byte, 4)
	for i := 0; i < pp.paramDA; i++ {
		coeff = a.coeffs[i]
		tmp[0] = byte(coeff >> 0)
		tmp[1] = byte(coeff >> 8)
		tmp[2] = byte(coeff >> 16)
		tmp[3] = byte(coeff >> 24)
		_, err := w.Write(tmp)
		if err != nil {
			return err
		}

		if byte(coeff>>32)&1 == 1 {
			// -signal
			signalBytes[i/8] = signalBytes[i/8] | (1 << (i % 8))
		}
	}

	_, err := w.Write(signalBytes)
	if err != nil {
		return err
	}

	return nil
}

// readPolyANTT
// reviewed by Alice, 2024.06.20
func (pp *PublicParameter) readPolyANTT(r io.Reader) (*PolyANTT, error) {

	tmp := make([]byte, 4)
	var coeff int64

	retPolyANTT := pp.NewPolyANTT()
	for i := 0; i < pp.paramDA; i++ {
		_, err := r.Read(tmp)
		if err != nil {
			return nil, err
		}
		coeff = int64(tmp[0]) << 0
		coeff |= int64(tmp[1]) << 8
		coeff |= int64(tmp[2]) << 16
		coeff |= int64(tmp[3]) << 24

		retPolyANTT.coeffs[i] = coeff
	}

	signalBytes := make([]byte, pp.paramDA/8)
	_, err := r.Read(signalBytes)
	if err != nil {
		return nil, err
	}

	var signalHint byte
	for i := 0; i < pp.paramDA; i++ {
		signalHint = 1 << (i % 8)
		if (signalBytes[i/8] & signalHint) == signalHint {
			//	- signal
			coeff = retPolyANTT.coeffs[i]
			retPolyANTT.coeffs[i] = int64(uint64(coeff) | 0xFFFFFFFF00000000)
		}
	}

	return retPolyANTT, nil
}

// PolyANTTVecSerializeSize
// reviewed by Alice, 2024.06.21
func (pp *PublicParameter) PolyANTTVecSerializeSize(a *PolyANTTVec) int {
	if a == nil {
		return VarIntSerializeSize(0)
	}
	return VarIntSerializeSize(uint64(len(a.polyANTTs))) + len(a.polyANTTs)*pp.PolyANTTSerializeSize()
}

// reviewed by Alice, 2024.06.21
func (pp *PublicParameter) writePolyANTTVec(w io.Writer, a *PolyANTTVec) error {
	if a == nil {
		//	write the length of the vector
		err := WriteVarInt(w, 0)
		if err != nil {
			return err
		}
		return nil
	}

	var err error
	// length
	count := len(a.polyANTTs)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		err = pp.writePolyANTT(w, a.polyANTTs[i])
		if err != nil {
			return err
		}
	}
	return nil
}

// reviewed by Alice, 2024.06.21
func (pp *PublicParameter) readPolyANTTVec(r io.Reader) (*PolyANTTVec, error) {
	var err error
	var count uint64
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil
	}

	res := make([]*PolyANTT, count)
	for i := uint64(0); i < count; i++ {
		res[i], err = pp.readPolyANTT(r)
		if err != nil {
			return nil, err
		}
	}
	return &PolyANTTVec{polyANTTs: res}, nil
}

// PolyASerializeSizeEta returns the serialize size of a PolyA in S_{eta_a - beta_a},
// where eta_a = 2^19 -1 is a 19-bits number.
// For each coefficient is in [-(eta_a - beta_a), (eta_a - beta_a)],
// we use 20-bits (19 bits for absolute and 1 bit for signal) to serialize/encode it.
// Each two coefficients use 40 bits = 5 bytes.
// As the response in proof has infinity form in [-(eta_a - beta_a), (eta_a - beta_a)], here we only handle Poly, rather than PolyNTT.
// reviewed by Alice, 2024.06.21
func (pp *PublicParameter) PolyASerializeSizeEta() int {
	return pp.paramDA / 2 * 5
}

// reviewed by Alice, 2024.06.21
func (pp *PublicParameter) writePolyAEta(w io.Writer, a *PolyA) error {
	if a == nil {
		return errors.New("writePolyAEta: attempting to serialize a nil PolyA")
	}
	if len(a.coeffs) != pp.paramDA {
		return errors.New("writePolyAEta: coeffs of the input PolyA has an invalid length")
	}

	var err error
	var lowCoeff, highCoeff int64
	var tmpLow, tmpHigh byte
	tmp := make([]byte, 5)
	for i := 0; i < pp.paramDA; i = i + 2 {
		lowCoeff = a.coeffs[i]
		highCoeff = a.coeffs[i+1] // assume paramDA is even, otherwise would panic here

		tmp[0] = byte(lowCoeff >> 0)
		tmp[1] = byte(lowCoeff >> 8)
		tmpLow = byte(lowCoeff >> 16)
		tmp[2] = byte(highCoeff >> 0)
		tmp[3] = byte(highCoeff >> 8)
		tmpHigh = byte(highCoeff >> 16)

		tmpLow = tmpLow & 0x0F   //	the low four bits include the signal bit. This is assuming that the signal bit is implied by the 3-rd bit.
		tmpHigh = tmpHigh & 0x0F // the low four bits include the signal bit. This is assuming that the signal bit is implied by the 3-rd bit.
		tmp[4] = (tmpHigh << 4) | tmpLow

		_, err = w.Write(tmp)
		if err != nil {
			return err
		}
	}

	return nil
}

// reviewed by Alice, 2024.06.21
func (pp *PublicParameter) readPolyAEta(r io.Reader) (*PolyA, error) {
	var err error

	polyA := pp.NewPolyA()

	tmp := make([]byte, 5)
	var lowCoef, highCoef int64
	var tmpLow, tmpHigh byte

	for i := 0; i < pp.paramDA; i = i + 2 {
		_, err = r.Read(tmp)
		if err != nil {
			return nil, err
		}

		lowCoef = int64(tmp[0]) << 0
		lowCoef |= int64(tmp[1]) << 8
		highCoef = int64(tmp[2]) << 0
		highCoef |= int64(tmp[3]) << 8

		tmpLow = tmp[4] & 0x0F
		tmpHigh = (tmp[4] & 0xF0) >> 4

		lowCoef |= int64(tmpLow) << 16
		if tmpLow&0x08 == 0x08 {
			//	- signal
			lowCoef = int64(uint64(lowCoef) | 0xFFFFFFFFFFF00000)
		}
		polyA.coeffs[i] = lowCoef

		highCoef |= int64(tmpHigh) << 16
		if tmpHigh&0x08 == 0x08 {
			//	- signal
			highCoef = int64(uint64(highCoef) | 0xFFFFFFFFFFF00000)
		}
		polyA.coeffs[i+1] = highCoef

	}
	return polyA, nil
}

// PolyAVecSerializeSizeEtaByVecLen returns the serialize size for a PolyAVec with the input length vecLen.
// added on 2023.12.18
// reviewed by Alice, 2024.06.21
func (pp *PublicParameter) PolyAVecSerializeSizeEtaByVecLen(vecLen int) int {
	if vecLen <= 0 {
		return VarIntSerializeSize(0)
	}
	return VarIntSerializeSize(uint64(vecLen)) + vecLen*pp.PolyASerializeSizeEta()
}

// PolyAVecSerializeSizeEta
// reviewed by Alice, 2024.06.21
func (pp *PublicParameter) PolyAVecSerializeSizeEta(a *PolyAVec) int {
	if a == nil {
		return VarIntSerializeSize(0)
	}
	return VarIntSerializeSize(uint64(len(a.polyAs))) + len(a.polyAs)*pp.PolyASerializeSizeEta()
}

// writePolyAVecEta
// reviewed by Alice, 2024.06.21
func (pp *PublicParameter) writePolyAVecEta(w io.Writer, a *PolyAVec) error {
	if a == nil {
		//	write the length of PolyAVec
		err := WriteVarInt(w, 0)
		if err != nil {
			return err
		}
		return nil
	}
	var err error
	// length
	count := len(a.polyAs)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		err = pp.writePolyAEta(w, a.polyAs[i])
		if err != nil {
			return err
		}
	}
	return nil
}

// readPolyAVecEta
// reviewed by Alice, 2024.06.21
func (pp *PublicParameter) readPolyAVecEta(r io.Reader) (*PolyAVec, error) {
	var err error
	var count uint64
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil
	}

	res := make([]*PolyA, count)
	for i := uint64(0); i < count; i++ {
		res[i], err = pp.readPolyAEta(r)
		if err != nil {
			return nil, err
		}
	}
	return &PolyAVec{polyAs: res}, nil
}

// PolyASerializeSizeGamma returns the serialize size of a PolyA in S_{gamma_a},
// where gamma_a = 2 is a 2-bits number.
// For each coefficient is in [-gamma_a, gamma_a],
// we use 3-bits (2 bits for absolute and 1 bit for signal) to serialize/encode it.
// Each 4 coefficients use 1 byte for their absolute values, and each 8 coefficients use 1 byte for their signals.
// As the AskSp in AddressSecretKey has infinity form in [-gamma_a, gamma_a], here we only handle Poly, rather than PolyNTT.
// reviewed by Alice, 2024.06.21
func (pp *PublicParameter) PolyASerializeSizeGamma() int {
	return pp.paramDA/4 + pp.paramDA/8 // pp.paramDA = 2^n for some n, at this moment pp.paramDA=256
}

// writePolyAGamma
// reviewed by Alice, 2024.06.21
func (pp *PublicParameter) writePolyAGamma(w io.Writer, polyA *PolyA) error {
	if polyA == nil {
		return errors.New("writePolyAGamma: attempting to serialize a nil PolyA")
	}
	if len(polyA.coeffs) != pp.paramDA {
		return errors.New("writePolyAGamma: coeffs of the input PolyA has an invalid length")
	}

	signalBytes := make([]byte, pp.paramDA/8)
	for i := 0; i < pp.paramDA/8; i++ {
		signalBytes[i] = 0
	}

	serialized := make([]byte, pp.paramDA/4)
	t := 0
	for i := 0; i < pp.paramDA; i = i + 4 {
		tmp0 := byte((polyA.coeffs[i] & 0x03) << 0)
		tmp1 := byte((polyA.coeffs[i+1] & 0x03) << 2)
		tmp2 := byte((polyA.coeffs[i+2] & 0x03) << 4)
		tmp3 := byte((polyA.coeffs[i+3] & 0x03) << 6)
		serialized[t] = tmp0 | tmp1 | tmp2 | tmp3
		t += 1
	}
	for i := 0; i < pp.paramDA; i++ {
		if (polyA.coeffs[i] & 0x04) == 0x04 { // us binary 00000100 to get the signal bit
			//	- signal
			signalBytes[i/8] = signalBytes[i/8] | (1 << (i % 8))
		}
	}

	_, err := w.Write(serialized)
	if err != nil {
		return err
	}

	_, err = w.Write(signalBytes)
	if err != nil {
		return err
	}

	return nil
}

// readPolyAGamma
// reviewed by Alice, 2024.06.21
func (pp *PublicParameter) readPolyAGamma(r io.Reader) (*PolyA, error) {
	polyA := pp.NewPolyA()

	serialized := make([]byte, pp.paramDA/4)
	_, err := r.Read(serialized)
	if err != nil {
		return nil, err
	}

	i := 0
	for t := 0; t < pp.paramDA/4; t++ {
		polyA.coeffs[i] = int64((serialized[t] >> 0) & 0x03)

		polyA.coeffs[i+1] = int64((serialized[t] >> 2) & 0x03)

		polyA.coeffs[i+2] = int64((serialized[t] >> 4) & 0x03)

		polyA.coeffs[i+3] = int64((serialized[t] >> 6) & 0x03)

		i = i + 4
	}

	signalBytes := make([]byte, pp.paramDA/8)
	_, err = r.Read(signalBytes)
	if err != nil {
		return nil, err
	}

	var coeff int64
	var signalHint byte
	for i = 0; i < pp.paramDA; i++ {
		signalHint = 1 << (i % 8)
		if (signalBytes[i/8] & signalHint) == signalHint {
			//	- signal
			coeff = polyA.coeffs[i]
			polyA.coeffs[i] = int64(uint64(coeff) | 0xFFFFFFFFFFFFFFFC)
		}
	}

	return polyA, nil
}

//func (pp *PublicParameter) PolyAVecSerializeSizeGamma(a *PolyAVec) int {
//	return VarIntSerializeSize(uint64(len(a.polyAs))) + len(a.polyAs)*pp.PolyASerializeSizeGamma()
//}
//func (pp *PublicParameter) writePolyAVecGamma(w io.Writer, a *PolyAVec) error {
//	var err error
//	// length
//	count := len(a.polyAs)
//	err = WriteVarInt(w, uint64(count))
//	if err != nil {
//		return err
//	}
//	for i := 0; i < count; i++ {
//		err = pp.writePolyAGamma(w, a.polyAs[i])
//		if err != nil {
//			return err
//		}
//	}
//	return nil
//}
//func (pp *PublicParameter) readPolyAVecGamma(r io.Reader) (*PolyAVec, error) {
//	var err error
//	var count uint64
//	count, err = ReadVarInt(r)
//	if err != nil {
//		return nil, err
//	}
//	res := make([]*PolyA, count)
//	for i := uint64(0); i < count; i++ {
//		res[i], err = pp.readPolyAGamma(r)
//		if err != nil {
//			return nil, err
//		}
//	}
//	return &PolyAVec{polyAs: res}, nil
//}

// PolyCNTTSerializeSize
// For PolyCNTT, each coefficient lies in the scope [-(q_c-1)/2, (q_c-1)/2].
// Note that q_c = 9007199254746113 = 2^{53} + 2^{12} + 2^{10} + 2^{0} is a 54-bit number
// We use 54-bit to encode/serialize a coefficient in [-(q_c-1)/2, (q_c-1)/2], say 53-bit for absolute value and 1 bit for signal.
// That is, we use 7-byte to encode/serialize a coefficient.
// reviewed by Alice, 2024.06.21
func (pp *PublicParameter) PolyCNTTSerializeSize() int {
	return pp.paramDC * 7
}

// writePolyCNTT
// reviewed by Alice, 2024.06.21
func (pp *PublicParameter) writePolyCNTT(w io.Writer, polyCNTT *PolyCNTT) error {
	if polyCNTT == nil {
		return errors.New("writePolyCNTT: attempting to serialize a nil PolyCNTT")
	}
	if len(polyCNTT.coeffs) != pp.paramDC {
		return errors.New("writePolyCNTT: coeffs of the input PolyCNTT has an invalid length")
	}

	var coeff int64
	tmp := make([]byte, 7)

	for i := 0; i < pp.paramDC; i++ {
		coeff = polyCNTT.coeffs[i]
		tmp[0] = byte(coeff >> 0)
		tmp[1] = byte(coeff >> 8)
		tmp[2] = byte(coeff >> 16)
		tmp[3] = byte(coeff >> 24)
		tmp[4] = byte(coeff >> 32)
		tmp[5] = byte(coeff >> 40)
		tmp[6] = byte(coeff >> 48)
		_, err := w.Write(tmp)
		if err != nil {
			return err
		}
	}
	return nil
}

// readPolyCNTT
// reviewed by Alice, 2024.06.21
func (pp *PublicParameter) readPolyCNTT(r io.Reader) (*PolyCNTT, error) {
	polyCNTT := pp.NewPolyCNTT()

	var coeff int64
	tmp := make([]byte, 7)

	for i := 0; i < pp.paramDC; i++ {
		_, err := r.Read(tmp)
		if err != nil {
			return nil, err
		}
		coeff = int64(tmp[0]) << 0
		coeff |= int64(tmp[1]) << 8
		coeff |= int64(tmp[2]) << 16
		coeff |= int64(tmp[3]) << 24
		coeff |= int64(tmp[4]) << 32
		coeff |= int64(tmp[5]) << 40
		coeff |= int64(tmp[6]) << 48

		//if tmp[6]>>7 == 1 {
		//	//	53-bit for absolute
		//	coeff = int64(uint64(coeff) | 0xFF00000000000000)
		//}

		// As we only need one bit (say, 53-rd bit) to denote the signal,
		// there are two bits (say, 55th, 54th bit) are free.
		// To avoid the two bits are manipulated somehow, here we guarantee them to be well-form.
		if (tmp[6] & 0xE0) == 0xE0 {
			// the (55th, 54th, 53rd, 52nd) bits are (111X), implying -
			coeff = int64(uint64(coeff) | 0xFF00000000000000)
		} else if (tmp[6] & 0xE0) == 0x00 {
			// the (55th, 54th, 53rd, 52nd) bits are (000X), implying +
			// do nothing
		} else {
			// bad-form
			return nil, fmt.Errorf("readPolyCNTT: %d-th coefficient's serializaiton is not well-form", i)
		}
		polyCNTT.coeffs[i] = coeff
	}
	return polyCNTT, nil
}

// PolyCNTTVecSerializeSizeByVecLen returns the serialize size of PolyCNTTVec, according to the length of the PolyCNTTVec.
// reviewed on 2023.12.07
// reviewed by Alice, 2024.06.21
func (pp *PublicParameter) PolyCNTTVecSerializeSizeByVecLen(vecLen int) int {
	if vecLen <= 0 {
		return VarIntSerializeSize(0)
	}
	return VarIntSerializeSize(uint64(vecLen)) + vecLen*pp.PolyCNTTSerializeSize()
}

// PolyCNTTVecSerializeSize
// reviewed by Alice, 2024.06.21
func (pp *PublicParameter) PolyCNTTVecSerializeSize(c *PolyCNTTVec) int {
	if c == nil {
		return VarIntSerializeSize(0)
	}
	return VarIntSerializeSize(uint64(len(c.polyCNTTs))) + len(c.polyCNTTs)*pp.PolyCNTTSerializeSize()
}

// writePolyCNTTVec
// reviewed by Alice, 2024.06.21
func (pp *PublicParameter) writePolyCNTTVec(w io.Writer, c *PolyCNTTVec) error {
	if c == nil {
		//	write the length of vector PolyCNTTVec
		err := WriteVarInt(w, 0)
		if err != nil {
			return err
		}
		return nil
	}
	var err error
	// length
	count := len(c.polyCNTTs)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}

	for i := 0; i < count; i++ {
		err = pp.writePolyCNTT(w, c.polyCNTTs[i])
		if err != nil {
			return err
		}
	}
	return nil
}

// readPolyCNTTVec
// reviewed by Alice, 2024.06.21
func (pp *PublicParameter) readPolyCNTTVec(r io.Reader) (*PolyCNTTVec, error) {
	var err error
	var count uint64
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil
	}
	res := make([]*PolyCNTT, count)
	for i := uint64(0); i < count; i++ {
		res[i], err = pp.readPolyCNTT(r)
		if err != nil {
			return nil, err
		}
	}
	return &PolyCNTTVec{polyCNTTs: res}, nil
}

// PolyCSerializeSizeEta returns the serialize size of a PolyC in S_{eta_c - beta_c},
// where eta_c = 2^24 -1 is a 24-bits number.
// For each coefficient is in [-(eta_c - beta_c), (eta_c - beta_c)],
// we use 25-bits (24 bits for absolute and 1 bit for signal) to serialize/encode it.
// That is, each coefficient use (24 bits = 3 bytes, 1 bit signal).
// As the response in proof has infinity form in [-(eta_c - beta_c), (eta_c - beta_c)], here we only handle PolyC, rather than PolyCNTT.
// reviewed by Alice, 2024.06.21
func (pp *PublicParameter) PolyCSerializeSizeEta() int {
	return pp.paramDC*3 + pp.paramDC/8 //	pp.paramDC = 128 at this moment, and basically,it should be a 2^n for some n
}

// writePolyCEta
// reviewed by Alice, 2024.06.21
func (pp *PublicParameter) writePolyCEta(w io.Writer, polyC *PolyC) error {
	if polyC == nil {
		return errors.New("writePolyCEta: attempting to serialize a nil PolyC")
	}
	if len(polyC.coeffs) != pp.paramDC {
		return errors.New("writePolyCEta: coeffs of the input polyC has an invalid length")
	}

	var err error
	var coeff int64
	var tmpSignal byte
	tmp := make([]byte, 3)

	signalBytes := make([]byte, pp.paramDC/8)
	for i := 0; i < pp.paramDC/8; i++ {
		signalBytes[i] = 0
	}
	for i := 0; i < pp.paramDC; i++ {
		coeff = polyC.coeffs[i]

		tmp[0] = byte(coeff >> 0)
		tmp[1] = byte(coeff >> 8)
		tmp[2] = byte(coeff >> 16)
		tmpSignal = byte(coeff >> 24)

		if (tmpSignal & 0x01) == 0x01 {
			signalBytes[i/8] = signalBytes[i/8] | (0x01 << (i % 8))
		}

		_, err = w.Write(tmp)
		if err != nil {
			return err
		}
	}

	_, err = w.Write(signalBytes)
	if err != nil {
		return err
	}

	return nil
}

// readPolyCEta
// reviewed by Alice, 2024.06.21
func (pp *PublicParameter) readPolyCEta(r io.Reader) (*PolyC, error) {
	var err error

	rst := pp.NewPolyC()

	tmp := make([]byte, 3)
	var coeff int64

	for i := 0; i < pp.paramDC; i++ {
		_, err = r.Read(tmp)
		if err != nil {
			return nil, err
		}

		coeff = int64(tmp[0]) << 0
		coeff |= int64(tmp[1]) << 8
		coeff |= int64(tmp[2]) << 16

		rst.coeffs[i] = coeff
	}

	signalBytes := make([]byte, pp.paramDC/8)
	_, err = r.Read(signalBytes)
	if err != nil {
		return nil, err
	}

	var signalHint byte
	for i := 0; i < pp.paramDC; i++ {
		signalHint = 0x01 << (i % 8)

		if (signalBytes[i/8] & signalHint) == signalHint {
			//	- signal
			coeff = rst.coeffs[i]
			rst.coeffs[i] = int64(uint64(coeff) | 0xFFFFFFFFFF000000)
		}
	}
	return rst, nil
}

// PolyCVecSerializeSizeEtaByVecLen can compute the serialized size for a PolyCVec with vecLen.
// reviewed on 2023.12.05
// reviewed by Alice, 2024.06.21
func (pp *PublicParameter) PolyCVecSerializeSizeEtaByVecLen(vecLen int) int {
	if vecLen <= 0 {
		return VarIntSerializeSize(0)
	}
	return VarIntSerializeSize(uint64(vecLen)) + vecLen*pp.PolyCSerializeSizeEta()
}

// PolyCVecSerializeSizeEta
// reviewed by Alice, 2024.06.21
func (pp *PublicParameter) PolyCVecSerializeSizeEta(a *PolyCVec) int {
	if a == nil {
		return VarIntSerializeSize(0)
	}
	return VarIntSerializeSize(uint64(len(a.polyCs))) + len(a.polyCs)*pp.PolyCSerializeSizeEta()
}

// writePolyCVecEta
// reviewed by Alice, 2024.06.21
func (pp *PublicParameter) writePolyCVecEta(w io.Writer, a *PolyCVec) error {
	if a == nil {
		//	write the length of the vector
		err := WriteVarInt(w, 0)
		if err != nil {
			return err
		}
		return nil
	}

	var err error
	// length
	count := len(a.polyCs)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		err = pp.writePolyCEta(w, a.polyCs[i])
		if err != nil {
			return err
		}
	}
	return nil
}

// readPolyCVecEta
// reviewed by Alice, 2024.06.21
func (pp *PublicParameter) readPolyCVecEta(r io.Reader) (*PolyCVec, error) {
	var err error
	var count uint64
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}

	if count == 0 {
		return nil, nil
	}
	res := make([]*PolyC, count)
	for i := uint64(0); i < count; i++ {
		res[i], err = pp.readPolyCEta(r)
		if err != nil {
			return nil, err
		}
	}
	return &PolyCVec{polyCs: res}, nil
}

// AddressPublicKeySerializeSize
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) AddressPublicKeySerializeSize() int {
	//return pp.PolyANTTVecSerializeSize(a.t) + pp.PolyANTTSerializeSize()
	return (pp.paramKA + 1) * pp.PolyANTTSerializeSize()
}

// SerializeAddressPublicKey
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) SerializeAddressPublicKey(apk *AddressPublicKey) ([]byte, error) {
	var err error
	if apk == nil || apk.t == nil || apk.e == nil {
		return nil, errors.New("SerializeAddressPublicKey: there is nil pointer in AddressPublicKey")
	}
	if len(apk.t.polyANTTs) != pp.paramKA {
		return nil, errors.New("SerializeAddressPublicKey: the format of AddressPublicKey does not match the design")
	}

	length := pp.AddressPublicKeySerializeSize()
	w := bytes.NewBuffer(make([]byte, 0, length))
	for i := 0; i < pp.paramKA; i++ {
		err = pp.writePolyANTT(w, apk.t.polyANTTs[i])
		if err != nil {
			return nil, err
		}
	}
	err = pp.writePolyANTT(w, apk.e)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// DeserializeAddressPublicKey
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) DeserializeAddressPublicKey(serializedAPk []byte) (*AddressPublicKey, error) {
	var err error
	r := bytes.NewReader(serializedAPk)

	t := pp.NewPolyANTTVec(pp.paramKA)
	var e *PolyANTT

	for i := 0; i < pp.paramKA; i++ {
		t.polyANTTs[i], err = pp.readPolyANTT(r)
		if err != nil {
			return nil, err
		}
	}
	e, err = pp.readPolyANTT(r)
	if err != nil {
		return nil, err
	}
	return &AddressPublicKey{t, e}, nil
}

//// AddressSecretKeySpSerializeSize() return the fixed size of AddressSecretKeySp
//func (pp *PublicParameter) AddressSecretKeySpSerializeSize() int {
//	// s polyAVec with length L_a, wih
//	return pp.paramLA * pp.PolyASerializeSizeGamma()
//}
//func (pp *PublicParameter) SerializeAddressSecretKeySp(asksp *AddressSecretKeySp) ([]byte, error) {
//	var err error
//	if asksp == nil || asksp.s == nil {
//		return nil, errors.New("SerializeAddressSecretKeySp: there is nil pointer in AddressSecretKeySp")
//	}
//
//	if len(asksp.s.polyAs) != pp.paramLA {
//		return nil, errors.New("the format of AddressSecretKeySp does not match the design")
//	}
//
//	// s is in its poly form and it has infinite normal in [-Gamma_a, Gamma_a] where Gamma_a is 5 at this moment,
//	// we serialize its poly from.
//	askSpLen := pp.AddressSecretKeySpSerializeSize()
//	w := bytes.NewBuffer(make([]byte, 0, askSpLen))
//	for i := 0; i < pp.paramLA; i++ {
//		err = pp.writePolyAGamma(w, asksp.s.polyAs[i])
//		if err != nil {
//			return nil, err
//		}
//	}
//	return w.Bytes(), nil
//}
//
//func (pp *PublicParameter) DeserializeAddressSecretKeySp(serialziedASkSp []byte) (*AddressSecretKeySp, error) {
//	var err error
//	r := bytes.NewReader(serialziedASkSp)
//	s := pp.NewPolyAVec(pp.paramLA)
//	for i := 0; i < pp.paramLA; i++ {
//		s.polyAs[i], err = pp.readPolyAGamma(r)
//		if err != nil {
//			return nil, err
//		}
//	}
//	return &AddressSecretKeySp{s}, nil
//}
//
//func (pp *PublicParameter) AddressSecretKeySnSerializeSize() int {
//	return pp.PolyANTTSerializeSize()
//}
//func (pp *PublicParameter) SerializeAddressSecretKeySn(asksn *AddressSecretKeySn) ([]byte, error) {
//	var err error
//	if asksn == nil || asksn.ma == nil {
//		return nil, errors.New("SerializeAddressSecretKeySn: there is nil pointer in AddressSecretKeySn")
//	}
//	snLength := pp.AddressSecretKeySnSerializeSize()
//	w := bytes.NewBuffer(make([]byte, 0, snLength))
//	err = pp.writePolyANTT(w, asksn.ma)
//	if err != nil {
//		return nil, err
//	}
//	return w.Bytes(), nil
//}
//func (pp *PublicParameter) DeserializeAddressSecretKeySn(serialziedASkSn []byte) (*AddressSecretKeySn, error) {
//	r := bytes.NewReader(serialziedASkSn)
//	ma, err := pp.readPolyANTT(r)
//	if err != nil {
//		return nil, err
//	}
//	return &AddressSecretKeySn{ma}, nil
//}

//
//func (pp *PublicParameter) AddressSecretKeySize(ask *AddressSecretKey) (int, int) {
//	return pp.AddressSecretKeySpSerializeSize(ask.AddressSecretKeySp), pp.AddressSecretKeySnSerializeSize(ask.AddressSecretKeySn)
//}
//func (pp *PublicParameter) AddressSecretKeySerialize(ask *AddressSecretKey) ([]byte, []byte, error) {
//	var err error
//	if ask == nil || ask.AddressSecretKeySp == nil || ask.AddressSecretKeySn == nil {
//		return nil, nil, errors.New(ErrNilPointer)
//	}
//
//	spLength, snLength := pp.AddressSecretKeySize(ask)
//	serializedSecretKeySp := make([]byte, spLength)
//	serializedSecretKeySn := make([]byte, snLength)
//
//	serializedSecretKeySp, err = pp.SerializeAddressSecretKeySp(ask.AddressSecretKeySp)
//	if err != nil {
//		return nil, nil, err
//	}
//	serializedSecretKeySn, err = pp.SerializeAddressSecretKeySn(ask.AddressSecretKeySn)
//	if err != nil {
//		return nil, nil, err
//	}
//
//	return serializedSecretKeySp, serializedSecretKeySn, nil
//}
//func (pp *PublicParameter) AddressSecretKeyDeserialize(serialziedASkSp []byte, serialziedASkSn []byte) (*AddressSecretKey, error) {
//	var err error
//
//	addressSecretKeySp, err := pp.DeserializeAddressSecretKeySp(serialziedASkSp)
//	if err != nil {
//		return nil, err
//	}
//	addressSecretKeySn, err := pp.DeserializeAddressSecretKeySn(serialziedASkSn)
//	if err != nil {
//		return nil, err
//	}
//
//	return &AddressSecretKey{
//		AddressSecretKeySp: addressSecretKeySp,
//		AddressSecretKeySn: addressSecretKeySn,
//	}, nil
//}

//func (pp *PublicParameter) ValueCommitmentRandSerializeSize() int {
//	//	return pp.PolyCNTTVecSerializeSize(v.b) + pp.PolyCNTTSerializeSize()
//	return pp.paramLC * pp.PolyCNTTSerializeSize()
//}

// TxoSerializeSize
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) TxoSerializeSize() int {
	return pp.AddressPublicKeySerializeSize() +
		pp.ValueCommitmentSerializeSize() +
		pp.TxoValueBytesLen() +
		VarIntSerializeSize(uint64(pqringctxkem.GetKemCiphertextBytesLen(pp.paramKem))) + pqringctxkem.GetKemCiphertextBytesLen(pp.paramKem)
}

// SerializeTxo
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) SerializeTxo(txo *Txo) ([]byte, error) {
	if txo == nil || txo.AddressPublicKey == nil || txo.ValueCommitment == nil {
		return nil, errors.New("SerializeTxo: there is nil pointer in Txo")
	}

	var err error
	length := pp.TxoSerializeSize()
	w := bytes.NewBuffer(make([]byte, 0, length))

	//	serializedAddressPublicKey is fixed-length
	serializedAddressPublicKey, err := pp.SerializeAddressPublicKey(txo.AddressPublicKey)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(serializedAddressPublicKey)
	if err != nil {
		return nil, err
	}

	//	serializedValueCmt is fixed-length
	serializedValueCmt, err := pp.SerializeValueCommitment(txo.ValueCommitment)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(serializedValueCmt)
	if err != nil {
		return nil, err
	}

	//	txo.Vct is fixed-length
	_, err = w.Write(txo.Vct)
	if err != nil {
		return nil, err
	}

	//	txo.CtKemSerialized depends on the KEM, the length is not in the scope of pqringct.
	err = writeVarBytes(w, txo.CtKemSerialized)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// DeserializeTxo
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) DeserializeTxo(serializedTxo []byte) (*Txo, error) {
	var err error
	r := bytes.NewReader(serializedTxo)

	var apk *AddressPublicKey
	tmp := make([]byte, pp.AddressPublicKeySerializeSize())
	_, err = r.Read(tmp)
	if err != nil {
		return nil, err
	}
	apk, err = pp.DeserializeAddressPublicKey(tmp)
	if err != nil {
		return nil, err
	}

	var cmt *ValueCommitment
	tmp = make([]byte, pp.ValueCommitmentSerializeSize())
	_, err = r.Read(tmp)
	if err != nil {
		return nil, err
	}
	cmt, err = pp.DeserializeValueCommitment(tmp)
	if err != nil {
		return nil, err
	}

	vct := make([]byte, pp.TxoValueBytesLen())
	_, err = r.Read(vct)
	if err != nil {
		return nil, err
	}

	ctKem, err := readVarBytes(r, MaxAllowedKemCiphertextSize, "txo.CtKemSerialized")
	if err != nil {
		return nil, err
	}

	return &Txo{apk, cmt, vct, ctKem}, nil
}

// LgrTxoIdSerializeSize returns HashOutputBytesLen, since we use Hash to compute LgrTxoId,
// to guarantee no one can tontrol the txo-id-in-ledger.
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) LgrTxoIdSerializeSize() int {
	return HashOutputBytesLen
}

// LgrTxoSerializeSize
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) LgrTxoSerializeSize() int {
	return pp.TxoSerializeSize() + pp.LgrTxoIdSerializeSize()
}

// SerializeLgrTxo
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) SerializeLgrTxo(lgrTxo *LgrTxo) ([]byte, error) {
	if lgrTxo.txo == nil {
		return nil, errors.New("SerializeLgrTxo: there is nil pointer in LgrTxo")
	}

	var err error
	length := pp.LgrTxoSerializeSize()
	w := bytes.NewBuffer(make([]byte, 0, length))

	//	txo: fixed length
	serializedTxo, err := pp.SerializeTxo(lgrTxo.txo)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(serializedTxo)
	if err != nil {
		return nil, err
	}

	//	id: fixed-length
	_, err = w.Write(lgrTxo.id)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// DeserializeLgrTxo
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) DeserializeLgrTxo(serializedLgrTxo []byte) (*LgrTxo, error) {

	r := bytes.NewReader(serializedLgrTxo)

	serializedTxo := make([]byte, pp.TxoSerializeSize())
	_, err := r.Read(serializedTxo)
	if err != nil {
		return nil, err
	}
	txo, err := pp.DeserializeTxo(serializedTxo)
	if err != nil {
		return nil, err
	}

	id := make([]byte, pp.LgrTxoIdSerializeSize())
	_, err = r.Read(id)
	if err != nil {
		return nil, err
	}

	return &LgrTxo{txo, id}, nil
}

// RpulpProofSerializeSize
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) RpulpProofSerializeSize(prf *rpulpProof) int {
	var length int
	lengthOfPolyCNTT := pp.PolyCNTTSerializeSize()
	length = VarIntSerializeSize(uint64(len(prf.c_waves))) + len(prf.c_waves)*lengthOfPolyCNTT + // c_waves []*PolyCNTT
		+3*lengthOfPolyCNTT + //c_hat_g,psi,phi  *PolyCNTT
		VarIntSerializeSize(uint64(len(prf.chseed))) + len(prf.chseed) //chseed  []byte
	//cmt_zs  [][]*PolyCVec eta
	length += VarIntSerializeSize(uint64(len(prf.cmt_zs)))
	for i := 0; i < len(prf.cmt_zs); i++ {
		length += VarIntSerializeSize(uint64(len(prf.cmt_zs[i])))
		for j := 0; j < len(prf.cmt_zs[i]); j++ {
			length += pp.PolyCVecSerializeSizeEta(prf.cmt_zs[i][j])
		}
	}
	//zs      []*PolyCVec
	length += VarIntSerializeSize(uint64(len(prf.zs)))
	for i := 0; i < len(prf.zs); i++ {
		length += pp.PolyCVecSerializeSizeEta(prf.zs[i])
	}
	return length
}

// SerializeRpulpProof
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) SerializeRpulpProof(prf *rpulpProof) ([]byte, error) {
	if prf == nil || prf.c_waves == nil ||
		prf.c_hat_g == nil || prf.psi == nil || prf.phi == nil ||
		len(prf.chseed) == 0 ||
		prf.cmt_zs == nil || prf.zs == nil {
		return nil, errors.New("SerializeRpulpProof: there is nil pointer in rpulpProof")
	}

	var err error
	length := pp.RpulpProofSerializeSize(prf)
	w := bytes.NewBuffer(make([]byte, 0, length))

	// c_waves []*PolyCNTT
	n := len(prf.c_waves)
	err = WriteVarInt(w, uint64(len(prf.c_waves)))
	for i := 0; i < n; i++ {
		err = pp.writePolyCNTT(w, prf.c_waves[i])
		if err != nil {
			return nil, err
		}
	}

	//c_hat_g *PolyCNTT
	err = pp.writePolyCNTT(w, prf.c_hat_g)
	if err != nil {
		return nil, err
	}

	//psi     *PolyCNTT
	err = pp.writePolyCNTT(w, prf.psi)
	if err != nil {
		return nil, err
	}

	//phi     *PolyCNTT
	err = pp.writePolyCNTT(w, prf.phi)
	if err != nil {
		return nil, err
	}

	//chseed  []byte
	err = writeVarBytes(w, prf.chseed)
	if err != nil {
		return nil, err
	}

	//cmt_zs  [][]*PolyCVec eta
	n = len(prf.cmt_zs)
	err = WriteVarInt(w, uint64(n))
	if err != nil {
		return nil, err
	}
	for i := 0; i < n; i++ {
		n1 := len(prf.cmt_zs[i])
		err = WriteVarInt(w, uint64(n1))
		if err != nil {
			return nil, err
		}
		for j := 0; j < n1; j++ {
			err = pp.writePolyCVecEta(w, prf.cmt_zs[i][j])
			if err != nil {
				return nil, err
			}
		}
	}

	//zs      []*PolyCVec eta
	n = len(prf.zs)
	err = WriteVarInt(w, uint64(n))
	if err != nil {
		return nil, err
	}
	for i := 0; i < n; i++ {
		err = pp.writePolyCVecEta(w, prf.zs[i])
		if err != nil {
			return nil, err
		}
	}

	return w.Bytes(), nil
}

// DeserializeRpulpProof
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) DeserializeRpulpProof(serializedRpulpProof []byte) (*rpulpProof, error) {

	r := bytes.NewReader(serializedRpulpProof)

	// c_waves []*PolyCNTT
	var c_waves []*PolyCNTT
	count, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		c_waves = make([]*PolyCNTT, count)
		for i := uint64(0); i < count; i++ {
			c_waves[i], err = pp.readPolyCNTT(r)
			if err != nil {
				return nil, err
			}
		}
	}

	//c_hat_g *PolyCNTT
	c_hat_g, err := pp.readPolyCNTT(r)
	if err != nil {
		return nil, err
	}

	//psi     *PolyCNTT
	psi, err := pp.readPolyCNTT(r)
	if err != nil {
		return nil, err
	}

	//phi     *PolyCNTT
	phi, err := pp.readPolyCNTT(r)
	if err != nil {
		return nil, err
	}

	//chseed  []byte
	chseed, err := readVarBytes(r, MaxAllowedChallengeSeedSize, "rpulpProof.chseed")
	if err != nil {
		return nil, err
	}

	//cmt_zs  [][]*PolyCVec eta
	var cmt_zs [][]*PolyCVec
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		cmt_zs = make([][]*PolyCVec, count)
		var tcount uint64
		for i := uint64(0); i < count; i++ {
			tcount, err = ReadVarInt(r)
			if err != nil {
				return nil, err
			}
			if tcount != 0 {
				cmt_zs[i] = make([]*PolyCVec, tcount)
				for j := uint64(0); j < tcount; j++ {
					cmt_zs[i][j], err = pp.readPolyCVecEta(r)
					if err != nil {
						return nil, err
					}
				}
			}
		}
	}

	//zs      []*PolyCNTTVec eta
	var zs []*PolyCVec
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		zs = make([]*PolyCVec, count)
		for i := uint64(0); i < count; i++ {
			zs[i], err = pp.readPolyCVecEta(r)
			if err != nil {
				return nil, err
			}
		}
	}
	return &rpulpProof{
		c_waves: c_waves,
		c_hat_g: c_hat_g,
		psi:     psi,
		phi:     phi,
		chseed:  chseed,
		cmt_zs:  cmt_zs,
		zs:      zs,
	}, nil
}

// challengeSeedCSerializeSizeApprox
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) challengeSeedCSerializeSizeApprox() int {
	return VarIntSerializeSize(uint64(HashOutputBytesLen)) + HashOutputBytesLen
}

// responseCSerializeSizeApprox
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) responseCSerializeSizeApprox() int {
	//	r \in (Ring_{q_c})^{L_c}
	//	z \in (Ring_{q_c})^{L_c}
	//	k
	return VarIntSerializeSize(uint64(pp.paramK)) + //	CResponse has a factor K
		pp.paramK*(VarIntSerializeSize(uint64(pp.paramLC))+pp.paramLC*pp.PolyCSerializeSizeEta())
}

// CbTxWitnessJ1SerializeSizeApprox
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) CbTxWitnessJ1SerializeSizeApprox() int {
	var lenApprox int

	//	chseed []byte
	lenApprox = pp.challengeSeedCSerializeSizeApprox()

	//	zs []*PolyCVec eta
	//	r \in \in (Ring_{q_c})^{L_c}
	//	z \in (Ring_{q_c})^{L_c}
	//	k
	lenApprox += pp.responseCSerializeSizeApprox()

	return lenApprox
}

// CbTxWitnessJ1SerializeSize
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) CbTxWitnessJ1SerializeSize(witness *CbTxWitnessJ1) int {
	if witness == nil {
		return 0
	}
	var length int
	length = VarIntSerializeSize(uint64(len(witness.chseed))) + len(witness.chseed)

	length += VarIntSerializeSize(uint64(len(witness.zs)))
	for i := 0; i < len(witness.zs); i++ {
		length += pp.PolyCVecSerializeSizeEta(witness.zs[i])
	}

	return length
}

// SerializeCbTxWitnessJ1
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) SerializeCbTxWitnessJ1(witness *CbTxWitnessJ1) ([]byte, error) {
	if witness.zs == nil || len(witness.chseed) == 0 {
		return nil, errors.New("SerializeCbTxWitnessJ1: there is nil pointer in CbTxWitnessJ1")
	}

	var err error
	length := pp.CbTxWitnessJ1SerializeSize(witness)
	w := bytes.NewBuffer(make([]byte, 0, length))

	//chseed  []byte
	err = writeVarBytes(w, witness.chseed)
	if err != nil {
		return nil, err
	}

	//zs      []*PolyCVec eta
	n := len(witness.zs)
	err = WriteVarInt(w, uint64(n))
	if err != nil {
		return nil, err
	}
	for i := 0; i < n; i++ {
		err = pp.writePolyCVecEta(w, witness.zs[i])
		if err != nil {
			return nil, err
		}
	}

	return w.Bytes(), nil
}

// DeserializeCbTxWitnessJ1
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) DeserializeCbTxWitnessJ1(serializedWitness []byte) (*CbTxWitnessJ1, error) {
	r := bytes.NewReader(serializedWitness)

	//chseed  []byte
	chseed, err := readVarBytes(r, MaxAllowedChallengeSeedSize, "CbTxWitnessJ1.chseed")
	if err != nil {
		return nil, err
	}

	//zs      []*PolyCNTTVec eta
	var zs []*PolyCVec
	count, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		zs = make([]*PolyCVec, count)
		for i := uint64(0); i < count; i++ {
			zs[i], err = pp.readPolyCVecEta(r)
			if err != nil {
				return nil, err
			}
		}
	}
	return &CbTxWitnessJ1{
		chseed: chseed,
		zs:     zs,
	}, nil
}

// boundingVecCSerializeSizeApprox
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) boundingVecCSerializeSizeApprox() int {
	//	PolyCNTTVec[k_c]
	return VarIntSerializeSize(uint64(pp.paramKC)) + pp.paramKC*pp.PolyCNTTSerializeSize()
}

// CbTxWitnessJ2SerializeSizeApprox
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) CbTxWitnessJ2SerializeSizeApprox(outTxoNum int) int {
	var lenApprox int

	//	b_hat
	//	PolyCNTTVec[k_c]
	lenApprox = pp.boundingVecCSerializeSizeApprox()

	//	c_hats     []*PolyCNTT, length J+2
	lenApprox += VarIntSerializeSize(uint64(outTxoNum+2)) + (outTxoNum+2)*pp.PolyCNTTSerializeSize()

	// u_p
	lenApprox += pp.CarryVectorRProofSerializeSize()

	// rpulpproof

	rpuprfLength := 0
	// c_waves []*PolyCNTT // length outTxoNum
	rpuprfLength = VarIntSerializeSize(uint64(outTxoNum)) + outTxoNum*pp.PolyCNTTSerializeSize()

	// c_hat_g,psi,phi  *PolyCNTT
	rpuprfLength += 3 * pp.PolyCNTTSerializeSize()

	// chseed  []byte
	rpuprfLength += pp.challengeSeedCSerializeSizeApprox()

	//cmt_zs  [][]*PolyCVec eta; n = (outTxoNum), (k, paramLc)
	lenTmp := (outTxoNum) * pp.responseCSerializeSizeApprox()
	rpuprfLength += VarIntSerializeSize(uint64(lenTmp)) + lenTmp

	//zs      []*PolyCVec eta
	rpuprfLength += pp.responseCSerializeSizeApprox()

	lenApprox += VarIntSerializeSize(uint64(rpuprfLength)) + rpuprfLength

	return lenApprox
}

// CbTxWitnessJ2SerializeSize
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) CbTxWitnessJ2SerializeSize(witness *CbTxWitnessJ2) int {
	if witness == nil {
		return 0
	}

	var length int

	length = pp.PolyCNTTVecSerializeSize(witness.b_hat) + // b_hat      *PolyCNTTVec
		VarIntSerializeSize(uint64(len(witness.c_hats))) + len(witness.c_hats)*pp.PolyCNTTSerializeSize() // c_hats     []*PolyCNTT, length J+2

	length += pp.CarryVectorRProofSerializeSize() // u_p        []int64
	rplPrfLen := pp.RpulpProofSerializeSize(witness.rpulpproof)
	length += VarIntSerializeSize(uint64(rplPrfLen)) + rplPrfLen

	return length
}

// SerializeCbTxWitnessJ2
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) SerializeCbTxWitnessJ2(witness *CbTxWitnessJ2) ([]byte, error) {
	if witness == nil || witness.b_hat == nil || len(witness.c_hats) == 0 ||
		len(witness.u_p) == 0 || witness.rpulpproof == nil {
		return nil, errors.New("SerializeCbTxWitnessJ2: there is nil pointer in SerializeCbTxWitnessJ2")
	}

	var err error
	length := pp.CbTxWitnessJ2SerializeSize(witness)
	w := bytes.NewBuffer(make([]byte, 0, length))

	// b_hat      *PolyCNTTVec
	err = pp.writePolyCNTTVec(w, witness.b_hat)
	if err != nil {
		return nil, err
	}

	// c_hats     []*PolyCNTT
	err = WriteVarInt(w, uint64(len(witness.c_hats)))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(witness.c_hats); i++ {
		err = pp.writePolyCNTT(w, witness.c_hats[i])
		if err != nil {
			return nil, err
		}
	}
	// u_p        []int64
	err = pp.writeCarryVectorRProof(w, witness.u_p)
	if err != nil {
		return nil, err
	}

	// rpulpproof *rpulpProof
	serializedRpuProof, err := pp.SerializeRpulpProof(witness.rpulpproof)
	if err != nil {
		return nil, err
	}

	err = writeVarBytes(w, serializedRpuProof)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// DeserializeCbTxWitnessJ2
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) DeserializeCbTxWitnessJ2(serializedCbTxWitness []byte) (*CbTxWitnessJ2, error) {
	var count uint64
	r := bytes.NewReader(serializedCbTxWitness)

	// b_hat      *PolyCNTTVec
	b_hat, err := pp.readPolyCNTTVec(r)
	if err != nil {
		return nil, err
	}

	// c_hats     []*PolyCNTT
	var c_hats []*PolyCNTT
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		c_hats = make([]*PolyCNTT, count)
		for i := uint64(0); i < count; i++ {
			c_hats[i], err = pp.readPolyCNTT(r)
			if err != nil {
				return nil, err
			}
		}
	}

	// u_p        []int64
	u_p, err := pp.readCarryVectorRProof(r)
	if err != nil {
		return nil, err
	}

	// rpulpproof *rpulpProof
	serializedRpulpProof, err := readVarBytes(r, MaxAllowedRpulpProofSize, "CbTxWitnessJ2.rpulpproof")
	if err != nil {
		return nil, err
	}
	rpulpproof, err := pp.DeserializeRpulpProof(serializedRpulpProof)
	if err != nil {
		return nil, err
	}

	return &CbTxWitnessJ2{
		b_hat:      b_hat,
		c_hats:     c_hats,
		u_p:        u_p,
		rpulpproof: rpulpproof,
	}, nil
}

// CoinbaseTxSerializeSize
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) CoinbaseTxSerializeSize(tx *CoinbaseTx, withWitness bool) int {
	var length int

	// Vin uint64
	length = 8

	//OutputTxos []*txo
	length += VarIntSerializeSize(uint64(len(tx.OutputTxos))) + len(tx.OutputTxos)*pp.TxoSerializeSize()

	//TxMemo []byte
	length += VarIntSerializeSize(uint64(len(tx.TxMemo))) + len(tx.TxMemo)

	// TxWitness
	if withWitness {
		if len(tx.OutputTxos) == 1 {
			witnessLen := pp.CbTxWitnessJ1SerializeSize(tx.TxWitnessJ1)
			length += VarIntSerializeSize(uint64(witnessLen)) + witnessLen
		} else { // >= 2
			witnessLen := pp.CbTxWitnessJ2SerializeSize(tx.TxWitnessJ2)
			length += VarIntSerializeSize(uint64(witnessLen)) + witnessLen
		}
	}
	return length
}

// SerializeCoinbaseTx
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) SerializeCoinbaseTx(tx *CoinbaseTx, withWitness bool) ([]byte, error) {
	if tx == nil || len(tx.OutputTxos) == 0 {
		return nil, errors.New("SerializeCoinbaseTx: there is nil pointer in CoinbaseTx")
	}
	var err error
	length := pp.CoinbaseTxSerializeSize(tx, withWitness)
	w := bytes.NewBuffer(make([]byte, 0, length))

	// Vin     uint64
	binarySerializer.PutUint64(w, binary.LittleEndian, tx.Vin)

	//OutputTxos []*txo
	err = WriteVarInt(w, uint64(len(tx.OutputTxos)))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(tx.OutputTxos); i++ {
		serializedTxo, err := pp.SerializeTxo(tx.OutputTxos[i])
		if err != nil {
			return nil, err
		}
		_, err = w.Write(serializedTxo)
		if err != nil {
			return nil, err
		}
	}

	//TxMemo []byte
	err = writeVarBytes(w, tx.TxMemo)
	if err != nil {
		return nil, err
	}

	if withWitness {
		var serializedTxWitness []byte
		var err error
		if len(tx.OutputTxos) == 1 { // TxWitnessJ1
			serializedTxWitness, err = pp.SerializeCbTxWitnessJ1(tx.TxWitnessJ1)
		} else { // TxWitnessJ2
			serializedTxWitness, err = pp.SerializeCbTxWitnessJ2(tx.TxWitnessJ2)
		}
		if err != nil {
			return nil, err
		}

		err = writeVarBytes(w, serializedTxWitness)
		if err != nil {
			return nil, err
		}
	}

	return w.Bytes(), nil
}

// DeserializeCoinbaseTx
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) DeserializeCoinbaseTx(serializedCbTx []byte, withWitness bool) (*CoinbaseTx, error) {
	r := bytes.NewReader(serializedCbTx)

	// Vin uint64
	vin, err := binarySerializer.Uint64(r, binary.LittleEndian)

	// OutputTxos []*txo
	var OutputTxos []*Txo
	outTxoNum, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if outTxoNum != 0 {
		OutputTxos = make([]*Txo, outTxoNum)
		tmp := make([]byte, pp.TxoSerializeSize())
		for i := uint64(0); i < outTxoNum; i++ {
			_, err = r.Read(tmp)
			if err != nil {
				return nil, err
			}
			OutputTxos[i], err = pp.DeserializeTxo(tmp)
			if err != nil {
				return nil, err
			}
		}
	}

	// TxMemo []byte
	var TxMemo []byte
	TxMemo, err = readVarBytes(r, MaxAllowedTxMemoSize, "CoinbaseTx.TxMemo")
	if err != nil {
		return nil, err
	}

	var txWitnessJ1 *CbTxWitnessJ1
	var txWitnessJ2 *CbTxWitnessJ2
	if withWitness {
		if outTxoNum == 1 { // J=1
			serializedWitness, err := readVarBytes(r, MaxAllowedTxWitnessSize, "CoinbaseTx.TxWitnessJ1")
			if err != nil {
				return nil, err
			}
			txWitnessJ1, err = pp.DeserializeCbTxWitnessJ1(serializedWitness)
			if err != nil {
				return nil, err
			}

			txWitnessJ2 = nil

		} else { // J >= 2
			txWitnessJ1 = nil

			serializedWitness, err := readVarBytes(r, MaxAllowedTxWitnessSize, "CoinbaseTx.TxWitnessJ2")
			if err != nil {
				return nil, err
			}
			txWitnessJ2, err = pp.DeserializeCbTxWitnessJ2(serializedWitness)
			if err != nil {
				return nil, err
			}
		}
	}

	return &CoinbaseTx{
		Vin:         vin,
		OutputTxos:  OutputTxos,
		TxMemo:      TxMemo,
		TxWitnessJ1: txWitnessJ1,
		TxWitnessJ2: txWitnessJ2,
	}, nil
}

// challengeSeedASerializeSizeApprox
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) challengeSeedASerializeSizeApprox() int {
	return VarIntSerializeSize(uint64(HashOutputBytesLen)) + HashOutputBytesLen
}

// responseASerializeSizeApprox
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) responseASerializeSizeApprox() int {
	//	r \in (Ring_{q_a})^{L_a}
	//	z \in (Ring_{q_a})^{L_a} eta
	return VarIntSerializeSize(uint64(pp.paramLA)) + pp.paramLA*pp.PolyASerializeSizeEta()
}

// ElrsSignatureSerializeSizeApprox
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) ElrsSignatureSerializeSizeApprox(ringSize int) int {
	var lenApprxo int
	// seeds [][]byte, each ring member has a seed []byte
	lenApprxo = VarIntSerializeSize(uint64(ringSize)) + ringSize*pp.challengeSeedASerializeSizeApprox()

	//z_as  []*PolyAVec eta, each ring member has a z_a, each z_a is a response A
	lenApprxo += VarIntSerializeSize(uint64(ringSize)) + ringSize*pp.responseASerializeSizeApprox()

	//z_cs  [][]*PolyCNTTVec
	lenApprxo += VarIntSerializeSize(uint64(ringSize)) + ringSize*pp.responseCSerializeSizeApprox()

	//z_cps [][]*PolyCNTTVec
	lenApprxo += VarIntSerializeSize(uint64(ringSize)) + ringSize*pp.responseCSerializeSizeApprox()

	return lenApprxo
}

// ElrsSignatureSerializeSize
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) ElrsSignatureSerializeSize(sig *elrsSignature) int {
	var length int
	// seeds [][]byte
	length = VarIntSerializeSize(uint64(len(sig.seeds)))
	for i := 0; i < len(sig.seeds); i++ {
		length += VarIntSerializeSize(uint64(len(sig.seeds[i]))) + len(sig.seeds[i])
	}
	//z_as  []*PolyAVec eta
	length += VarIntSerializeSize(uint64(len(sig.z_as)))
	for i := 0; i < len(sig.z_as); i++ {
		length += pp.PolyAVecSerializeSizeEta(sig.z_as[i])
	}
	//z_cs  [][]*PolyCVec eta
	length += VarIntSerializeSize(uint64(len(sig.z_cs)))
	for i := 0; i < len(sig.z_cs); i++ {
		length += VarIntSerializeSize(uint64(len(sig.z_cs[i])))
		for j := 0; j < len(sig.z_cs[i]); j++ {
			length += pp.PolyCVecSerializeSizeEta(sig.z_cs[i][j])
		}
	}
	//z_cps [][]*PolyCVec eta
	length += VarIntSerializeSize(uint64(len(sig.z_cps)))
	for i := 0; i < len(sig.z_cps); i++ {
		length += VarIntSerializeSize(uint64(len(sig.z_cps[i])))
		for j := 0; j < len(sig.z_cps[i]); j++ {
			length += pp.PolyCVecSerializeSizeEta(sig.z_cps[i][j])
		}
	}
	return length
}

// SerializeElrsSignature
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) SerializeElrsSignature(sig *elrsSignature) ([]byte, error) {
	if sig == nil {
		return nil, errors.New(ErrNilPointer)
	}

	var err error
	length := pp.ElrsSignatureSerializeSize(sig)
	w := bytes.NewBuffer(make([]byte, 0, length))

	// seeds [][]byte
	err = WriteVarInt(w, uint64(len(sig.seeds)))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(sig.seeds); i++ {
		err = writeVarBytes(w, sig.seeds[i])
		if err != nil {
			return nil, err
		}
	}

	// z_as  []*PolyAVec eta
	err = WriteVarInt(w, uint64(len(sig.z_as)))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(sig.z_as); i++ {
		err = pp.writePolyAVecEta(w, sig.z_as[i])
		if err != nil {
			return nil, err
		}
	}

	// z_cs  [][]*PolyCVec eta
	err = WriteVarInt(w, uint64(len(sig.z_cs)))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(sig.z_cs); i++ {
		tlength := len(sig.z_cs[i])
		err = WriteVarInt(w, uint64(tlength))
		if err != nil {
			return nil, err
		}
		for j := 0; j < tlength; j++ {
			err = pp.writePolyCVecEta(w, sig.z_cs[i][j])
			if err != nil {
				return nil, err
			}
		}
	}

	// z_cps [][]*PolyCVec eta
	err = WriteVarInt(w, uint64(len(sig.z_cps)))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(sig.z_cps); i++ {
		tlength := len(sig.z_cps[i])
		err = WriteVarInt(w, uint64(tlength))
		if err != nil {
			return nil, err
		}
		for j := 0; j < tlength; j++ {
			err = pp.writePolyCVecEta(w, sig.z_cps[i][j])
			if err != nil {
				return nil, err
			}
		}
	}

	return w.Bytes(), nil
}

// DeserializeElrsSignature
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) DeserializeElrsSignature(serializeElrsSignature []byte) (*elrsSignature, error) {
	var err error
	var count uint64
	r := bytes.NewReader(serializeElrsSignature)

	// seeds [][]byte
	var seeds [][]byte
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		seeds = make([][]byte, count)
		for i := uint64(0); i < count; i++ {
			seeds[i], err = readVarBytes(r, MaxAllowedChallengeSeedSize, "elrsSignature.seeds")
			if err != nil {
				return nil, err
			}
		}
	}

	// z_as  []*PolyAVec eta
	var z_as []*PolyAVec
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		z_as = make([]*PolyAVec, count)
		for i := uint64(0); i < count; i++ {
			z_as[i], err = pp.readPolyAVecEta(r)
			if err != nil {
				return nil, err
			}
		}
	}
	// z_cs  [][]*PolyCVec
	var z_cs [][]*PolyCVec
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		z_cs = make([][]*PolyCVec, count)
		var tcount uint64
		for i := uint64(0); i < count; i++ {
			tcount, err = ReadVarInt(r)
			if err != nil {
				return nil, err
			}
			z_cs[i] = make([]*PolyCVec, tcount)
			for j := uint64(0); j < tcount; j++ {
				z_cs[i][j], err = pp.readPolyCVecEta(r)
				if err != nil {
					return nil, err
				}
			}
		}
	}
	// z_cps [][]*PolyCVec eta
	var z_cps [][]*PolyCVec
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		z_cps = make([][]*PolyCVec, count)
		var tcount uint64
		for i := uint64(0); i < count; i++ {
			tcount, err = ReadVarInt(r)
			if err != nil {
				return nil, err
			}
			z_cps[i] = make([]*PolyCVec, tcount)
			for j := uint64(0); j < tcount; j++ {
				z_cps[i][j], err = pp.readPolyCVecEta(r)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	return &elrsSignature{
		seeds: seeds,
		z_as:  z_as,
		z_cs:  z_cs,
		z_cps: z_cps,
	}, nil
}

// TrTxWitnessSerializeSizeApprox returns the approximate size of TrTxWitnessSerializeSize, based on the inputRingSizes and outputTxoNum.
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) TrTxWitnessSerializeSizeApprox(inputRingSizes []int, outputTxoNum int) int {
	lenApprox := VarIntSerializeSize(uint64(len(inputRingSizes))) + len(inputRingSizes)*pp.PolyANTTSerializeSize() + // ma_ps      []*PolyANTT, each ring has a ma_ps
		VarIntSerializeSize(uint64(len(inputRingSizes))) + len(inputRingSizes)*pp.ValueCommitmentSerializeSize() // cmt_ps     []*ValueCommitment, each ring has a cnt_ps

	// elrsSigs   []*elrsSignature, each ring has a elrsSig
	lenApprox += VarIntSerializeSize(uint64(len(inputRingSizes)))
	for i := 0; i < len(inputRingSizes); i++ {
		sigLenApprox := pp.ElrsSignatureSerializeSizeApprox(inputRingSizes[i])
		lenApprox += VarIntSerializeSize(uint64(sigLenApprox)) + sigLenApprox
	}

	// b_hats
	lenApprox += pp.boundingVecCSerializeSizeApprox()

	// c_hats
	if len(inputRingSizes) == 1 { // I =1 : n_2 = I+J+2
		n2 := len(inputRingSizes) + outputTxoNum + 2
		lenApprox += VarIntSerializeSize(uint64(n2)) + n2*pp.PolyCNTTSerializeSize()
	} else { // I > 1: n_2 = I+J+4
		n2 := len(inputRingSizes) + outputTxoNum + 4
		lenApprox += VarIntSerializeSize(uint64(n2)) + n2*pp.PolyCNTTSerializeSize()
	}

	// u_p
	lenApprox += pp.CarryVectorRProofSerializeSize()

	//rpulpproof *rpulpProof
	rpuprfLength := 0
	// c_waves []*PolyCNTT // length n = I+J
	n := len(inputRingSizes) + outputTxoNum
	rpuprfLength += VarIntSerializeSize(uint64(n)) + n*pp.PolyCNTTSerializeSize()

	// c_hat_g,psi,phi  *PolyCNTT
	rpuprfLength += 3 * pp.PolyCNTTSerializeSize()

	// chseed  []byte
	rpuprfLength += pp.challengeSeedCSerializeSizeApprox()

	//cmt_zs  [][]*PolyCVec eta; n = (I+J), (k, paramLc)
	lenTmp := n * pp.responseCSerializeSizeApprox()
	rpuprfLength += VarIntSerializeSize(uint64(lenTmp)) + lenTmp

	//zs      []*PolyCVec eta
	rpuprfLength += pp.responseCSerializeSizeApprox()

	lenApprox += VarIntSerializeSize(uint64(rpuprfLength)) + rpuprfLength

	return lenApprox
}

// TrTxWitnessSerializeSize
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) TrTxWitnessSerializeSize(witness *TrTxWitness) int {
	if witness == nil {
		return 0
	}

	length := VarIntSerializeSize(uint64(len(witness.ma_ps))) + len(witness.ma_ps)*pp.PolyANTTSerializeSize() + // ma_ps      []*PolyANTT
		VarIntSerializeSize(uint64(len(witness.cmt_ps))) + len(witness.cmt_ps)*pp.ValueCommitmentSerializeSize() // cmt_ps     []*ValueCommitment

	// elrsSigs   []*elrsSignature
	length += VarIntSerializeSize(uint64(len(witness.elrsSigs)))
	for i := 0; i < len(witness.elrsSigs); i++ {
		sigLen := pp.ElrsSignatureSerializeSize(witness.elrsSigs[i])
		length += VarIntSerializeSize(uint64(sigLen)) + sigLen
	}

	length += pp.PolyCNTTVecSerializeSize(witness.b_hat) + //b_hat      *PolyCNTTVec
		VarIntSerializeSize(uint64(len(witness.c_hats))) + len(witness.c_hats)*pp.PolyCNTTSerializeSize() + //c_hats     []*PolyCNTT
		pp.CarryVectorRProofSerializeSize() //u_p        []int64

	//rpulpproof *rpulpProof
	rpfLen := pp.RpulpProofSerializeSize(witness.rpulpproof)
	length += VarIntSerializeSize(uint64(rpfLen)) + rpfLen

	return length
}

// SerializeTrTxWitness
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) SerializeTrTxWitness(witness *TrTxWitness) ([]byte, error) {
	if witness == nil || witness.ma_ps == nil || witness.cmt_ps == nil ||
		witness.elrsSigs == nil || witness.b_hat == nil || witness.c_hats == nil ||
		witness.u_p == nil || witness.rpulpproof == nil {
		return nil, errors.New("SerializeTrTxWitness: there is nil pointer in TrTxWitness")
	}
	var err error
	length := pp.TrTxWitnessSerializeSize(witness)
	w := bytes.NewBuffer(make([]byte, 0, length))

	// ma_ps      []*PolyANTT
	err = WriteVarInt(w, uint64(len(witness.ma_ps)))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(witness.ma_ps); i++ {
		err = pp.writePolyANTT(w, witness.ma_ps[i])
		if err != nil {
			return nil, err
		}
	}

	// cmt_ps     []*ValueCommitment
	err = WriteVarInt(w, uint64(len(witness.cmt_ps)))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(witness.cmt_ps); i++ {
		serializedVCmt, err := pp.SerializeValueCommitment(witness.cmt_ps[i])
		if err != nil {
			return nil, err
		}
		_, err = w.Write(serializedVCmt)
		if err != nil {
			return nil, err
		}
	}

	// elrsSigs   []*elrsSignature
	err = WriteVarInt(w, uint64(len(witness.elrsSigs)))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(witness.elrsSigs); i++ {
		serializedElrSig, err := pp.SerializeElrsSignature(witness.elrsSigs[i])
		if err != nil {
			return nil, err
		}
		err = writeVarBytes(w, serializedElrSig)
		if err != nil {
			return nil, err
		}
	}

	// b_hat      *PolyCNTTVec
	err = pp.writePolyCNTTVec(w, witness.b_hat)
	if err != nil {
		return nil, err
	}

	// c_hats     []*PolyCNTT
	err = WriteVarInt(w, uint64(len(witness.c_hats)))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(witness.c_hats); i++ {
		err = pp.writePolyCNTT(w, witness.c_hats[i])
		if err != nil {
			return nil, err
		}
	}

	// u_p        []int64
	err = pp.writeCarryVectorRProof(w, witness.u_p)
	if err != nil {
		return nil, err
	}

	// rpulpproof *rpulpProof
	serializedRpuProof, err := pp.SerializeRpulpProof(witness.rpulpproof)
	if err != nil {
		return nil, err
	}
	err = writeVarBytes(w, serializedRpuProof)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// DeserializeTrTxWitness
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) DeserializeTrTxWitness(serializedTrTxWitness []byte) (*TrTxWitness, error) {
	var err error
	var count uint64
	r := bytes.NewReader(serializedTrTxWitness)

	// ma_ps     []*PolyANTT
	var ma_ps []*PolyANTT
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		ma_ps = make([]*PolyANTT, count)
		for i := uint64(0); i < count; i++ {
			ma_ps[i], err = pp.readPolyANTT(r)
			if err != nil {
				return nil, err
			}
		}
	}

	// cmt_ps     []*ValueCommitment
	var cmt_ps []*ValueCommitment
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		cmt_ps = make([]*ValueCommitment, count)
		tmp := make([]byte, pp.ValueCommitmentSerializeSize())
		for i := uint64(0); i < count; i++ {
			_, err = r.Read(tmp)
			if err != nil {
				return nil, err
			}
			cmt_ps[i], err = pp.DeserializeValueCommitment(tmp)
			if err != nil {
				return nil, err
			}
		}
	}

	// elrsSigs   []*elrsSignature
	var elrsSigs []*elrsSignature
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		elrsSigs = make([]*elrsSignature, count)
		for i := uint64(0); i < count; i++ {
			serializedSig, err := readVarBytes(r, MaxAllowedElrsSignatureSize, "TrTxWitness.elrsSigs")
			if err != nil {
				return nil, err
			}
			elrsSigs[i], err = pp.DeserializeElrsSignature(serializedSig)
			if err != nil {
				return nil, err
			}
		}
	}

	// b_hat      *PolyCNTTVec
	var b_hat *PolyCNTTVec
	b_hat, err = pp.readPolyCNTTVec(r)
	if err != nil {
		return nil, err
	}

	// c_hats     []*PolyCNTT
	var c_hats []*PolyCNTT
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		c_hats = make([]*PolyCNTT, count)
		for i := uint64(0); i < count; i++ {
			c_hats[i], err = pp.readPolyCNTT(r)
			if err != nil {
				return nil, err
			}
		}
	}

	// u_p        []int64
	u_p, err := pp.readCarryVectorRProof(r)
	if err != nil {
		return nil, err
	}

	// rpulpproof *rpulpProof
	// var rpulpproof *rpulpProof
	serializedProof, err := readVarBytes(r, MaxAllowedRpulpProofSize, "TrTxWitness.rpulpproof")
	if err != nil {
		return nil, err
	}
	rpulpproof, err := pp.DeserializeRpulpProof(serializedProof)
	if err != nil {
		return nil, err
	}

	return &TrTxWitness{
		ma_ps:      ma_ps,
		cmt_ps:     cmt_ps,
		elrsSigs:   elrsSigs,
		b_hat:      b_hat,
		c_hats:     c_hats,
		u_p:        u_p,
		rpulpproof: rpulpproof,
	}, nil
}

// TrTxInputSerializeSize
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) TrTxInputSerializeSize(trTxIn *TrTxInput) int {
	var length int
	//	TxoList      []*LgrTxo
	length = VarIntSerializeSize(uint64(len(trTxIn.TxoList))) + len(trTxIn.TxoList)*pp.LgrTxoSerializeSize()

	//	SerialNumber []byte
	length += VarIntSerializeSize(uint64(len(trTxIn.SerialNumber))) + len(trTxIn.SerialNumber)

	return length
}

// serializeTrTxInput() is called only SerializeTransferTx() to prepare TrTxCon to be authenticated.
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) serializeTrTxInput(trTxIn *TrTxInput) ([]byte, error) {
	if trTxIn == nil || len(trTxIn.TxoList) == 0 {
		return nil, errors.New("serializeTrTxInput: there is nil pointer in TrTxInput")
	}

	if len(trTxIn.SerialNumber) == 0 {
		return nil, errors.New("serializeTrTxInput: nil serialNumber in TrTxInput")
	}

	var err error
	length := pp.TrTxInputSerializeSize(trTxIn)
	w := bytes.NewBuffer(make([]byte, 0, length))

	//TxoList      []*LgrTxo
	err = WriteVarInt(w, uint64(len(trTxIn.TxoList)))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(trTxIn.TxoList); i++ {
		serializedLgrTxo, err := pp.SerializeLgrTxo(trTxIn.TxoList[i])
		if err != nil {
			return nil, err
		}

		_, err = w.Write(serializedLgrTxo)
		if err != nil {
			return nil, err
		}
	}

	//SerialNumber []byte
	err = writeVarBytes(w, trTxIn.SerialNumber)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// deserializeTrTxInput
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) deserializeTrTxInput(serialziedTrTxInput []byte) (*TrTxInput, error) {
	var err error
	var count uint64
	r := bytes.NewReader(serialziedTrTxInput)

	//TxoList      []*LgrTxo
	var TxoList []*LgrTxo
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		TxoList = make([]*LgrTxo, count)
		tmp := make([]byte, pp.LgrTxoSerializeSize())
		for i := uint64(0); i < count; i++ {
			_, err = r.Read(tmp)
			if err != nil {
				return nil, err
			}
			TxoList[i], err = pp.DeserializeLgrTxo(tmp)
			if err != nil {
				return nil, err
			}
		}
	}

	//SerialNumber []byte
	var SerialNumber []byte
	SerialNumber, err = readVarBytes(r, MaxAllowedSerialNumberSize, "TrTxInput.SerialNumber")
	if err != nil {
		return nil, err
	}

	return &TrTxInput{
		TxoList:      TxoList,
		SerialNumber: SerialNumber,
	}, nil
}

// TransferTxSerializeSize
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) TransferTxSerializeSize(tx *TransferTx, withWitness bool) int {
	var length int

	//Inputs     []*TrTxInput
	length = VarIntSerializeSize(uint64(len(tx.Inputs)))
	for i := 0; i < len(tx.Inputs); i++ {
		txInLen := pp.TrTxInputSerializeSize(tx.Inputs[i])
		length += VarIntSerializeSize(uint64(txInLen)) + txInLen
	}

	//OutputTxos []*txo
	length += VarIntSerializeSize(uint64(len(tx.OutputTxos))) + len(tx.OutputTxos)*pp.TxoSerializeSize()

	//Fee        uint64
	length += 8

	//TxMemo []byte
	length += VarIntSerializeSize(uint64(len(tx.TxMemo))) + len(tx.TxMemo)

	// TxWitness
	if withWitness {
		//TxWitness *TrTxWitness
		witnessLen := pp.TrTxWitnessSerializeSize(tx.TxWitness)
		length += VarIntSerializeSize(uint64(witnessLen)) + witnessLen
	}

	return length
}

// SerializeTransferTx
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) SerializeTransferTx(tx *TransferTx, withWitness bool) ([]byte, error) {
	if tx == nil || len(tx.Inputs) == 0 || len(tx.OutputTxos) == 0 {
		return nil, errors.New("SerializeTransferTx: there is nil pointer in TransferTx")
	}

	var err error
	length := pp.TransferTxSerializeSize(tx, withWitness)
	w := bytes.NewBuffer(make([]byte, 0, length))

	// Inputs     []*TrTxInput
	err = WriteVarInt(w, uint64(len(tx.Inputs)))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(tx.Inputs); i++ {
		serializedTxInput, err := pp.serializeTrTxInput(tx.Inputs[i])
		if err != nil {
			return nil, err
		}
		err = writeVarBytes(w, serializedTxInput)
		if err != nil {
			return nil, err
		}
	}

	//OutputTxos []*txo
	err = WriteVarInt(w, uint64(len(tx.OutputTxos)))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(tx.OutputTxos); i++ {
		serializedTxo, err := pp.SerializeTxo(tx.OutputTxos[i])
		if err != nil {
			return nil, err
		}
		_, err = w.Write(serializedTxo)
		if err != nil {
			return nil, err
		}
	}

	//Fee        uint64
	err = binarySerializer.PutUint64(w, binary.LittleEndian, tx.Fee)
	if err != nil {
		return nil, err
	}

	//TxMemo []byte
	err = writeVarBytes(w, tx.TxMemo)
	if err != nil {
		return nil, err
	}

	//TxWitness *TrTxWitness
	if withWitness {
		serializedWitness, err := pp.SerializeTrTxWitness(tx.TxWitness)
		if err != nil {
			return nil, err
		}

		err = writeVarBytes(w, serializedWitness)
		if err != nil {
			return nil, err
		}

	}

	return w.Bytes(), nil
}

// DeserializeTransferTx
// not used anymore, should be removed. reviewed/commented by Alice, 2024.06.21
func (pp *PublicParameter) DeserializeTransferTx(serializedTrTx []byte, withWitness bool) (*TransferTx, error) {
	var err error
	var count uint64
	r := bytes.NewReader(serializedTrTx)

	// Inputs     []*TrTxInput
	var Inputs []*TrTxInput
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		Inputs = make([]*TrTxInput, count)
		for i := uint64(0); i < count; i++ {
			serializedTxInput, err := readVarBytes(r, MaxAllowedTrTxInputSize, "TransferTx.TrTxInput")
			if err != nil {
				return nil, err
			}
			Inputs[i], err = pp.deserializeTrTxInput(serializedTxInput)
			if err != nil {
				return nil, err
			}
		}
	}

	// OutputTxos []*txo
	var OutputTxos []*Txo
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		OutputTxos = make([]*Txo, count)
		tmp := make([]byte, pp.TxoSerializeSize())
		for i := uint64(0); i < count; i++ {
			_, err = r.Read(tmp)
			if err != nil {
				return nil, err
			}
			OutputTxos[i], err = pp.DeserializeTxo(tmp)
			if err != nil {
				return nil, err
			}
		}
	}

	// Fee        uint64
	Fee, err := binarySerializer.Uint64(r, binary.LittleEndian)
	if err != nil {
		return nil, err
	}

	// TxMemo []byte
	var TxMemo []byte
	TxMemo, err = readVarBytes(r, MaxAllowedTxMemoSize, "TransferTx.TxMemo")
	if err != nil {
		return nil, err
	}

	var TxWitness *TrTxWitness
	if withWitness {
		// TxWitness *TrTxWitness
		//	Note that if call this function with withWitness = true on a serializedTrTx with witness = false,
		//	error will happen.
		//	And we do not want to hide this error (for example, by check and return nil).
		//	Instead, we want to explore this error during development, unless there is requirements from practice.
		serializedTrTxWitness, err := readVarBytes(r, MaxAllowedTxWitnessSize, "TransferTx.TxWitness")
		if err != nil {
			return nil, err
		}
		TxWitness, err = pp.DeserializeTrTxWitness(serializedTrTxWitness)
		if err != nil {
			return nil, err
		}
	}

	return &TransferTx{
		Inputs:     Inputs,
		OutputTxos: OutputTxos,
		Fee:        Fee,
		TxMemo:     TxMemo,
		TxWitness:  TxWitness,
	}, nil
}

//const (
//	MAXALLOWED                  uint32 = 4294967295 // 2^32-1
//	MaxAllowedKemCiphertextSize uint32 = 1048576    // 2^20
//	MaxAllowedTxMemoSize        uint32 = 1024       // bytes
//	MaxAllowedSerialNumberSize  uint32 = 64         // 512 bits = 64 bytes
//	MaxAllowedChallengeSeedSize uint32 = 64         // use SHA512 to generate the challenge seed
//	MaxAllowedRpulpProofSize    uint32 = 8388608    // 2^23, 8M bytes
//	MaxAllowedTxWitnessSize     uint32 = 16777216   // 2^24, 16M bytes
//	MaxAllowedElrsSignatureSize uint32 = 8388608    // 2^23, 8M bytes
//	MaxAllowedTrTxInputSize     uint32 = 8388608    // 2^23, 8M bytes
//)
