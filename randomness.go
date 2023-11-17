package pqringct

import (
	"crypto/rand"
	"errors"
	"golang.org/x/crypto/sha3"
)

var ErrLength = errors.New("invalid length")

const RandSeedBytesLen = 64 // 512-bits

// extendable output function is instanced as sha3.Shake128()
// to get expected length number but the input of sha3.Shake128()
// is output of sha3.Sha512() function.

// filterWithBound() returns numbers in [0, bound], where bound is assumed to < 2^{63}-1。
// i.e., it is assumed that bitNumPerSample <= 63
func filterWithBound(buf []byte, expectedCount int, bitNumPerSample int, positiveBound int64) []int64 {
	rst := make([]int64, 0, expectedCount)

	byteNum := bitNumPerSample / 8
	bitNum := bitNumPerSample % 8

	var tmpByte byte
	var tmpSample int64

	bitCur := 0
	byteCur := 0
	gotNum := 0
	remainderBitsNum := len(buf) * 8
	for gotNum < expectedCount && remainderBitsNum >= bitNumPerSample {
		tmpSample = int64(0)
		for i := 0; i < byteNum; i++ {
			tmpByte = ((buf[byteCur+1] & (1<<bitCur - 1)) << (8 - bitCur)) | (buf[byteCur] >> bitCur)
			tmpSample |= int64(tmpByte) << (i * 8)

			byteCur += 1
		}

		if bitCur+bitNum < 8 {
			// fetch bitCur ~ bitCur+bitNum-1 of buf[byteCur]
			tmpByte = (buf[byteCur] >> bitCur) & (1<<bitNum - 1)
			tmpSample |= int64(tmpByte) << (byteNum * 8)

			bitCur = bitCur + bitNum
		} else if bitCur+bitNum == 8 {
			tmpByte = buf[byteCur] >> bitCur
			tmpSample |= int64(tmpByte) << (byteNum * 8)

			byteCur += 1
			bitCur = 0
		} else {
			//	fetch buf[byteCur][bitCur]~buf[byteCur][7]~buf[byteCur+1][(bitCur + bitNum)%8-1]
			nextBitCur := (bitCur + bitNum) % 8
			tmpByte = ((buf[byteCur+1] & (1<<nextBitCur - 1)) << (8 - bitCur)) | (buf[byteCur] >> bitCur)
			tmpSample |= int64(tmpByte) << (byteNum * 8)

			byteCur += 1
			bitCur = nextBitCur
		}

		if tmpSample <= positiveBound {
			rst = append(rst, tmpSample)
			gotNum += 1
		}

		// update remainderBitsNum
		remainderBitsNum -= bitNumPerSample
	}

	return rst
}

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

// 523987 = 0111_1111_1110_1101_0011
// randomPolyAForResponseA() returns a PolyA, where each coefficient lies in [-(eta_a - beta_a), (eta_a - beta_a)],
// where eta_a = 2^{19}-1 and beta=120
func (pp *PublicParameter) randomPolyAForResponseA() (*PolyA, error) {
	seed := RandomBytes(RandSeedBytesLen)

	xof := sha3.NewShake128()
	xof.Reset()
	_, err := xof.Write(seed)
	if err != nil {
		return nil, err
	}
	var buf []byte

	// Note that eta_a = 2^{19}-1 is a 19-bit number, and beta_a = 120, so that (eta_a - beta_a) is also a 19-bit number.
	// For [-(eta_a - beta_a), (eta_a - beta_a)], the bound is (eta_a - beta_a), and each number in [-(eta_a - beta_a), (eta_a - beta_a)] = [0, 2*(eta_a - beta_a)] needs 20 bits to sample.
	// probability: (2*bound+1) / (1 << 20) // should be float
	// needBits for each sample: 20*((1<<20)/(2*bound+1))
	bound := pp.paramEtaA - int64(pp.paramBetaA) // [-(eta_a - beta_a), (eta_a - beta_a)] = [0, 2*(eta_a - beta_a)]
	bitNumPerSample := 20
	expectedBitsPerSample := int(20*((1<<20)/float64(2*bound+1))) + 1 // should be less than 2^{32} bits

	targetSampleCount := pp.paramDA
	//	store the numbers that have been sampled, the target length is pp.paramDC
	sampled := make([]int64, 0, targetSampleCount)

	for len(sampled) < targetSampleCount {
		// uniform reject sample from the buf
		expectedSampleCount := targetSampleCount - len(sampled)
		buf = make([]byte, (expectedSampleCount*expectedBitsPerSample+7)/8)
		_, err = xof.Read(buf)
		if err != nil {
			return nil, err
		}
		tmp := filterWithBound(buf, expectedSampleCount, bitNumPerSample, 2*bound)
		sampled = append(sampled, tmp...)
	}

	for i := 0; i < targetSampleCount; i++ {
		sampled[i] = sampled[i] - bound
	}

	return &PolyA{sampled}, nil

	//bound := int64(523987) // 1 << 19 - 1 - 300
	//length := pp.paramDA   // 128
	//coeffs := make([]int64, 0, length)
	//
	//seed := RandomBytes(RandSeedBytesLen)
	//xof := sha3.NewShake128()
	//xof.Reset()
	//_, err := xof.Write(seed)
	//if err != nil {
	//	return nil, err
	//}
	//
	//// random the number in range [0,2*bound], and then reduce to [-bound, bound]
	//// 2*bound=0b1111_1111_1101_1010_0110, means that an element needs 20 bits
	//// expected (20 * length * (1<<19) / bound + 7 ) / 8 bytes
	//buf := make([]byte, (20*int64(length)*(1<<19)/bound+7)/8)
	//_, err = xof.Read(buf)
	//if err != nil {
	//	return nil, err
	//}
	//res := fillWithBoundOld(buf, length, 20, 2*bound)
	//coeffs = append(coeffs, res...)
	//for len(coeffs) < length {
	//	// uniform reject sample from the buf
	//	buf = make([]byte, 5) // gcd(20,8)=4*5*2=8*5
	//	_, err = xof.Read(buf)
	//	if err != nil {
	//		return nil, err
	//	}
	//	res = fillWithBoundOld(buf, length-len(coeffs), 20, 2*bound)
	//	coeffs = append(coeffs, res...)
	//}
	//for i := 0; i < length; i++ {
	//	coeffs[i] = coeffs[i] - bound
	//}
	//return &PolyA{coeffs}, nil
}

// randomPolyAinEtaA() outputs a PolyA, where each coefficient lies in [-eta_a, eta_a].
func (pp *PublicParameter) randomPolyAinEtaA() (*PolyA, error) {

	seed := RandomBytes(RandSeedBytesLen)

	xof := sha3.NewShake128()
	xof.Reset()
	_, err := xof.Write(seed)
	if err != nil {
		return nil, err
	}
	var buf []byte

	// Note that eta_a = 2^{19}-1 is a 19-bit number.
	// For [-eta_a, eta_a], the bound is eta_a, and each number in [-eta_a, eta_a] = [0, 2*eta_a] needs 20 bits to sample.
	// probability: (2*bound+1) / (1 << 20) // should be float
	// needBits for each sample: 20*((1<<20)/(2*bound+1))
	bound := pp.paramEtaA // [-eta_a, eta_a] = [0, 2*eta_a]
	bitNumPerSample := 20
	expectedBitsPerSample := int(20*((1<<20)/float64(2*bound+1))) + 1 // should be less than 2^{32} bits

	targetSampleCount := pp.paramDA
	//	store the numbers that have been sampled, the target length is pp.paramDC
	sampled := make([]int64, 0, targetSampleCount)

	for len(sampled) < targetSampleCount {
		// uniform reject sample from the buf
		expectedSampleCount := targetSampleCount - len(sampled)
		buf = make([]byte, (expectedSampleCount*expectedBitsPerSample+7)/8)
		_, err = xof.Read(buf)
		if err != nil {
			return nil, err
		}
		tmp := filterWithBound(buf, expectedSampleCount, bitNumPerSample, 2*bound)
		sampled = append(sampled, tmp...)
	}

	for i := 0; i < targetSampleCount; i++ {
		sampled[i] = sampled[i] - bound
	}

	return &PolyA{sampled}, nil

	//bound := int64(1<<19 - 1)
	//length := pp.paramDA
	//coeffs := make([]int64, 0, length)
	//
	//seed := RandomBytes(RandSeedBytesLen)
	//xof := sha3.NewShake128()
	//xof.Reset()
	//_, err := xof.Write(seed)
	//if err != nil {
	//	return nil, err
	//}
	//var buf []byte
	//// random the number in range [0,2*bound], and then reduce to [-bound, bound]
	//// 2*bound=0b00001_1111_1111_1111_1110_1111_1110, means that an element needs 25 bits
	//// expected (25 * length * (1<<24) / bound + 7 ) / 8 bytes
	//buf = make([]byte, (20*int64(length)*(1<<19)/bound+7)/8)
	//_, err = xof.Read(buf)
	//if err != nil {
	//	return nil, err
	//}
	//// uniform reject sample from the buf
	//res := fillWithBoundOld(buf, length, 20, 2*bound)
	//coeffs = append(coeffs, res...)
	//for len(coeffs) < length {
	//	// uniform reject sample from the buf
	//	buf = make([]byte, 5) // gcd(20,8)=4*5*2=8*5
	//	_, err = xof.Read(buf)
	//	if err != nil {
	//		return nil, err
	//	}
	//	res = fillWithBoundOld(buf, length-len(coeffs), 20, 2*bound)
	//	coeffs = append(coeffs, res...)
	//}
	//for i := 0; i < length; i++ {
	//	coeffs[i] = coeffs[i] - bound
	//}
	//return &PolyA{coeffs}, nil
}

// 16777087 = 1111_1111_1111_1111_0111_1111
// randomPolyCForResponseC() returns a PolyC, where each coefficient lies in [-(eta_c - beta_c), (eta_c - beta_c)],
// where eta_c = 2^{24}-1 and beta_c=128
func (pp *PublicParameter) randomPolyCForResponseC() (*PolyC, error) {
	seed := RandomBytes(RandSeedBytesLen)

	xof := sha3.NewShake128()
	xof.Reset()
	_, err := xof.Write(seed)
	if err != nil {
		return nil, err
	}
	var buf []byte

	// Note that eta_c = 2^{24}-1 is a 24-bit number, and beta_c = 128, so that (eta_c - beta_c) is also a 24-bit number.
	// For [-(eta_c - beta_c), (eta_c - beta_c)], the bound is (eta_c - beta_c), and each number in [-(eta_c - beta_c), (eta_c - beta_c)] = [0, 2*(eta_c - beta_c)] needs 25 bits to sample.
	// probability: (2*bound+1) / (1 << 25) // should be float
	// needBits for each sample: 25*((1<<25)/(2*bound+1))
	bound := pp.paramEtaC - int64(pp.paramBetaC) // [-(eta_c - beta_c), (eta_c - beta_c)] = [0, 2*(eta_c - beta_c)]
	bitNumPerSample := 25
	expectedBitsPerSample := int(25*((1<<25)/float64(2*bound+1))) + 1 // should be less than 2^{32} bits

	targetSampleCount := pp.paramDC
	//	store the numbers that have been sampled, the target length is pp.paramDC
	sampled := make([]int64, 0, targetSampleCount)

	for len(sampled) < targetSampleCount {
		// uniform reject sample from the buf
		expectedSampleCount := targetSampleCount - len(sampled)
		buf = make([]byte, (expectedSampleCount*expectedBitsPerSample+7)/8)
		_, err = xof.Read(buf)
		if err != nil {
			return nil, err
		}
		tmp := filterWithBound(buf, expectedSampleCount, bitNumPerSample, 2*bound)
		sampled = append(sampled, tmp...)
	}

	for i := 0; i < targetSampleCount; i++ {
		sampled[i] = sampled[i] - bound
	}

	return &PolyC{sampled}, nil

	//bound := int64(16777087)
	//length := pp.paramDC
	//coeffs := make([]int64, 0, length)
	//
	//seed := RandomBytes(RandSeedBytesLen)
	//xof := sha3.NewShake128()
	//xof.Reset()
	//_, err := xof.Write(seed)
	//if err != nil {
	//	return nil, err
	//}
	//var buf []byte
	//// random the number in range [0,2*bound], and then reduce to [-bound, bound]
	//// 2*bound=0b00001_1111_1111_1111_1110_1111_1110, means that an element needs 25 bits
	//// expected (25 * length * (1<<24) / bound + 7 ) / 8 bytes
	//buf = make([]byte, (25*int64(length)*(1<<24)/bound+7)/8)
	//_, err = xof.Read(buf)
	//if err != nil {
	//	return nil, err
	//}
	//// uniform reject sample from the buf
	//res := fillWithBoundOld(buf, length, 25, 2*bound)
	//coeffs = append(coeffs, res...)
	//for len(coeffs) < length {
	//	// uniform reject sample from the buf
	//	buf = make([]byte, 25) // gcd(25,8)=8*25
	//	_, err = xof.Read(buf)
	//	if err != nil {
	//		return nil, err
	//	}
	//	res = fillWithBoundOld(buf, length-len(coeffs), 25, 2*bound)
	//	coeffs = append(coeffs, res...)
	//}
	//for i := 0; i < length; i++ {
	//	coeffs[i] = coeffs[i] - bound
	//}
	//return &PolyC{coeffs}, nil
}

// 2^24-1= 1111_1111_1111_1111_1111_1111
//
//	randomPolyCinEtaC() outputs a PolyC, where each coefficient lies in [-eta_c, eta_c].
//	eta_c = 2^{24}-1, so that each coefficient needs 3 bytes (for absolute) and 1 bit (for signal)
func (pp *PublicParameter) randomPolyCinEtaC() (*PolyC, error) {

	seed := RandomBytes(RandSeedBytesLen)

	xof := sha3.NewShake128()
	xof.Reset()
	_, err := xof.Write(seed)
	if err != nil {
		return nil, err
	}
	var buf []byte

	// Note that eta_c = 2^{24}-1 is a 24-bit number.
	// For [-eta_c, eta_c], the bound is eta_c, and each number in [-eta_c, eta_c] = [0, 2*eta_c] needs 25 bit to sample.
	// probability: (2*bound+1) / (1 << 25) // should be float
	// needBits for each sample: 25*((1<<25)/(2*bound+1))
	bound := pp.paramEtaC // [-eta_c, eta_c] = [0, 2*eta_c]
	bitNumPerSample := 25
	expectedBitsPerSample := int(25*((1<<25)/float64(2*bound+1))) + 1 // should be less than 2^{32} bits

	targetSampleCount := pp.paramDC
	//	store the numbers that have been sampled, the target length is pp.paramDC
	sampled := make([]int64, 0, targetSampleCount)

	for len(sampled) < targetSampleCount {
		// uniform reject sample from the buf
		expectedSampleCount := targetSampleCount - len(sampled)
		buf = make([]byte, (expectedSampleCount*expectedBitsPerSample+7)/8)
		_, err = xof.Read(buf)
		if err != nil {
			return nil, err
		}
		tmp := filterWithBound(buf, expectedSampleCount, bitNumPerSample, 2*bound)
		sampled = append(sampled, tmp...)
	}

	for i := 0; i < targetSampleCount; i++ {
		sampled[i] = sampled[i] - bound
	}

	return &PolyC{sampled}, nil

	//bound := int64(1<<24 - 1)
	//length := pp.paramDC
	//coeffs := make([]int64, 0, length)
	//
	//seed := RandomBytes(RandSeedBytesLen)
	//xof := sha3.NewShake128()
	//xof.Reset()
	//_, err := xof.Write(seed)
	//if err != nil {
	//	return nil, err
	//}
	//var buf []byte
	//// random the number in range [0,2*bound], and then reduce to [-bound, bound]
	//// 2*bound=0b00001_1111_1111_1111_1110_1111_1110, means that an element needs 25 bits
	//// expected (25 * length * (1<<24) / bound + 7 ) / 8 bytes
	//buf = make([]byte, (25*int64(length)*(1<<24)/bound+7)/8)
	//_, err = xof.Read(buf)
	//if err != nil {
	//	return nil, err
	//}
	//// uniform reject sample from the buf
	//res := fillWithBoundOld(buf, length, 25, 2*bound)
	//coeffs = append(coeffs, res...)
	//for len(coeffs) < length {
	//	// uniform reject sample from the buf
	//	buf = make([]byte, 25) // gcd(25,8)=8*25
	//	_, err = xof.Read(buf)
	//	if err != nil {
	//		return nil, err
	//	}
	//	res = fillWithBoundOld(buf, length-len(coeffs), 25, 2*bound)
	//	coeffs = append(coeffs, res...)
	//
	//}
	//for i := 0; i < length; i++ {
	//	coeffs[i] = coeffs[i] - bound
	//}
	//return &PolyC{coeffs}, nil
}

// [-2,2]
func (pp *PublicParameter) randomPolyAinGammaA2(seed []byte) (*PolyA, error) {

	var seedUsed []byte
	if seed == nil {
		seedUsed = RandomBytes(RandSeedBytesLen)
	} else {
		seedUsed = make([]byte, len(seed))
		copy(seedUsed, seed)
	}

	xof := sha3.NewShake128()
	xof.Reset()
	_, err := xof.Write(seedUsed)
	if err != nil {
		return nil, err
	}
	var buf []byte
	// random the number in range [0,2*bound], and then reduce to [-bound, bound]
	// bound = 2, 2*bound=4, 3 bits are used to sample 1 number
	// probability: (2*bound+1) / (1 << 3) // should be float
	// needBits for each sample: 3*((1<<3)/(2*bound+1))
	bound := int64(2) // [-2, 2] = [0,4]
	bitNumPerSample := 3
	expectedBitsPerSample := int(3*((1<<3)/float64(2*bound+1))) + 1 // should be less than 2^{32} bits

	targetSampleCount := pp.paramDA
	//	store the numbers that have been sampled, the target length is pp.paramDA
	sampled := make([]int64, 0, targetSampleCount)

	for len(sampled) < targetSampleCount {
		// uniform reject sample from the buf
		expectedSampleCount := targetSampleCount - len(sampled)
		buf = make([]byte, (expectedSampleCount*expectedBitsPerSample+7)/8)
		_, err = xof.Read(buf)
		if err != nil {
			return nil, err
		}
		tmp := filterWithBound(buf, expectedSampleCount, bitNumPerSample, 2*bound)
		sampled = append(sampled, tmp...)
	}

	for i := 0; i < targetSampleCount; i++ {
		sampled[i] = sampled[i] - bound
	}
	return &PolyA{sampled}, nil
}

// This is a WRONG implementation.
func (pp *PublicParameter) randomPolyAinGammaA2Wrong(seed []byte) (*PolyA, error) {

	var seedUsed []byte
	if seed == nil {
		seedUsed = RandomBytes(RandSeedBytesLen)
	} else {
		seedUsed = make([]byte, len(seed))
		copy(seedUsed, seed)
	}

	xof := sha3.NewShake128()
	xof.Reset()
	_, err := xof.Write(seedUsed)
	if err != nil {
		return nil, err
	}
	//	bound = 2, each 4 bits can be used to sample a number in [-2, 2], by using the hamming weight
	buf := make([]byte, pp.paramDA/2)
	_, err = xof.Read(buf)
	if err != nil {
		return nil, err
	}

	var lowWight, highWeight int8
	coeffs := make([]int64, pp.paramDA)
	t := 0
	for i := 0; i < pp.paramDA/2; i++ {
		lowWight = int8((buf[i] >> 0) & 1)
		lowWight += int8((buf[i] >> 1) & 1)
		highWeight = int8((buf[i] >> 2) & 1)
		highWeight += int8((buf[i] >> 3) & 1)

		coeffs[t] = int64(highWeight - lowWight)

		lowWight = int8((buf[i] >> 4) & 1)
		lowWight += int8((buf[i] >> 5) & 1)
		highWeight = int8((buf[i] >> 6) & 1)
		highWeight += int8((buf[i] >> 7) & 1)

		coeffs[t+1] = int64(highWeight - lowWight)

		t += 2
	}

	return &PolyA{coeffs}, nil
}

// expandValuePadRandomness() return pp.TxoValueBytesLen() bytes,
// which will be used to encrypt the value-bytes.
// pp.TxoValueBytesLen() is 7, which means we use XOF to generate 7*8 = 56 bits.
// For security, the length of output does not matter,
// since the seed (KEM-generated key) is used only once.
func (pp *PublicParameter) expandValuePadRandomness(seed []byte) ([]byte, error) {
	if len(seed) == 0 {
		//	for such an expand function, the seed should not be empty.
		return nil, errors.New("expandValuePadRandomness: the seed is empty")
	}

	buf := make([]byte, pp.TxoValueBytesLen())
	realSeed := append([]byte{'V'}, seed...)

	XOF := sha3.NewShake128()
	XOF.Reset()
	_, err := XOF.Write(realSeed)
	if err != nil {
		return nil, err
	}
	_, err = XOF.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

// expandAddressSKsp() expand s \in (S_{\gamma_a})^{L_a} from input seed.
// To be self-completed, this function append 'ASKSP' before seed to form the real used seed.
func (pp *PublicParameter) expandAddressSKsp(seed []byte) (*PolyAVec, error) {
	if len(seed) == 0 {
		//	for such an expand function, the seed should not be empty.
		return nil, errors.New("expandAddressSKsp: the seed is empty")
	}

	realSeed := append([]byte{'A', 'S', 'K', 'S', 'P'}, seed...) // AskSp

	tmpSeedLen := len(realSeed) + 1
	tmpSeed := make([]byte, tmpSeedLen) // 1 byte for index i \in [0, paramLA -1], where paramLA is assumed to be smaller than 127

	var err error
	rst := pp.NewPolyAVec(pp.paramLA)
	for i := 0; i < pp.paramLA; i++ {
		copy(tmpSeed, realSeed)
		tmpSeed[tmpSeedLen-1] = byte(i)

		rst.polyAs[i], err = pp.randomPolyAinGammaA2(tmpSeed)
		if err != nil {
			return nil, err
		}
		//rst.polyAs[i] = tmp
	}
	return rst, nil
}

func (pp *PublicParameter) isAddressSKspNormalInBound(addressSKsp *PolyAVec) (inBound bool) {
	if addressSKsp.infNorm() > 2 {
		// 2 is consistent with the pp.randomPolyAinGammaA2(tmpSeed)
		return false
	}

	return true
}

// expandAddressSKsn() expand AddressSKsn from an input seed, and directly output the NTT form.
// To be self-completed, this function append 'ASKSN' before seed to form the real used seed.
func (pp *PublicParameter) expandAddressSKsn(seed []byte) (*PolyANTT, error) {
	if len(seed) == 0 {
		return nil, ErrLength
	}

	realSeed := append([]byte{'A', 'S', 'K', 'S', 'N'}, seed...) // AskSn

	coeffs, err := pp.randomDaIntegersInQa(realSeed)
	if err != nil {
		return nil, err
	}

	return &PolyANTT{coeffs: coeffs}, nil
}

// review done 0413
// expandValueCmtRandomness() expand r \in (\chi^{d_c})^{L_c} from a given seed.
// \chi^{d_c} is regarded as a polyC, and r is regarded as a PolyCVec
func (pp *PublicParameter) expandValueCmtRandomness(seed []byte) (*PolyCVec, error) {
	if len(seed) == 0 {
		return nil, ErrLength
	}
	realSeed := append([]byte{'C', 'M', 'T', 'R'}, seed...) // CmtR

	tmpSeedLen := len(realSeed) + 1
	tmpSeed := make([]byte, tmpSeedLen) // 1 byte for index i \in [0, paramLc -1], where paramLc is assumed to be smaller than 127

	var err error
	rst := pp.NewPolyCVec(pp.paramLC)
	for i := 0; i < pp.paramLC; i++ {
		copy(tmpSeed, realSeed)
		tmpSeed[tmpSeedLen-1] = byte(i)
		rst.polyCs[i], err = pp.randomPolyCinDistributionChi(tmpSeed)
		if err != nil {
			return nil, err
		}
	}
	return rst, nil
}

// sampleValueCmtRandomness() return a random r \in (\chi^{d_c})^{L_c}.
// \chi^{d_c} is regarded as a polyC, and r is regarded as a PolyCVec
func (pp *PublicParameter) sampleValueCmtRandomness() (*PolyCVec, error) {
	var err error
	rst := pp.NewPolyCVec(pp.paramLC)
	for i := 0; i < pp.paramLC; i++ {
		rst.polyCs[i], err = pp.randomPolyCinDistributionChi(nil)
		if err != nil {
			return nil, err
		}
	}
	return rst, nil
}

// review done 0413
// Each coefficient of PolyCinDistributionChi is sampled from {-1, 0, 1}, where both 1 and -1 has probability 5/16, and 0 has probability 6/16.
func (pp *PublicParameter) randomPolyCinDistributionChi(seed []byte) (*PolyC, error) {

	var seedUsed []byte
	if len(seed) == 0 {
		seedUsed = RandomBytes(RandSeedBytesLen)
	} else {
		seedUsed = make([]byte, len(seed))
		copy(seedUsed, seed)
	}

	coeffs := make([]int64, pp.paramDC)

	buf := make([]byte, pp.paramDC/2) //	each coefficient needs 4 bits to sample
	XOF := sha3.NewShake128()
	XOF.Reset()

	_, err := XOF.Write(seedUsed)
	if err != nil {
		return nil, err
	}
	_, err = XOF.Read(buf)
	if err != nil {
		return nil, err
	}

	var tmp byte
	t := 0
	for i := 0; i < pp.paramDC/2; i++ {
		tmp = buf[i] & 0x0F // low 4 bits
		if tmp < 5 {
			coeffs[t] = -1
		} else if tmp < 10 {
			coeffs[t] = 1
		} else {
			coeffs[t] = 0
		}

		t += 1

		tmp = buf[i] >> 4 // high 4 bits
		if tmp < 5 {
			coeffs[t] = -1
		} else if tmp < 10 {
			coeffs[t] = 1
		} else {
			coeffs[t] = 0
		}

		t += 1
	}

	return &PolyC{coeffs}, nil
}

// sampleMaskingVecA() returns a masking vector y \in (S_{eta_a})^{L_a}.
func (pp PublicParameter) sampleMaskingVecA() (*PolyAVec, error) {
	rst := pp.NewPolyAVec(pp.paramLA)

	var err error
	for i := 0; i < pp.paramLA; i++ {
		rst.polyAs[i], err = pp.randomPolyAinEtaA()
		if err != nil {
			return nil, err
		}
	}
	return rst, nil
}

// sampleMaskingVecC() returns a masking vector y \in (S_{eta_c})^{L_c}
func (pp *PublicParameter) sampleMaskingVecC() (*PolyCVec, error) {
	// etaC
	var err error

	polys := make([]*PolyC, pp.paramLC)

	for i := 0; i < pp.paramLC; i++ {
		polys[i], err = pp.randomPolyCinEtaC()
		if err != nil {
			return nil, err
		}
	}

	return &PolyCVec{
		polyCs: polys,
	}, nil

}

// sampleResponseA() returns a PolyAVec with length paramLa,
// where each coefficient lies in [-(eta_a-beta_a), (eta_a-beta_a)], where eta_a = 2^{19}-1, beta_a = 300
func (pp *PublicParameter) sampleResponseA() (*PolyAVec, error) {
	rst := pp.NewPolyAVec(pp.paramLA)

	var err error
	for i := 0; i < pp.paramLA; i++ {
		rst.polyAs[i], err = pp.randomPolyAForResponseA()
		if err != nil {
			return nil, err
		}
	}

	return rst, nil
}

// sampleResponseC() returns a PolyCVec with length paramLc,
// where each coefficient lies in [-(eta_c - beta_c), (eta_c - beta_c)]
func (pp PublicParameter) sampleResponseC() (*PolyCVec, error) {
	rst := pp.NewPolyCVec(pp.paramLC)

	var err error
	for i := 0; i < pp.paramLC; i++ {
		rst.polyCs[i], err = pp.randomPolyCForResponseC()
		if err != nil {
			return nil, err
		}
	}
	return rst, nil
}

// 9007199254746113 = 0010_0000_0000_0000_0000_0000_0000_0000_0000_0000_0001_0100_0000_0001
// 4503599627373056 = 0001_0000_0000_0000_0000_0000_0000_0000_0000_0000_000_1010_0000_0000
//
//	randomDcIntegersInQc() outputs Dc int64,  by sampling uniformly (when seed is nil) or expanding from a seed (when seed is not nil)
//	Each integer lies in [-(Q_c-1)/2, (Q_c-2)/2].
func (pp *PublicParameter) randomDcIntegersInQc(seed []byte) ([]int64, error) {
	var tmpSeed []byte
	if len(seed) == 0 {
		tmpSeed = RandomBytes(RandSeedBytesLen)
	} else {
		tmpSeed = make([]byte, len(seed))
		copy(tmpSeed, seed)
	}

	xof := sha3.NewShake128()
	xof.Reset()
	_, err := xof.Write(tmpSeed)
	if err != nil {
		return nil, err
	}
	var buf []byte

	// Note that q_c = 9007199254746113 = 2^53 + 2^12 + 2^10 + 2^0 is a 54-bit number
	// 2*bound=q_c-1, [0, 2*bound], 54 bits are used to sample 1 number
	// probability: (2*bound+1) / (1 << 54) // should be float
	// needBits for each sample: 54*((1<<54)/(2*bound+1))
	bound := (pp.paramQC - 1) >> 1 // [-(q_c-1)/2, (q_c -1)/2] = [0, q_c-1]
	bitNumPerSample := 54
	expectedBitsPerSample := int(54*((1<<54)/float64(2*bound+1))) + 1 // should be less than 2^{32} bits

	targetSampleCount := pp.paramDC
	//	store the numbers that have been sampled, the target length is pp.paramDC
	sampled := make([]int64, 0, targetSampleCount)

	for len(sampled) < targetSampleCount {
		// uniform reject sample from the buf
		expectedSampleCount := targetSampleCount - len(sampled)
		buf = make([]byte, (expectedSampleCount*expectedBitsPerSample+7)/8)
		_, err = xof.Read(buf)
		if err != nil {
			return nil, err
		}
		tmp := filterWithBound(buf, expectedSampleCount, bitNumPerSample, 2*bound)
		sampled = append(sampled, tmp...)
	}

	for i := 0; i < targetSampleCount; i++ {
		sampled[i] = sampled[i] - bound
	}

	return sampled, nil

	//var tmpSeed []byte
	//if len(seed) == 0 {
	//	tmpSeed = RandomBytes(RandSeedBytesLen)
	//} else {
	//	tmpSeed = make([]byte, len(seed))
	//	copy(tmpSeed, seed)
	//}
	//bitNum := 54
	//bound := pp.paramQC
	//xof := sha3.NewShake128()
	//xof.Reset()
	//length := pp.paramDC
	//coeffs := make([]int64, 0, length)
	//xof.Write(tmpSeed)
	//buf := make([]byte, (int64(bitNum)*int64(length)+7)/8)
	//xof.Read(buf)
	//tmp := fillWithBoundOld(buf, length, bitNum, bound)
	//coeffs = append(coeffs, tmp...)
	//for len(coeffs) < length {
	//	buf = make([]byte, 27) // gcd(54,8)=2*27*4=27*8
	//	xof.Read(buf)
	//	tmp = fillWithBoundOld(buf, length-len(coeffs), bitNum, bound)
	//	coeffs = append(coeffs, tmp...)
	//}
	//
	//for i := 0; i < length; i++ {
	//	coeffs[i] = reduceInt64(coeffs[i], pp.paramQC)
	//}
	//return coeffs
}

// randomDcIntegersInQcEtaF() outputs Dc int64,  by sampling uniformly.
// Each integer lies in [-eta_f, eta_f].
// eta_f = 2^23-1.
func (pp *PublicParameter) randomDcIntegersInQcEtaF() ([]int64, error) {

	seed := RandomBytes(RandSeedBytesLen)

	xof := sha3.NewShake128()
	xof.Reset()
	_, err := xof.Write(seed)
	if err != nil {
		return nil, err
	}
	var buf []byte

	// Note that eta_f = 2^23-1 is a 23-bit number.
	// For each number in [-eta_f, eta_f] = [0, 2*eta_f], 24 bits are used to sample 1 number
	// bound := eta_f
	// probability: (2*bound+1) / (1 << 24) // should be float
	// needBits for each sample: 23*((1<<23)/(2*bound+1))
	bound := pp.paramEtaF // [-eta_f, eta_f] = [0, 2*eta_f]
	bitNumPerSample := 24
	expectedBitsPerSample := int(24*((1<<24)/float64(2*bound+1))) + 1 // should be less than 2^{32} bits

	targetSampleCount := pp.paramDC
	//	store the numbers that have been sampled, the target length is pp.paramDC
	sampled := make([]int64, 0, targetSampleCount)

	for len(sampled) < targetSampleCount {
		// uniform reject sample from the buf
		expectedSampleCount := targetSampleCount - len(sampled)
		buf = make([]byte, (expectedSampleCount*expectedBitsPerSample+7)/8)
		_, err = xof.Read(buf)
		if err != nil {
			return nil, err
		}
		tmp := filterWithBound(buf, expectedSampleCount, bitNumPerSample, 2*bound)
		sampled = append(sampled, tmp...)
	}

	for i := 0; i < targetSampleCount; i++ {
		sampled[i] = sampled[i] - bound
	}

	return sampled, nil

	//bitNum := 24
	//bound := pp.paramEtaF
	//length := pp.paramDC
	//
	//coeffs := make([]int64, 0, length)
	//
	//xof := sha3.NewShake128()
	//xof.Reset()
	//xof.Write(RandomBytes(RandSeedBytesLen))
	//
	//buf := make([]byte, (24*int64(length)*(1<<23)/bound+7)/8)
	//xof.Read(buf)
	//tmp := fillWithBoundOld(buf, length-len(coeffs), bitNum, 2*bound)
	//coeffs = append(coeffs, tmp...)
	//for len(coeffs) < length {
	//	buf = make([]byte, 3) // gcd(24,8)=3*8
	//	xof.Read(buf)
	//	tmp = fillWithBoundOld(buf, length-len(coeffs), bitNum, 2*bound)
	//	coeffs = append(coeffs, tmp...)
	//}
	//
	//for i := 0; i < length; i++ {
	//	coeffs[i] = coeffs[i] - bound
	//}
	//
	//return coeffs, nil

}

// q_a = 8522826353 = 2^32+2^31+2^30+2^29+2^28+2^27+2^26+2^9+2^6+2^5+2^4+1
//
//	randomDaIntegersInQa() returns paramDA int64, each in the scope [-(q_a-1)/2, (q_a-1)/2].
func (pp *PublicParameter) randomDaIntegersInQa(seed []byte) ([]int64, error) {
	var tmpSeed []byte
	if len(seed) == 0 {
		tmpSeed = RandomBytes(RandSeedBytesLen)
	} else {
		tmpSeed = make([]byte, len(seed))
		copy(tmpSeed, seed)
	}

	xof := sha3.NewShake128()
	xof.Reset()
	_, err := xof.Write(tmpSeed)
	if err != nil {
		return nil, err
	}
	var buf []byte

	// Note that q_a = 8522826353 = 2^32+2^31+2^30+2^29+2^28+2^27+2^26+2^9+2^6+2^5+2^4+1 is a 33-bit number.
	// bound = (q_a-1)/2, 2*bound=q_a-1, [0, 2*bound], 33 bits are used to sample 1 number
	// probability: (2*bound+1) / (1 << 33) // should be float
	// needBits for each sample: 33*((1<<33)/(2*bound+1))
	bound := (pp.paramQA - 1) >> 1 // [-(q_a-1)/2, (q_a -1)/2] = [0, q_a-1]
	bitNumPerSample := 33
	expectedBitsPerSample := int(33*((1<<33)/float64(2*bound+1))) + 1 // should be less than 2^{32} bits

	targetSampleCount := pp.paramDA
	//	store the numbers that have been sampled, the target length is pp.paramDA
	sampled := make([]int64, 0, targetSampleCount)

	for len(sampled) < targetSampleCount {
		// uniform reject sample from the buf
		expectedSampleCount := targetSampleCount - len(sampled)
		buf = make([]byte, (expectedSampleCount*expectedBitsPerSample+7)/8)
		_, err = xof.Read(buf)
		if err != nil {
			return nil, err
		}
		tmp := filterWithBound(buf, expectedSampleCount, bitNumPerSample, 2*bound)
		sampled = append(sampled, tmp...)
	}

	for i := 0; i < targetSampleCount; i++ {
		sampled[i] = sampled[i] - bound
	}

	return sampled, nil
}

// expandSigACh should output a {-1,0,1}^DC vector with the number of not-0 is theta_a from a byte array.
//
//	The seed could not be empty.
//
// Firstly, set the 1 or -1 with total number is theta
// Secondly, shuffle the array using the Knuth-Durstenfeld Shuffle
func (pp *PublicParameter) expandChallengeA(seed []byte) (*PolyA, error) {
	//tmpSeed := make([]byte, len(seed))
	//copy(tmpSeed, seed)
	if len(seed) == 0 {
		//	for such an expand function, the seed could not be empty.
		return nil, errors.New("expandChallengeA: the seed is empty")
	}
	tmpSeed := append([]byte{'C', 'H', 'A'}, seed...)

	xof := sha3.NewShake128()
	xof.Reset()
	xof.Write(tmpSeed)
	// because the ThetaA must less than DA, so there would use the
	// 8-th binary for Setting and 0-th to 7-th for Shuffling.
	// Setting
	buf := make([]byte, (pp.paramThetaA+7)/8)
	xof.Read(buf)
	signs := uint64(0)
	for i := 0; i < 8; i++ {
		signs |= uint64(buf[i]) << (8 * i)
	}

	coeffs := make([]int64, pp.paramDA)
	buf = make([]byte, pp.paramDA)
	pos := 0
	xof.Read(buf)
	for i := int64(pp.paramDA - pp.paramThetaA); i < int64(pp.paramDA); i++ {
		b := int64(pp.paramDA)
		for b > i && pos < len(buf) {
			b = int64(buf[pos])
			pos++
			if pos == len(buf) {
				xof.Read(buf)
				pos = 0
			}
		}
		coeffs[i], coeffs[b] = coeffs[b], int64(1-2*(signs&1))
		signs >>= 1
	}
	return &PolyA{coeffs: coeffs}, nil
}

// expandChallengeC() returns a challenge for proof in value commitment, say a PolyC, //
// where each coefficient is sampled from {-1, 0, 1}, with Pr(0)=1/2, Pr(1)=Pr(-1)= 1/4.
// The seed could not be empty.
func (pp PublicParameter) expandChallengeC(seed []byte) (*PolyC, error) {
	if len(seed) == 0 {
		//	for such an expand fucntion, the seed could not be empty.
		return nil, errors.New("expandChallengeC: the seed is empty")
	}

	tmpSeed := append([]byte{'C', 'H', 'C'}, seed...)

	var err error
	// extend seed via sha3.Shake128
	rst := pp.NewPolyC()
	buf := make([]byte, pp.paramDC/4) //	Each coefficient needs 2 bits, each byte can be used to generate 4 coefficients.

	XOF := sha3.NewShake128()
	XOF.Reset()
	_, err = XOF.Write(tmpSeed)
	if err != nil {
		return nil, err
	}
	_, err = XOF.Read(buf)
	if err != nil {
		return nil, err
	}

	var a1, a2, a3, a4, b1, b2, b3, b4 int64
	t := 0
	for i := 0; i < pp.paramDC/4; i++ {
		a1 = int64((buf[i] & (1 << 0)) >> 0)
		b1 = int64((buf[i] & (1 << 1)) >> 1)
		a2 = int64((buf[i] & (1 << 2)) >> 2)
		b2 = int64((buf[i] & (1 << 3)) >> 3)
		a3 = int64((buf[i] & (1 << 4)) >> 4)
		b3 = int64((buf[i] & (1 << 5)) >> 5)
		a4 = int64((buf[i] & (1 << 6)) >> 6)
		b4 = int64((buf[i] & (1 << 7)) >> 7)

		rst.coeffs[t] = a1 - b1
		rst.coeffs[t+1] = a2 - b2
		rst.coeffs[t+2] = a3 - b3
		rst.coeffs[t+3] = a4 - b4

		t += 4
	}
	return rst, nil
}

func (pp *PublicParameter) samplePloyCWithLowZeros() (*PolyC, error) {

	coeffs, err := pp.randomDcIntegersInQc(nil)
	if err != nil {
		return nil, err
	}

	for i := 0; i < pp.paramK; i++ {
		coeffs[i] = 0
	}

	return &PolyC{coeffs}, nil
}

//func (pp *PublicParameter) samplePloyCWithLowZeros() *PolyC {
//	rst := pp.NewZeroPolyC()
//	bitNum := 54
//	bound := pp.paramQC
//	xof := sha3.NewShake128()
//	xof.Reset()
//	length := pp.paramDC
//	coeffs := make([]int64, pp.paramK, length)
//	xof.Write(RandomBytes(RandSeedBytesLen))
//	buf := make([]byte, (int64(bitNum*(length-pp.paramK))+7)/8)
//	xof.Read(buf)
//	tmp := fillWithBoundOld(buf, length, bitNum, bound)
//	coeffs = append(coeffs, tmp...)
//	for len(coeffs) < length {
//		buf = make([]byte, 27) // gcd(54,8)=2*27*8=27*8
//		xof.Read(buf)
//		tmp = fillWithBoundOld(buf, length-len(coeffs), bitNum, bound)
//		coeffs = append(coeffs, tmp...)
//	}
//
//	for i := pp.paramK; i < pp.paramDC; i++ {
//		rst.coeffs[i] = reduceInt64(coeffs[i], pp.paramQC)
//	}
//	return rst
//}

func expandBinaryMatrix(seed []byte, rownum int, colnum int) (binM [][]byte, err error) {
	if len(seed) == 0 {
		//	for such an expand function, the seed should not be empty.
		return nil, errors.New("expandBinaryMatrix: the seed is empty")
	}

	seedUsed := append([]byte{'B', 'I', 'N', 'M'}, seed...)

	binM = make([][]byte, rownum)
	colByteLen := (colnum + 7) / 8
	buf := make([]byte, colByteLen)

	XOF := sha3.NewShake128()
	XOF.Reset()
	_, err = XOF.Write(seedUsed)
	for i := 0; i < rownum; i++ {
		binM[i] = make([]byte, colByteLen)
		_, err = XOF.Read(buf)
		if err != nil {
			return nil, err
		}
		copy(binM[i], buf)
	}
	return binM, nil
}

func expandBinaryMatrixOld(seed []byte, rownum int, colnum int) (binM [][]byte, err error) {
	binM = make([][]byte, rownum)
	XOF := sha3.NewShake128()
	for i := 0; i < rownum; i++ {
		buf := make([]byte, (colnum+7)/8)
		binM[i] = make([]byte, (colnum+7)/8)
		XOF.Reset()
		_, err = XOF.Write(append(seed, byte(i)))
		if err != nil {
			return nil, err
		}
		_, err = XOF.Read(buf)
		if err != nil {
			return nil, err
		}
		binM[i] = buf
	}
	return binM, nil
}
