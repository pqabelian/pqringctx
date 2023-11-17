package pqringct

import (
	"log"
	"math/big"
)

type PolyA struct {
	coeffs []int64
}
type PolyANTT struct {
	coeffs []int64
}

type PolyAVec struct {
	polyAs []*PolyA
}
type PolyANTTVec struct {
	polyANTTs []*PolyANTT
}

func (pp *PublicParameter) NewPolyA() *PolyA {
	return &PolyA{coeffs: make([]int64, pp.paramDA)}
}
func (pp *PublicParameter) NewZeroPolyA() *PolyA {
	rst := &PolyA{coeffs: make([]int64, pp.paramDA)}
	for i := 0; i < pp.paramDA; i++ {
		rst.coeffs[i] = 0
	}
	return rst
}
func (pp *PublicParameter) NewPolyANTT() *PolyANTT {
	return &PolyANTT{coeffs: make([]int64, pp.paramDA)}
}
func (pp *PublicParameter) NewZeroPolyANTT() *PolyANTT {
	rst := &PolyANTT{coeffs: make([]int64, pp.paramDA)}
	for i := 0; i < pp.paramDA; i++ {
		rst.coeffs[i] = 0
	}
	return rst
}

func (polyA *PolyA) infNorm() (infNorm int64) {
	rst := int64(0)
	for _, coeff := range polyA.coeffs {
		if coeff > rst {
			rst = coeff
		} else if coeff < 0 && -coeff > rst {
			rst = -coeff
		}
	}
	return rst
}

func (polyAVec *PolyAVec) infNorm() (infNorm int64) {
	rst := int64(0)
	for _, polyA := range polyAVec.polyAs {
		tmp := polyA.infNorm()
		if tmp > rst {
			rst = tmp
		}
	}

	return rst
}

func (pp *PublicParameter) NTTPolyA(polyA *PolyA) *PolyANTT {
	//	NTT
	zetaAOrder := pp.paramZetaAOrder
	slotNum := zetaAOrder / 2 //	will factor to irreducible factors
	segNum := 1
	segLen := pp.paramDA
	factors := make([]int, 1)
	factors[0] = slotNum / 2

	coeffs := make([]int64, pp.paramDA)
	//for i := 0; i < pp.paramDA; i++ {
	//	coeffs[i] = polyA.coeffs[i]
	//}
	copy(coeffs, polyA.coeffs)

	var qaBig, tmp, tmp1, tmp2, zetaTmp big.Int
	qaBig.SetInt64(pp.paramQA)
	for {
		segLenHalf := segLen / 2
		for k := 0; k < segNum; k++ {
			zetaTmp.SetInt64(pp.paramZetasA[factors[k]])
			for i := 0; i < segLenHalf; i++ {
				//	X^2 - Y^2 = (X+Y)(X-Y)
				//				tmp := int64(coeffs[k*segLen+i+segLenHalf]) * zetas[factors[k]]
				tmp.SetInt64(coeffs[k*segLen+i+segLenHalf])
				tmp.Mul(&tmp, &zetaTmp)
				tmp.Mod(&tmp, &qaBig)
				//				tmp1 := reduceToQc(int64(coeffs[k*segLen+i]) - tmp)
				//				tmp2 := reduceToQc(int64(coeffs[k*segLen+i]) + tmp)
				tmp1.SetInt64(coeffs[k*segLen+i])
				tmp2.SetInt64(coeffs[k*segLen+i])
				tmp1.Sub(&tmp1, &tmp)
				tmp2.Add(&tmp2, &tmp)
				//				coeffs[k*segLen+i] = tmp1
				//				coeffs[k*segLen+i+segLenHalf] = tmp2
				coeffs[k*segLen+i] = reduceInt64(tmp1.Int64(), pp.paramQA)
				coeffs[k*segLen+i+segLenHalf] = reduceInt64(tmp2.Int64(), pp.paramQA)
			}
		}
		segNum = segNum << 1
		segLen = segLen >> 1
		if segNum == slotNum {
			break
		}

		tmpFactors := make([]int, 2*len(factors))
		for i := 0; i < len(factors); i++ {
			tmpFactors[2*i] = (factors[i] + slotNum) / 2
			tmpFactors[2*i+1] = factors[i] / 2
		}
		factors = tmpFactors
	}

	//	factors: 7, 3, 5, 1
	//if pp.paramNTTAFactors == nil {
	//	pp.paramNTTAFactors = make([]int, 2*len(factors))
	//	for i := 0; i < len(factors); i++ {
	//		pp.paramNTTAFactors[2*i] = factors[i] + slotNum
	//		pp.paramNTTAFactors[2*i+1] = factors[i]
	//	}
	//}
	//	finalFactors: 15,7, 11,3, 13,5, 9,1

	//rst := pp.NewPolyANTT()
	//for i := 0; i < pp.paramDA; i++ {
	//	rst.coeffs[i] = coeffs[i]
	//}
	//return rst

	return &PolyANTT{coeffs}
}

func (pp *PublicParameter) NTTInvPolyA(polyANTT *PolyANTT) (polyA *PolyA) {
	// NTT Inverse
	zetaAOrder := pp.paramZetaAOrder
	slotNum := zetaAOrder / 2 //	have been factored to irreducible factors
	segNum := slotNum
	segLen := pp.paramDA / segNum
	//factors := pp.paramNTTAFactors
	factors := make([]int, len(pp.paramNTTAFactors))
	copy(factors, pp.paramNTTAFactors)

	nttCoeffs := make([]int64, pp.paramDA)
	//for i := 0; i < pp.paramDA; i++ {
	//	nttCoeffs[i] = polyANTT.nttCoeffs[i]
	//}
	copy(nttCoeffs, polyANTT.coeffs)

	// twoInv := int64((pp.paramQC+1)/2) - int64(pp.paramQC)
	var qaBig, twoInv, tmp1, tmp2, tmpZetaInv big.Int
	qaBig.SetInt64(pp.paramQA)
	twoInv.SetInt64((pp.paramQA+1)/2 - pp.paramQA)

	for {
		segLenDouble := segLen * 2

		for k := 0; k < segNum/2; k++ {
			tmpZetaInv.SetInt64(pp.paramZetasA[zetaAOrder-factors[k]])
			for i := 0; i < segLen; i++ {
				//				tmp1 := reduceToQc(pp.reduceInt64(int64(nttCoeffs[k*segLenDouble+i+segLen])+int64(nttCoeffs[k*segLenDouble+i])) * twoInv)
				//				nttCoeffs[k*segLenDouble+i] = tmp1
				tmp1.SetInt64(nttCoeffs[k*segLenDouble+i+segLen] + nttCoeffs[k*segLenDouble+i])
				tmp1.Mul(&tmp1, &twoInv)
				tmp1.Mod(&tmp1, &qaBig)
				//				tmp2 := reduceToQc(pp.reduceInt64(pp.reduceInt64(int64(nttCoeffs[k*segLenDouble+i+segLen])-int64(nttCoeffs[k*segLenDouble+i]))*twoInv) * zetas[2*pp.paramDC-factors[k]])
				//				nttCoeffs[k*segLenDouble+i+segLen] = tmp2
				tmp2.SetInt64(nttCoeffs[k*segLenDouble+i+segLen] - nttCoeffs[k*segLenDouble+i])
				tmp2.Mul(&tmp2, &twoInv)
				tmp2.Mod(&tmp2, &qaBig)
				tmp2.Mul(&tmp2, &tmpZetaInv)
				tmp2.Mod(&tmp2, &qaBig)

				nttCoeffs[k*segLenDouble+i] = reduceInt64(tmp1.Int64(), pp.paramQA)
				nttCoeffs[k*segLenDouble+i+segLen] = reduceInt64(tmp2.Int64(), pp.paramQA)
			}
		}
		segNum = segNum >> 1
		segLen = segLen << 1
		if segNum == 1 {
			break
		}

		tmpFactors := make([]int, len(factors)/2)
		for i := 0; i < len(tmpFactors); i++ {
			tmpFactors[i] = factors[2*i+1] * 2
		}
		factors = tmpFactors
	}

	//rst := pp.NewPolyA()
	//for i := 0; i < pp.paramDA; i++ {
	//	rst.nttCoeffs[i] = nttCoeffs[i]
	//}
	//return rst

	return &PolyA{nttCoeffs}
}

func (pp *PublicParameter) NewPolyAVec(vecLen int) *PolyAVec {
	polys := make([]*PolyA, vecLen)
	for i := 0; i < vecLen; i++ {
		polys[i] = pp.NewPolyA()
	}
	return &PolyAVec{polyAs: polys}
}

func (pp *PublicParameter) NewPolyANTTVec(vecLen int) *PolyANTTVec {
	polyNTTs := make([]*PolyANTT, vecLen)
	for i := 0; i < vecLen; i++ {
		polyNTTs[i] = pp.NewPolyANTT()
	}
	return &PolyANTTVec{polyANTTs: polyNTTs}
}

func (pp *PublicParameter) NewZeroPolyANTTVec(vecLen int) *PolyANTTVec {
	polyANTTs := make([]*PolyANTT, vecLen)
	for i := 0; i < vecLen; i++ {
		polyANTTs[i] = pp.NewZeroPolyANTT()
	}
	return &PolyANTTVec{polyANTTs}
}

func (pp *PublicParameter) NTTPolyAVec(polyAVec *PolyAVec) *PolyANTTVec {
	if polyAVec == nil {
		return nil
	}

	rst := pp.NewPolyANTTVec(len(polyAVec.polyAs))

	for i := 0; i < len(polyAVec.polyAs); i++ {
		rst.polyANTTs[i] = pp.NTTPolyA(polyAVec.polyAs[i])
	}

	return rst
}

func (pp *PublicParameter) NTTInvPolyAVec(polyANTTVec *PolyANTTVec) (polyAVec *PolyAVec) {
	if polyANTTVec == nil {
		return nil
	}

	rst := pp.NewPolyAVec(len(polyANTTVec.polyANTTs))

	for i := 0; i < len(polyANTTVec.polyANTTs); i++ {
		rst.polyAs[i] = pp.NTTInvPolyA(polyANTTVec.polyANTTs[i])
	}

	return rst
}

func (pp *PublicParameter) PolyANTTAdd(a *PolyANTT, b *PolyANTT) (r *PolyANTT) {
	if len(a.coeffs) != pp.paramDA || len(b.coeffs) != pp.paramDA {
		log.Panic("the length of the input polyANTT is not paramDA")
	}

	rst := pp.NewPolyANTT()
	//	var tmp, tmp1, tmp2 big.Int
	for i := 0; i < pp.paramDA; i++ {
		/*		tmp1.SetInt64(a.coeffs[i])
				tmp2.SetInt64(b.coeffs[i])
				tmp.Add(&tmp1, &tmp2)
				rst.coeffs[i] = reduceBigInt(&tmp, pp.paramQA)*/
		rst.coeffs[i] = reduceInt64(a.coeffs[i]+b.coeffs[i], pp.paramQA)
	}
	return rst
}

func (pp *PublicParameter) PolyANTTSub(a *PolyANTT, b *PolyANTT) (r *PolyANTT) {
	if len(a.coeffs) != pp.paramDA || len(b.coeffs) != pp.paramDA {
		log.Panic("the length of the input polyANTT is not paramDA")
	}

	rst := pp.NewPolyANTT()
	//	var tmp, tmp1, tmp2 big.Int
	for i := 0; i < pp.paramDA; i++ {
		/*		tmp1.SetInt64(a.coeffs[i])
				tmp2.SetInt64(b.coeffs[i])
				tmp.Sub(&tmp1, &tmp2)
				rst.coeffs[i] = reduceBigInt(&tmp, pp.paramQA)*/
		rst.coeffs[i] = reduceInt64(a.coeffs[i]-b.coeffs[i], pp.paramQA)
	}
	return rst
}

func (pp *PublicParameter) PolyANTTMul(a *PolyANTT, b *PolyANTT) *PolyANTT {
	bigQA := big.NewInt(pp.paramQA)
	if len(a.coeffs) != pp.paramDA || len(b.coeffs) != pp.paramDA {
		log.Panic("the length of the input polyANTT is not paramDA")
	}
	rst := pp.NewPolyANTT()
	factor := make([]int, pp.paramZetaAOrder/2)
	for i := 0; i < pp.paramZetaAOrder/4; i++ {
		factor[2*i] = pp.paramNTTAFactors[i] + pp.paramZetaAOrder/2
		factor[2*i+1] = pp.paramNTTAFactors[i]
	}
	// the size of every group is pp.paramDA/(pp.paramZetaAOrder/2)
	groupSize := 2 * pp.paramDA / pp.paramZetaAOrder
	// the group num is pp.paramDA / groupSize
	groupNum := pp.paramDA / groupSize
	left := make([]int64, groupSize)
	right := make([]int64, groupSize)
	// perform multiply in every group
	for i := 0; i < groupNum; i++ {
		for j := 0; j < groupSize; j++ {
			left[j] = a.coeffs[i*groupSize+j]
			right[j] = b.coeffs[i*groupSize+j]
		}
		tr := pp.MulKaratsuba(left, right, groupSize/2)
		// reduce with zetasA[i]
		var op1, op2 *big.Int
		for j := 0; j < groupSize; j++ {
			op1 = big.NewInt(tr[j+groupSize])
			op2 = big.NewInt(pp.paramZetasA[factor[i]])
			op1.Mul(op1, op2)
			op1.Mod(op1, bigQA)
			tr[j] = reduceInt64(tr[j]+op1.Int64(), pp.paramQA)
		}
		for j := 0; j < groupSize; j++ {
			rst.coeffs[i*groupSize+j] = tr[j]
		}
	}
	return rst
}

func (pp *PublicParameter) PolyANTTVecAdd(a *PolyANTTVec, b *PolyANTTVec, vecLen int) (r *PolyANTTVec) {
	var rst = pp.NewPolyANTTVec(vecLen)
	for i := 0; i < vecLen; i++ {
		rst.polyANTTs[i] = pp.PolyANTTAdd(a.polyANTTs[i], b.polyANTTs[i])
	}
	return rst
}

func (pp *PublicParameter) PolyANTTVecSub(a *PolyANTTVec, b *PolyANTTVec, vecLen int) (r *PolyANTTVec) {
	var rst = pp.NewPolyANTTVec(vecLen)
	for i := 0; i < vecLen; i++ {
		rst.polyANTTs[i] = pp.PolyANTTSub(a.polyANTTs[i], b.polyANTTs[i])
	}
	return rst
}

func (pp *PublicParameter) PolyANTTVecInnerProduct(a *PolyANTTVec, b *PolyANTTVec, vecLen int) (r *PolyANTT) {
	var rst = pp.NewZeroPolyANTT()
	for i := 0; i < vecLen; i++ {
		tmp := pp.PolyANTTMul(a.polyANTTs[i], b.polyANTTs[i])
		rst = pp.PolyANTTAdd(rst, tmp)
	}
	return rst
}

func (pp *PublicParameter) PolyANTTMatrixMulVector(M []*PolyANTTVec, vec *PolyANTTVec, rowNum int, vecLen int) (r *PolyANTTVec) {
	rst := pp.NewPolyANTTVec(rowNum)

	for i := 0; i < rowNum; i++ {
		rst.polyANTTs[i] = pp.PolyANTTVecInnerProduct(M[i], vec, vecLen)
	}

	return rst
}

func (pp *PublicParameter) PolyANTTVecScaleMul(polyANTTScale *PolyANTT, polyANTTVec *PolyANTTVec, vecLen int) (r *PolyANTTVec) {
	if polyANTTScale == nil || polyANTTVec == nil {
		return nil
	}
	if vecLen > len(polyANTTVec.polyANTTs) {
		log.Panic("PolyANTTVecScaleMul: vecLen is bigger than the length of polyANTTVec")
	}

	rst := pp.NewPolyANTTVec(vecLen)
	for i := 0; i < vecLen; i++ {
		rst.polyANTTs[i] = pp.PolyANTTMul(polyANTTScale, polyANTTVec.polyANTTs[i])
	}
	return rst
}

// MulKaratsuba performs vector multiplication with split
// F -> F[0] + F[1]x^n
// G-> G[0] + G[1]x^n
// F*G = F[0]G[0]+(F[0]G[1]+F[1]G[0])x^n+F[1]G[1]x^(2n)
//     = F[0]G[0]+{(F[0]+F[1])(G[0]+G[1])-F[0]G[0]-F[1]G[1]}x^n+F[1]G[1]x^(2n)
// F[0]+F[1],G[0]+G[1],F[0]G[0],F[1]G[1] as intermediate variables
// It uses several addition/subtraction to substitute  multiplication
func (pp *PublicParameter) MulKaratsuba(a, b []int64, n int) []int64 {
	bigQA := big.NewInt(pp.paramQA)
	if len(a) != 2*n || len(b) != 2*n {
		log.Fatal("MulKaratsuba() called by array with invalid length")
	}
	res := make([]int64, 4*n)
	f := make([][]int64, 2)
	g := make([][]int64, 2)
	// low n  -> f[0],g[0]
	// high n -> f[1],g[1]
	for i := 0; i < 2; i++ {
		f[i] = make([]int64, n)
		g[i] = make([]int64, n)
		for j := 0; j < n; j++ {
			f[i][j] = a[j+i*n]
			g[i][j] = b[j+i*n]
		}
	}
	f0g0 := make([]int64, 2*n)
	f1g1 := make([]int64, 2*n)

	var left, right big.Int
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			// f0*g0
			left.SetInt64(f[0][i])
			right.SetInt64(g[0][j])
			left.Mul(&left, &right)
			left.Mod(&left, bigQA)
			f0g0[i+j] = reduceInt64(f0g0[i+j]+left.Int64(), pp.paramQA)
			// f1*g1
			left.SetInt64(f[1][i])
			right.SetInt64(g[1][j])
			left.Mul(&left, &right)
			left.Mod(&left, bigQA)
			f1g1[i+j] = reduceInt64(f1g1[i+j]+left.Int64(), pp.paramQA)
		}
	}
	// f0g0 + x^(2n) * f1g1
	for i := 0; i < 2*n; i++ {
		res[i] = reduceInt64(res[i]+f0g0[i], pp.paramQA)
		res[i+2*n] = reduceInt64(res[i+2*n]+f1g1[i], pp.paramQA)
	}
	// f0g0=f0g0+f1g1
	for i := 0; i < 2*n; i++ {
		f0g0[i] = reduceInt64(f0g0[i]+f1g1[i], pp.paramQA)
		f1g1[i] = 0
	}
	// f1g1=(f0+f1)(g0+g1)
	for i := 0; i < n; i++ {
		f[0][i] = reduceInt64(f[0][i]+f[1][i], pp.paramQA)
		g[0][i] = reduceInt64(g[0][i]+g[1][i], pp.paramQA)
	}
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			// f1g1[i+j]+= f[0][i] * g[0][j]
			left.SetInt64(f[0][i])
			right.SetInt64(g[0][j])
			left.Mul(&left, &right)
			left.Mod(&left, bigQA)
			f1g1[i+j] = reduceInt64(f1g1[i+j]+left.Int64(), pp.paramQA)
		}
	}
	// f1g1 = f1g1 - f0g0 = (f0+f1)(g0+g1)-(f0g0+f1g1)
	for i := 0; i < 2*n; i++ {
		f1g1[i] = reduceInt64(f1g1[i]-f0g0[i], pp.paramQA)
	}
	for i := 0; i < 2*n; i++ {
		res[i+n] = reduceInt64(res[i+n]+f1g1[i], pp.paramQA)
	}
	return res
}
func (pp *PublicParameter) PolyANTTVecEqualCheck(a *PolyANTTVec, b *PolyANTTVec) (eq bool) {
	if a == nil || b == nil {
		return false
	}

	if a.polyANTTs == nil || b.polyANTTs == nil {
		return false
	}

	if len(a.polyANTTs) != len(b.polyANTTs) {
		return false
	}

	for i := 0; i < len(a.polyANTTs); i++ {
		if pp.PolyANTTEqualCheck(a.polyANTTs[i], b.polyANTTs[i]) != true {
			return false
		}
	}

	return true
}

func (pp *PublicParameter) PolyANTTEqualCheck(a *PolyANTT, b *PolyANTT) (eq bool) {
	if a == nil || b == nil {
		return false
	}

	if len(a.coeffs) != pp.paramDA || len(b.coeffs) != pp.paramDA {
		return false
	}

	for i := 0; i < pp.paramDA; i++ {
		if a.coeffs[i] != b.coeffs[i] {
			return false
		}
	}

	return true
}
