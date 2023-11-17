package pqringct

import (
	"log"
	"math/big"
)

type PolyC struct {
	coeffs []int64
}
type PolyCNTT struct {
	coeffs []int64
}
type PolyCVec struct {
	polyCs []*PolyC
}
type PolyCNTTVec struct {
	polyCNTTs []*PolyCNTT
}

func (pp *PublicParameter) NewPolyC() *PolyC {
	return &PolyC{coeffs: make([]int64, pp.paramDC)}
}
func (pp *PublicParameter) NewZeroPolyC() *PolyC {
	rst := &PolyC{coeffs: make([]int64, pp.paramDC)}
	for i := 0; i < pp.paramDC; i++ {
		rst.coeffs[i] = 0
	}
	return rst
}
func (pp *PublicParameter) NewPolyCNTT() *PolyCNTT {
	return &PolyCNTT{coeffs: make([]int64, pp.paramDC)}
}
func (pp *PublicParameter) NewZeroPolyCNTT() *PolyCNTT {
	rst := &PolyCNTT{coeffs: make([]int64, pp.paramDC)}
	for i := 0; i < pp.paramDC; i++ {
		rst.coeffs[i] = 0
	}
	return rst
}

func (pp *PublicParameter) NewZeroPolyCNTTVec(vecLen int) *PolyCNTTVec {
	polyCNTTs := make([]*PolyCNTT, vecLen)
	for i := 0; i < vecLen; i++ {
		polyCNTTs[i] = pp.NewZeroPolyCNTT()
	}
	return &PolyCNTTVec{polyCNTTs}
}

func (polyC *PolyC) infNorm() (infNorm int64) {
	rst := int64(0)
	for _, coeff := range polyC.coeffs {
		if coeff > rst {
			rst = coeff
		} else if coeff < 0 && -coeff > rst {
			rst = -coeff
		}
	}
	return rst
}

func (polyCVec *PolyCVec) infNorm() (infNorm int64) {
	rst := int64(0)
	for _, polyC := range polyCVec.polyCs {
		tmp := polyC.infNorm()
		if tmp > rst {
			rst = tmp
		}
	}
	return rst
}

func (pp *PublicParameter) NTTPolyC(polyC *PolyC) *PolyCNTT {
	//	NTT
	zetaCOrder := pp.paramZetaCOrder
	slotNum := zetaCOrder / 2 // fully splitting
	segNum := 1
	segLen := pp.paramDC
	factors := make([]int, 1)
	factors[0] = slotNum / 2

	coeffs := make([]int64, pp.paramDC)
	//for i := 0; i < len(polyC.coeffs); i++ {
	//	coeffs[i] = polyC.coeffs[i]
	//}
	copy(coeffs, polyC.coeffs)

	var qcBig, tmp, tmp1, tmp2, zetaTmp big.Int
	qcBig.SetInt64(pp.paramQC)
	for {
		segLenHalf := segLen / 2
		for k := 0; k < segNum; k++ {
			zetaTmp.SetInt64(pp.paramZetasC[factors[k]])
			for i := 0; i < segLenHalf; i++ {
				//	X^2 - a^2 = (X+a)(X-a)
				//				tmp := int64(coeffs[k*segLen+i+segLenHalf]) * zetas[factors[k]]
				tmp.SetInt64(coeffs[k*segLen+i+segLenHalf])
				tmp.Mul(&tmp, &zetaTmp)
				tmp.Mod(&tmp, &qcBig)
				//				tmp1 := reduceToQc(int64(coeffs[k*segLen+i]) - tmp)
				//				tmp2 := reduceToQc(int64(coeffs[k*segLen+i]) + tmp)
				tmp1.SetInt64(coeffs[k*segLen+i])
				tmp2.SetInt64(coeffs[k*segLen+i])
				tmp1.Sub(&tmp1, &tmp)
				tmp2.Add(&tmp2, &tmp)

				//				coeffs[k*segLen+i] = tmp1
				//				coeffs[k*segLen+i+segLenHalf] = tmp2
				coeffs[k*segLen+i] = reduceInt64(tmp1.Int64(), pp.paramQC)
				coeffs[k*segLen+i+segLenHalf] = reduceInt64(tmp2.Int64(), pp.paramQC)
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

	finalFactors := make([]int, 2*len(factors))
	for i := 0; i < len(factors); i++ {
		finalFactors[2*i] = factors[i] + slotNum
		finalFactors[2*i+1] = factors[i]
	}

	nttCoeffs := make([]int64, pp.paramDC)
	for i := 0; i < pp.paramDC; i++ {
		nttCoeffs[(finalFactors[i]-1)/2] = coeffs[i]
	}
	return &PolyCNTT{coeffs: nttCoeffs}

	/*	rst := pp.NewPolyCNTT()
		for i := 0; i < pp.paramDC; i++ {
			rst.coeffs[i] = coeffs[i].Int64()
		}
		return rst*/
}

func (pp *PublicParameter) NTTInvPolyC(polyCNTT *PolyCNTT) (polyC *PolyC) {
	//	NTT Inverse
	zetaCOrder := pp.paramZetaCOrder
	slotNum := zetaCOrder / 2 //	have been factored to irreducible factors, i.e., fully splitting
	segNum := slotNum
	segLen := 1
	//	factors := pp.paramNTTCFactors
	factors := make([]int, len(pp.paramNTTCFactors))
	copy(factors, pp.paramNTTCFactors)

	finalFactors := make([]int, 2*len(factors))
	for i := 0; i < len(factors); i++ {
		finalFactors[2*i] = factors[i] + slotNum
		finalFactors[2*i+1] = factors[i]
	}

	nttCoeffs := make([]int64, pp.paramDC)
	for i := 0; i < pp.paramDC; i++ {
		nttCoeffs[i] = polyCNTT.coeffs[(finalFactors[i]-1)/2]
	}

	/*	nttCoeffs := make([]big.Int, pp.paramDC)
		for i := 0; i < pp.paramDC; i++ {
			nttCoeffs[i].SetInt64( polyCNTT.coeffs[i] )
		}*/
	// twoInv := int64((pp.paramQC+1)/2) - int64(pp.paramQC)
	var twoInv, qcBig, tmp1, tmp2, tmpZetaInv big.Int
	twoInv.SetInt64((pp.paramQC+1)/2 - pp.paramQC)
	qcBig.SetInt64(pp.paramQC)

	for {
		segLenDouble := segLen * 2

		for k := 0; k < segNum/2; k++ {
			// tmpZeta.SetInt64( zetas[2*pp.paramDC-factors[k]] )
			tmpZetaInv.SetInt64(pp.paramZetasC[zetaCOrder-factors[k]])
			for i := 0; i < segLen; i++ {
				// tmp1 := reduceToQc(pp.reduceInt64(int64(nttCoeffs[k*segLenDouble+i+segLen])+int64(nttCoeffs[k*segLenDouble+i])) * twoInv)
				// nttCoeffs[k*segLenDouble+i] = tmp1
				tmp1.SetInt64(nttCoeffs[k*segLenDouble+i+segLen] + nttCoeffs[k*segLenDouble+i])
				tmp1.Mul(&tmp1, &twoInv)
				tmp1.Mod(&tmp1, &qcBig)
				// tmp2 := reduceToQc(pp.reduceInt64(pp.reduceInt64(int64(nttCoeffs[k*segLenDouble+i+segLen])-int64(nttCoeffs[k*segLenDouble+i]))*twoInv) * zetas[2*pp.paramDC-factors[k]])
				// nttCoeffs[k*segLenDouble+i+segLen] = tmp2
				tmp2.SetInt64(nttCoeffs[k*segLenDouble+i+segLen] - nttCoeffs[k*segLenDouble+i])
				tmp2.Mul(&tmp2, &twoInv)
				tmp2.Mod(&tmp2, &qcBig)
				tmp2.Mul(&tmp2, &tmpZetaInv)
				tmp2.Mod(&tmp2, &qcBig)

				nttCoeffs[k*segLenDouble+i] = reduceInt64(tmp1.Int64(), pp.paramQC)
				nttCoeffs[k*segLenDouble+i+segLen] = reduceInt64(tmp2.Int64(), pp.paramQC)
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

	//rst := pp.NewPolyC()
	//for i := 0; i < pp.paramDC; i++ {
	//	rst.coeffs[i] = reduceInt64(nttCoeffs[i], pp.paramQC)
	//}
	//return rst

	return &PolyC{nttCoeffs}
}

func (pp *PublicParameter) NewPolyCVec(vecLen int) *PolyCVec {
	polys := make([]*PolyC, vecLen)
	for i := 0; i < vecLen; i++ {
		polys[i] = pp.NewPolyC()
	}
	return &PolyCVec{polyCs: polys}
}

func (pp *PublicParameter) NewPolyCNTTVec(vecLen int) *PolyCNTTVec {
	polyNTTs := make([]*PolyCNTT, vecLen)
	for i := 0; i < vecLen; i++ {
		polyNTTs[i] = pp.NewPolyCNTT()
	}
	return &PolyCNTTVec{polyCNTTs: polyNTTs}
}

func (pp *PublicParameter) NTTPolyCVec(polyCVec *PolyCVec) *PolyCNTTVec {
	if polyCVec == nil {
		return nil
	}

	rst := pp.NewPolyCNTTVec(len(polyCVec.polyCs))

	for i := 0; i < len(polyCVec.polyCs); i++ {
		rst.polyCNTTs[i] = pp.NTTPolyC(polyCVec.polyCs[i])
	}
	return rst
}

func (pp *PublicParameter) NTTInvPolyCVec(polyCNTTVec *PolyCNTTVec) (polyCVec *PolyCVec) {
	if polyCNTTVec == nil {
		return nil
	}

	rst := pp.NewPolyCVec(len(polyCNTTVec.polyCNTTs))

	for i := 0; i < len(polyCNTTVec.polyCNTTs); i++ {
		rst.polyCs[i] = pp.NTTInvPolyC(polyCNTTVec.polyCNTTs[i])
	}

	return rst
}

func (pp *PublicParameter) PolyCNTTAdd(a *PolyCNTT, b *PolyCNTT) (r *PolyCNTT) {
	if len(a.coeffs) != pp.paramDC || len(b.coeffs) != pp.paramDC {
		log.Panic("the length of the input polyCNTT is not paramDC")
	}
	rst := pp.NewPolyCNTT()
	//	var tmp, tmp1, tmp2 big.Int
	for i := 0; i < pp.paramDC; i++ {
		/*		tmp1.SetInt64(a.coeffs[i])
				tmp2.SetInt64(b.coeffs[i])
				tmp.Add(&tmp1, &tmp2)
				rst.coeffs[i] = reduceBigInt(&tmp, pp.paramQC)*/
		rst.coeffs[i] = reduceInt64(a.coeffs[i]+b.coeffs[i], pp.paramQC)
	}
	return rst
}

func (pp *PublicParameter) PolyCNTTSub(a *PolyCNTT, b *PolyCNTT) (r *PolyCNTT) {
	if len(a.coeffs) != pp.paramDC || len(b.coeffs) != pp.paramDC {
		log.Panic("the length of the input polyCNTT is not paramDC")
	}
	rst := pp.NewPolyCNTT()
	//	var tmp, tmp1, tmp2 big.Int
	for i := 0; i < pp.paramDC; i++ {
		/*		tmp1.SetInt64(a.coeffs[i])
				tmp2.SetInt64(b.coeffs[i])
				tmp.Sub(&tmp1, &tmp2)
				rst.coeffs[i] = reduceBigInt(&tmp, pp.paramQC)*/
		rst.coeffs[i] = reduceInt64(a.coeffs[i]-b.coeffs[i], pp.paramQC)
	}
	return rst
}

func (pp *PublicParameter) PolyCNTTMul(a *PolyCNTT, b *PolyCNTT) (r *PolyCNTT) {
	if len(a.coeffs) != pp.paramDC || len(b.coeffs) != pp.paramDC {
		log.Panic("PolyCNTTMul: the length of the input polyCNTT is not paramDC")
	}

	bigQc := new(big.Int).SetInt64(pp.paramQC)

	rst := pp.NewPolyCNTT()
	var tmp, tmp1, tmp2 big.Int
	for i := 0; i < pp.paramDC; i++ {
		tmp1.SetInt64(a.coeffs[i])
		tmp2.SetInt64(b.coeffs[i])
		tmp.Mul(&tmp1, &tmp2)
		//		rst.coeffs[i] = reduceBigInt(&tmp, pp.paramQC)
		tmp.Mod(&tmp, bigQc)
		rst.coeffs[i] = reduceInt64(tmp.Int64(), pp.paramQC)
	}
	return rst
}

func (pp *PublicParameter) PolyCNTTVecAdd(a *PolyCNTTVec, b *PolyCNTTVec, vecLen int) (r *PolyCNTTVec) {
	var rst = pp.NewPolyCNTTVec(vecLen)
	for i := 0; i < vecLen; i++ {
		rst.polyCNTTs[i] = pp.PolyCNTTAdd(a.polyCNTTs[i], b.polyCNTTs[i])
	}
	return rst
}

func (pp *PublicParameter) PolyCNTTVecSub(a *PolyCNTTVec, b *PolyCNTTVec, vecLen int) (r *PolyCNTTVec) {
	var rst = pp.NewPolyCNTTVec(vecLen)
	for i := 0; i < vecLen; i++ {
		rst.polyCNTTs[i] = pp.PolyCNTTSub(a.polyCNTTs[i], b.polyCNTTs[i])
	}
	return rst
}

func (pp *PublicParameter) PolyCNTTVecInnerProduct(a *PolyCNTTVec, b *PolyCNTTVec, vecLen int) (r *PolyCNTT) {
	var rst = pp.NewZeroPolyCNTT()
	for i := 0; i < vecLen; i++ {
		tmp := pp.PolyCNTTMul(a.polyCNTTs[i], b.polyCNTTs[i])
		rst = pp.PolyCNTTAdd(rst, tmp)
	}
	return rst
}

func (pp *PublicParameter) PolyCNTTMatrixMulVector(M []*PolyCNTTVec, vec *PolyCNTTVec, rowNum int, vecLen int) (r *PolyCNTTVec) {
	rst := pp.NewPolyCNTTVec(rowNum)
	for i := 0; i < rowNum; i++ {
		rst.polyCNTTs[i] = pp.PolyCNTTVecInnerProduct(M[i], vec, vecLen)
	}
	return rst
}

func (pp *PublicParameter) PolyCNTTVecScaleMul(polyCNTTScale *PolyCNTT, polyCNTTVec *PolyCNTTVec, vecLen int) (r *PolyCNTTVec) {
	if polyCNTTScale == nil || polyCNTTVec == nil {
		return nil
	}
	if vecLen > len(polyCNTTVec.polyCNTTs) {
		log.Panic("PolyCNTTVecScaleMul: vecLen is bigger than the length of polyCNTTVec")
	}

	rst := pp.NewPolyCNTTVec(vecLen)
	for i := 0; i < vecLen; i++ {
		rst.polyCNTTs[i] = pp.PolyCNTTMul(polyCNTTScale, polyCNTTVec.polyCNTTs[i])
	}
	return rst
}

func (pp *PublicParameter) sigmaPowerPolyCNTT(polyCNTT *PolyCNTT, t int) (r *PolyCNTT) {
	rst := pp.NewPolyCNTT()
	for i := 0; i < pp.paramDC; i++ {
		rst.coeffs[i] = polyCNTT.coeffs[pp.paramSigmaPermutations[t][i]]
	}
	return rst
}

func (pp *PublicParameter) PolyCNTTVecEqualCheck(a *PolyCNTTVec, b *PolyCNTTVec) (eq bool) {
	if a == nil || b == nil {
		return false
	}

	if a.polyCNTTs == nil || b.polyCNTTs == nil {
		return false
	}

	if len(a.polyCNTTs) != len(b.polyCNTTs) {
		return false
	}

	for i := 0; i < len(a.polyCNTTs); i++ {
		if pp.PolyCNTTEqualCheck(a.polyCNTTs[i], b.polyCNTTs[i]) != true {
			return false
		}
	}

	return true
}

func (pp *PublicParameter) PolyCNTTEqualCheck(a *PolyCNTT, b *PolyCNTT) (eq bool) {
	if a == nil || b == nil {
		return false
	}

	if len(a.coeffs) != pp.paramDC || len(b.coeffs) != pp.paramDC {
		return false
	}

	for i := 0; i < pp.paramDC; i++ {
		if a.coeffs[i] != b.coeffs[i] {
			return false
		}
	}

	return true
}
