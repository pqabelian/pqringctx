package pqringct

import (
	"errors"
	"math/big"
)

// RpUlpType is the type for difference transaction
type RpUlpType uint8

const (
	RpUlpTypeCbTx1 RpUlpType = 0
	RpUlpTypeCbTx2 RpUlpType = 1
	RpUlpTypeTrTx1 RpUlpType = 2
	RpUlpTypeTrTx2 RpUlpType = 3
)

// generatePolyCNTTMatrix generate a matrix with rowLength * colLength, and the element in matrix is length
func (pp *PublicParameter) generatePolyCNTTMatrix(seed []byte, rowLength int, colLength int) ([]*PolyCNTTVec, error) {
	// check the length of seed

	var err error

	tmpSeedLen := len(seed) + 2
	tmpSeed := make([]byte, tmpSeedLen) //	1 byte for row index, and 1 byte for col index, assuming the row and col number is smaller than 127

	rst := make([]*PolyCNTTVec, rowLength)
	for i := 0; i < rowLength; i++ {
		//rst[i] = pp.NewZeroPolyCNTTVec(colLength)
		rst[i] = pp.NewPolyCNTTVec(colLength)
		for j := 0; j < colLength; j++ {
			copy(tmpSeed, seed)
			tmpSeed[tmpSeedLen-2] = byte(i)
			tmpSeed[tmpSeedLen-1] = byte(j)
			rst[i].polyCNTTs[j].coeffs, err = pp.randomDcIntegersInQc(tmpSeed)
			if err != nil {
				return nil, err
			}
			//copy(rst[i].polyCNTTs[j].coeffs, pp.randomDcIntegersInQc(tmpSeed))
		}
	}
	return rst, nil
}

// generatePolyANTTMatrix() expands the seed to a polyANTT matrix.
func (pp *PublicParameter) generatePolyANTTMatrix(seed []byte, rowLength int, colLength int) ([]*PolyANTTVec, error) {
	// check the length of seed
	tmpSeedLen := len(seed) + 2
	tmpSeed := make([]byte, tmpSeedLen)

	var err error
	rst := make([]*PolyANTTVec, rowLength)
	for i := 0; i < rowLength; i++ {
		rst[i] = pp.NewPolyANTTVec(colLength)
		for j := 0; j < colLength; j++ {
			copy(tmpSeed, seed)
			tmpSeed[tmpSeedLen-2] = byte(i)
			tmpSeed[tmpSeedLen-1] = byte(j)

			rst[i].polyANTTs[j].coeffs, err = pp.randomDaIntegersInQa(tmpSeed)
			if err != nil {
				return nil, err
			}
			//copy(rst[i].polyANTTs[j].coeffs, pp.randomDaIntegersInQa(tmpSeed))
		}
	}
	return rst, nil
}

func (pp *PublicParameter) collectBytesForRPULP1(message []byte, cmts []*ValueCommitment, n uint8,
	b_hat *PolyCNTTVec, c_hats []*PolyCNTT, n2 uint8, n1 uint8,
	rpulpType RpUlpType, binMatrixB [][]byte, I uint8, J uint8, m uint8, u_hats [][]int64,
	c_waves []*PolyCNTT, c_hat_g *PolyCNTT, cmt_ws [][]*PolyCNTTVec,
	delta_waves [][]*PolyCNTT, delta_hats [][]*PolyCNTT, ws []*PolyCNTTVec) []byte {

	length := len(message) + // message
		int(n)*(pp.paramKC+1)*pp.paramDC*8 + // cmts []*ValueCommitment length 8, (k_c+1) PolyCNTT
		1 + // n
		pp.paramKC*pp.paramDC*8 + // b_hat *PolyCNTTVec, length K_c
		int(n2)*pp.paramDC*8 + // c_hats length n2 PolyCNTT
		1 + 1 + // n2, n1
		1 + // rpulpType
		len(binMatrixB)*len(binMatrixB[0]) + 1 + 1 + 1 + // binMatrixB [][]byte, I uint8, J uint8, m uint8
		int(m)*pp.paramDC*8 + // u_hats [][]int64
		int(n)*pp.paramDC*8 + // c_waves []*PolyCNTT, length n
		pp.paramDC*8 + // c_hat_g *PolyCNTT
		pp.paramK*int(n)*(pp.paramLC*pp.paramDC*8) + //
		int(n)*pp.paramK*pp.paramDC*8*2 + // delta_waves [][]*PolyCNTT, delta_hats [][]*PolyCNTT,
		pp.paramK*(pp.paramLC*pp.paramDC*8) // ws []*PolyCNTTVec

	rst := make([]byte, 0, length)

	appendPolyNTTToBytes := func(a *PolyCNTT) {
		for k := 0; k < pp.paramDC; k++ {
			rst = append(rst, byte(a.coeffs[k]>>0))
			rst = append(rst, byte(a.coeffs[k]>>8))
			rst = append(rst, byte(a.coeffs[k]>>16))
			rst = append(rst, byte(a.coeffs[k]>>24))
			rst = append(rst, byte(a.coeffs[k]>>32))
			rst = append(rst, byte(a.coeffs[k]>>40))
			rst = append(rst, byte(a.coeffs[k]>>48))
			rst = append(rst, byte(a.coeffs[k]>>56))
		}
	}
	appendInt64ToBytes := func(a int64) {
		rst = append(rst, byte(a>>0))
		rst = append(rst, byte(a>>8))
		rst = append(rst, byte(a>>16))
		rst = append(rst, byte(a>>24))
		rst = append(rst, byte(a>>32))
		rst = append(rst, byte(a>>40))
		rst = append(rst, byte(a>>48))
		rst = append(rst, byte(a>>56))
	}

	// message
	rst = append(rst, message...)

	//	cmts with length n
	for i := 0; i < len(cmts); i++ {
		for j := 0; j < len(cmts[i].b.polyCNTTs); j++ {
			appendPolyNTTToBytes(cmts[i].b.polyCNTTs[j])
		}
		appendPolyNTTToBytes(cmts[i].c)
	}

	//	n uint8
	rst = append(rst, n)

	// b_hat
	for i := 0; i < pp.paramKC; i++ {
		appendPolyNTTToBytes(b_hat.polyCNTTs[i])
	}
	// c_hats []*PolyCNTT with length n2
	for i := 0; i < len(c_hats); i++ {
		appendPolyNTTToBytes(c_hats[i])
	}

	//	n2 uint8
	rst = append(rst, n2)

	//	n1 uint8
	rst = append(rst, n1)

	//TODO_DONE:A = ulpType B I J m
	rst = append(rst, byte(rpulpType))
	// B
	appendBinaryMartix := func(data [][]byte) {
		for i := 0; i < len(data); i++ {
			rst = append(rst, data[i]...)
		}
	}
	appendBinaryMartix(binMatrixB)
	// I
	rst = append(rst, I)
	// J
	rst = append(rst, J)

	// m
	rst = append(rst, m)

	//u_hats length m
	for i := 0; i < len(u_hats); i++ {
		for j := 0; j < len(u_hats[i]); j++ {
			appendInt64ToBytes(u_hats[i][j])
		}
	}

	//c_waves
	for i := 0; i < len(c_waves); i++ {
		appendPolyNTTToBytes(c_waves[i])
	}

	//c_hat_g [n2+1]
	appendPolyNTTToBytes(c_hat_g)

	// cmt_ws [][]*PolyCNTTVec
	for i := 0; i < len(cmt_ws); i++ {
		for j := 0; j < len(cmt_ws[i]); j++ {
			for k := 0; k < len(cmt_ws[i][j].polyCNTTs); k++ {
				appendPolyNTTToBytes(cmt_ws[i][j].polyCNTTs[k])
			}
		}
	}

	// delta_waves [][]*PolyCNTT
	for i := 0; i < len(delta_waves); i++ {
		for j := 0; j < len(delta_waves[i]); j++ {
			appendPolyNTTToBytes(delta_waves[i][j])
		}
	}
	// delta_hats [][]*PolyCNTT
	for i := 0; i < len(delta_hats); i++ {
		for j := 0; j < len(delta_hats[i]); j++ {
			appendPolyNTTToBytes(delta_hats[i][j])

		}
	}

	// ws []*PolyCNTTVec
	for i := 0; i < len(ws); i++ {
		for j := 0; j < len(ws[i].polyCNTTs); j++ {
			appendPolyNTTToBytes(ws[i].polyCNTTs[j])
		}
	}

	return rst
}

// collectBytesForRPULP2 is an auxiliary function for rpulpProve and rpulpVerify to collect some information into a byte slice
func (pp *PublicParameter) collectBytesForRPULP2(
	preMsg []byte,
	psi *PolyCNTT, psip *PolyCNTT, phi *PolyCNTT, phips []*PolyCNTT) []byte {

	length := len(preMsg) + 3*pp.paramDC*8 + len(phips)*pp.paramDC*8
	rst := make([]byte, 0, length)

	appendPolyNTTToBytes := func(a *PolyCNTT) {
		for k := 0; k < pp.paramDC; k++ {
			rst = append(rst, byte(a.coeffs[k]>>0))
			rst = append(rst, byte(a.coeffs[k]>>8))
			rst = append(rst, byte(a.coeffs[k]>>16))
			rst = append(rst, byte(a.coeffs[k]>>24))
			rst = append(rst, byte(a.coeffs[k]>>32))
			rst = append(rst, byte(a.coeffs[k]>>40))
			rst = append(rst, byte(a.coeffs[k]>>48))
			rst = append(rst, byte(a.coeffs[k]>>56))
		}
	}

	// preMsg
	rst = append(rst, preMsg...)

	// psi
	appendPolyNTTToBytes(psi)

	// psip
	appendPolyNTTToBytes(psip)

	// phi
	appendPolyNTTToBytes(phi)

	// phips
	for i := 0; i < len(phips); i++ {
		appendPolyNTTToBytes(phips[i])
	}
	return rst
}

// expandCombChallengeInRpulp() outputs n1 *PolyCNTT, paramK *PolyCNTT, paramK [m][paramDc]int64
func (pp *PublicParameter) expandCombChallengeInRpulp(seed []byte, n1 uint8, m uint8) (alphas []*PolyCNTT, betas []*PolyCNTT, gammas [][][]int64, err error) {

	// check the length of seed
	if len(seed) == 0 {
		return nil, nil, nil, errors.New("expandCombChallengeInRpulp: seed is empty")
	}

	// alpha
	alphas = make([]*PolyCNTT, n1)

	alphaSeed := append([]byte{'A'}, seed...)
	tmpSeedLen := len(alphaSeed) + 1 //	1 byte for index in [0, n1-1]
	tmpSeed := make([]byte, tmpSeedLen)
	for i := uint8(0); i < n1; i++ {
		copy(tmpSeed, alphaSeed)
		tmpSeed[tmpSeedLen-1] = i
		//tmpSeed = append(tmpSeed, byte(i))
		var coeffs []int64
		coeffs, err = pp.randomDcIntegersInQc(tmpSeed)
		if err != nil {
			return nil, nil, nil, err
		}
		alphas[i] = &PolyCNTT{coeffs}
	}

	// betas
	betas = make([]*PolyCNTT, pp.paramK)

	betaSeed := append([]byte{'B'}, seed...)
	tmpSeedLen = len(betaSeed) + 1 //	1 byte for index in [0, paramK]
	tmpSeed = make([]byte, tmpSeedLen)
	for i := 0; i < pp.paramK; i++ {
		copy(tmpSeed, betaSeed)
		tmpSeed[tmpSeedLen-1] = byte(i)
		//tmpSeed = append(tmpSeed, byte(i))
		coeffs, err := pp.randomDcIntegersInQc(tmpSeed)
		if err != nil {
			return nil, nil, nil, err
		}
		betas[i] = &PolyCNTT{coeffs}
	}

	// gammas
	gammas = make([][][]int64, pp.paramK)

	gammaSeed := append([]byte{'G'}, seed...)
	tmpSeedLen = len(gammaSeed) + 2 //	1 byte for index in [0, paramK], 1 byte for index in [0, m-1]
	tmpSeed = make([]byte, tmpSeedLen)
	for i := 0; i < pp.paramK; i++ {
		gammas[i] = make([][]int64, m)
		for j := uint8(0); j < m; j++ {
			copy(tmpSeed, gammaSeed)
			tmpSeed[tmpSeedLen-2] = byte(i)
			tmpSeed[tmpSeedLen-1] = byte(j)
			//tmpSeed = append(tmpSeed, byte(i))
			//tmpSeed = append(tmpSeed, byte(j))
			gammas[i][j], err = pp.randomDcIntegersInQc(tmpSeed)
			if err != nil {
				return nil, nil, nil, err
			}
		}
	}

	return alphas, betas, gammas, nil
}

func (pp *PublicParameter) sigmaInvPolyCNTT(polyCNTT *PolyCNTT, t int) (r *PolyCNTT) {
	coeffs := make([]int64, pp.paramDC)
	for i := 0; i < pp.paramDC; i++ {
		coeffs[i] = polyCNTT.coeffs[pp.paramSigmaPermutations[(pp.paramK-t)%pp.paramK][i]]
	}
	return &PolyCNTT{coeffs: coeffs}
}

func (pp *PublicParameter) genUlpPolyCNTTs(rpulpType RpUlpType, binMatrixB [][]byte, I uint8, J uint8, gammas [][][]int64) (ps [][]*PolyCNTT) {
	p := make([][]*PolyCNTT, pp.paramK)
	//	var tmp1, tmp2 big.Int

	switch rpulpType {
	case RpUlpTypeCbTx1:
		break
	case RpUlpTypeCbTx2:
		n := J
		n2 := n + 2
		// m = 3
		for t := 0; t < pp.paramK; t++ {
			p[t] = make([]*PolyCNTT, n2)
			for j := uint8(0); j < n; j++ {
				p[t][j] = &PolyCNTT{coeffs: gammas[t][0]}
			}
			//	p[t][n] = NTT^{-1}(F^T gamma[t][0] + F_1^T gamma[t][1] + B^T gamma[t][2])
			coeffs := make([]int64, pp.paramDC)
			for i := 0; i < pp.paramDC; i++ {
				// F^T[i] gamma[t][0] + F_1^T[i] gamma[t][1] + B^T[i] gamma[t][2]
				// B^T[i]: ith-col of B
				coeffs[i] = pp.intVecInnerProductWithReductionQc(getMatrixColumn(binMatrixB, pp.paramDC, i), gammas[t][2], pp.paramDC)
				if i == 0 {
					//coeffs[i] = pp.reduceBigInt(int64(coeffs[i] + gammas[t][1][i] + gammas[t][0][i]))
					//					coeffs[i] = reduceToQc(int64(coeffs[i]) + int64(gammas[t][1][i]) + int64(gammas[t][0][i]))
					coeffs[i] = reduceInt64(coeffs[i]+gammas[t][1][i]+gammas[t][0][i], pp.paramQC)
					// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
					/*					tmp1.SetInt64(coeffs[i])
										tmp2.SetInt64(gammas[t][1][i])
										tmp1.Add(&tmp1, &tmp2)
										tmp2.SetInt64(gammas[t][0][i])
										tmp1.Add(&tmp1, &tmp2)
										coeffs[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				} else if i < (pp.paramN - 1) {
					//coeffs[i] = reduceToQc()(int64(coeffs[i] - 2*gammas[t][0][i-1] + gammas[t][0][i]))
					//coeffs[i] = reduceToQc(int64(coeffs[i]) - 2*int64(gammas[t][0][i-1]) + int64(gammas[t][0][i]))
					coeffs[i] = reduceInt64(coeffs[i]-2*gammas[t][0][i-1]+gammas[t][0][i], pp.paramQC)
					// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
					/*				tmp1.SetInt64(coeffs[i])
									tmp2.SetInt64(gammas[t][0][i-1])
									tmp2.Add(&tmp2, &tmp2)
									tmp1.Sub(&tmp1, &tmp2)
									tmp2.SetInt64(gammas[t][0][i])
									tmp1.Add(&tmp1, &tmp2)
									coeffs[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				} else { // i in [N-1, d-1]
					//coeffs[i] = reduceToQc()(int64(coeffs[i] + gammas[t][1][i] - 2*gammas[t][0][i-1] + gammas[t][0][i]))
					//coeffs[i] = reduceToQc(int64(coeffs[i]) + int64(gammas[t][1][i]) - 2*int64(gammas[t][0][i-1]) + int64(gammas[t][0][i]))
					coeffs[i] = reduceInt64(coeffs[i]+gammas[t][1][i]-2*gammas[t][0][i-1]+gammas[t][0][i], pp.paramQC)
					// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
					/*					tmp1.SetInt64(coeffs[i])
										tmp2.SetInt64(gammas[t][1][i])
										tmp1.Add(&tmp1, &tmp2)
										tmp2.SetInt64(gammas[t][0][i-1])
										tmp2.Add(&tmp2, &tmp2)
										tmp1.Sub(&tmp1, &tmp2)
										tmp2.SetInt64(gammas[t][0][i])
										tmp1.Add(&tmp1, &tmp2)
										coeffs[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				}
			}
			p[t][n] = &PolyCNTT{coeffs: coeffs}

			p[t][n+1] = &PolyCNTT{coeffs: gammas[t][2]}
		}
	case RpUlpTypeTrTx1:
		n := I + J
		n2 := n + 2
		// m = 3
		for t := 0; t < pp.paramK; t++ {
			p[t] = make([]*PolyCNTT, n2)

			p[t][0] = &PolyCNTT{coeffs: gammas[t][0]}

			minuscoeffs := make([]int64, pp.paramDC)
			for i := 0; i < pp.paramDC; i++ {
				minuscoeffs[i] = -gammas[t][0][i]
			}
			for j := uint8(1); j < n; j++ {
				p[t][j] = &PolyCNTT{coeffs: minuscoeffs}
			}

			//	p[t][n] = NTT^{-1}((-F)^T gamma[t][0] + F_1^T gamma[t][1] + B^T gamma[t][2])
			coeffs := make([]int64, pp.paramDC)
			for i := 0; i < pp.paramDC; i++ {
				//(-F)^T[i] gamma[t][0] + F_1^T[i] gamma[t][1] + B^T[i] gamma[t][2]
				// B^T[i]: ith-col of B
				coeffs[i] = pp.intVecInnerProductWithReductionQc(getMatrixColumn(binMatrixB, pp.paramDC, i), gammas[t][2], pp.paramDC)
				if i == 0 {
					//coeffs[i] = pp.reduceBigInt(int64(coeffs[i] + gammas[t][1][i] - gammas[t][0][i]))
					//coeffs[i] = reduceToQc(int64(coeffs[i]) + int64(gammas[t][1][i]) - int64(gammas[t][0][i]))
					coeffs[i] = reduceInt64(coeffs[i]+gammas[t][1][i]-gammas[t][0][i], pp.paramQC)
					// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
					/*					tmp1.SetInt64(coeffs[i])
										tmp2.SetInt64(gammas[t][1][i])
										tmp1.Add(&tmp1, &tmp2)
										tmp2.SetInt64(gammas[t][0][i])
										tmp1.Sub(&tmp1, &tmp2)
										coeffs[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				} else if i < (pp.paramN - 1) {
					//coeffs[i] = reduceToQc()(int64(coeffs[i] + 2*gammas[t][0][i-1] - gammas[t][0][i]))
					//coeffs[i] = reduceToQc(int64(coeffs[i]) + 2*int64(gammas[t][0][i-1]) - int64(gammas[t][0][i]))
					coeffs[i] = reduceInt64(coeffs[i]+2*gammas[t][0][i-1]-gammas[t][0][i], pp.paramQC)
					// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
					/*					tmp1.SetInt64(coeffs[i])
										tmp2.SetInt64(gammas[t][0][i-1])
										tmp2.Add(&tmp2, &tmp2)
										tmp1.Add(&tmp1, &tmp2)
										tmp2.SetInt64(gammas[t][0][i])
										tmp1.Sub(&tmp1, &tmp2)
										coeffs[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				} else { // i in [N-1, d-1]
					//coeffs[i] = reduceToQc()(int64(coeffs[i] + gammas[t][1][i] + 2*gammas[t][0][i-1] - gammas[t][0][i]))
					//coeffs[i] = reduceToQc(int64(coeffs[i]) + int64(gammas[t][1][i]) + 2*int64(gammas[t][0][i-1]) - int64(gammas[t][0][i]))
					coeffs[i] = reduceInt64(coeffs[i]+gammas[t][1][i]+2*gammas[t][0][i-1]-gammas[t][0][i], pp.paramQC)
					// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
					/*					tmp1.SetInt64(coeffs[i])
										tmp2.SetInt64(gammas[t][1][i])
										tmp1.Add(&tmp1, &tmp2)
										tmp2.SetInt64(gammas[t][0][i-1])
										tmp2.Add(&tmp2, &tmp2)
										tmp1.Add(&tmp1, &tmp2)
										tmp2.SetInt64(gammas[t][0][i])
										tmp1.Sub(&tmp1, &tmp2)
										coeffs[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				}
			}
			p[t][n] = &PolyCNTT{coeffs: coeffs}

			p[t][n+1] = &PolyCNTT{coeffs: gammas[t][2]}
		}
	case RpUlpTypeTrTx2:
		n := int(I + J)
		n2 := n + 4
		//	B : d rows 2d columns
		//	m = 5
		for t := 0; t < pp.paramK; t++ {
			p[t] = make([]*PolyCNTT, n2)

			for j := uint8(0); j < I; j++ {
				p[t][j] = &PolyCNTT{coeffs: gammas[t][0]}
			}
			for j := I; j < I+J; j++ {
				p[t][j] = &PolyCNTT{coeffs: gammas[t][1]}
			}

			coeffs_n := make([]int64, pp.paramDC)
			for i := 0; i < pp.paramDC; i++ {
				//coeffs_n[i] = reduceToQc(int64(-gammas[t][0][i]) + int64(-gammas[t][1][i]))
				coeffs_n[i] = reduceInt64(-gammas[t][0][i]-gammas[t][1][i], pp.paramQC)
				// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				/*				tmp1.SetInt64(-gammas[t][0][i])
								tmp2.SetInt64(-gammas[t][1][i])
								tmp1.Add(&tmp1, &tmp2)
								coeffs_n[i] = reduceBigInt(&tmp1, pp.paramQC)*/
			}
			p[t][n] = &PolyCNTT{coeffs: coeffs_n}

			//	p[t][n+1] = NTT^{-1}(F^T gamma[t][0] + F_1^T gamma[t][2] + B_1^T gamma[t][4])
			coeffs_np1 := make([]int64, pp.paramDC)
			for i := 0; i < pp.paramDC; i++ {
				//F^T[i] gamma[t][0] + F_1^T[i] gamma[t][2] + B^T[i] gamma[t][4]
				coeffs_np1[i] = pp.intVecInnerProductWithReductionQc(getMatrixColumn(binMatrixB, pp.paramDC, i), gammas[t][4], pp.paramDC)
				if i == 0 {
					//coeffs_np1[i] = reduceToQc()(int64(coeffs_np1[i] + gammas[t][2][i] + gammas[t][0][i]))
					//coeffs_np1[i] = reduceToQc(int64(coeffs_np1[i]) + int64(gammas[t][2][i]) + int64(gammas[t][0][i]))
					coeffs_np1[i] = reduceInt64(coeffs_np1[i]+gammas[t][2][i]+gammas[t][0][i], pp.paramQC)
					// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
					/*				tmp1.SetInt64(coeffs_np1[i])
									tmp2.SetInt64(gammas[t][2][i])
									tmp1.Add(&tmp1, &tmp2)
									tmp2.SetInt64(gammas[t][0][i])
									tmp1.Add(&tmp1, &tmp2)
									coeffs_np1[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				} else if i < (pp.paramN - 1) {
					//coeffs_np1[i] = reduceToQc()(int64(coeffs_np1[i] - 2*gammas[t][0][i-1] + gammas[t][0][i]))
					//coeffs_np1[i] = reduceToQc(int64(coeffs_np1[i]) - 2*int64(gammas[t][0][i-1]) + int64(gammas[t][0][i]))
					coeffs_np1[i] = reduceInt64(coeffs_np1[i]-2*gammas[t][0][i-1]+gammas[t][0][i], pp.paramQC)
					// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
					/*					tmp1.SetInt64(coeffs_np1[i])
										tmp2.SetInt64(gammas[t][0][i-1])
										tmp2.Add(&tmp2, &tmp2)
										tmp1.Sub(&tmp1, &tmp2)
										tmp2.SetInt64(gammas[t][0][i])
										tmp1.Add(&tmp1, &tmp2)
										coeffs_np1[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				} else { // i in [N-1, d-1]
					//coeffs_np1[i] = reduceToQc()(int64(coeffs_np1[i] + gammas[t][2][i] - 2*gammas[t][0][i-1] + gammas[t][0][i]))
					//coeffs_np1[i] = reduceToQc(int64(coeffs_np1[i]) + int64(gammas[t][2][i]) - 2*int64(gammas[t][0][i-1]) + int64(gammas[t][0][i]))
					coeffs_np1[i] = reduceInt64(coeffs_np1[i]+gammas[t][2][i]-2*gammas[t][0][i-1]+gammas[t][0][i], pp.paramQC)
					// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
					/*					tmp1.SetInt64(coeffs_np1[i])
										tmp2.SetInt64(gammas[t][2][i])
										tmp1.Add(&tmp1, &tmp2)
										tmp2.SetInt64(gammas[t][0][i-1])
										tmp2.Add(&tmp2, &tmp2)
										tmp1.Sub(&tmp1, &tmp2)
										tmp2.SetInt64(gammas[t][0][i])
										tmp1.Add(&tmp1, &tmp2)
										coeffs_np1[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				}
			}
			p[t][n+1] = &PolyCNTT{coeffs: coeffs_np1}

			//	p[t][n+2] = NTT^{-1}(F^T gamma[t][1] + F_1^T gamma[t][3] + B_2^T gamma[t][4])
			coeffs_np2 := make([]int64, pp.paramDC)
			for i := 0; i < pp.paramDC; i++ {
				//F^T[i] gamma[t][1] + F_1^T[i] gamma[t][3] + B_2^T[i] gamma[t][4]
				coeffs_np2[i] = pp.intVecInnerProductWithReductionQc(getMatrixColumn(binMatrixB, pp.paramDC, pp.paramDC+i), gammas[t][4], pp.paramDC)
				if i == 0 {
					//coeffs_np2[i] = reduceToQc()(int64(coeffs_np2[i] + gammas[t][3][i] + gammas[t][1][i]))
					//coeffs_np2[i] = reduceToQc(int64(coeffs_np2[i]) + int64(gammas[t][3][i]) + int64(gammas[t][1][i]))
					coeffs_np2[i] = reduceInt64(coeffs_np2[i]+gammas[t][3][i]+gammas[t][1][i], pp.paramQC)
					// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
					/*					tmp1.SetInt64(coeffs_np2[i])
										tmp2.SetInt64(gammas[t][3][i])
										tmp1.Add(&tmp1, &tmp2)
										tmp2.SetInt64(gammas[t][1][i])
										tmp1.Add(&tmp1, &tmp2)
										coeffs_np2[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				} else if i < (pp.paramN - 1) {
					//coeffs_np2[i] = reduceToQc()(int64(coeffs_np2[i] - 2*gammas[t][1][i-1] + gammas[t][1][i]))
					//coeffs_np2[i] = reduceToQc(int64(coeffs_np2[i]) - 2*int64(gammas[t][1][i-1]) + int64(gammas[t][1][i]))
					coeffs_np2[i] = reduceInt64(coeffs_np2[i]-2*gammas[t][1][i-1]+gammas[t][1][i], pp.paramQC)
					// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
					/*					tmp1.SetInt64(coeffs_np2[i])
										tmp2.SetInt64(gammas[t][1][i-1])
										tmp2.Add(&tmp2, &tmp2)
										tmp1.Sub(&tmp1, &tmp2)
										tmp2.SetInt64(gammas[t][1][i])
										tmp1.Add(&tmp1, &tmp2)
										coeffs_np2[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				} else { // i in [N-1, d-1]
					//coeffs_np2[i] = reduceToQc()(int64(coeffs_np2[i] + gammas[t][3][i] - 2*gammas[t][1][i-1] + gammas[t][1][i]))
					//coeffs_np2[i] = reduceToQc(int64(coeffs_np2[i]) + int64(gammas[t][3][i]) - 2*int64(gammas[t][1][i-1]) + int64(gammas[t][1][i]))
					coeffs_np2[i] = reduceInt64(coeffs_np2[i]+gammas[t][3][i]-2*gammas[t][1][i-1]+gammas[t][1][i], pp.paramQC)
					// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
					/*					tmp1.SetInt64(coeffs_np2[i])
										tmp2.SetInt64(gammas[t][3][i])
										tmp1.Add(&tmp1, &tmp2)
										tmp2.SetInt64(gammas[t][1][i-1])
										tmp2.Add(&tmp2, &tmp2)
										tmp1.Sub(&tmp1, &tmp2)
										tmp2.SetInt64(gammas[t][1][i])
										tmp1.Add(&tmp1, &tmp2)
										coeffs_np2[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				}
			}
			p[t][n+2] = &PolyCNTT{coeffs: coeffs_np2}

			p[t][n+3] = &PolyCNTT{coeffs: gammas[t][4]}
		}
	}

	return p
}

func (pp *PublicParameter) intVecInnerProductWithReductionQc(a []int64, b []int64, vecLen int) (r int64) {
	var tmp1, tmp2 big.Int
	bigQc := new(big.Int).SetInt64(pp.paramQC)

	rst := new(big.Int).SetInt64(0)
	for i := 0; i < vecLen; i++ {
		tmp1.SetInt64(a[i])
		tmp2.SetInt64(b[i])
		tmp1.Mul(&tmp1, &tmp2)
		tmp1.Mod(&tmp1, bigQc)

		rst.Add(rst, &tmp1)
		rst.Mod(rst, bigQc)
	}

	return reduceInt64(rst.Int64(), pp.paramQC)
}

func (pp *PublicParameter) intMatrixInnerProductWithReductionQc(a [][]int64, b [][]int64, rowNum int, colNum int) (r int64) {
	var tmp1, tmp2 big.Int

	rst := new(big.Int).SetInt64(0)
	bigQc := new(big.Int).SetInt64(pp.paramQC)
	for i := 0; i < rowNum; i++ {
		for j := 0; j < colNum; j++ {
			tmp1.SetInt64(a[i][j])
			tmp2.SetInt64(b[i][j])
			tmp1.Mul(&tmp1, &tmp2)
			tmp1.Mod(&tmp1, bigQc)

			rst.Add(rst, &tmp1)
			rst.Mod(rst, bigQc)
		}
	}

	return reduceInt64(rst.Int64(), pp.paramQC)
}

// q is assumed to be an odd number
//	applied to q_a and q_c
func reduceInt64(a int64, q int64) int64 {
	r := a % q

	m := (q - 1) >> 1

	//	make sure the result in the scope [-(q-1)/2, (q-1)/2]
	if r < (-m) {
		r = r + q
	} else if r > m {
		r = r - q
	}

	return r
}

//	intToBinary() returns the bit representation of v, supposing paramDc >= 64
func (pp *PublicParameter) intToBinary(v uint64) (bits []int64) {
	rstBits := make([]int64, pp.paramDC)
	for i := 0; i < pp.paramDC; i++ {
		rstBits[i] = int64((v >> i) & 1)
	}
	return rstBits
}

func getMatrixColumn(matrix [][]byte, rowNum int, j int) (col []int64) {
	retcol := make([]int64, rowNum)
	for i := 0; i < rowNum; i++ {
		retcol[i] = int64((matrix[i][j/8] >> (j % 8)) & 1)
	}
	return retcol
}
