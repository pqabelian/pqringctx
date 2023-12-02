package pqringctx

import (
	"bytes"
	"math/big"
)

func (pp *PublicParameter) rpulpProve(message []byte, cmts []*ValueCommitment, cmt_rs []*PolyCNTTVec, n uint8,
	b_hat *PolyCNTTVec, r_hat *PolyCNTTVec, c_hats []*PolyCNTT, msg_hats [][]int64, n2 uint8,
	n1 uint8, rpulpType RpUlpType, binMatrixB [][]byte,
	I uint8, J uint8, m uint8, u_hats [][]int64) (rpulppi *rpulpProof, err error) {

	// c_waves[i] = <h_i, r_i> + m_i
	c_waves := make([]*PolyCNTT, n)
	for i := uint8(0); i < n; i++ {
		tmp := pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[i+1], cmt_rs[i], pp.paramLC)
		c_waves[i] = pp.PolyCNTTAdd(tmp, &PolyCNTT{coeffs: msg_hats[i]})
	}

rpUlpProveRestart:
	tmpg, err := pp.samplePloyCWithLowZeros()
	if err != nil {
		return nil, err
	}
	g := pp.NTTPolyC(tmpg)
	// c_hat(n2+1)
	c_hat_g := pp.PolyCNTTAdd(pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[pp.paramI+pp.paramJ+5], r_hat, pp.paramLC), g)

	cmt_ys := make([][]*PolyCNTTVec, pp.paramK)
	ys := make([]*PolyCNTTVec, pp.paramK)
	cmt_ws := make([][]*PolyCNTTVec, pp.paramK)
	ws := make([]*PolyCNTTVec, pp.paramK)
	for t := 0; t < pp.paramK; t++ {
		cmt_ys[t] = make([]*PolyCNTTVec, n)
		cmt_ws[t] = make([]*PolyCNTTVec, n)
		for i := uint8(0); i < n; i++ {
			// random some element in the {s_etaC}^Lc space
			y_ploy, err := pp.sampleMaskingVecC()
			if err != nil {
				return nil, err
			}
			cmt_ys[t][i] = pp.NTTPolyCVec(y_ploy)
			cmt_ws[t][i] = pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, cmt_ys[t][i], pp.paramKC, pp.paramLC)
		}

		y_ploy, err := pp.sampleMaskingVecC()
		if err != nil {
			return nil, err
		}
		ys[t] = pp.NTTPolyCVec(y_ploy)
		ws[t] = pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, ys[t], pp.paramKC, pp.paramLC)
	}

	//	\tilde{\delta}^(t)_i, \hat{\delta}^(t)_i,
	delta_waves := make([][]*PolyCNTT, pp.paramK)
	delta_hats := make([][]*PolyCNTT, pp.paramK)
	for t := 0; t < pp.paramK; t++ {
		delta_waves[t] = make([]*PolyCNTT, n)
		delta_hats[t] = make([]*PolyCNTT, n)
		for i := uint8(0); i < n; i++ {
			delta_waves[t][i] = pp.PolyCNTTVecInnerProduct(pp.PolyCNTTVecSub(pp.paramMatrixH[i+1], pp.paramMatrixH[0], pp.paramLC), cmt_ys[t][i], pp.paramLC)
			delta_hats[t][i] = pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[i+1], pp.PolyCNTTVecSub(ys[t], cmt_ys[t][i], pp.paramLC), pp.paramLC)
		}
	}

	// splicing the data to be processed
	preMsg := pp.collectBytesForRPULP1(message, cmts, n, b_hat, c_hats, n2, n1, rpulpType, binMatrixB, I, J, m, u_hats, c_waves, c_hat_g, cmt_ws, delta_waves, delta_hats, ws)
	seed_rand, err := Hash(preMsg) // todo_DONE
	if err != nil {
		return nil, err
	}
	//fmt.Println("prove seed_rand=", seed_rand)
	alphas, betas, gammas, err := pp.expandCombChallengeInRpulp(seed_rand, n1, m)
	if err != nil {
		return nil, err
	}

	//	psi, psi'
	psi := pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[pp.paramI+pp.paramJ+6], r_hat, pp.paramLC)
	psip := pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[pp.paramI+pp.paramJ+6], ys[0], pp.paramLC)

	for t := 0; t < pp.paramK; t++ {
		tmp1 := pp.NewZeroPolyCNTT()
		tmp2 := pp.NewZeroPolyCNTT()
		// sum(0->n1-1)
		for i := uint8(0); i < n1; i++ {
			// <h_i , y_t>
			tmp := pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[i+1], ys[t], pp.paramLC)

			tmp1 = pp.PolyCNTTAdd(
				tmp1,
				// alpha[i] * (2 * m_i - mu) <h_i , y_t>
				pp.PolyCNTTMul(
					alphas[i],
					// (2 * m_i - mu) <h_i , y_t>
					pp.PolyCNTTMul(
						// 2 * m_i - mu
						pp.PolyCNTTSub(
							//  m_i+m_i
							pp.PolyCNTTAdd(
								&PolyCNTT{coeffs: msg_hats[i]},
								&PolyCNTT{coeffs: msg_hats[i]},
							),
							pp.paramMu,
						),
						tmp,
					),
				),
			)
			tmp2 = pp.PolyCNTTAdd(
				tmp2,
				// alpha[i] * <h_i , y_t> * <h_i , y_t>
				pp.PolyCNTTMul(
					alphas[i],
					pp.PolyCNTTMul(tmp, tmp),
				),
			)
		}

		psi = pp.PolyCNTTSub(psi, pp.PolyCNTTMul(betas[t], pp.sigmaInvPolyCNTT(tmp1, t)))
		psip = pp.PolyCNTTAdd(psip, pp.PolyCNTTMul(betas[t], pp.sigmaInvPolyCNTT(tmp2, t)))
	}
	//fmt.Printf("Prove\n")
	//fmt.Printf("psip = %v\n", psip)
	//	p^(t)_j:
	p := pp.genUlpPolyCNTTs(rpulpType, binMatrixB, I, J, gammas)

	//	phi
	phi := pp.NewZeroPolyCNTT()

	var inprd, dcInv big.Int
	dcInv.SetInt64(pp.paramDCInv)
	bigQc := new(big.Int).SetInt64(pp.paramQC)

	for t := 0; t < pp.paramK; t++ {
		tmp1 := pp.NewZeroPolyCNTT()
		for tau := 0; tau < pp.paramK; tau++ {

			tmp := pp.NewZeroPolyCNTT()
			for j := uint8(0); j < n2; j++ {
				tmp = pp.PolyCNTTAdd(tmp, pp.PolyCNTTMul(p[t][j], &PolyCNTT{coeffs: msg_hats[j]}))
			}

			constPoly := pp.NewZeroPolyC()
			//constPoly.coeffs[0] = reduceToQc(intMatrixInnerProductWithReductionQc(u_hats, gammas[t], m, pp.paramDC, pp.paramQC) * int64(pp.paramDCInv))
			inprd.SetInt64(pp.intMatrixInnerProductWithReductionQc(u_hats, gammas[t], int(m), pp.paramDC))
			inprd.Mul(&inprd, &dcInv)
			//constPoly.coeffs[0] = reduceBigInt(&inprd, pp.paramQC)
			inprd.Mod(&inprd, bigQc)
			constPoly.coeffs[0] = reduceInt64(inprd.Int64(), pp.paramQC)

			tmp = pp.PolyCNTTSub(tmp, pp.NTTPolyC(constPoly))
			tmp1 = pp.PolyCNTTAdd(tmp1, pp.sigmaPowerPolyCNTT(tmp, tau))
		}

		xt := pp.NewZeroPolyC()
		xt.coeffs[t] = pp.paramKInv

		tmp1 = pp.PolyCNTTMul(pp.NTTPolyC(xt), tmp1)

		phi = pp.PolyCNTTAdd(phi, tmp1)
	}

	phi = pp.PolyCNTTAdd(phi, g)
	//phiinv := pp.NTTInv(phi)
	//fmt.Println(phiinv)
	//fmt.Printf("Prove\n")
	//fmt.Printf("phi = %v\n", phi)
	//	phi'^(\xi)
	phips := make([]*PolyCNTT, pp.paramK)
	for xi := 0; xi < pp.paramK; xi++ {
		phips[xi] = pp.NewZeroPolyCNTT()

		for t := 0; t < pp.paramK; t++ {

			tmp1 := pp.NewZeroPolyCNTT()
			for tau := 0; tau < pp.paramK; tau++ {

				tmp := pp.NewZeroPolyCNTTVec(pp.paramLC)

				for j := uint8(0); j < n2; j++ {
					tmp = pp.PolyCNTTVecAdd(
						tmp,
						pp.PolyCNTTVecScaleMul(p[t][j], pp.paramMatrixH[j+1], pp.paramLC),
						pp.paramLC)
				}

				tmp1 = pp.PolyCNTTAdd(
					tmp1,
					pp.sigmaPowerPolyCNTT(
						pp.PolyCNTTVecInnerProduct(tmp, ys[(xi-tau+pp.paramK)%pp.paramK], pp.paramLC),
						tau),
				)
			}

			xt := pp.NewZeroPolyC()
			xt.coeffs[t] = pp.paramKInv

			tmp1 = pp.PolyCNTTMul(pp.NTTPolyC(xt), tmp1)

			phips[xi] = pp.PolyCNTTAdd(phips[xi], tmp1)
		}

		phips[xi] = pp.PolyCNTTAdd(
			phips[xi],
			pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[pp.paramI+pp.paramJ+5], ys[xi], pp.paramLC))
	}
	//fmt.Println("phips = ")
	//for i := 0; i < pp.paramK; i++ {
	//	fmt.Printf("phips[%d] = %v \n", i, phips[i])
	//}
	//fmt.Println("Prove")
	//fmt.Printf("rpulppi.phi =\n")
	//for i := 0; i < len(delta_hats); i++ {
	//	fmt.Printf("delta_hats[%d] = %v\n", i, phips[i])
	//}
	//	seed_ch and ch
	preMsgAll := pp.collectBytesForRPULP2(preMsg, psi, psip, phi, phips)
	chseed, err := Hash(preMsgAll)
	if err != nil {
		return nil, err
	}
	ch_ploy, err := pp.expandChallengeC(chseed)
	if err != nil {
		return nil, err
	}
	ch := pp.NTTPolyC(ch_ploy)
	// z = y + sigma^t(c) * r
	cmt_zs_ntt := make([][]*PolyCNTTVec, pp.paramK)
	zs_ntt := make([]*PolyCNTTVec, pp.paramK)
	cmt_zs := make([][]*PolyCVec, pp.paramK)
	zs := make([]*PolyCVec, pp.paramK)
	for t := 0; t < pp.paramK; t++ {
		cmt_zs_ntt[t] = make([]*PolyCNTTVec, n)
		cmt_zs[t] = make([]*PolyCVec, n)
		sigma_t_ch := pp.sigmaPowerPolyCNTT(ch, t)
		for i := uint8(0); i < n; i++ {
			cmt_zs_ntt[t][i] = pp.PolyCNTTVecAdd(
				cmt_ys[t][i],
				pp.PolyCNTTVecScaleMul(sigma_t_ch, cmt_rs[i], pp.paramLC),
				pp.paramLC)

			cmt_zs[t][i] = pp.NTTInvPolyCVec(cmt_zs_ntt[t][i])
			if cmt_zs[t][i].infNorm() > pp.paramEtaC-int64(pp.paramBetaC) {
				goto rpUlpProveRestart
			}
		}

		zs_ntt[t] = pp.PolyCNTTVecAdd(ys[t], pp.PolyCNTTVecScaleMul(sigma_t_ch, r_hat, pp.paramLC), pp.paramLC)
		zs[t] = pp.NTTInvPolyCVec(zs_ntt[t])
		if zs[t].infNorm() > pp.paramEtaC-int64(pp.paramBetaC) {
			goto rpUlpProveRestart
		}
	}

	retrpulppi := &rpulpProof{
		c_waves: c_waves,
		c_hat_g: c_hat_g,
		psi:     psi,
		phi:     phi,
		chseed:  chseed,
		cmt_zs:  cmt_zs,
		zs:      zs,
	}

	return retrpulppi, nil
}

func (pp *PublicParameter) rpulpVerify(message []byte,
	cmts []*ValueCommitment, n uint8,
	b_hat *PolyCNTTVec, c_hats []*PolyCNTT, n2 uint8,
	n1 uint8, rpulpType RpUlpType, binMatrixB [][]byte, I uint8, J uint8, m uint8, u_hats [][]int64,
	rpulppi *rpulpProof) (valid bool) {

	if !(n >= 2 && n <= n1 && n1 <= n2 && int(n) <= pp.paramI+pp.paramJ && int(n2) <= pp.paramI+pp.paramJ+4) {
		return false
	}

	if len(cmts) != int(n) {
		return false
	}

	if b_hat == nil {
		return false
	}

	if len(c_hats) != int(n2) {
		return false
	}

	// check the matrix and u_hats
	if len(binMatrixB) != pp.paramDC {
		return false
	} else {
		for i := 0; i < len(binMatrixB); i++ {
			switch rpulpType {
			case RpUlpTypeCbTx2:
				fallthrough
			case RpUlpTypeTrTx1:
				if len(binMatrixB[i]) != pp.paramDC/8 {
					return false
				}
			case RpUlpTypeTrTx2:
				if len(binMatrixB[i]) != 2*pp.paramDC/8 {
					return false
				}
			default:
				return false
			}
		}
	}
	if len(u_hats) != int(m) {
		return false
	} else {
		for i := 0; i < len(u_hats); i++ {
			if len(u_hats[0]) != pp.paramDC {
				return false
			}
		}

	}
	// check the well-formness of the \pi
	if len(rpulppi.c_waves) != int(n) || len(rpulppi.c_hat_g.coeffs) != pp.paramDC || len(rpulppi.psi.coeffs) != pp.paramDC || len(rpulppi.phi.coeffs) != pp.paramDC || len(rpulppi.zs) != pp.paramK || len(rpulppi.zs[0].polyCs) != pp.paramLC {
		return false
	}
	if rpulppi == nil {
		return false
	}
	if len(rpulppi.c_waves) != int(n) {
		return false
	}

	if rpulppi.c_hat_g == nil || rpulppi.psi == nil || rpulppi.phi == nil || rpulppi.chseed == nil {
		return false
	}

	if rpulppi.cmt_zs == nil || len(rpulppi.cmt_zs) != pp.paramK || rpulppi.zs == nil || len(rpulppi.zs) != pp.paramK {
		return false
	}

	for t := 0; t < pp.paramK; t++ {
		if rpulppi.cmt_zs[t] == nil || len(rpulppi.cmt_zs[t]) != int(n) {
			return false
		}
	}

	//	(phi_t[0] ... phi_t[k-1] = 0)
	phiPoly := pp.NTTInvPolyC(rpulppi.phi)
	//fmt.Println("phiPoly", phiPoly.coeffs1)
	for t := 0; t < pp.paramK; t++ {
		if phiPoly.coeffs[t] != 0 {
			return false
		}
	}

	// infNorm of z^t_i and z^t
	for t := 0; t < pp.paramK; t++ {
		for i := uint8(0); i < n; i++ {
			if rpulppi.cmt_zs[t][i].infNorm() > pp.paramEtaC-int64(pp.paramBetaC) {
				return false
			}
		}
		if rpulppi.zs[t].infNorm() > pp.paramEtaC-int64(pp.paramBetaC) {
			return false
		}
	}
	ch_poly, err := pp.expandChallengeC(rpulppi.chseed)
	if err != nil {
		return false
	}
	ch := pp.NTTPolyC(ch_poly)

	sigma_chs := make([]*PolyCNTT, pp.paramK)
	//	w^t_i, w_t
	cmt_ws := make([][]*PolyCNTTVec, pp.paramK)
	ws := make([]*PolyCNTTVec, pp.paramK)

	cmt_zs_ntt := make([][]*PolyCNTTVec, pp.paramK)
	zs_ntt := make([]*PolyCNTTVec, pp.paramK)

	for t := 0; t < pp.paramK; t++ {
		sigma_chs[t] = pp.sigmaPowerPolyCNTT(ch, t)

		cmt_ws[t] = make([]*PolyCNTTVec, n)
		cmt_zs_ntt[t] = make([]*PolyCNTTVec, n)

		for i := uint8(0); i < n; i++ {
			cmt_zs_ntt[t][i] = pp.NTTPolyCVec(rpulppi.cmt_zs[t][i])

			cmt_ws[t][i] = pp.PolyCNTTVecSub(
				pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, cmt_zs_ntt[t][i], pp.paramKC, pp.paramLC),
				pp.PolyCNTTVecScaleMul(sigma_chs[t], cmts[i].b, pp.paramKC),
				pp.paramKC)
		}

		zs_ntt[t] = pp.NTTPolyCVec(rpulppi.zs[t])
		ws[t] = pp.PolyCNTTVecSub(
			pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, zs_ntt[t], pp.paramKC, pp.paramLC),
			pp.PolyCNTTVecScaleMul(sigma_chs[t], b_hat, pp.paramKC),
			pp.paramKC)
	}

	//	\tilde{\delta}^(t)_i, \hat{\delta}^(t)_i,
	delta_waves := make([][]*PolyCNTT, pp.paramK)
	delta_hats := make([][]*PolyCNTT, pp.paramK)
	for t := 0; t < pp.paramK; t++ {
		delta_waves[t] = make([]*PolyCNTT, n)
		delta_hats[t] = make([]*PolyCNTT, n)

		for i := uint8(0); i < n; i++ {
			delta_waves[t][i] = pp.PolyCNTTSub(
				pp.PolyCNTTVecInnerProduct(
					pp.PolyCNTTVecSub(pp.paramMatrixH[i+1], pp.paramMatrixH[0], pp.paramLC),
					cmt_zs_ntt[t][i],
					pp.paramLC),
				pp.PolyCNTTMul(sigma_chs[t], pp.PolyCNTTSub(rpulppi.c_waves[i], cmts[i].c)),
			)

			delta_hats[t][i] = pp.PolyCNTTSub(
				pp.PolyCNTTVecInnerProduct(
					pp.paramMatrixH[i+1],
					pp.PolyCNTTVecSub(zs_ntt[t], cmt_zs_ntt[t][i], pp.paramLC),
					pp.paramLC),
				pp.PolyCNTTMul(sigma_chs[t], pp.PolyCNTTSub(c_hats[i], rpulppi.c_waves[i])),
			)
		}
	}

	// splicing the data to be processed

	preMsg := pp.collectBytesForRPULP1(message, cmts, n, b_hat, c_hats, n2, n1, rpulpType, binMatrixB, I, J, m, u_hats,
		rpulppi.c_waves, rpulppi.c_hat_g, cmt_ws, delta_waves, delta_hats, ws)
	seed_rand, err := Hash(preMsg)
	if err != nil {
		return false
	}
	//fmt.Println("verify seed_rand=", seed_rand)
	alphas, betas, gammas, err := pp.expandCombChallengeInRpulp(seed_rand, n1, m)
	if err != nil {
		return false
	}

	// psi'
	psip := pp.NewZeroPolyCNTT()
	//mu := pp.paramMu
	for t := 0; t < pp.paramK; t++ {

		tmp1 := pp.NewZeroPolyCNTT()
		tmp2 := pp.NewZeroPolyCNTT()

		for i := uint8(0); i < n1; i++ {
			f_t_i := pp.PolyCNTTSub(
				//<h_i,z_t>
				pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[i+1], zs_ntt[t], pp.paramLC),
				// sigma_c_t
				pp.PolyCNTTMul(sigma_chs[t], c_hats[i]),
			)

			tmp := pp.PolyCNTTMul(alphas[i], f_t_i)

			tmp1 = pp.PolyCNTTAdd(
				tmp1,
				pp.PolyCNTTMul(tmp, f_t_i),
			)

			tmp2 = pp.PolyCNTTAdd(
				tmp2,
				tmp,
			)
		}
		tmp2 = pp.PolyCNTTMul(tmp2, pp.paramMu)
		tmp2 = pp.PolyCNTTMul(tmp2, sigma_chs[t])

		tmp1 = pp.PolyCNTTAdd(tmp1, tmp2)
		tmp1 = pp.sigmaInvPolyCNTT(tmp1, t)
		tmp1 = pp.PolyCNTTMul(betas[t], tmp1)

		psip = pp.PolyCNTTAdd(psip, tmp1)
	}

	psip = pp.PolyCNTTSub(psip, pp.PolyCNTTMul(ch, rpulppi.psi))
	psip = pp.PolyCNTTAdd(psip,
		pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[pp.paramI+pp.paramJ+6], zs_ntt[0], pp.paramLC))
	//fmt.Printf("Verify\n")
	//fmt.Printf("psip = %v\n", psip)
	//	p^(t)_j:
	p := pp.genUlpPolyCNTTs(rpulpType, binMatrixB, I, J, gammas)

	//	phip
	phip := pp.NewZeroPolyCNTT()
	var inprd, dcInv big.Int
	dcInv.SetInt64(pp.paramDCInv)
	bigQc := new(big.Int).SetInt64(pp.paramQC)

	for t := 0; t < pp.paramK; t++ {
		tmp1 := pp.NewZeroPolyCNTT()
		for tau := 0; tau < pp.paramK; tau++ {

			tmp := pp.NewZeroPolyCNTT()
			for j := uint8(0); j < n2; j++ {
				tmp = pp.PolyCNTTAdd(tmp, pp.PolyCNTTMul(p[t][j], c_hats[j]))
			}

			constPoly := pp.NewZeroPolyC()
			inprd.SetInt64(pp.intMatrixInnerProductWithReductionQc(u_hats, gammas[t], int(m), pp.paramDC))
			inprd.Mul(&inprd, &dcInv)
			//constPoly.coeffs[0] = reduceBigInt(&inprd, pp.paramQC)
			inprd.Mod(&inprd, bigQc)
			constPoly.coeffs[0] = reduceInt64(inprd.Int64(), pp.paramQC)

			tmp = pp.PolyCNTTSub(tmp, pp.NTTPolyC(constPoly))

			tmp1 = pp.PolyCNTTAdd(tmp1, pp.sigmaPowerPolyCNTT(tmp, tau))
		}

		xt := pp.NewZeroPolyC()
		xt.coeffs[t] = pp.paramKInv

		tmp1 = pp.PolyCNTTMul(pp.NTTPolyC(xt), tmp1)

		phip = pp.PolyCNTTAdd(phip, tmp1)
	}

	//	phi'^(\xi)
	phips := make([]*PolyCNTT, pp.paramK)
	constterm := pp.PolyCNTTSub(pp.PolyCNTTAdd(phip, rpulppi.c_hat_g), rpulppi.phi)

	for xi := 0; xi < pp.paramK; xi++ {
		phips[xi] = pp.NewZeroPolyCNTT()

		for t := 0; t < pp.paramK; t++ {

			tmp1 := pp.NewZeroPolyCNTT()
			for tau := 0; tau < pp.paramK; tau++ {

				tmp := pp.NewZeroPolyCNTTVec(pp.paramLC)

				for j := uint8(0); j < n2; j++ {
					tmp = pp.PolyCNTTVecAdd(
						tmp,
						pp.PolyCNTTVecScaleMul(p[t][j], pp.paramMatrixH[j+1], pp.paramLC),
						pp.paramLC)
				}

				tmp1 = pp.PolyCNTTAdd(
					tmp1,
					pp.sigmaPowerPolyCNTT(
						pp.PolyCNTTVecInnerProduct(tmp, zs_ntt[(xi-tau+pp.paramK)%pp.paramK], pp.paramLC),
						tau),
				)
			}

			xt := pp.NewZeroPolyC()
			xt.coeffs[t] = pp.paramKInv

			tmp1 = pp.PolyCNTTMul(pp.NTTPolyC(xt), tmp1)

			phips[xi] = pp.PolyCNTTAdd(phips[xi], tmp1)
		}

		phips[xi] = pp.PolyCNTTAdd(
			phips[xi],
			pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[pp.paramI+pp.paramJ+5], zs_ntt[xi], pp.paramLC))

		phips[xi] = pp.PolyCNTTSub(
			phips[xi],
			pp.PolyCNTTMul(sigma_chs[xi], constterm))
	}
	//fmt.Printf("Verify\n")
	//
	//fmt.Printf("phips = \n")
	//for i := 0; i < pp.paramK; i++ {
	//	fmt.Printf("phips[%d] = %v \n", i, phips[i])
	//}
	//fmt.Println("Verify")
	//fmt.Printf("rpulppi.phi =\n")
	//for i := 0; i < len(delta_hats); i++ {
	//	for j := 0; j < len(delta_hats[i]); j++ {
	//		fmt.Printf("delta_hats[%d][%d] = %v\n", i, j, delta_hats[i][j])
	//	}
	//}
	//	seed_ch and ch
	preMsgAll := pp.collectBytesForRPULP2(preMsg, rpulppi.psi, psip, rpulppi.phi, phips)
	seed_ch, err := Hash(preMsgAll)
	if err != nil {
		return false
	}
	if bytes.Compare(seed_ch, rpulppi.chseed) != 0 {
		return false
	}

	return true
}

func (pp *PublicParameter) genUlpPolyCNTTsMLP(rpulpType RpUlpType, binMatrixB [][]byte, nL uint8, nR uint8, gammas [][][]int64) (ps [][]*PolyCNTT) {
	p := make([][]*PolyCNTT, pp.paramK)
	//	var tmp1, tmp2 big.Int

	switch rpulpType {
	case RpUlpTypeCbTx1:
		break
	case RpUlpTypeCbTx2:
		//	nL=0, nR >=2: A_{L0R2}
		// n := J
		n := nR
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

				if i < pp.paramDC-1 {
					// i=0, ... d_c-2
					// The i-th row of F^T. i.e., the i-th column of F,
					//     is (0, ..., 0, -2, 1, 0, ..., 0), where -2 is the i-th coordinate and 1 is the (i+1)-th.
					// The i-th row of F_1^T. i.e., the i-th column of F_1,
					//     is (0, ..., 0), i.e., all zeros.
					coeffs[i] = reduceInt64(coeffs[i]-2*gammas[t][0][i]+gammas[t][0][i+1], pp.paramQC)
					// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				} else {
					// i = d_c -1
					// The i-th row of F^T. i.e., the i-th column of F,
					//     is (0, ..., 0, 0, 0, 0, ..., -2), i.e., all zeros except the last coordinate is -2.
					// The i-th row of F_1^T. i.e., the i-th column of F_1,
					//     is (0, ..., 1), i.e., all zeros, except the last coordinate is 1.
					coeffs[i] = reduceInt64(coeffs[i]-2*gammas[t][0][i]+gammas[t][1][i], pp.paramQC)
				}

				//if i == 0 {
				//	//coeffs[i] = pp.reduceBigInt(int64(coeffs[i] + gammas[t][1][i] + gammas[t][0][i]))
				//	//					coeffs[i] = reduceToQc(int64(coeffs[i]) + int64(gammas[t][1][i]) + int64(gammas[t][0][i]))
				//	coeffs[i] = reduceInt64(coeffs[i]+gammas[t][1][i]+gammas[t][0][i], pp.paramQC)
				//	// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				//	/*					tmp1.SetInt64(coeffs[i])
				//						tmp2.SetInt64(gammas[t][1][i])
				//						tmp1.Add(&tmp1, &tmp2)
				//						tmp2.SetInt64(gammas[t][0][i])
				//						tmp1.Add(&tmp1, &tmp2)
				//						coeffs[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				//} else if i < (pp.paramN - 1) {
				//	//coeffs[i] = reduceToQc()(int64(coeffs[i] - 2*gammas[t][0][i-1] + gammas[t][0][i]))
				//	//coeffs[i] = reduceToQc(int64(coeffs[i]) - 2*int64(gammas[t][0][i-1]) + int64(gammas[t][0][i]))
				//	coeffs[i] = reduceInt64(coeffs[i]-2*gammas[t][0][i-1]+gammas[t][0][i], pp.paramQC)
				//	// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				//	/*				tmp1.SetInt64(coeffs[i])
				//					tmp2.SetInt64(gammas[t][0][i-1])
				//					tmp2.Add(&tmp2, &tmp2)
				//					tmp1.Sub(&tmp1, &tmp2)
				//					tmp2.SetInt64(gammas[t][0][i])
				//					tmp1.Add(&tmp1, &tmp2)
				//					coeffs[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				//} else { // i in [N-1, d-1]
				//	//coeffs[i] = reduceToQc()(int64(coeffs[i] + gammas[t][1][i] - 2*gammas[t][0][i-1] + gammas[t][0][i]))
				//	//coeffs[i] = reduceToQc(int64(coeffs[i]) + int64(gammas[t][1][i]) - 2*int64(gammas[t][0][i-1]) + int64(gammas[t][0][i]))
				//	coeffs[i] = reduceInt64(coeffs[i]+gammas[t][1][i]-2*gammas[t][0][i-1]+gammas[t][0][i], pp.paramQC)
				//	// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				//	/*					tmp1.SetInt64(coeffs[i])
				//						tmp2.SetInt64(gammas[t][1][i])
				//						tmp1.Add(&tmp1, &tmp2)
				//						tmp2.SetInt64(gammas[t][0][i-1])
				//						tmp2.Add(&tmp2, &tmp2)
				//						tmp1.Sub(&tmp1, &tmp2)
				//						tmp2.SetInt64(gammas[t][0][i])
				//						tmp1.Add(&tmp1, &tmp2)
				//						coeffs[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				//}
			}
			p[t][n] = &PolyCNTT{coeffs: coeffs}

			p[t][n+1] = &PolyCNTT{coeffs: gammas[t][2]}
		}
	case RpUlpTypeTrTx1:
		//	(nL==1 AND nR >=2) OR ( nL==1 AND (nR===1 AND vRPub>0) ): A_{L1R2}
		// n := I + J
		n := nL + nR // n = 1+nR, note that the following computation is based on such a setting.
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

				if i < pp.paramDC-1 {
					// i=0, ... d_c-2
					// The i-th row of (-F)^T. i.e., the i-th column of (-F),
					//     is (0, ..., 0, 2, -1, 0, ..., 0), where 2 is the i-th coordinate and -1 is the (i+1)-th.
					// The i-th row of F_1^T. i.e., the i-th column of F_1,
					//     is (0, ..., 0), i.e., all zeros.
					coeffs[i] = reduceInt64(coeffs[i]+2*gammas[t][0][i]-gammas[t][0][i+1], pp.paramQC)
					// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				} else {
					// i = d_c -1
					// The i-th row of (-F)^T. i.e., the i-th column of (-F),
					//     is (0, ..., 0, 0, 0, 0, ..., 2), i.e., all zeros except the last coordinate is 2.
					// The i-th row of F_1^T. i.e., the i-th column of F_1,
					//     is (0, ..., 1), i.e., all zeros, except the last coordinate is 1.
					coeffs[i] = reduceInt64(coeffs[i]+2*gammas[t][0][i]+gammas[t][1][i], pp.paramQC)
				}

				//if i == 0 {
				//	//coeffs[i] = pp.reduceBigInt(int64(coeffs[i] + gammas[t][1][i] - gammas[t][0][i]))
				//	//coeffs[i] = reduceToQc(int64(coeffs[i]) + int64(gammas[t][1][i]) - int64(gammas[t][0][i]))
				//	coeffs[i] = reduceInt64(coeffs[i]+gammas[t][1][i]-gammas[t][0][i], pp.paramQC)
				//	// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				//	/*					tmp1.SetInt64(coeffs[i])
				//						tmp2.SetInt64(gammas[t][1][i])
				//						tmp1.Add(&tmp1, &tmp2)
				//						tmp2.SetInt64(gammas[t][0][i])
				//						tmp1.Sub(&tmp1, &tmp2)
				//						coeffs[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				//} else if i < (pp.paramN - 1) {
				//	//coeffs[i] = reduceToQc()(int64(coeffs[i] + 2*gammas[t][0][i-1] - gammas[t][0][i]))
				//	//coeffs[i] = reduceToQc(int64(coeffs[i]) + 2*int64(gammas[t][0][i-1]) - int64(gammas[t][0][i]))
				//	coeffs[i] = reduceInt64(coeffs[i]+2*gammas[t][0][i-1]-gammas[t][0][i], pp.paramQC)
				//	// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				//	/*					tmp1.SetInt64(coeffs[i])
				//						tmp2.SetInt64(gammas[t][0][i-1])
				//						tmp2.Add(&tmp2, &tmp2)
				//						tmp1.Add(&tmp1, &tmp2)
				//						tmp2.SetInt64(gammas[t][0][i])
				//						tmp1.Sub(&tmp1, &tmp2)
				//						coeffs[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				//} else { // i in [N-1, d-1]
				//	//coeffs[i] = reduceToQc()(int64(coeffs[i] + gammas[t][1][i] + 2*gammas[t][0][i-1] - gammas[t][0][i]))
				//	//coeffs[i] = reduceToQc(int64(coeffs[i]) + int64(gammas[t][1][i]) + 2*int64(gammas[t][0][i-1]) - int64(gammas[t][0][i]))
				//	coeffs[i] = reduceInt64(coeffs[i]+gammas[t][1][i]+2*gammas[t][0][i-1]-gammas[t][0][i], pp.paramQC)
				//	// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				//	/*					tmp1.SetInt64(coeffs[i])
				//						tmp2.SetInt64(gammas[t][1][i])
				//						tmp1.Add(&tmp1, &tmp2)
				//						tmp2.SetInt64(gammas[t][0][i-1])
				//						tmp2.Add(&tmp2, &tmp2)
				//						tmp1.Add(&tmp1, &tmp2)
				//						tmp2.SetInt64(gammas[t][0][i])
				//						tmp1.Sub(&tmp1, &tmp2)
				//						coeffs[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				//}
			}
			p[t][n] = &PolyCNTT{coeffs: coeffs}

			p[t][n+1] = &PolyCNTT{coeffs: gammas[t][2]}
		}
	case RpUlpTypeTrTx2:
		//	(nL>=2 AND nR >=2): A_{L2R2}
		// n := int(I + J)
		n := nL + nR
		n2 := n + 4
		//	B : d rows 2d columns
		//	m = 5
		for t := 0; t < pp.paramK; t++ {
			p[t] = make([]*PolyCNTT, n2)

			for j := uint8(0); j < nL; j++ {
				p[t][j] = &PolyCNTT{coeffs: gammas[t][0]}
			}
			for j := nL; j < nL+nR; j++ {
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

				if i < pp.paramDC-1 {
					// i=0, ... d_c-2
					// The i-th row of F^T. i.e., the i-th column of F,
					//     is (0, ..., 0, -2, 1, 0, ..., 0), where -2 is the i-th coordinate and 1 is the (i+1)-th.
					// The i-th row of F_1^T. i.e., the i-th column of F_1,
					//     is (0, ..., 0), i.e., all zeros.
					coeffs_np1[i] = reduceInt64(coeffs_np1[i]-2*gammas[t][0][i]+gammas[t][0][i+1], pp.paramQC)
					// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				} else {
					// i = d_c -1
					// The i-th row of F^T. i.e., the i-th column of F,
					//     is (0, ..., 0, 0, 0, 0, ..., -2), i.e., all zeros except the last coordinate is -2.
					// The i-th row of F_1^T. i.e., the i-th column of F_1,
					//     is (0, ..., 1), i.e., all zeros, except the last coordinate is 1.
					coeffs_np1[i] = reduceInt64(coeffs_np1[i]-2*gammas[t][0][i]+gammas[t][2][i], pp.paramQC)
				}

				//if i == 0 {
				//	//coeffs_np1[i] = reduceToQc()(int64(coeffs_np1[i] + gammas[t][2][i] + gammas[t][0][i]))
				//	//coeffs_np1[i] = reduceToQc(int64(coeffs_np1[i]) + int64(gammas[t][2][i]) + int64(gammas[t][0][i]))
				//	coeffs_np1[i] = reduceInt64(coeffs_np1[i]+gammas[t][2][i]+gammas[t][0][i], pp.paramQC)
				//	// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				//	/*				tmp1.SetInt64(coeffs_np1[i])
				//					tmp2.SetInt64(gammas[t][2][i])
				//					tmp1.Add(&tmp1, &tmp2)
				//					tmp2.SetInt64(gammas[t][0][i])
				//					tmp1.Add(&tmp1, &tmp2)
				//					coeffs_np1[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				//} else if i < (pp.paramN - 1) {
				//	//coeffs_np1[i] = reduceToQc()(int64(coeffs_np1[i] - 2*gammas[t][0][i-1] + gammas[t][0][i]))
				//	//coeffs_np1[i] = reduceToQc(int64(coeffs_np1[i]) - 2*int64(gammas[t][0][i-1]) + int64(gammas[t][0][i]))
				//	coeffs_np1[i] = reduceInt64(coeffs_np1[i]-2*gammas[t][0][i-1]+gammas[t][0][i], pp.paramQC)
				//	// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				//	/*					tmp1.SetInt64(coeffs_np1[i])
				//						tmp2.SetInt64(gammas[t][0][i-1])
				//						tmp2.Add(&tmp2, &tmp2)
				//						tmp1.Sub(&tmp1, &tmp2)
				//						tmp2.SetInt64(gammas[t][0][i])
				//						tmp1.Add(&tmp1, &tmp2)
				//						coeffs_np1[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				//} else { // i in [N-1, d-1]
				//	//coeffs_np1[i] = reduceToQc()(int64(coeffs_np1[i] + gammas[t][2][i] - 2*gammas[t][0][i-1] + gammas[t][0][i]))
				//	//coeffs_np1[i] = reduceToQc(int64(coeffs_np1[i]) + int64(gammas[t][2][i]) - 2*int64(gammas[t][0][i-1]) + int64(gammas[t][0][i]))
				//	coeffs_np1[i] = reduceInt64(coeffs_np1[i]+gammas[t][2][i]-2*gammas[t][0][i-1]+gammas[t][0][i], pp.paramQC)
				//	// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				//	/*					tmp1.SetInt64(coeffs_np1[i])
				//						tmp2.SetInt64(gammas[t][2][i])
				//						tmp1.Add(&tmp1, &tmp2)
				//						tmp2.SetInt64(gammas[t][0][i-1])
				//						tmp2.Add(&tmp2, &tmp2)
				//						tmp1.Sub(&tmp1, &tmp2)
				//						tmp2.SetInt64(gammas[t][0][i])
				//						tmp1.Add(&tmp1, &tmp2)
				//						coeffs_np1[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				//}
			}
			p[t][n+1] = &PolyCNTT{coeffs: coeffs_np1}

			//	p[t][n+2] = NTT^{-1}(F^T gamma[t][1] + F_1^T gamma[t][3] + B_2^T gamma[t][4])
			coeffs_np2 := make([]int64, pp.paramDC)
			for i := 0; i < pp.paramDC; i++ {
				//F^T[i] gamma[t][1] + F_1^T[i] gamma[t][3] + B_2^T[i] gamma[t][4]
				coeffs_np2[i] = pp.intVecInnerProductWithReductionQc(getMatrixColumn(binMatrixB, pp.paramDC, pp.paramDC+i), gammas[t][4], pp.paramDC)

				if i < pp.paramDC-1 {
					// i=0, ... d_c-2
					// The i-th row of F^T. i.e., the i-th column of F,
					//     is (0, ..., 0, -2, 1, 0, ..., 0), where -2 is the i-th coordinate and 1 is the (i+1)-th.
					// The i-th row of F_1^T. i.e., the i-th column of F_1,
					//     is (0, ..., 0), i.e., all zeros.
					coeffs_np2[i] = reduceInt64(coeffs_np2[i]-2*gammas[t][1][i]+gammas[t][1][i+1], pp.paramQC)
					// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				} else {
					// i = d_c -1
					// The i-th row of F^T. i.e., the i-th column of F,
					//     is (0, ..., 0, 0, 0, 0, ..., -2), i.e., all zeros except the last coordinate is -2.
					// The i-th row of F_1^T. i.e., the i-th column of F_1,
					//     is (0, ..., 1), i.e., all zeros, except the last coordinate is 1.
					coeffs_np2[i] = reduceInt64(coeffs_np2[i]-2*gammas[t][1][i]+gammas[t][3][i], pp.paramQC)
				}

				//if i == 0 {
				//	//coeffs_np2[i] = reduceToQc()(int64(coeffs_np2[i] + gammas[t][3][i] + gammas[t][1][i]))
				//	//coeffs_np2[i] = reduceToQc(int64(coeffs_np2[i]) + int64(gammas[t][3][i]) + int64(gammas[t][1][i]))
				//	coeffs_np2[i] = reduceInt64(coeffs_np2[i]+gammas[t][3][i]+gammas[t][1][i], pp.paramQC)
				//	// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				//	/*					tmp1.SetInt64(coeffs_np2[i])
				//						tmp2.SetInt64(gammas[t][3][i])
				//						tmp1.Add(&tmp1, &tmp2)
				//						tmp2.SetInt64(gammas[t][1][i])
				//						tmp1.Add(&tmp1, &tmp2)
				//						coeffs_np2[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				//} else if i < (pp.paramN - 1) {
				//	//coeffs_np2[i] = reduceToQc()(int64(coeffs_np2[i] - 2*gammas[t][1][i-1] + gammas[t][1][i]))
				//	//coeffs_np2[i] = reduceToQc(int64(coeffs_np2[i]) - 2*int64(gammas[t][1][i-1]) + int64(gammas[t][1][i]))
				//	coeffs_np2[i] = reduceInt64(coeffs_np2[i]-2*gammas[t][1][i-1]+gammas[t][1][i], pp.paramQC)
				//	// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				//	/*					tmp1.SetInt64(coeffs_np2[i])
				//						tmp2.SetInt64(gammas[t][1][i-1])
				//						tmp2.Add(&tmp2, &tmp2)
				//						tmp1.Sub(&tmp1, &tmp2)
				//						tmp2.SetInt64(gammas[t][1][i])
				//						tmp1.Add(&tmp1, &tmp2)
				//						coeffs_np2[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				//} else { // i in [N-1, d-1]
				//	//coeffs_np2[i] = reduceToQc()(int64(coeffs_np2[i] + gammas[t][3][i] - 2*gammas[t][1][i-1] + gammas[t][1][i]))
				//	//coeffs_np2[i] = reduceToQc(int64(coeffs_np2[i]) + int64(gammas[t][3][i]) - 2*int64(gammas[t][1][i-1]) + int64(gammas[t][1][i]))
				//	coeffs_np2[i] = reduceInt64(coeffs_np2[i]+gammas[t][3][i]-2*gammas[t][1][i-1]+gammas[t][1][i], pp.paramQC)
				//	// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				//	/*					tmp1.SetInt64(coeffs_np2[i])
				//						tmp2.SetInt64(gammas[t][3][i])
				//						tmp1.Add(&tmp1, &tmp2)
				//						tmp2.SetInt64(gammas[t][1][i-1])
				//						tmp2.Add(&tmp2, &tmp2)
				//						tmp1.Sub(&tmp1, &tmp2)
				//						tmp2.SetInt64(gammas[t][1][i])
				//						tmp1.Add(&tmp1, &tmp2)
				//						coeffs_np2[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				//}
			}
			p[t][n+2] = &PolyCNTT{coeffs: coeffs_np2}

			p[t][n+3] = &PolyCNTT{coeffs: gammas[t][4]}
		}
	}

	return p
}
