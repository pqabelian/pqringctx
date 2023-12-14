package pqringctx

import "errors"

func (pp *PublicParameter) elrsMLPSign(
	lgrTxoList []*LgrTxo, ma_p *PolyANTT, cmt_p *ValueCommitment,
	msg []byte, sindex uint8, sa *PolyANTTVec, rc *PolyCNTTVec, rc_p *PolyCNTTVec) (*elrsSignature, error) {
	var err error
	ringLen := len(lgrTxoList)
	if ringLen == 0 {
		return nil, errors.New("elrsSign is called on input empty ring")
	}
	if int(sindex) >= ringLen {
		return nil, errors.New("The signer index is not in the scope")
	}

	seeds := make([][]byte, ringLen)
	z_as_ntt := make([]*PolyANTTVec, ringLen)
	z_as := make([]*PolyAVec, ringLen)

	w_as := make([]*PolyANTTVec, ringLen)
	delta_as := make([]*PolyANTT, ringLen)

	z_cs_ntt := make([][]*PolyCNTTVec, ringLen)
	z_cps_ntt := make([][]*PolyCNTTVec, ringLen)
	z_cs := make([][]*PolyCVec, ringLen)
	z_cps := make([][]*PolyCVec, ringLen)

	w_cs := make([][]*PolyCNTTVec, ringLen)
	w_cps := make([][]*PolyCNTTVec, ringLen)
	delta_cs := make([][]*PolyCNTT, ringLen)

	for j := 0; j < ringLen; j++ {
		if j == int(sindex) {
			continue
		}
		seeds[j] = RandomBytes(HashOutputBytesLen) // we use Hash to generate seed for challenge

		tmpA, err := pp.expandChallengeA(seeds[j])
		if err != nil {
			return nil, err
		}
		da := pp.NTTPolyA(tmpA)

		tmpC, err := pp.expandChallengeC(seeds[j])
		if err != nil {
			return nil, err
		}
		dc := pp.NTTPolyC(tmpC)

		// sample randomness for z_a_j
		z_as[j], err = pp.sampleResponseA()
		if err != nil {
			return nil, err
		}
		z_as_ntt[j] = pp.NTTPolyAVec(z_as[j])

		// w_a_j = A*z_a_j - d_a_j*t_j
		w_as[j] = pp.PolyANTTVecSub(
			pp.PolyANTTMatrixMulVector(pp.paramMatrixA, z_as_ntt[j], pp.paramKA, pp.paramLA),
			pp.PolyANTTVecScaleMul(da, lgrTxoList[j].txo.AddressPublicKey.t, pp.paramKA),
			pp.paramKA,
		)
		// delta_a_j = <a,z_a_j> - d_a_j * (e_j + expandKIDR(txo[j]) - m_a_p)
		lgrTxoH, err := pp.expandKIDR(lgrTxoList[j])
		if err != nil {
			return nil, err
		}
		delta_as[j] = pp.PolyANTTSub(
			pp.PolyANTTVecInnerProduct(pp.paramVectorA, z_as_ntt[j], pp.paramLA),
			pp.PolyANTTMul(
				da,
				pp.PolyANTTSub(
					pp.PolyANTTAdd(
						lgrTxoList[j].txo.AddressPublicKey.e,
						lgrTxoH,
					),
					ma_p,
				),
			),
		)

		z_cs_ntt[j] = make([]*PolyCNTTVec, pp.paramK)
		z_cps_ntt[j] = make([]*PolyCNTTVec, pp.paramK)
		z_cs[j] = make([]*PolyCVec, pp.paramK)
		z_cps[j] = make([]*PolyCVec, pp.paramK)

		w_cs[j] = make([]*PolyCNTTVec, pp.paramK)
		w_cps[j] = make([]*PolyCNTTVec, pp.paramK)

		delta_cs[j] = make([]*PolyCNTT, pp.paramK)
		for tao := 0; tao < pp.paramK; tao++ {
			z_cs[j][tao], err = pp.sampleResponseC()
			if err != nil {
				return nil, err
			}
			z_cps[j][tao], err = pp.sampleResponseC()
			if err != nil {
				return nil, err
			}

			z_cs_ntt[j][tao] = pp.NTTPolyCVec(z_cs[j][tao])
			z_cps_ntt[j][tao] = pp.NTTPolyCVec(z_cps[j][tao])
			sigmataodc := pp.sigmaPowerPolyCNTT(dc, tao)
			w_cs[j][tao] = pp.PolyCNTTVecSub(
				pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, z_cs_ntt[j][tao], pp.paramKC, pp.paramLC),
				pp.PolyCNTTVecScaleMul(
					sigmataodc,
					lgrTxoList[j].txo.ValueCommitment.b,
					pp.paramKC,
				),
				pp.paramKC,
			)
			w_cps[j][tao] = pp.PolyCNTTVecSub(
				pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, z_cps_ntt[j][tao], pp.paramKC, pp.paramLC),
				pp.PolyCNTTVecScaleMul(
					sigmataodc,
					cmt_p.b,
					pp.paramKC,
				),
				pp.paramKC,
			)
			delta_cs[j][tao] = pp.PolyCNTTSub(
				pp.PolyCNTTVecInnerProduct(
					pp.paramMatrixH[0],
					pp.PolyCNTTVecSub(z_cs_ntt[j][tao], z_cps_ntt[j][tao], pp.paramLC),
					pp.paramLC,
				),
				pp.PolyCNTTMul(
					sigmataodc,
					pp.PolyCNTTSub(lgrTxoList[j].txo.ValueCommitment.c, cmt_p.c),
				),
			)
		}
	}

	z_cs_ntt[sindex] = make([]*PolyCNTTVec, pp.paramK)
	z_cps_ntt[sindex] = make([]*PolyCNTTVec, pp.paramK)
	z_cs[sindex] = make([]*PolyCVec, pp.paramK)
	z_cps[sindex] = make([]*PolyCVec, pp.paramK)

	w_cs[sindex] = make([]*PolyCNTTVec, pp.paramK)
	w_cps[sindex] = make([]*PolyCNTTVec, pp.paramK)
	delta_cs[sindex] = make([]*PolyCNTT, pp.paramK)
ELRSSignRestart:
	// randomness y_a_j_bar
	tmpYa, err := pp.sampleMaskingVecA()
	if err != nil {
		return nil, err
	}
	y_a := pp.NTTPolyAVec(tmpYa)
	w_as[sindex] = pp.PolyANTTMatrixMulVector(pp.paramMatrixA, y_a, pp.paramKA, pp.paramLA)
	delta_as[sindex] = pp.PolyANTTVecInnerProduct(pp.paramVectorA, y_a, pp.paramLA)

	y_cs := make([]*PolyCNTTVec, pp.paramK)
	y_cps := make([]*PolyCNTTVec, pp.paramK)

	for tao := 0; tao < pp.paramK; tao++ {
		tmpYc, err := pp.sampleMaskingVecC()
		if err != nil {
			return nil, err
		}
		tmpYcp, err := pp.sampleMaskingVecC()
		if err != nil {
			return nil, err
		}

		y_cs[tao] = pp.NTTPolyCVec(tmpYc)
		y_cps[tao] = pp.NTTPolyCVec(tmpYcp)
		w_cs[sindex][tao] = pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, y_cs[tao], pp.paramKC, pp.paramLC)
		w_cps[sindex][tao] = pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, y_cps[tao], pp.paramKC, pp.paramLC)
		delta_cs[sindex][tao] = pp.PolyCNTTVecInnerProduct(
			pp.paramMatrixH[0],
			pp.PolyCNTTVecSub(y_cs[tao], y_cps[tao], pp.paramLC),
			pp.paramLC,
		)
	}

	preMsg, err := pp.collectBytesForElrsChallenge(lgrTxoList, ma_p, cmt_p, msg, w_as, delta_as, w_cs, w_cps, delta_cs)
	if err != nil {
		return nil, err
	}
	seed_ch, err := Hash(preMsg)
	if err != nil {
		return nil, err
	}
	/*	seeds[sindex] = make([]byte, len(seed_ch))
		for i := 0; i < len(seed_ch); i++ {
			seeds[sindex][i] = seed_ch[i]
		}*/
	seeds[sindex] = seed_ch
	seedByteLen := len(seed_ch)
	for j := 0; j < ringLen; j++ {
		if j == int(sindex) {
			continue
		}
		for i := 0; i < seedByteLen; i++ {
			seeds[sindex][i] ^= seeds[j][i]
		}
	}

	tmpA, err := pp.expandChallengeA(seeds[sindex])
	if err != nil {
		return nil, err
	}
	tmpC, err := pp.expandChallengeC(seeds[sindex])
	if err != nil {
		return nil, err
	}
	dA := pp.NTTPolyA(tmpA)
	dC := pp.NTTPolyC(tmpC)

	z_as_ntt[sindex] = pp.PolyANTTVecAdd(y_a, pp.PolyANTTVecScaleMul(dA, sa, pp.paramLA), pp.paramLA)
	z_as[sindex] = pp.NTTInvPolyAVec(z_as_ntt[sindex])

	for tao := 0; tao < pp.paramK; tao++ {
		sigmaTaoDc := pp.sigmaPowerPolyCNTT(dC, tao)
		z_cs_ntt[sindex][tao] = pp.PolyCNTTVecAdd(
			y_cs[tao],
			pp.PolyCNTTVecScaleMul(sigmaTaoDc, rc, pp.paramLC),
			pp.paramLC,
		)
		z_cps_ntt[sindex][tao] = pp.PolyCNTTVecAdd(
			y_cps[tao],
			pp.PolyCNTTVecScaleMul(sigmaTaoDc, rc_p, pp.paramLC),
			pp.paramLC,
		)

		z_cs[sindex][tao] = pp.NTTInvPolyCVec(z_cs_ntt[sindex][tao])
		z_cps[sindex][tao] = pp.NTTInvPolyCVec(z_cps_ntt[sindex][tao])
	}

	if z_as[sindex].infNorm() > pp.paramEtaA-int64(pp.paramBetaA) {
		goto ELRSSignRestart
	}

	boundC := pp.paramEtaC - int64(pp.paramBetaC)
	for tao := 0; tao < pp.paramK; tao++ {
		if (z_cs[sindex][tao].infNorm() > boundC) || (z_cps[sindex][tao].infNorm() > boundC) {
			goto ELRSSignRestart
		}
		//if z_cps[sindex][tao].infNorm() > boundC {
		//	goto ELRSSignRestart
		//}
	}
	return &elrsSignature{
		seeds: seeds,
		z_as:  z_as,
		z_cs:  z_cs,
		z_cps: z_cps,
	}, nil
}

// todo_DONE: the paper is not accurate, use the following params
func (pp *PublicParameter) collectBytesForElrsMLPChallenge(
	lgxTxoList []*LgrTxo, ma_p *PolyANTT, cmt_p *ValueCommitment,
	msg []byte,
	w_as []*PolyANTTVec, delta_as []*PolyANTT,
	w_cs [][]*PolyCNTTVec, w_cps [][]*PolyCNTTVec, delta_cs [][]*PolyCNTT) ([]byte, error) {

	length := len(lgxTxoList)*pp.LgrTxoSerializeSize() +
		pp.paramDA*8 + (pp.paramKC+1)*8 +
		len(msg) +
		len(lgxTxoList)*(pp.paramKA+1)*8 +
		len(lgxTxoList)*pp.paramK*(pp.paramKC*2+1)

	rst := make([]byte, 0, length)

	appendPolyANTTToBytes := func(a *PolyANTT) {
		for k := 0; k < pp.paramDA; k++ {
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

	appendPolyCNTTToBytes := func(a *PolyCNTT) {
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

	// lgrTxoList
	for i := 0; i < len(lgxTxoList); i++ {
		serializeLgrTxo, err := pp.SerializeLgrTxo(lgxTxoList[i])
		if err != nil {
			//log.Fatalln("error for pp.SerializeLgrTxo()")
			return nil, err
		}
		rst = append(rst, serializeLgrTxo...)
		//_, err = w.Write(serializeLgrTxo)
		//if err != nil {
		//	//log.Fatalln("error for w.Write()")
		//	return nil, err
		//}
	}

	// ma_p *PolyANTT
	appendPolyANTTToBytes(ma_p)

	// cmt_p *ValueCommitment
	for i := 0; i < len(cmt_p.b.polyCNTTs); i++ {
		appendPolyCNTTToBytes(cmt_p.b.polyCNTTs[i])
	}
	appendPolyCNTTToBytes(cmt_p.c)

	// msg
	rst = append(rst, msg...)

	// w_as []*PolyANTTVec
	for i := 0; i < len(w_as); i++ {
		for j := 0; j < len(w_as[i].polyANTTs); j++ {
			appendPolyANTTToBytes(w_as[i].polyANTTs[j])
		}
	}
	// delta_as []*PolyANTT
	for i := 0; i < len(delta_as); i++ {
		appendPolyANTTToBytes(delta_as[i])
	}

	// w_cs [][]*PolyCNTTVec
	for i := 0; i < len(w_cs); i++ {
		for j := 0; j < len(w_cs[i]); j++ {
			for k := 0; k < len(w_cs[i][j].polyCNTTs); k++ {
				appendPolyCNTTToBytes(w_cs[i][j].polyCNTTs[k])
			}
		}
	}
	// w_cps [][]*PolyCNTTVec
	for i := 0; i < len(w_cps); i++ {
		for j := 0; j < len(w_cps[i]); j++ {
			for k := 0; k < len(w_cps[i][j].polyCNTTs); k++ {
				appendPolyCNTTToBytes(w_cps[i][j].polyCNTTs[k])
			}
		}
	}
	// delta_cs [][]*PolyCNTT
	for i := 0; i < len(delta_cs); i++ {
		for j := 0; j < len(delta_cs[i]); j++ {
			appendPolyCNTTToBytes(delta_cs[i][j])
		}
	}

	return rst, nil
}

// elrsVerify() verify the validity of a given (message, signature) pair.
func (pp *PublicParameter) elrsMLPVerify(lgrTxoList []*LgrTxo, ma_p *PolyANTT, cmt_p *ValueCommitment, msg []byte, sig *elrsSignature) (bool, error) {
	ringLen := len(lgrTxoList)
	if ringLen == 0 {
		return false, nil
	}
	boundA := pp.paramEtaA - int64(pp.paramBetaA)
	boundC := pp.paramEtaC - int64(pp.paramBetaC)
	for j := 0; j < ringLen; j++ {
		if sig.z_as[j].infNorm() > boundA {
			return false, nil
		}
		for tao := 0; tao < pp.paramK; tao++ {
			if (sig.z_cs[j][tao].infNorm() > boundC) || (sig.z_cps[j][tao].infNorm() > boundC) {
				return false, nil
			}
			//if sig.z_cps[j][tao].infNorm() > boundC {
			//	return false, nil
			//}
		}
	}

	w_as := make([]*PolyANTTVec, ringLen)
	delta_as := make([]*PolyANTT, ringLen)

	w_cs := make([][]*PolyCNTTVec, ringLen)
	w_cps := make([][]*PolyCNTTVec, ringLen)
	delta_cs := make([][]*PolyCNTT, ringLen)
	for j := 0; j < ringLen; j++ {
		tmpDA, err := pp.expandChallengeA(sig.seeds[j])
		if err != nil {
			return false, err
		}
		da := pp.NTTPolyA(tmpDA)

		tmpDC, err := pp.expandChallengeC(sig.seeds[j])
		if err != nil {
			return false, err
		}
		dc := pp.NTTPolyC(tmpDC)

		z_as_ntt := pp.NTTPolyAVec(sig.z_as[j])
		// w_a_j = A*z_a_j - d_a_j*t_j
		w_as[j] = pp.PolyANTTVecSub(
			pp.PolyANTTMatrixMulVector(pp.paramMatrixA, z_as_ntt, pp.paramKA, pp.paramLA),
			pp.PolyANTTVecScaleMul(da, lgrTxoList[j].txo.AddressPublicKey.t, pp.paramKA),
			pp.paramKA,
		)
		// theta_a_j = <a,z_a_j> - d_a_j * (e_j + expandKIDR(txo[j]) - m_a_p)
		lgrTxoH, err := pp.expandKIDR(lgrTxoList[j])
		if err != nil {
			return false, err
		}
		delta_as[j] = pp.PolyANTTSub(
			pp.PolyANTTVecInnerProduct(pp.paramVectorA, z_as_ntt, pp.paramLA),
			pp.PolyANTTMul(
				da,
				pp.PolyANTTSub(
					pp.PolyANTTAdd(
						lgrTxoList[j].txo.AddressPublicKey.e,
						lgrTxoH,
					),
					ma_p,
				),
			),
		)

		w_cs[j] = make([]*PolyCNTTVec, pp.paramK)
		w_cps[j] = make([]*PolyCNTTVec, pp.paramK)
		delta_cs[j] = make([]*PolyCNTT, pp.paramK)
		for tao := 0; tao < pp.paramK; tao++ {
			z_cs_ntt := pp.NTTPolyCVec(sig.z_cs[j][tao])
			z_cps_ntt := pp.NTTPolyCVec(sig.z_cps[j][tao])
			sigmataodc := pp.sigmaPowerPolyCNTT(dc, tao)

			w_cs[j][tao] = pp.PolyCNTTVecSub(
				pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, z_cs_ntt, pp.paramKC, pp.paramLC),
				pp.PolyCNTTVecScaleMul(
					sigmataodc,
					lgrTxoList[j].txo.ValueCommitment.b,
					pp.paramKC,
				),
				pp.paramKC,
			)
			w_cps[j][tao] = pp.PolyCNTTVecSub(
				pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, z_cps_ntt, pp.paramKC, pp.paramLC),
				pp.PolyCNTTVecScaleMul(
					sigmataodc,
					cmt_p.b,
					pp.paramKC,
				),
				pp.paramKC,
			)
			delta_cs[j][tao] = pp.PolyCNTTSub(
				pp.PolyCNTTVecInnerProduct(
					pp.paramMatrixH[0],
					pp.PolyCNTTVecSub(z_cs_ntt, z_cps_ntt, pp.paramLC),
					pp.paramLC,
				),
				pp.PolyCNTTMul(
					sigmataodc,
					pp.PolyCNTTSub(lgrTxoList[j].txo.ValueCommitment.c, cmt_p.c),
				),
			)
		}
	}

	preMsg, err := pp.collectBytesForElrsChallenge(lgrTxoList, ma_p, cmt_p, msg, w_as, delta_as, w_cs, w_cps, delta_cs)
	if err != nil {
		return false, err
	}
	seed_ch, err := Hash(preMsg)
	if err != nil {
		return false, err
	}

	seedByteLen := len(seed_ch)
	for j := 0; j < ringLen; j++ {
		for i := 0; i < len(seed_ch); i++ {
			seed_ch[i] ^= sig.seeds[j][i]
		}
	}
	for i := 0; i < seedByteLen; i++ {
		if seed_ch[i] != 0 {
			return false, nil
		}
	}
	return true, nil
}
