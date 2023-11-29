package pqringctx

import (
	"errors"
	"fmt"
)

// CoinbaseTxGen() generates a coinbase transaction.
func (pp *PublicParameter) CoinbaseTxGenMLP(vin uint64, txOutputDescs []*TxOutputDescMLP, txMemo []byte) (cbTx *CoinbaseTxMLP, err error) {
	//V := uint64(1)<<pp.paramN - 1
	//
	//if vin > V {
	//	return nil, errors.New("coinbaseTxGen: vin is not in [0, V]")
	//}
	//
	//if len(txOutputDescs) == 0 || len(txOutputDescs) > pp.paramJ {
	//	return nil, errors.New("the number of outputs is not in [1, I_max]")
	//}
	//
	//J := len(txOutputDescs)
	//
	//retcbTx := &CoinbaseTx{}
	//retcbTx.Vin = vin
	//retcbTx.OutputTxos = make([]*Txo, J)
	//retcbTx.TxMemo = txMemo
	//
	//cmts := make([]*ValueCommitment, J)
	//cmt_rs := make([]*PolyCNTTVec, J)
	//
	//vout := uint64(0)
	//// generate the output using txoGen
	//for j, txOutputDesc := range txOutputDescs {
	//	if txOutputDesc.value > V {
	//		return nil, fmt.Errorf("txOutputDescs[%d].value is not in [0, V]", j)
	//	}
	//	vout += txOutputDesc.value
	//	if vout > V {
	//		return nil, fmt.Errorf("the total output value is not in [0, V]")
	//	}
	//
	//	// restore the apk from serializedAPk
	//	apk, err := pp.DeserializeAddressPublicKey(txOutputDesc.serializedAPk)
	//	if err != nil {
	//		return nil, err
	//	}
	//	txo, cmtr, err := pp.txoGen(apk, txOutputDesc.serializedVPk, txOutputDesc.value)
	//	if err != nil {
	//		return nil, err
	//	}
	//	cmt_rs[j] = cmtr
	//	cmts[j] = txo.ValueCommitment
	//	retcbTx.OutputTxos[j] = txo
	//}
	//if vout != vin {
	//	return nil, errors.New("the output value and the input value should be equal")
	//}
	//
	//cbTxCon, err := pp.SerializeCoinbaseTx(retcbTx, false)
	//if err != nil {
	//	return nil, err
	//}
	//////	todo_done: serialize	begin
	////cbTxCon := make([]byte, 0, 8)
	////tw := bytes.NewBuffer(cbTxCon)
	////tw.WriteByte(byte(vin >> 0))
	////tw.WriteByte(byte(vin >> 8))
	////tw.WriteByte(byte(vin >> 16))
	////tw.WriteByte(byte(vin >> 24))
	////tw.WriteByte(byte(vin >> 32))
	////tw.WriteByte(byte(vin >> 40))
	////tw.WriteByte(byte(vin >> 48))
	////tw.WriteByte(byte(vin >> 56))
	////for i := 0; i < J; i++ {
	////	serializedTxo, err := pp.SerializeTxo(retcbTx.OutputTxos[i])
	////	if err != nil {
	////		return nil, err
	////	}
	////	_, err = tw.Write(serializedTxo)
	////	if err != nil {
	////		return nil, errors.New("error in serializing txo")
	////	}
	////}
	//////	todo_done: serialize	end
	//
	//if J == 1 {
	//	// random from S_etaC^lc
	//	ys := make([]*PolyCNTTVec, pp.paramK)
	//	// w^t = B * y^t
	//	ws := make([]*PolyCNTTVec, pp.paramK)
	//	// delta = <h,y^t>
	//	deltas := make([]*PolyCNTT, pp.paramK)
	//	// z^t = y^t + sigma^t(c) * r_(out,j), r_(out,j) is from txoGen, in there, r_(out,j) is cmt_rs_j
	//	zs_ntt := make([]*PolyCNTTVec, pp.paramK)
	//	zs := make([]*PolyCVec, pp.paramK)
	//
	//cbTxGenJ1Restart:
	//	for t := 0; t < pp.paramK; t++ {
	//		// random y
	//		tmpY, err := pp.sampleMaskingVecC()
	//		if err != nil {
	//			return nil, err
	//		}
	//		ys[t] = pp.NTTPolyCVec(tmpY)
	//
	//		ws[t] = pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, ys[t], pp.paramKC, pp.paramLC)
	//		deltas[t] = pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[0], ys[t], pp.paramLC)
	//	}
	//
	//	preMsg := pp.collectBytesForCoinbaseTxJ1(cbTxCon, ws, deltas)
	//	chseed, err := Hash(preMsg)
	//	if err != nil {
	//		return nil, err
	//	}
	//
	//	boundC := pp.paramEtaC - int64(pp.paramBetaC)
	//	chtmp, err := pp.expandChallengeC(chseed)
	//	if err != nil {
	//		return nil, err
	//	}
	//	ch := pp.NTTPolyC(chtmp)
	//	for t := 0; t < pp.paramK; t++ {
	//		zs_ntt[t] = pp.PolyCNTTVecAdd(
	//			ys[t],
	//			pp.PolyCNTTVecScaleMul(
	//				pp.sigmaPowerPolyCNTT(ch, t),
	//				cmt_rs[0],
	//				pp.paramLC,
	//			),
	//			pp.paramLC,
	//		)
	//		// check the norm
	//		zs[t] = pp.NTTInvPolyCVec(zs_ntt[t])
	//		if zs[t].infNorm() > boundC {
	//			goto cbTxGenJ1Restart
	//		}
	//	}
	//
	//	retcbTx.TxWitnessJ1 = &CbTxWitnessJ1{
	//		chseed: chseed,
	//		zs:     zs,
	//	}
	//	retcbTx.TxWitnessJ2 = nil
	//} else {
	//	//	J >= 2
	//	n := J
	//	n2 := n + 2
	//
	//	c_hats := make([]*PolyCNTT, n2)
	//
	//	msg_hats := make([][]int64, n2)
	//
	//	u_hats := make([][]int64, 3)
	//
	//	for j := 0; j < J; j++ {
	//		msg_hats[j] = pp.intToBinary(txOutputDescs[j].value)
	//	}
	//
	//	u := pp.intToBinary(vin)
	//
	//	//	f is the carry vector, such that, u = m_0 + m_1 + ... + m_{J-1}
	//	//	f[0] = 0, and for i=1 to d-1,
	//	//	m_0[i-1]+ ... + m_{J-1}[i-1] + f[i-1] = u[i-1] + 2 f[i],
	//	//	m_0[i-1]+ ... + m_{J-1}[i-1] + f[i-1] = u[i-1]
	//	f := make([]int64, pp.paramDC)
	//	f[0] = 0
	//	for i := 1; i < pp.paramDC; i++ {
	//		tmp := int64(0)
	//		for j := 0; j < J; j++ {
	//			tmp = tmp + msg_hats[j][i-1]
	//		}
	//
	//		//	-1 >> 1 = -1, -1/2=0
	//		//	In our design, the carry should be in [0, J] and (tmp + f[i-1] - u[i-1]) >=0,
	//		//	which means >> 1 and /2 are equivalent.
	//		//	A negative carry bit will not pass the verification,
	//		//	and the case (tmp + f[i-1] - u[i-1]) < 0 will not pass the verification.
	//		//	f[0] = 0 and other proved verification (msg[i] \in {0,1}, |f[i]| < q_c/8) are important.
	//		f[i] = (tmp + f[i-1] - u[i-1]) >> 1
	//		// f[i] = (tmp + f[i-1] - u[i-1]) / 2
	//	}
	//	msg_hats[J] = f
	//
	//	r_hat_poly, err := pp.sampleValueCmtRandomness()
	//	if err != nil {
	//		return nil, err
	//	}
	//	r_hat := pp.NTTPolyCVec(r_hat_poly)
	//
	//	// b_hat =B * r_hat
	//	b_hat := pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, r_hat, pp.paramKC, pp.paramLC)
	//
	//	//	c_hats[0]~c_hats[J-1], c_hats[J] (for f)
	//	for i := 0; i < J+1; i++ {
	//		c_hats[i] = pp.PolyCNTTAdd(
	//			pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[i+1], r_hat, pp.paramLC),
	//			&PolyCNTT{coeffs: msg_hats[i]},
	//		)
	//	}
	//
	//cbTxGenJ2Restart:
	//	//e := make([]int64, pp.paramDC)
	//	e, err := pp.randomDcIntegersInQcEtaF()
	//	if err != nil {
	//		return nil, err
	//	}
	//	msg_hats[J+1] = e
	//
	//	// c_hats[J+1] (for e)
	//	c_hats[J+1] = pp.PolyCNTTAdd(
	//		pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[J+2], r_hat, pp.paramLC),
	//		&PolyCNTT{coeffs: msg_hats[J+1]},
	//	)
	//
	//	//	todo_done 2022.04.03: check the scope of u_p in theory
	//	//	u_p = B f + e, where e \in [-eta_f, eta_f], with eta_f < q_c/16.
	//	//	As Bf should be bound by d_c J, so that |B f + e| < q_c/2, there should not modular reduction.
	//	betaF := pp.paramDC * J
	//	boundF := pp.paramEtaF - int64(betaF)
	//
	//	u_p := make([]int64, pp.paramDC)
	//	//u_p_tmp := make([]int64, pp.paramDC)
	//
	//	preMsg := pp.collectBytesForCoinbaseTxJ2(cbTxCon, b_hat, c_hats)
	//	seed_binM, err := Hash(preMsg) // todo_DONE: compute the seed using hash function on (b_hat, c_hats).
	//
	//	if err != nil {
	//		return nil, err
	//	}
	//	binM, err := expandBinaryMatrix(seed_binM, pp.paramDC, pp.paramDC)
	//	if err != nil {
	//		return nil, err
	//	}
	//	// compute B f + e and check the normal
	//	for i := 0; i < pp.paramDC; i++ {
	//		//u_p_tmp[i] = e[i]
	//		u_p[i] = e[i]
	//		for j := 0; j < pp.paramDC; j++ {
	//			if (binM[i][j/8]>>(j%8))&1 == 1 {
	//				// u_p_tmp[i] = u_p_tmp[i] + f[j]
	//				u_p[i] = u_p[i] + f[j]
	//			}
	//		}
	//
	//		//infNorm := u_p_tmp[i]
	//		infNorm := u_p[i]
	//		if infNorm < 0 {
	//			infNorm = -infNorm
	//		}
	//		if infNorm > boundF {
	//			goto cbTxGenJ2Restart
	//		}
	//
	//		//			u_p[i] = reduceInt64(u_p_tmp[i], pp.paramQC) // todo_done: 202203 Do need reduce? no.
	//	}
	//
	//	u_hats[0] = u
	//	u_hats[1] = make([]int64, pp.paramDC)
	//	for i := 0; i < pp.paramDC; i++ {
	//		u_hats[1][i] = 0
	//	}
	//	u_hats[2] = u_p
	//
	//	n1 := n
	//	rprlppi, pi_err := pp.rpulpProve(cbTxCon, cmts, cmt_rs, uint8(n), b_hat, r_hat, c_hats, msg_hats, uint8(n2), uint8(n1), RpUlpTypeCbTx2, binM, 0, uint8(J), 3, u_hats)
	//
	//	if pi_err != nil {
	//		return nil, pi_err
	//	}
	//
	//	retcbTx.TxWitnessJ1 = nil
	//	retcbTx.TxWitnessJ2 = &CbTxWitnessJ2{
	//		b_hat:      b_hat,
	//		c_hats:     c_hats,
	//		u_p:        u_p,
	//		rpulpproof: rprlppi,
	//	}
	//}
	//
	//return retcbTx, nil
	return nil, err
}

// TXO		begin

//	TXO		end

//	TxWitness		begin

func (pp *PublicParameter) GetCbTxWitnessSerializeSizeApprox(coinAddressList [][]byte) (int, error) {
	if len(coinAddressList) == 0 {
		return 0, errors.New("GetCbTxWitnessSerializeSizeApprox: the input coinAddressList is empty")

	}

	outForRing := 0
	outForSingle := 0
	for i := 0; i < len(coinAddressList); i++ {
		coinAddressType, err := pp.ExtractCoinAddressType(coinAddressList[i])
		if err != nil {
			return 0, err
		}

		if coinAddressType == CoinAddressTypePublicKeyForRingPre || coinAddressType == CoinAddressTypePublicKeyForRing {
			if i == outForRing {
				outForRing += 1
			} else {
				return 0, errors.New("GetCbTxWitnessSerializeSizeApprox: the coinAddresses for RingCT-Privacy should be at the fist successive positions")
			}
		} else if coinAddressType == CoinAddressTypePublicKeyHashForSingle {
			outForSingle += 1
		} else {
			return 0, errors.New("GetCbTxWitnessSerializeSizeApprox: unsupported coinAddress type appears in coinAddressList")
		}
	}

	if outForRing > pp.GetTxOutputMaxNumForRing() {
		errStr := fmt.Sprintf("GetCbTxWitnessSerializeSizeApprox: the number of output coins for RingCT-privacy exceeds the max allowed on: %d vs %d", outForRing, pp.GetTxOutputMaxNumForRing())
		return 0, errors.New(errStr)
	}

	if outForSingle > pp.GetTxOutputMaxNumForSingle() {
		errStr := fmt.Sprintf("GetCbTxWitnessSerializeSizeApprox: the number of output coins for Pseudonym-privacy exceeds the max allowed on: %d vs %d", outForSingle, pp.GetTxOutputMaxNumForSingle())
		return 0, errors.New(errStr)
	}

	//	Note that coinbaseTx's witness contains only bpf.
	if outForRing == 0 {
		return 0, nil
	} else if outForRing == 1 {
		return pp.GetBpfL0R1Size()
	} else {
		// outForRing > 1
		return pp.GetBpfL0R2Size(outForRing)
	}
}

//	TxWitness		end

// BPF		begin
func (pp *PublicParameter) GetBpfL0R1Size() (int, error) {
	// todo(MLP): todo
	return 0, nil
}

func (pp *PublicParameter) GetBpfL0R2Size(nR int) (int, error) {
	// todo(MLP): todo
	return 0, nil
}

//	BPF		end
