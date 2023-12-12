package pqringctx

import (
	"errors"
	"fmt"
	"github.com/cryptosuite/pqringctx/pqringctxkem"
)

// CoinbaseTxMLPGen generates a coinbase transaction.
// reviewed on 2023.12.07
func (pp *PublicParameter) CoinbaseTxMLPGen(vin uint64, txOutputDescMLPs []*TxOutputDescMLP, txMemo []byte) (cbTx *CoinbaseTxMLP, err error) {
	V := uint64(1)<<pp.paramN - 1

	if vin > V {
		return nil, fmt.Errorf("CoinbaseTxMLPGen: vin (%d) is not in [0, V= %d]", vin, V)
	}

	if len(txOutputDescMLPs) == 0 || len(txOutputDescMLPs) > pp.paramJ+pp.paramJSingle {
		return nil, fmt.Errorf("CoinbaseTxMLPGen: the number of outputs (%d) is not in [1, %d]", len(txOutputDescMLPs), pp.paramJ+pp.paramJSingle)
	}

	// identify the J_ring
	outForRing := 0
	outForSingle := 0
	for i := 0; i < len(txOutputDescMLPs); i++ {
		coinAddressType, err := pp.ExtractCoinAddressTypeFromCoinAddress(txOutputDescMLPs[i].coinAddress)
		if err != nil {
			return nil, err
		}
		if coinAddressType == CoinAddressTypePublicKeyForRingPre || coinAddressType == CoinAddressTypePublicKeyForRing {
			if i == outForRing {
				outForRing += 1
			} else {
				//	The coinAddresses for RingCT-Privacy should be at the fist successive positions.
				return nil, fmt.Errorf("CoinbaseTxMLPGen: the coinAddresses for RingCT-Privacy should be at the fist successive positions, but the %d -th one is not", i)
			}
		} else if coinAddressType == CoinAddressTypePublicKeyHashForSingle {
			outForSingle += 1
		} else {
			return nil, fmt.Errorf("CoinbaseTxMLPGen: the %d -th coinAddresses of the input txOutputDescMLPs (%d) is not supported", i, coinAddressType)
		}
	}
	if outForRing > pp.paramJ {
		return nil, fmt.Errorf("CoinbaseTxMLPGen: the number of RingCT-Privacy coinAddresses in the input txOutputDescMLPs %d exceeds the allowd maxumim %d", outForRing, pp.paramJ)
	}

	if outForSingle > pp.paramJSingle {
		return nil, fmt.Errorf("CoinbaseTxMLPGen: the number of Pseudonym-Privacy coinAddresses in the input txOutputDescMLPs %d exceeds the allowd maxumim %d", outForSingle, pp.paramJSingle)
	}

	retCbTx := &CoinbaseTxMLP{}
	retCbTx.vin = vin
	retCbTx.txos = make([]TxoMLP, len(txOutputDescMLPs))
	retCbTx.txMemo = txMemo

	cmts := make([]*ValueCommitment, outForRing)
	cmt_rs := make([]*PolyCNTTVec, outForRing)
	vRs := make([]uint64, outForRing)

	vout := uint64(0)
	voutPublic := uint64(0)
	// generate the output using txoGen
	for j, txOutputDescMLP := range txOutputDescMLPs {
		if txOutputDescMLP.value > V {
			return nil, fmt.Errorf("CoinbaseTxMLPGen: txOutputDescMLPs[%d].value (%d) is not in [0, %d]", j, txOutputDescMLP.value, V)
		}
		vout += txOutputDescMLP.value
		if vout > V {
			return nil, fmt.Errorf("CoinbaseTxMLPGen: the total output value is not in [0, %d]", V)
		}

		coinAddressType, err := pp.ExtractCoinAddressTypeFromCoinAddress(txOutputDescMLP.coinAddress)
		if err != nil {
			return nil, err
		}
		switch coinAddressType {
		case CoinAddressTypePublicKeyForRingPre:
			txoRCTPre, cmtr, err := pp.txoRCTPreGen(txOutputDescMLP.coinAddress, txOutputDescMLP.coinValuePublicKey, txOutputDescMLP.value)
			if err != nil {
				return nil, err
			}
			retCbTx.txos[j] = txoRCTPre
			cmts[j] = txoRCTPre.valueCommitment
			cmt_rs[j] = cmtr
			vRs[j] = txOutputDescMLP.value

		case CoinAddressTypePublicKeyForRing:
			txoRCT, cmtr, err := pp.txoRCTGen(txOutputDescMLP.coinAddress, txOutputDescMLP.coinValuePublicKey, txOutputDescMLP.value)
			if err != nil {
				return nil, err
			}
			retCbTx.txos[j] = txoRCT
			cmts[j] = txoRCT.valueCommitment
			cmt_rs[j] = cmtr
			vRs[j] = txOutputDescMLP.value

		case CoinAddressTypePublicKeyHashForSingle:
			txoSDN := pp.txoSDNGen(txOutputDescMLP.coinAddress, txOutputDescMLP.value)
			if err != nil {
				return nil, err
			}
			retCbTx.txos[j] = txoSDN
			//cmts[j] = txoRCT.valueCommitment
			//cmt_rs[j] = cmtr
			//vRs[j] = txOutputDescMLP.value
			voutPublic += txOutputDescMLP.value

		default:
			return nil, fmt.Errorf("CoinbaseTxMLPGen: the %d -th coinAddresses of the input txOutputDescMLPs (%d) is not supported", j, coinAddressType)
		}
	}
	if vout != vin {
		return nil, fmt.Errorf("CoinbaseTxMLPGen: the output value (%d) and the input value (%d) are not equal", vout, vin)
	}
	vL := vin - voutPublic //	note that vout == vin above implies vL >= 0 here.

	//	TxWitness
	serializedCbTxCon, err := pp.SerializeCoinbaseTxMLP(retCbTx, false)
	if err != nil {
		return nil, err
	}
	txWitness, err := pp.genTxWitnessCbTx(serializedCbTxCon, vL, uint8(outForRing), cmts, cmt_rs, vRs)
	if err != nil {
		return nil, err
	}

	retCbTx.txWitness = txWitness

	return retCbTx, nil
}

// CoinbaseTxMLPVerify verifies the input CoinbaseTxMLP.
// todo: review
func (pp *PublicParameter) CoinbaseTxMLPVerify(cbTx *CoinbaseTxMLP) (bool, error) {
	if cbTx == nil {
		return false, nil
	}

	V := uint64(1)<<pp.paramN - 1

	if cbTx.vin > V {
		return false, nil
	}

	if len(cbTx.txos) == 0 {
		return false, nil
	}

	// identify the J_ring
	outForRing := 0
	outForSingle := 0
	for i := 0; i < len(cbTx.txos); i++ {
		coinAddressType := cbTx.txos[i].CoinAddressType()
		if coinAddressType == CoinAddressTypePublicKeyForRingPre || coinAddressType == CoinAddressTypePublicKeyForRing {
			if i == outForRing {
				outForRing += 1
			} else {
				//	The coinAddresses for RingCT-Privacy should be at the fist successive positions.
				return false, fmt.Errorf("CoinbaseTxMLPVerify: the coinAddresses for RingCT-Privacy should be at the fist successive positions, but the %d -th one is not", i)
			}
		} else if coinAddressType == CoinAddressTypePublicKeyHashForSingle {
			outForSingle += 1
		} else {
			return false, fmt.Errorf("CoinbaseTxMLPVerify: the %d -th coinAddresses of the input txOutputDescMLPs (%d) is not supported", i, coinAddressType)
		}
	}
	if outForRing > pp.paramJ {
		return false, fmt.Errorf("CoinbaseTxMLPVerify: the number of RingCT-Privacy coinAddresses in the input cbTx.txos (%d) exceeds the allowd maxumim %d", outForRing, pp.paramJ)
	}

	if outForSingle > pp.paramJSingle {
		return false, fmt.Errorf("CoinbaseTxMLPVerify: the number of Pseudonym-Privacy coinAddresses in the input cbTx.txos (%d) exceeds the allowd maxumim %d", outForSingle, pp.paramJSingle)
	}

	if cbTx.txWitness == nil {
		return false, nil
	}

	cmts := make([]*ValueCommitment, outForRing)

	voutPublic := uint64(0)
	// generate the output using txoGen
	for j, txoMLP := range cbTx.txos {
		switch txoInst := txoMLP.(type) {
		case *TxoRCTPre:
			if txoMLP.CoinAddressType() != CoinAddressTypePublicKeyForRingPre {
				return false, fmt.Errorf("CoinbaseTxMLPVerify: the %d-th Txo is TxoRCTPre, but its coinAddressType is not CoinAddressTypePublicKeyForRingPre", j)
			}
			cmts[j] = txoInst.valueCommitment

		case *TxoRCT:
			if txoMLP.CoinAddressType() != CoinAddressTypePublicKeyForRing {
				return false, fmt.Errorf("CoinbaseTxMLPVerify: the %d-th Txo is TxoRCT, but its coinAddressType is not CoinAddressTypePublicKeyForRing", j)
			}
			cmts[j] = txoInst.valueCommitment

		case *TxoSDN:
			if txoMLP.CoinAddressType() != CoinAddressTypePublicKeyHashForSingle {
				return false, fmt.Errorf("CoinbaseTxMLPVerify: the %d-th Txo is TxoSDN, but its coinAddressType is not CoinAddressTypePublicKeyHashForSingle", j)
			}
			if txoInst.value > V {
				return false, nil
			}

			voutPublic = voutPublic + txoInst.value

			if voutPublic > V {
				return false, nil
			}

		default:
			return false, fmt.Errorf("CoinbaseTxMLPVerify: the %d-th Txo is not TxoRCTPre, TxoRCT, or TxoSDN", j)
		}
	}

	if cbTx.vin < voutPublic {
		return false, nil
	}

	vL := cbTx.vin - voutPublic

	serializedCbTxCon, err := pp.SerializeCoinbaseTxMLP(cbTx, false)
	if err != nil {
		return false, err
	}

	return pp.verifyTxWitnessCbTx(serializedCbTxCon, vL, uint8(outForRing), cmts, cbTx.txWitness)
}

// todo:
func (pp *PublicParameter) TransferTxMLPGen(inputDescs []*TxInputDescMLP, outputDescs []*TxOutputDescMLP, fee uint64, txMemo []byte) (trTx *TransferTxMLP, err error) {
	//	check the well-formness of the inputs and outputs
	inputNum := len(inputDescs)
	outputNum := len(outputDescs)
	if inputNum == 0 || outputNum == 0 {
		return nil, errors.New("some information is empty")
	}

	if inputNum > pp.paramI {
		return nil, fmt.Errorf("%d inputs but max %d ", inputNum, pp.paramI)
	}
	if outputNum > pp.paramJ {
		return nil, fmt.Errorf("%d output but max %d ", outputNum, pp.paramJ)
	}

	V := uint64(1)<<pp.paramN - 1

	if fee > V {
		return nil, errors.New("the transaction fee is more than V")
	}

	//	check on the outputDesc is simple, so check it first
	outputTotal := fee
	apks := make([]*AddressPublicKey, outputNum)
	for i, outputDescItem := range outputDescs {
		if outputDescItem.value > V {
			return nil, errors.New("the value is more than max value")
		}
		outputTotal = outputTotal + outputDescItem.value
		if outputTotal > V {
			return nil, errors.New("the value is more than max value")
		}

		if outputDescItem.serializedAPk == nil || outputDescItem.serializedVPk == nil {
			return nil, errors.New("the address public key or value public key is nil")
		}
		apks[i], err = pp.DeserializeAddressPublicKey(outputDescItem.serializedAPk)
		if err != nil || apks[i] == nil {
			return nil, errors.New("the apk is not well-form")
		}
	}

	I := inputNum
	J := outputNum
	cmtrs_in := make([]*PolyCNTTVec, I)
	msgs_in := make([][]int64, I)

	inputTotal := uint64(0)
	asks := make([]*AddressSecretKey, inputNum)
	for i, inputDescItem := range inputDescs {
		if inputDescItem.value > V {
			return nil, errors.New("the value is more than max value")
		}
		inputTotal = inputTotal + inputDescItem.value
		if inputTotal > V {
			return nil, errors.New("the value is more than max value")
		}

		if len(inputDescItem.lgrTxoList) == 0 {
			return nil, errors.New("the input Txo Ring is empty")
		}

		if inputDescItem.sidx < 0 || int(inputDescItem.sidx) >= len(inputDescItem.lgrTxoList) {
			return nil, errors.New("the index is not suitable")
		}
		/*		if inputDescItem.lgrTxoList[inputDescItem.sidx].ask == nil || inputDescItem.sk == nil {
				return nil, errors.New("some information is empty")
			}*/
		if inputDescItem.lgrTxoList[inputDescItem.sidx].txo.AddressPublicKey == nil ||
			inputDescItem.lgrTxoList[inputDescItem.sidx].txo.ValueCommitment == nil ||
			len(inputDescItem.lgrTxoList[inputDescItem.sidx].txo.Vct) == 0 ||
			len(inputDescItem.lgrTxoList[inputDescItem.sidx].txo.CtKemSerialized) == 0 ||
			len(inputDescItem.serializedASksp) == 0 ||
			len(inputDescItem.serializedASksn) == 0 ||
			len(inputDescItem.serializedVPk) == 0 ||
			len(inputDescItem.serializedVSk) == 0 {
			return nil, errors.New("some information for inoutDescItem is empty")
		}
		asks[i] = &AddressSecretKey{}
		asks[i].AddressSecretKeySp, err = pp.deserializeAddressSecretKeySp(inputDescItem.serializedASksp)
		if err != nil {
			return nil, err
		}
		asks[i].AddressSecretKeySn, err = pp.deserializeAddressSecretKeySn(inputDescItem.serializedASksn)
		if err != nil || asks[i] == nil {
			return nil, err
		}

		if asks[i].checkMatchPublciKey(inputDescItem.lgrTxoList[inputDescItem.sidx].txo.AddressPublicKey, pp) == false {
			return nil, errors.New("the address secret key and corresponding public key does not match")
		}

		// run kem.decaps to get kappa
		kappa, err := pqringctxkem.Decaps(pp.paramKem, inputDescItem.lgrTxoList[inputDescItem.sidx].txo.CtKemSerialized, inputDescItem.serializedVSk)
		if err != nil {
			return nil, err
		}

		//	msgs_in[i] <-- inputDescItem.value
		msgs_in[i] = pp.intToBinary(inputDescItem.value)
		// then get cmtrs_in[i]
		cmtr_ploy, err := pp.expandValueCmtRandomness(kappa)
		if err != nil {
			return nil, err
		}
		cmtrs_in[i] = pp.NTTPolyCVec(cmtr_ploy)
		b := pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, cmtrs_in[i], pp.paramKC, pp.paramLC)
		c := pp.PolyCNTTAdd(
			pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[0], cmtrs_in[i], pp.paramLC),
			&PolyCNTT{msgs_in[i]})

		// and check the validity
		if !pp.PolyCNTTVecEqualCheck(b, inputDescItem.lgrTxoList[inputDescItem.sidx].txo.b) {
			return nil, errors.New("fail to receive some transaction output : the computed commitment is not equal to input")
		}

		if !pp.PolyCNTTEqualCheck(c, inputDescItem.lgrTxoList[inputDescItem.sidx].txo.c) {
			return nil, errors.New("fail to receive some transaction output : the computed commitment is not equal to input")
		}
	}

	if outputTotal != inputTotal {
		return nil, errors.New("the input value and output value should be equal")
	}

	rettrTx := &TransferTx{}
	rettrTx.Inputs = make([]*TrTxInput, I)
	rettrTx.OutputTxos = make([]*Txo, J)
	rettrTx.Fee = fee
	rettrTx.TxMemo = txMemo

	cmtrs_out := make([]*PolyCNTTVec, J)
	for j := 0; j < J; j++ {
		txo, cmtr, err := pp.txoGen(apks[j], outputDescs[j].serializedVPk, outputDescs[j].value)
		if err != nil {
			return nil, err
		}
		rettrTx.OutputTxos[j] = txo
		cmtrs_out[j] = cmtr
	}

	ma_ps := make([]*PolyANTT, I)
	cmt_ps := make([]*ValueCommitment, I)
	cmtr_ps := make([]*PolyCNTTVec, I)
	for i := 0; i < I; i++ {
		//m_r := pp.expandKIDR(inputDescs[i].lgrTxoList[inputDescs[i].sidx])
		m_r, err := pp.expandKIDR(inputDescs[i].lgrTxoList[inputDescs[i].sidx])
		if err != nil {
			return nil, err
		}

		ma_ps[i] = pp.PolyANTTAdd(asks[i].ma, m_r)
		sn, err := pp.ledgerTxoSerialNumberCompute(ma_ps[i])
		if err != nil {
			return nil, err
		}
		rettrTx.Inputs[i] = &TrTxInput{
			TxoList:      inputDescs[i].lgrTxoList,
			SerialNumber: sn,
		}

		cmtrp_poly, err := pp.sampleValueCmtRandomness()
		if err != nil {
			return nil, err
		}
		cmtr_ps[i] = pp.NTTPolyCVec(cmtrp_poly)
		cmt_ps[i] = &ValueCommitment{}
		cmt_ps[i].b = pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, cmtr_ps[i], pp.paramKC, pp.paramLC)
		cmt_ps[i].c = pp.PolyCNTTAdd(
			pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[0], cmtr_ps[i], pp.paramLC),
			&PolyCNTT{coeffs: msgs_in[i]},
		)
	}

	/*	rettrTx.TxWitness = &TrTxWitness{
		b_hat:      nil,
		c_hats:     nil,
		u_p:        nil,
		rpulpproof: nil,
		cmtps:      cmt_in_ips,
		elrsSigs:   nil,
	}*/

	msgTrTxCon, err := pp.SerializeTransferTx(rettrTx, false)
	if msgTrTxCon == nil || err != nil {
		return nil, errors.New("error in rettrTx.Serialize ")
	}

	elrsSigs := make([]*elrsSignature, I)
	for i := 0; i < I; i++ {
		asksp_ntt := pp.NTTPolyAVec(asks[i].AddressSecretKeySp.s)
		elrsSigs[i], err = pp.elrsSign(inputDescs[i].lgrTxoList, ma_ps[i], cmt_ps[i], msgTrTxCon,
			inputDescs[i].sidx, asksp_ntt, cmtrs_in[i], cmtr_ps[i])
		if err != nil {
			return nil, errors.New("fail to generate the extend linkable signature")
		}
	}

	n := I + J
	n2 := I + J + 2
	if I > 1 {
		n2 = I + J + 4
	}

	c_hats := make([]*PolyCNTT, n2)
	msg_hats := make([][]int64, n2)

	cmtrs := make([]*PolyCNTTVec, n)
	cmts := make([]*ValueCommitment, n)
	for i := 0; i < I; i++ {
		cmts[i] = cmt_ps[i]
		cmtrs[i] = cmtr_ps[i]
		msg_hats[i] = msgs_in[i]
	}
	for j := 0; j < J; j++ {
		cmts[I+j] = rettrTx.OutputTxos[j].ValueCommitment
		cmtrs[I+j] = cmtrs_out[j]
		msg_hats[I+j] = pp.intToBinary(outputDescs[j].value)
	}

	r_hat_poly, err := pp.sampleValueCmtRandomness()
	if err != nil {
		return nil, err
	}
	r_hat := pp.NTTPolyCVec(r_hat_poly)
	b_hat := pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, r_hat, pp.paramKC, pp.paramLC)
	for i := 0; i < n; i++ { // n = I+J
		c_hats[i] = pp.PolyCNTTAdd(
			pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[i+1], r_hat, pp.paramLC),
			&PolyCNTT{coeffs: msg_hats[i]},
		)
	}

	//	fee
	u := pp.intToBinary(fee)

	if I == 1 {
		//	n2 = n+2
		//	f is the carry vector, such that, m_1 = m_2+ ... + m_n + u
		//	f[0] = 0, and for i=1 to d-1,
		//	m_0[i-1] + 2 f[i] = m_1[i-1] + .. + m_{n-1}[i-1] + u[i-1] + f[i-1],
		//	m_0[d-1] 		  = m_1[d-1] + .. + m_{n-1}[d-1] + f[d-1],
		f := make([]int64, pp.paramDC)
		f[0] = 0
		for i := 1; i < pp.paramDC; i++ {
			tmp := int64(0)
			for j := 1; j < n; j++ {
				tmp = tmp + msg_hats[j][i-1]
			}

			//	-1 >> 1 = -1, -1/2=0
			//	In our design, the carry should be in [0, J] and (tmp + u[i-1] + f[i-1] - msg_hats[0][i-1]) >=0,
			//	which means >> 1 and /2 are equivalent.
			//	A negative carry bit will not pass the verification,
			//	and the case (tmp + u[i-1] + f[i-1] - msg_hats[0][i-1]) < 0 will not pass the verification.
			//	f[0] = 0 and other proved verification (msg[i] \in {0,1}, |f[i]| < q_c/8) are important.

			f[i] = (tmp + u[i-1] + f[i-1] - msg_hats[0][i-1]) >> 1
			//f[i] = (tmp + u[i-1] + f[i-1] - msg_hats[0][i-1]) / 2
		}
		msg_hats[n] = f
		c_hats[n] = pp.PolyCNTTAdd(
			pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[n+1], r_hat, pp.paramLC),
			&PolyCNTT{coeffs: msg_hats[n]},
		)

	trTxGenI1Restart:
		//e, err := pp.sampleUniformWithinEtaFv2()
		e, err := pp.randomDcIntegersInQcEtaF()
		if err != nil {
			return nil, err
		}
		msg_hats[n+1] = e
		c_hats[n+1] = pp.PolyCNTTAdd(
			pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[n+2], r_hat, pp.paramLC),
			&PolyCNTT{coeffs: msg_hats[n+1]},
		)

		//	todo_done 2022.04.03: check the scope of u_p in theory
		//	u_p = B f + e, where e \in [-eta_f, eta_f], with eta_f < q_c/16.
		//	As Bf should be bound by d_c J, so that |B f + e| < q_c/2, there should not modular reduction.
		betaF := pp.paramDC * (J + 1)
		boundF := pp.paramEtaF - int64(betaF)
		u_p := make([]int64, pp.paramDC)
		//u_p_temp := make([]int64, pp.paramDC) // todo_done 2022.04.03: make sure that (eta_f, d) will not make the value of u_p[i] over int32
		preMsg := pp.collectBytesForTransferTx(msgTrTxCon, b_hat, c_hats)
		seed_binM, err := Hash(preMsg)
		if err != nil {
			return nil, err
		}
		binM, err := expandBinaryMatrix(seed_binM, pp.paramDC, pp.paramDC)
		if err != nil {
			return nil, err
		}
		// compute B f + e and check the normal
		// up = B * f + e
		for i := 0; i < pp.paramDC; i++ {
			//u_p_temp[i] = e[i]
			u_p[i] = e[i]
			for j := 0; j < pp.paramDC; j++ {
				if (binM[i][j/8]>>(j%8))&1 == 1 {
					//u_p_temp[i] += f[j]
					u_p[i] += f[j]
				}
			}

			//infNorm := u_p_temp[i]
			infNorm := u_p[i]
			if infNorm < 0 {
				infNorm = -infNorm
			}

			if infNorm > boundF {
				goto trTxGenI1Restart
			}

			// u_p[i] = reduceInt64(u_p_temp[i], pp.paramQC) // todo_done: need to confirm. Do not need to modulo.
		}

		u_hats := make([][]int64, 3)
		u_hats[0] = u
		u_hats[1] = make([]int64, pp.paramDC)
		for i := 0; i < pp.paramDC; i++ {
			u_hats[1][i] = 0
		}
		u_hats[2] = u_p

		n1 := n
		rpulppi, pi_err := pp.rpulpProve(msgTrTxCon, cmts, cmtrs, uint8(n), b_hat, r_hat, c_hats, msg_hats, uint8(n2), uint8(n1), RpUlpTypeTrTx1, binM, uint8(I), uint8(J), 3, u_hats)

		if pi_err != nil {
			return nil, pi_err
		}

		rettrTx.TxWitness = &TrTxWitness{
			ma_ps,
			cmt_ps,
			elrsSigs,
			b_hat,
			c_hats,
			u_p,
			rpulppi,
		}
	} else {
		//	n2 = n+4
		msg_hats[n] = pp.intToBinary(inputTotal) //	the sum of input coins
		c_hats[n] = pp.PolyCNTTAdd(
			pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[n+1], r_hat, pp.paramLC),
			&PolyCNTT{coeffs: msg_hats[n]},
		)
		//	f1 is the carry vector, such that, m_0 + m_1+ ... + m_{I-1} = m_{n}
		//	f1[0] = 0, and for i=1 to d-1,
		//	m_0[i-1] + .. + m_{I-1}[i-1] + f1[i-1] = m_n[i-1] + 2 f[i] ,
		//	m_0[d-1] + .. + m_{I-1}[d-1] + f1[d-1] = m_n[d-1] ,
		f1 := make([]int64, pp.paramDC)
		f1[0] = 0
		for i := 1; i < pp.paramDC; i++ {
			tmp := int64(0)
			for j := 0; j < I; j++ {
				tmp = tmp + msg_hats[j][i-1]
			}

			//	-1 >> 1 = -1, -1/2=0
			//	In our design, the carry should be in [0, J] and (tmp + f1[i-1] - msg_hats[n][i-1]) >=0,
			//	which means >> 1 and /2 are equivalent.
			//	A negative carry bit will not pass the verification,
			//	and the case (tmp + f1[i-1] - msg_hats[n][i-1]) < 0 will not pass the verification.
			//	f[0] = 0 and other proved verification (msg[i] \in {0,1}, |f[i]| < q_c/8) are important.
			f1[i] = (tmp + f1[i-1] - msg_hats[n][i-1]) >> 1
			//f1[i] = (tmp + f1[i-1] - msg_hats[n][i-1]) / 2
		}
		msg_hats[n+1] = f1
		c_hats[n+1] = pp.PolyCNTTAdd(
			pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[n+2], r_hat, pp.paramLC),
			&PolyCNTT{coeffs: msg_hats[n+1]},
		)

		//	f2 is the carry vector, such that, m_I + m_{I+1}+ ... + m_{(I+J)-1} + u = m_{n}
		//	f2[0] = 0, and for i=1 to d-1,
		//	m_I[i-1] + .. + m_{I+J-1}[i-1] + u[i-1] + f2[i-1] = m_n[i-1] + 2 f[i] ,
		//	m_I[d-1] + .. + m_{I+J-1}[d-1] + u[d-1] + f2[d-1] = m_n[d-1] ,
		f2 := make([]int64, pp.paramDC)
		f2[0] = 0
		for i := 1; i < pp.paramDC; i++ {
			tmp := int64(0)
			for j := 0; j < J; j++ {
				tmp = tmp + msg_hats[I+j][i-1]
			}
			//	-1 >> 1 = -1, -1/2=0
			//	In our design, the carry should be in [0, J] and (tmp + u[i-1] + f2[i-1] - msg_hats[n][i-1]) >=0,
			//	which means >> 1 and /2 are equivalent.
			//	A negative carry bit will not pass the verification,
			//	and the case (tmp + u[i-1] + f2[i-1] - msg_hats[n][i-1]) < 0 will not pass the verification.
			//	f[0] = 0 and other proved verification (msg[i] \in {0,1}, |f[i]| < q_c/8) are important.

			f2[i] = (tmp + u[i-1] + f2[i-1] - msg_hats[n][i-1]) >> 1
			//f2[i] = (tmp + u[i-1] + f2[i-1] - msg_hats[n][i-1]) / 2
		}
		msg_hats[n+2] = f2
		c_hats[n+2] = pp.PolyCNTTAdd(
			pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[n+3], r_hat, pp.paramLC),
			&PolyCNTT{coeffs: msg_hats[n+2]},
		)
	trTxGenI2Restart:
		//e, err := pp.sampleUniformWithinEtaFv2()
		e, err := pp.randomDcIntegersInQcEtaF()
		if err != nil {
			return nil, err
		}
		msg_hats[n+3] = e
		c_hats[n+3] = pp.PolyCNTTAdd(
			pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[n+4], r_hat, pp.paramLC),
			&PolyCNTT{coeffs: msg_hats[n+3]},
		)

		// todo_done: (2022.04.03) check the scope of u_p in theory
		//	u_p = B f + e, where e \in [-eta_f, eta_f], with eta_f < q_c/16.
		//	As Bf should be bound by d_c J, so that |B f + e| < q_c/2, there should not modular reduction.
		betaF := pp.paramDC * (I + J + 1)
		boundF := pp.paramEtaF - int64(betaF)

		u_p := make([]int64, pp.paramDC)
		//u_p_temp := make([]int64, pp.paramDC) // todo_done: make sure that (eta_f, d) will not make the value of u_p[i] over int32
		preMsg := pp.collectBytesForTransferTx(msgTrTxCon, b_hat, c_hats)
		seed_binM, err := Hash(preMsg)
		if err != nil {
			return nil, err
		}
		binM, err := expandBinaryMatrix(seed_binM, pp.paramDC, 2*pp.paramDC)
		if err != nil {
			return nil, err
		}
		// compute B (f_1 || f_2) + e and check the normal
		for i := 0; i < pp.paramDC; i++ {
			//u_p_temp[i] = e[i]
			u_p[i] = e[i]
			for j := 0; j < pp.paramDC; j++ {
				//	u_p_temp[i] = u_p_temp[i] + int64(e[j])

				if (binM[i][j/8]>>(j%8))&1 == 1 {
					//u_p_temp[i] += f1[j]
					u_p[i] += f1[j]
				}
				if (binM[i][(pp.paramDC+j)/8]>>((pp.paramDC+j)%8))&1 == 1 {
					//u_p_temp[i] += f2[j]
					u_p[i] += f2[j]
				}
			}

			//infNorm := u_p_temp[i]
			infNorm := u_p[i]
			if infNorm < 0 {
				infNorm = -infNorm
			}

			if infNorm > boundF {
				goto trTxGenI2Restart
			}

			// u_p[i] = reduceInt64(u_p_temp[i], pp.paramQC) // todo_done: 2022.04.03 confirm whether need to reduce
		}

		u_hats := make([][]int64, 5)
		u_hats[0] = make([]int64, pp.paramDC)
		// todo_DONE: -u
		u_hats[1] = make([]int64, pp.paramDC)
		for i := 0; i < pp.paramDC; i++ {
			u_hats[1][i] = -u[i]
		}
		u_hats[2] = make([]int64, pp.paramDC)
		u_hats[3] = make([]int64, pp.paramDC)
		u_hats[4] = u_p
		for i := 0; i < pp.paramDC; i++ {
			u_hats[0][i] = 0
			u_hats[2][i] = 0
			u_hats[3][i] = 0
		}

		n1 := n + 1
		rpulppi, pi_err := pp.rpulpProve(msgTrTxCon, cmts, cmtrs, uint8(n), b_hat, r_hat, c_hats, msg_hats, uint8(n2), uint8(n1), RpUlpTypeTrTx2, binM, uint8(I), uint8(J), 5, u_hats)

		if pi_err != nil {
			return nil, pi_err
		}

		rettrTx.TxWitness = &TrTxWitness{
			ma_ps,
			cmt_ps,
			elrsSigs,
			b_hat,
			c_hats,
			u_p,
			rpulppi,
		}
	}
	return rettrTx, err
}

//	TxWitness		begin

func (pp *PublicParameter) GetCbTxWitnessSerializeSizeByDesc(coinAddressList [][]byte) (int, error) {
	if len(coinAddressList) == 0 {
		return 0, errors.New("GetCbTxWitnessSerializeSizeApprox: the input coinAddressList is empty")

	}

	outForRing := 0
	outForSingle := 0
	for i := 0; i < len(coinAddressList); i++ {
		coinAddressType, err := pp.ExtractCoinAddressTypeFromCoinAddress(coinAddressList[i])
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

	return pp.TxWitnessCbTxSerializeSize(uint8(outForRing)), nil
}

//	TxWitness		end

//	TxInput		begin

// GetNullSerialNumberMLP returns null-serial-number.
// reviewed on 2023.12.07.
func (pp *PublicParameter) GetNullSerialNumberMLP() []byte {
	snSize := pp.ledgerTxoSerialNumberMLPSerializeSize()
	nullSn := make([]byte, snSize)
	for i := 0; i < snSize; i++ {
		nullSn[i] = 0
	}
	return nullSn
}

// ledgerTxoSerialNumberMLPSerializeSize returns serial size of null-serial-number.
// reviewed on 2023.12.07.
func (pp *PublicParameter) ledgerTxoSerialNumberMLPSerializeSize() int {
	return HashOutputBytesLen
}

//	TxInput		end
