package pqringctx

import (
	"errors"
	"fmt"
	"github.com/cryptosuite/pqringctx/pqringctxkem"
)

// CoinbaseTxGenMLP generates a coinbase transaction.
func (pp *PublicParameter) CoinbaseTxGenMLP(vin uint64, txOutputDescMLPs []*TxOutputDescMLP, txMemo []byte) (cbTx *CoinbaseTxMLP, err error) {
	V := uint64(1)<<pp.paramN - 1

	if vin > V {
		return nil, fmt.Errorf("CoinbaseTxGenMLP: vin (%d) is not in [0, V= %d]", vin, V)
	}

	if len(txOutputDescMLPs) == 0 || len(txOutputDescMLPs) > pp.paramJ+pp.paramJSingle {
		return nil, fmt.Errorf("CoinbaseTxGenMLP: the number of outputs is not in [1, %d]", pp.paramJ+pp.paramJSingle)
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
				return nil, fmt.Errorf("CoinbaseTxGenMLP: the coinAddresses for RingCT-Privacy should be at the fist successive positions, but the %d -th one is not", i)
			}
		} else if coinAddressType == CoinAddressTypePublicKeyHashForSingle {
			outForSingle += 1
		} else {
			return nil, fmt.Errorf("CoinbaseTxGenMLP: the %d -th coinAddresses of the input txOutputDescMLPs (%d) is not supported", i, coinAddressType)
		}
	}
	if outForRing > pp.paramJ {
		return nil, fmt.Errorf("CoinbaseTxGenMLP: the number of RingCT-Privacy coinAddresses in the input txOutputDescMLPs %d exceeds the allowd maxumim %d", outForRing, pp.paramJ)
	}

	if outForSingle > pp.paramJSingle {
		return nil, fmt.Errorf("CoinbaseTxGenMLP: the number of Pseudonym-Privacy coinAddresses in the input txOutputDescMLPs %d exceeds the allowd maxumim %d", outForSingle, pp.paramJSingle)
	}

	txCase := TxCaseCbTxI0C0
	if outForRing == 0 {
		txCase = TxCaseCbTxI0C0
	} else if outForRing == 1 {
		txCase = TxCaseCbTxI0C1
	} else {
		//	outForRing >= 2
		txCase = TxCaseCbTxI0Cn
	}

	// J := len(txOutputDescMLPs)

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
			return nil, fmt.Errorf("txOutputDescMLPs[%d].value (%d) is not in [0, %d]", j, txOutputDescMLP.value, V)
		}
		vout += txOutputDescMLP.value
		if vout > V {
			return nil, fmt.Errorf("the total output value is not in [0, %d]", V)
		}

		coinAddressType, err := pp.ExtractCoinAddressTypeFromCoinAddress(txOutputDescMLP.coinAddress)
		if err != nil {
			return nil, err
		}
		switch coinAddressType {
		case CoinAddressTypePublicKeyForRingPre:
			txoRCTPre, cmtr, err := pp.txoRCTPreGen(txOutputDescMLP.coinAddress, txOutputDescMLP.serializedVPK, txOutputDescMLP.value)
			if err != nil {
				return nil, err
			}
			cmt_rs[j] = cmtr
			cmts[j] = txoRCTPre.valueCommitment
			retCbTx.txos[j] = txoRCTPre
			vRs[j] = txOutputDescMLP.value

		case CoinAddressTypePublicKeyForRing:
			txoRCT, cmtr, err := pp.txoRCTGen(txOutputDescMLP.coinAddress, txOutputDescMLP.serializedVPK, txOutputDescMLP.value)
			if err != nil {
				return nil, err
			}
			cmt_rs[j] = cmtr
			cmts[j] = txoRCT.valueCommitment
			retCbTx.txos[j] = txoRCT
			vRs[j] = txOutputDescMLP.value

		case CoinAddressTypePublicKeyHashForSingle:
			txoSDN := pp.txoSDNGen(txOutputDescMLP.coinAddress, txOutputDescMLP.value)
			if err != nil {
				return nil, err
			}
			//cmt_rs[j] = cmtr
			//cmts[j] = txoRCT.valueCommitment
			voutPublic += txOutputDescMLP.value
			retCbTx.txos[j] = txoSDN

		default:
			return nil, fmt.Errorf("CoinbaseTxGenMLP: the %d -th coinAddresses of the input txOutputDescMLPs (%d) is not supported", j, coinAddressType)
		}
	}
	if vout != vin {
		return nil, fmt.Errorf("CoinbaseTxGenMLP: the output value (%d) and the input value (%d) are not equal", vout, vin)
	}
	vPublic := vin - voutPublic //	note that vout == vin above implies vPublic >= 0 here.

	//	TxWitness
	cbTxCon, err := pp.SerializeCoinbaseTxMLP(retCbTx, false)
	if err != nil {
		return nil, err
	}

	var txWitness TxWitnessMLP
	switch txCase {
	case TxCaseCbTxI0C0:
		// vPublic = 0
		txWitness, err = pp.genTxWitnessCbTxI0C0()
		if err != nil {
			return nil, err
		}
		retCbTx.txWitness = txWitness

	case TxCaseCbTxI0C1:
		// vPublic = cmt_0
		//	Note that outForRing = 1
		txWitness, err = pp.genTxWitnessCbTxI0C1(cbTxCon, vPublic, cmts[0], cmt_rs[0])
		if err != nil {
			return nil, err
		}
		retCbTx.txWitness = txWitness

	case TxCaseCbTxI0Cn:
		// vPublic = cmt_0 + ... + cmt_{outForRing}
		txWitness, err = pp.genTxWitnessCbTxI0Cn(cbTxCon, vPublic, cmts, cmt_rs, vRs)
		if err != nil {
			return nil, err
		}
		retCbTx.txWitness = txWitness
	}

	return retCbTx, nil
}

// TXO		begin
// txoRCTPreGen() returns a transaction output and the randomness used to generate the commitment.
// It is same as the txoGen in pqringct, with coinAddress be exactly the serializedAddressPublicKey.
// Note that the coinAddress should be serializedAddressPublicKeyForRing = serializedAddressPublicKey (in pqringct).
// Note that the vpk should be serializedValuePublicKey = serializedViewPublicKey (in pqringct).
func (pp *PublicParameter) txoRCTPreGen(coinAddress []byte, vpk []byte, vin uint64) (txo *TxoRCTPre, cmtr *PolyCNTTVec, err error) {
	//	got (C, kappa) from key encapsulate mechanism
	// Restore the KEM version
	CtKemSerialized, kappa, err := pqringctxkem.Encaps(pp.paramKem, vpk)
	if err != nil {
		return nil, nil, err
	}

	//	expand the kappa to PolyCVec with length Lc
	cmtr_poly, err := pp.expandValueCmtRandomness(kappa)
	if err != nil {
		return nil, nil, err
	}
	cmtr = pp.NTTPolyCVec(cmtr_poly)

	mtmp := pp.intToBinary(vin)
	m := &PolyCNTT{coeffs: mtmp}
	// [b c]^T = C*r + [0 m]^T
	cmt := &ValueCommitment{}
	cmt.b = pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, cmtr, pp.paramKC, pp.paramLC)
	cmt.c = pp.PolyCNTTAdd(
		pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[0], cmtr, pp.paramLC),
		m,
	)

	//	vc = m ^ sk
	//	todo_done: the vc should have length only N, to prevent the unused D-N bits of leaking information
	sk, err := pp.expandValuePadRandomness(kappa)
	if err != nil {
		return nil, nil, err
	}
	vpt, err := pp.encodeTxoValueToBytes(vin)
	if err != nil {
		return nil, nil, err
	}
	vct := make([]byte, pp.TxoValueBytesLen())
	for i := 0; i < pp.TxoValueBytesLen(); i++ {
		vct[i] = sk[i] ^ vpt[i]
	}
	// This is hard coded, based on the  value of N, and the algorithm encodeTxoValueToBytes().
	//	N = 51, encodeTxoValueToBytes() uses only the lowest 3 bits of 7-th byte.
	vct[6] = vct[6] & 0x07
	// This is to make the 56th~52th bit always to be 0, while keeping the 51th,50th, 49th bits to be their real value.
	//	By this way, we can avoid the leaking the corresponding bits of pad.

	//rettxo := &Txo{
	//	apk,
	//	cmt,
	//	vct,
	//	CtKemSerialized,
	//}

	addressPublicKeyForRing, err := pp.DeserializeAddressPublicKeyForRing(coinAddress)
	if err != nil {
		return nil, nil, err
	}
	retTxo := &TxoRCTPre{
		CoinAddressTypePublicKeyForRingPre,
		addressPublicKeyForRing,
		cmt,
		vct,
		CtKemSerialized,
	}

	return retTxo, cmtr, nil
}

// txoGenRCT() returns a transaction output and the randomness used to generate the commitment.
// Note that the coinAddress should be 1 byte (CoinAddressType) + serializedAddressPublicKeyForRing.
// Note that the vpk should be 1 byte (CoinAddressType) + serializedValuePublicKey.
func (pp *PublicParameter) txoRCTGen(coinAddress []byte, vpk []byte, vin uint64) (txo *TxoRCT, cmtr *PolyCNTTVec, err error) {

	//	got (C, kappa) from key encapsulate mechanism
	// Restore the KEM version
	CtKemSerialized, kappa, err := pqringctxkem.Encaps(pp.paramKem, vpk[1:])
	if err != nil {
		return nil, nil, err
	}

	//	expand the kappa to PolyCVec with length Lc
	cmtr_poly, err := pp.expandValueCmtRandomness(kappa)
	if err != nil {
		return nil, nil, err
	}
	cmtr = pp.NTTPolyCVec(cmtr_poly)

	mtmp := pp.intToBinary(vin)
	m := &PolyCNTT{coeffs: mtmp}
	// [b c]^T = C*r + [0 m]^T
	cmt := &ValueCommitment{}
	cmt.b = pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, cmtr, pp.paramKC, pp.paramLC)
	cmt.c = pp.PolyCNTTAdd(
		pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[0], cmtr, pp.paramLC),
		m,
	)

	//	vc = m ^ sk
	//	todo_done: the vc should have length only N, to prevent the unused D-N bits of leaking information
	sk, err := pp.expandValuePadRandomness(kappa)
	if err != nil {
		return nil, nil, err
	}
	vpt, err := pp.encodeTxoValueToBytes(vin)
	if err != nil {
		return nil, nil, err
	}
	vct := make([]byte, pp.TxoValueBytesLen())
	for i := 0; i < pp.TxoValueBytesLen(); i++ {
		vct[i] = sk[i] ^ vpt[i]
	}
	// This is hard coded, based on the  value of N, and the algorithm encodeTxoValueToBytes().
	//	N = 51, encodeTxoValueToBytes() uses only the lowest 3 bits of 7-th byte.
	vct[6] = vct[6] & 0x07
	// This is to make the 56th~52th bit always to be 0, while keeping the 51th,50th, 49th bits to be their real value.
	//	By this way, we can avoid the leaking the corresponding bits of pad.

	//rettxo := &Txo{
	//	apk,
	//	cmt,
	//	vct,
	//	CtKemSerialized,
	//}

	addressPublicKeyForRing, err := pp.DeserializeAddressPublicKeyForRing(coinAddress[1:])

	retTxo := &TxoRCT{
		CoinAddressTypePublicKeyForRing,
		addressPublicKeyForRing,
		cmt,
		vct,
		CtKemSerialized,
	}

	return retTxo, cmtr, nil
}

// txoSDNGen() returns a transaction output and the randomness used to generate the commitment.
// Note that coinAddress should be 1 byte (CoinAddressType) + AddressPublicKeyForSingleHash.
func (pp *PublicParameter) txoSDNGen(coinAddress []byte, vin uint64) (txo *TxoSDN) {
	return &TxoSDN{
		CoinAddressTypePublicKeyHashForSingle,
		coinAddress[1:],
		vin,
	}
}

//	TXO		end

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

	//	Note that coinbaseTx's witness contains only bpf.
	if outForRing == 0 {
		return pp.TxWitnessCbTxI0C0SerializeSize(), nil
	} else if outForRing == 1 {
		return pp.TxWitnessCbTxI0C1SerializeSize(), nil
	} else {
		// outForRing > 1
		return pp.TxWitnessCbTxI0CnSerializeSize(uint8(outForRing)), nil // Note that outForRing < pp.GetTxOutputMaxNumForRing(), should be in the scope of uint8.
	}
}

// genTxWitnessCbTxI0C0 generates TxWitnessCbTxI0C0, which is for the coinbaseTx where there are no RingCT-privacy coins on the output side.
func (pp *PublicParameter) genTxWitnessCbTxI0C0() (*TxWitnessCbTxI0C0, error) {
	return &TxWitnessCbTxI0C0{
		txCase: TxCaseCbTxI0C0,
	}, nil
}

func (pp *PublicParameter) genTxWitnessCbTxI0C1(cbTxCon []byte, vPub uint64, cmt *ValueCommitment, cmtr *PolyCNTTVec) (*TxWitnessCbTxI0C1, error) {
	bpf, err := pp.genBalanceProofL0R1(cbTxCon, vPub, cmt, cmtr)
	if err != nil {
		return nil, err
	}

	return &TxWitnessCbTxI0C1{
		txCase:       TxCaseCbTxI0C1,
		balanceProof: bpf,
	}, nil
}

func (pp *PublicParameter) genTxWitnessCbTxI0Cn(cbTxCon []byte, vL uint64, cmtRs []*ValueCommitment, cmtrRs []*PolyCNTTVec, vRs []uint64) (*TxWitnessCbTxI0Cn, error) {
	bpf, err := pp.genBalanceProofL0Rn(cbTxCon, vL, cmtRs, cmtrRs, vRs)
	if err != nil {
		return nil, err
	}

	return &TxWitnessCbTxI0Cn{
		txCase:       TxCaseCbTxI0Cn,
		outForRing:   uint8(len(cmtRs)),
		balanceProof: bpf,
	}, nil
}

// genBalanceProofL0R1 generates BalanceProofL0R1, proving vL = cmt.
// This is almost identical to J == 1 case of pqringct.coinbaseTxGen.
func (pp *PublicParameter) genBalanceProofL0R1(preMsg []byte, vL uint64, cmt *ValueCommitment, cmtr *PolyCNTTVec) (*balanceProofL0R1, error) {
	// random from S_etaC^lc
	ys := make([]*PolyCNTTVec, pp.paramK)
	// w^t = B * y^t
	ws := make([]*PolyCNTTVec, pp.paramK)
	// delta = <h,y^t>
	deltas := make([]*PolyCNTT, pp.paramK)
	// z^t = y^t + sigma^t(c) * r_(out,j), r_(out,j) is from txoGen, in there, r_(out,j) is cmt_rs_j
	zs_ntt := make([]*PolyCNTTVec, pp.paramK)
	zs := make([]*PolyCVec, pp.paramK)

balanceProofL0R1Restart:
	for t := 0; t < pp.paramK; t++ {
		// random y
		tmpY, err := pp.sampleMaskingVecC()
		if err != nil {
			return nil, err
		}
		ys[t] = pp.NTTPolyCVec(tmpY)

		ws[t] = pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, ys[t], pp.paramKC, pp.paramLC)
		deltas[t] = pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[0], ys[t], pp.paramLC)
	}

	seedMsg, err := pp.collectBytesForBalanceProofL0R1(preMsg, vL, cmt, ws, deltas)
	if err != nil {
		return nil, err
	}

	chseed, err := Hash(seedMsg)
	if err != nil {
		return nil, err
	}

	boundC := pp.paramEtaC - int64(pp.paramBetaC)
	chtmp, err := pp.expandChallengeC(chseed)
	if err != nil {
		return nil, err
	}
	ch := pp.NTTPolyC(chtmp)
	for t := 0; t < pp.paramK; t++ {
		zs_ntt[t] = pp.PolyCNTTVecAdd(
			ys[t],
			pp.PolyCNTTVecScaleMul(
				pp.sigmaPowerPolyCNTT(ch, t),
				cmtr,
				pp.paramLC,
			),
			pp.paramLC,
		)
		// check the norm
		zs[t] = pp.NTTInvPolyCVec(zs_ntt[t])
		if zs[t].infNorm() > boundC {
			goto balanceProofL0R1Restart
		}
	}

	return &balanceProofL0R1{
		balanceProofCase: BalanceProofCaseL0R1,
		leftCommNum:      0,
		rightCommNum:     1,
		chseed:           chseed,
		zs:               zs,
	}, nil
}

// genBalanceProofL0R2 generates BalanceProofL0R2, proving vL = cmts[0] + ... + cmts[nR-1].
// This is almost identical to J >= 2 case of pqringct.coinbaseTxGen.
// Note that this prove algorithm does not check the sanity of the inputs, since we need the corresponding verify algorithm to guarantee the security.
func (pp *PublicParameter) genBalanceProofL0Rn(preMsg []byte, vL uint64, cmtRs []*ValueCommitment, cmtrRs []*PolyCNTTVec, vRs []uint64) (*balanceProofLmRn, error) {

	nR := len(cmtRs)

	n := nR
	n2 := n + 2

	if n != len(cmtrRs) || n != len(vRs) {
		return nil, errors.New("genBalanceProofL0Rn: The input cmtRs, cmtrRs, vRs should have the same length")
	}

	if n > pp.paramJ {
		// Note that pp.paramI == pp.paramI
		return nil, fmt.Errorf("genBalanceProofL0Rn: the number of cmtRs (%d) is not in [1, %d]", n, pp.paramJ)
	}

	c_hats := make([]*PolyCNTT, n2)

	msg_hats := make([][]int64, n2)

	u_hats := make([][]int64, 3)

	u := pp.intToBinary(vL)

	// msg_hats[0], ..., msg_hats[n-1]
	for j := 0; j < n; j++ {
		msg_hats[j] = pp.intToBinary(vRs[j])
	}

	// msg_hats[n] := f
	// f is the carry vector for m_0 + m_1 + ... + m_{n-1}, in particular,
	// f[0] = (m_0[0] + ... + m_{n-1}[0]       )/2
	// f[1] = (m_0[1] + ... + m_{n-1}[1] + f[0])/2
	// ...
	// f[t] = (m_0[t] + ... + m_{n-1}[t] + f[t-1])/2
	// ...
	// f[d-1] = (m_0[d-1] + ... + m_{n-1}[d-1] + f[d-2])/2

	// that is,
	// f[0] = (m_0[0] + ... + m_{n-1}[0]         )/2
	// for t = 1, ..., d-1
	// f[t] = (m_0[t] + ... + m_{n-1}[t] + f[t-1])/2
	f := make([]int64, pp.paramDC)

	// f[0]
	tmp := int64(0)
	for j := 0; j < n; j++ {
		tmp = tmp + msg_hats[j][0]
	}
	f[0] = tmp >> 1

	// f[1], ..., f[n-2], f[d-1]
	for t := 1; t < pp.paramDC; t++ {
		tmp = int64(0)
		for j := 0; j < n; j++ {
			tmp = tmp + msg_hats[j][t]
		}
		f[t] = (tmp + f[t-1]) >> 1
	}

	msg_hats[n] = f

	////	f is the carry vector, such that, u = m_0 + m_1 + ... + m_{n-1}
	////	f[0] = 0, and for i=1 to d-1,
	////	m_0[i-1]+ ... + m_{J-1}[i-1] + f[i-1] = u[i-1] + 2 f[i],
	////	m_0[i-1]+ ... + m_{J-1}[i-1] + f[i-1] = u[i-1]
	//f := make([]int64, pp.paramDC)
	//f[0] = 0
	//for i := 1; i < pp.paramDC; i++ {
	//	tmp := int64(0)
	//	for j := 0; j < J; j++ {
	//		tmp = tmp + msg_hats[j][i-1]
	//	}
	//
	//	//	-1 >> 1 = -1, -1/2=0
	//	//	In our design, the carry should be in [0, J] and (tmp + f[i-1] - u[i-1]) >=0,
	//	//	which means >> 1 and /2 are equivalent.
	//	//	A negative carry bit will not pass the verification,
	//	//	and the case (tmp + f[i-1] - u[i-1]) < 0 will not pass the verification.
	//	//	f[0] = 0 and other proved verification (msg[i] \in {0,1}, |f[i]| < q_c/8) are important.
	//	f[i] = (tmp + f[i-1] - u[i-1]) >> 1
	//	// f[i] = (tmp + f[i-1] - u[i-1]) / 2
	//}
	//msg_hats[J] = f

	r_hat_poly, err := pp.sampleValueCmtRandomness()
	if err != nil {
		return nil, err
	}
	r_hat := pp.NTTPolyCVec(r_hat_poly)

	// b_hat =B * r_hat
	b_hat := pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, r_hat, pp.paramKC, pp.paramLC)

	//	c_hats[0]~c_hats[n-1], c_hats[n] (for f)
	for i := 0; i < n+1; i++ {
		msgNTTi, err := pp.NewPolyCNTTFromCoeffs(msg_hats[i])
		if err != nil {
			return nil, err
		}
		c_hats[i] = pp.PolyCNTTAdd(
			pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[i+1], r_hat, pp.paramLC),
			msgNTTi,
			//&PolyCNTT{coeffs: msg_hats[i]},
		)
	}

balanceProofL0RnRestart:
	//e := make([]int64, pp.paramDC)
	e, err := pp.randomDcIntegersInQcEtaF()
	if err != nil {
		return nil, err
	}
	msg_hats[n+1] = e

	// c_hats[n+1] (for e)
	msgNTTe, err := pp.NewPolyCNTTFromCoeffs(msg_hats[n+1])
	if err != nil {
		return nil, err
	}
	c_hats[n+1] = pp.PolyCNTTAdd(
		pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[n+2], r_hat, pp.paramLC),
		//&PolyCNTT{coeffs: msg_hats[n+1]},
		msgNTTe,
	)

	////	todo_done 2022.04.03: check the scope of u_p in theory
	////	u_p = B f + e, where e \in [-eta_f, eta_f], with eta_f < q_c/16.
	////	As Bf should be bound by d_c J, so that |B f + e| < q_c/2, there should not modular reduction.
	//betaF := pp.paramDC * J
	//	2023.12.1 Using the accurate bound
	betaF := (pp.paramN - 1) * (n - 1)
	boundF := pp.paramEtaF - int64(betaF)

	u_p := make([]int64, pp.paramDC)
	//u_p_tmp := make([]int64, pp.paramDC)

	seedMsg, err := pp.collectBytesForBalanceProofL0Rn(preMsg, vL, cmtRs, b_hat, c_hats)
	if err != nil {
		return nil, err
	}

	seed_binM, err := Hash(seedMsg) // todo_DONE: compute the seed using hash function on (b_hat, c_hats).

	if err != nil {
		return nil, err
	}
	binM, err := expandBinaryMatrix(seed_binM, pp.paramDC, pp.paramDC)
	if err != nil {
		return nil, err
	}
	// compute B f + e and check the normal
	for i := 0; i < pp.paramDC; i++ {
		//u_p_tmp[i] = e[i]
		u_p[i] = e[i]
		for j := 0; j < pp.paramDC; j++ {
			if (binM[i][j/8]>>(j%8))&1 == 1 {
				// u_p_tmp[i] = u_p_tmp[i] + f[j]
				u_p[i] = u_p[i] + f[j]
			}
		}

		//infNorm := u_p_tmp[i]
		infNorm := u_p[i]
		if infNorm < 0 {
			infNorm = -infNorm
		}
		if infNorm > boundF {
			goto balanceProofL0RnRestart
		}

		//			u_p[i] = reduceInt64(u_p_tmp[i], pp.paramQC) // todo_done: 202203 Do need reduce? no.
	}

	u_hats[0] = u
	u_hats[1] = make([]int64, pp.paramDC)
	for i := 0; i < pp.paramDC; i++ {
		u_hats[1][i] = 0
	}
	u_hats[2] = u_p

	n1 := n
	rprlppi, pi_err := pp.rpulpProveMLP(preMsg, cmtRs, cmtrRs, uint8(n), b_hat, r_hat, c_hats, msg_hats, uint8(n2), uint8(n1), RpUlpTypeL0Rn, binM, 0, uint8(nR), 3, u_hats)

	if pi_err != nil {
		return nil, pi_err
	}

	return &balanceProofLmRn{
		balanceProofCase: BalanceProofCaseLmRn,
		leftCommNum:      0,
		rightCommNum:     uint8(nR), // Note that nR has been checked previously, being smaller than paramJ
		// bpf
		b_hat:      b_hat,
		c_hats:     c_hats,
		u_p:        u_p,
		rpulpproof: rprlppi,
	}, nil
}

// collectBytesForTxWitnessCbTxI0C1 collect bytes for genTxWitnessCbTxI0C1() and verifyTxWitnessCbTxI0C1().
//
//	developed based on collectBytesForCoinbaseTxJ1()
func (pp *PublicParameter) collectBytesForBalanceProofL0R1(preMsg []byte, vL uint64, cmt *ValueCommitment, ws []*PolyCNTTVec, deltas []*PolyCNTT) ([]byte, error) {
	length := len(preMsg) + 8 + pp.ValueCommitmentSerializeSize() +
		pp.paramK*(pp.paramKC+1)*pp.paramDC*8
	rst := make([]byte, 0, length)

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

	// preMsg
	rst = append(rst, preMsg...)

	// vL
	rst = append(rst, byte(vL>>0))
	rst = append(rst, byte(vL>>8))
	rst = append(rst, byte(vL>>16))
	rst = append(rst, byte(vL>>24))
	rst = append(rst, byte(vL>>32))
	rst = append(rst, byte(vL>>40))
	rst = append(rst, byte(vL>>48))
	rst = append(rst, byte(vL>>56))

	// cmt
	serializedCmt, err := pp.SerializeValueCommitment(cmt)
	if err != nil {
		return nil, err
	}
	rst = append(rst, serializedCmt...)

	// ws []*PolyCNTTVec
	for i := 0; i < len(ws); i++ {
		for j := 0; j < len(ws[i].polyCNTTs); j++ {
			appendPolyCNTTToBytes(ws[i].polyCNTTs[i])
		}
	}

	// deltas []*PolyCNTT
	for i := 0; i < len(deltas); i++ {
		appendPolyCNTTToBytes(deltas[i])
	}

	return rst, nil
}

// collectBytesForCoinbaseTxJ2 is an auxiliary function for CoinbaseTxGen and CoinbaseTxVerify to collect some information into a byte slice
//
//	developed based on collectBytesForCoinbaseTxJ2()
func (pp *PublicParameter) collectBytesForBalanceProofL0Rn(preMsg []byte, vL uint64, cmts []*ValueCommitment, b_hat *PolyCNTTVec, c_hats []*PolyCNTT) ([]byte, error) {

	length := len(preMsg) + 8 + pp.ValueCommitmentSerializeSize()*len(cmts) +
		len(b_hat.polyCNTTs)*pp.paramDC*8 + len(c_hats)*pp.paramDC*8

	rst := make([]byte, 0, length)

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

	// preMsg
	rst = append(rst, preMsg...)

	// vL
	rst = append(rst, byte(vL>>0))
	rst = append(rst, byte(vL>>8))
	rst = append(rst, byte(vL>>16))
	rst = append(rst, byte(vL>>24))
	rst = append(rst, byte(vL>>32))
	rst = append(rst, byte(vL>>40))
	rst = append(rst, byte(vL>>48))
	rst = append(rst, byte(vL>>56))

	// cmts
	for i := 0; i < len(cmts); i++ {
		serializedCmt, err := pp.SerializeValueCommitment(cmts[i])
		if err != nil {
			return nil, err
		}
		rst = append(rst, serializedCmt...)
	}

	// b_hat
	for i := 0; i < len(b_hat.polyCNTTs); i++ {
		appendPolyCNTTToBytes(b_hat.polyCNTTs[i])
	}

	// c_hats
	for i := 0; i < len(c_hats); i++ {
		appendPolyCNTTToBytes(c_hats[i])
	}

	return rst, nil
}

//	TxWitness		end
