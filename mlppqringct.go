package pqringctx

import (
	"errors"
	"fmt"
	"github.com/cryptosuite/pqringctx/pqringctxkem"
)

// CoinbaseTxGenMLP generates a coinbase transaction.
// todo: review
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
			retCbTx.txos[j] = txoRCTPre
			cmts[j] = txoRCTPre.valueCommitment
			cmt_rs[j] = cmtr
			vRs[j] = txOutputDescMLP.value

		case CoinAddressTypePublicKeyForRing:
			txoRCT, cmtr, err := pp.txoRCTGen(txOutputDescMLP.coinAddress, txOutputDescMLP.serializedVPK, txOutputDescMLP.value)
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
			voutPublic += txOutputDescMLP.value

		default:
			return nil, fmt.Errorf("CoinbaseTxGenMLP: the %d -th coinAddresses of the input txOutputDescMLPs (%d) is not supported", j, coinAddressType)
		}
	}
	if vout != vin {
		return nil, fmt.Errorf("CoinbaseTxGenMLP: the output value (%d) and the input value (%d) are not equal", vout, vin)
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

	addressPublicKeyForRing, err := pp.deserializeAddressPublicKeyForRing(coinAddress)
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

	addressPublicKeyForRing, err := pp.deserializeAddressPublicKeyForRing(coinAddress[1:])

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

//	TxWitness		end
