package pqringctx

import (
	"errors"
	"fmt"
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
