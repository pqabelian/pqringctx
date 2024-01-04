package pqringctx

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
)

// CoinbaseTxMLPGen generates a coinbase transaction.
// reviewed on 2023.12.07
// reviewed on 2023.12.19
// reviewed on 2023.12.20
func (pp *PublicParameter) CoinbaseTxMLPGen(vin uint64, txOutputDescMLPs []*TxOutputDescMLP, txMemo []byte) (*CoinbaseTxMLP, error) {
	V := uint64(1)<<pp.paramN - 1

	if vin > V {
		return nil, fmt.Errorf("CoinbaseTxMLPGen: vin (%d) is not in [0, V= %d]", vin, V)
	}

	if len(txOutputDescMLPs) == 0 || len(txOutputDescMLPs) > int(pp.paramJ)+int(pp.paramJSingle) {
		return nil, fmt.Errorf("CoinbaseTxMLPGen: the number of outputs (%d) is not in [1, %d]", len(txOutputDescMLPs), int(pp.paramJ)+int(pp.paramJSingle))
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
	if outForRing > int(pp.paramJ) {
		return nil, fmt.Errorf("CoinbaseTxMLPGen: the number of RingCT-Privacy coinAddresses in the input txOutputDescMLPs %d exceeds the allowd maxumim %d", outForRing, pp.paramJ)
	}

	if outForSingle > int(pp.paramJSingle) {
		return nil, fmt.Errorf("CoinbaseTxMLPGen: the number of Pseudonym-Privacy coinAddresses in the input txOutputDescMLPs %d exceeds the allowd maxumim %d", outForSingle, pp.paramJSingle)
	}

	retCbTx := &CoinbaseTxMLP{}
	retCbTx.vin = vin
	retCbTx.txos = make([]TxoMLP, len(txOutputDescMLPs))
	retCbTx.txMemo = txMemo

	cmts := make([]*ValueCommitment, outForRing)
	cmtrs := make([]*PolyCNTTVec, outForRing)
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
			cmtrs[j] = cmtr
			vRs[j] = txOutputDescMLP.value

		case CoinAddressTypePublicKeyForRing:
			txoRCT, cmtr, err := pp.txoRCTGen(txOutputDescMLP.coinAddress, txOutputDescMLP.coinValuePublicKey, txOutputDescMLP.value)
			if err != nil {
				return nil, err
			}
			retCbTx.txos[j] = txoRCT
			cmts[j] = txoRCT.valueCommitment
			cmtrs[j] = cmtr
			vRs[j] = txOutputDescMLP.value

		case CoinAddressTypePublicKeyHashForSingle:
			txoSDN, err := pp.txoSDNGen(txOutputDescMLP.coinAddress, txOutputDescMLP.value)
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

	txCase, balanceProof, err := pp.genBalanceProofCbTx(serializedCbTxCon, vL, uint8(outForRing), cmts, cmtrs, vRs)
	if err != nil {
		return nil, err
	}
	retCbTx.txWitness = &TxWitnessCbTx{
		txCase:       txCase,
		vL:           vL,
		outForRing:   uint8(outForRing),
		outForSingle: uint8(outForSingle),
		balanceProof: balanceProof,
	}

	return retCbTx, nil
}

// CoinbaseTxMLPVerify verifies the input CoinbaseTxMLP.
// reviewed on 2023.12.20
func (pp *PublicParameter) CoinbaseTxMLPVerify(cbTx *CoinbaseTxMLP) (bool, error) {
	if cbTx == nil || len(cbTx.txos) == 0 || cbTx.txWitness == nil {
		return false, nil
	}

	V := uint64(1)<<pp.paramN - 1

	if cbTx.vin > V {
		return false, nil
	}

	//	As the following checks will use cbTx.txWitness,
	//	here we first conduct checks on cbTx.txWitness.
	if cbTx.txWitness.vL != cbTx.vin {
		return false, nil
	}

	outputNum := len(cbTx.txos)
	if cbTx.txWitness.outForRing > pp.paramJ || cbTx.txWitness.outForSingle > pp.paramJSingle {
		return false, nil
	}

	if int(cbTx.txWitness.outForRing)+int(cbTx.txWitness.outForSingle) != outputNum {
		return false, nil
	}

	if cbTx.txWitness.balanceProof == nil {
		return false, nil
	}

	//	txos
	vOutPublic := uint64(0)
	cmts_out := make([]*ValueCommitment, cbTx.txWitness.outForRing)
	for j := 0; j < outputNum; j++ {
		txo := cbTx.txos[j]
		coinAddressType := txo.CoinAddressType()

		if j < int(cbTx.txWitness.outForRing) {
			//	outForRing
			if coinAddressType != CoinAddressTypePublicKeyForRingPre && coinAddressType != CoinAddressTypePublicKeyForRing {
				return false, fmt.Errorf("CoinbaseTxMLPVerify: the fisrt %d txo should have RingCT-privacy, but %d-th does not", cbTx.txWitness.outForRing, j)
			}
			switch txoInst := txo.(type) {
			case *TxoRCTPre:
				if txoInst.coinAddressType != CoinAddressTypePublicKeyForRingPre {
					return false, fmt.Errorf("CoinbaseTxMLPVerify: the %d -th txo is TxoRCTPre, but the coinAddressType(%d) is not CoinAddressTypePublicKeyForRingPre", j, coinAddressType)
				}
				cmts_out[j] = txoInst.valueCommitment

			case *TxoRCT:
				if txoInst.coinAddressType != CoinAddressTypePublicKeyForRing {
					return false, fmt.Errorf("CoinbaseTxMLPVerify: the %d -th txo is TxoRCT, but the coinAddressType(%d) is not CoinAddressTypePublicKeyForRing", j, coinAddressType)
				}
				cmts_out[j] = txoInst.valueCommitment

			default:
				//	just assert
				return false, fmt.Errorf("CoinbaseTxMLPVerify: This should not happen, where the %d -th txo is not TxoRCTPre or TxoRCT", j)
			}

		} else {
			//	outForSingle
			if coinAddressType != CoinAddressTypePublicKeyHashForSingle {
				return false, fmt.Errorf("CoinbaseTxMLPVerify: the %d-th txo should have Pseudonym-privacy, but it does not", j)
			}
			switch txoInst := txo.(type) {
			case *TxoSDN:
				if txoInst.value > V {
					return false, nil
				}
				vOutPublic += txoInst.value
				if vOutPublic > V {
					return false, nil
				}

			default:
				//	just assert
				return false, fmt.Errorf("CoinbaseTxMLPVerify: This should not happen, where the %d -th txo is not TxoSDN", j)
			}
		}
	}

	if cbTx.vin < vOutPublic {
		return false, nil
	}

	vL := cbTx.vin - vOutPublic
	if cbTx.txWitness.vL != vL {
		return false, nil
	}

	serializedCbTxCon, err := pp.SerializeCoinbaseTxMLP(cbTx, false)
	if err != nil {
		return false, err
	}

	//	verify the witness
	return pp.verifyBalanceProofCbTx(serializedCbTxCon, cbTx.txWitness.vL, cbTx.txWitness.outForRing, cmts_out, cbTx.txWitness.txCase, cbTx.txWitness.balanceProof)
}

// TransferTxMLPGen generates TransferTxMLP.
// reviewed 2023.12.19
// todo: review pp.CoinValueKeyVerify
func (pp *PublicParameter) TransferTxMLPGen(txInputDescs []*TxInputDescMLP, txOutputDescs []*TxOutputDescMLP, fee uint64, txMemo []byte) (*TransferTxMLP, error) {

	//	check the well-form of the inputs and outputs
	inputNum := len(txInputDescs)
	outputNum := len(txOutputDescs)
	if inputNum == 0 || outputNum == 0 {
		return nil, fmt.Errorf("TransferTxMLPGen: neither txInputDescs or txOutputDescs could be empty")
	}

	V := uint64(1)<<pp.paramN - 1

	//	check the fee is simple, check it first
	if fee > V {
		return nil, fmt.Errorf("TransferTxMLPGen: the transaction fee (%d) is not in the scope[0, V (%d)]", fee, V)
	}

	//	check on the txOutputDescs
	outForRing := 0
	outForSingle := 0
	vOutTotal := fee
	vOutPublic := fee
	for j := 0; j < outputNum; j++ {
		txOutputDescItem := txOutputDescs[j]
		if txOutputDescItem.value > V {
			return nil, fmt.Errorf("TransferTxMLPGen: txOutputDescs[%d].value (%d) is not in the scope [0,V(%d)]", j, txOutputDescItem.value, V)
		}
		vOutTotal += txOutputDescItem.value
		if vOutTotal > V {
			return nil, fmt.Errorf("TransferTxMLPGen: the vOutTotal of the first %d txOutputDescs[].value, say %d, exceeds V(%d)", j+1, vOutTotal, V)
		}

		coinAddressType, err := pp.ExtractCoinAddressTypeFromCoinAddress(txOutputDescItem.coinAddress)
		if err != nil {
			return nil, err
		}
		if coinAddressType == CoinAddressTypePublicKeyForRingPre || coinAddressType == CoinAddressTypePublicKeyForRing {
			if j == outForRing {
				outForRing += 1
			} else {
				//	The coinAddresses for RingCT-Privacy output should be at the fist successive positions.
				return nil, fmt.Errorf("TransferTxMLPGen: on the output side, the coinAddresses for RingCT-Privacy should be at the fist successive positions, but the %d -th one is not", j)
			}

			if len(txOutputDescItem.coinValuePublicKey) == 0 {
				// The coinValuePublicKey for  RingCT-Privacy output could not be nil.
				return nil, fmt.Errorf("TransferTxMLPGen: txOutputDescs[%d].coinAddress has coinAddressType=%d, but txOutputDescs[%d].coinValuePublicKey is nil/empty", j, coinAddressType, j)
			}

		} else if coinAddressType == CoinAddressTypePublicKeyHashForSingle {
			outForSingle += 1
			vOutPublic += txOutputDescItem.value

			// skip the check on coinValuePublicKey, to allow the caller uses dummy one for some reason, e.g., safety.

		} else {
			return nil, fmt.Errorf("TransferTxMLPGen: txOutputDescs[%d].coinAddress's coinAddressType(%d) is not supported", j, coinAddressType)
		}
	}

	if outForRing > int(pp.paramJ) {
		return nil, fmt.Errorf("TransferTxMLPGen: outForRing (%d) exceeds the allowed maximum value (%d)", outForRing, pp.paramJ)
	}
	if outForSingle > int(pp.paramJSingle) {
		return nil, fmt.Errorf("TransferTxMLPGen: outForSingle (%d) exceeds the the allowed maximum value (%d)", outForSingle, pp.paramJSingle)
	}

	// check the txInputDescss
	inForRing := 0
	inForSingle := 0
	inForSingleDistinct := 0
	cmtrs_in := make([]*PolyCNTTVec, 0, inputNum)                   // This is used to collect the cmtr for the coin-to-spend in inForRing.
	coinAddressForSingleDistinctList := make([][]byte, 0, inputNum) // This is used to collect the set of distinct coinAddress for the coin-to-spend in outForSingle.
	coinAddressSpendSecretKeyMap := make(map[string][]byte)         // This is used to map the (distinct) coinAddress for the coin-to-spend in outForSingle to the corresponding SpendSecretKey.
	vInTotal := uint64(0)
	vInPublic := uint64(0)
	lgrTxoIdsToSpendMap := make(map[string]int) // There should not be double spending in one transaction.
	for i := 0; i < inputNum; i++ {
		txInputDescItem := txInputDescs[i]

		//	check the value
		if txInputDescItem.value > V {
			return nil, fmt.Errorf("TransferTxMLPGen: txInputDescs[%d].value (%d) is not in the scope [0, V(%d)]", i, txInputDescItem.value, V)
		}
		vInTotal += txInputDescItem.value
		if vInTotal > V {
			return nil, fmt.Errorf("TransferTxMLPGen: the vInTotal of the first %d txInputDescs[].value, say %d, exceeds V (%d)", i+1, vInTotal, V)
		}

		//	check the sidx
		if int(txInputDescItem.sidx) >= len(txInputDescItem.lgrTxoList) {
			return nil, fmt.Errorf("TransferTxMLPGen: txInputDescs[%d].sidx is %d, while the length of txInputDescs[%d].lgrTxoList is %d", i, txInputDescItem.sidx, i, len(txInputDescItem.lgrTxoList))
		}

		lgrTxoToSpend := txInputDescItem.lgrTxoList[txInputDescItem.sidx]
		if lgrTxoToSpend == nil || len(lgrTxoToSpend.id) == 0 || lgrTxoToSpend.txo == nil {
			return nil, fmt.Errorf("TransferTxMLPGen: the coin to spend, say txInputDescs[%d].lgrTxoList[%d] has nil/empty id or nil txo", i, txInputDescItem.sidx)
		}

		//	check double-spending among the inputs
		idStringToSpend := hex.EncodeToString(lgrTxoToSpend.id)
		if index, exists := lgrTxoIdsToSpendMap[idStringToSpend]; exists {
			return nil, fmt.Errorf("TransferTxMLPGen: the %d-th coin-to-spend, say txInputDescs[%d].lgrTxoList[%d], has the same lgrTxoId as the the %d-th coin-to-spend, say txInputDescs[%d].lgrTxoList[%d]", i, i, txInputDescItem.sidx, index, index, txInputDescs[index].sidx)
		}
		lgrTxoIdsToSpendMap[idStringToSpend] = i

		//	identify inForRing, inForSingle, and inForSingleDistinct
		coinAddressType := lgrTxoToSpend.txo.CoinAddressType()
		coinAddress, err := pp.GetCoinAddressFromTxoMLP(lgrTxoToSpend.txo)
		if err != nil {
			return nil, err
		}

		if coinAddressType == CoinAddressTypePublicKeyForRingPre || coinAddressType == CoinAddressTypePublicKeyForRing {
			if i == inForRing {
				inForRing += 1
			} else {
				//	The coinAddresses for RingCT-Privacy should be at the fist successive positions.
				return nil, fmt.Errorf("TransferTxMLPGen: on the input side, the coins-to-spend with RingCT-Privacy should be at the fist successive positions, but the %d -th one is not", i)
			}

			//	To spend a coin with RingCT-Privacy, none of the (coinSerialNumberSecretKey, coinValuePublicKey, coinValueSecretKey) could be nil.
			if len(txInputDescItem.coinSpendSecretKey) == 0 ||
				len(txInputDescItem.coinSerialNumberSecretKey) == 0 ||
				len(txInputDescItem.coinValuePublicKey) == 0 || len(txInputDescItem.coinValueSecretKey) == 0 {
				return nil, fmt.Errorf("TransferTxMLPGen: the coin to spend, say txInputDescs[%d].lgrTxoList[%d] has RingCT-Privacy, but at least one of the (coinSpendSecretKey, coinSerialNumberSecretKey, coinValuePublicKey, coinValueSecretKey) nil", i, txInputDescItem.sidx)
			}

			//	check the validity of (coinAddress, coinSpendSecretKey, coinSerialNumberSecretKey)
			validAddressKey, err := pp.CoinAddressKeyForPKRingVerify(coinAddress, txInputDescItem.coinSpendSecretKey, txInputDescItem.coinSerialNumberSecretKey, txInputDescItem.coinDetectorKey)
			if err != nil {
				return nil, err
			}
			if !validAddressKey {
				return nil, fmt.Errorf("TransferTxMLPGen: the coin to spend, say txInputDescs[%d].lgrTxoList[%d] and corresponding coinSpendSecretKey and coinSerialNumberSecretKey, say txInputDescs[%d].coinSpendSecretKey and txInputDescs[%d].coinSerialNumberSecretKey, do not match", i, txInputDescItem.sidx, i, i)
			}

			//	Check the validity of (coinValuePublicKey, coinValueSecretKey)
			validValueKey, hints := pp.CoinValueKeyVerify(txInputDescItem.coinValuePublicKey, txInputDescItem.coinValueSecretKey)
			if !validValueKey {
				return nil, fmt.Errorf("TransferTxMLPGen: the coin value key pair for %d -th coin to spend, say txInputDescs[%d].coinValuePublicKey and txInputDescs[%d].coinValueSecretKey, does not match. Hints = "+hints, i, i)
			}

			//	Check the value-commitment and value-ciphertext
			valueInCmt, cmtr, err := pp.ExtractValueAndRandFromTxoMLP(lgrTxoToSpend.txo, txInputDescItem.coinValuePublicKey, txInputDescItem.coinValueSecretKey)
			if err != nil {
				return nil, err
			}
			if valueInCmt != txInputDescItem.value {
				return nil, fmt.Errorf("TransferTxMLPGen: for the %d -th coin to spend, txInputDescs[%d].value (%d) is different from the extratced value from the commitment", i, i, txInputDescs[i].value)
			}
			//	collect the randomness for cmt for coin-to-spend in inForRing
			cmtrs_in = append(cmtrs_in, cmtr)

			// In one ring,
			// (1) there should not be repeated lgrTxoId,
			// (2) the txos should have the 'same' coinAddressType (which imply the same privacy-level)
			lgrTxoIdsMap := make(map[string]int)
			for t := 0; t < len(txInputDescItem.lgrTxoList); t++ {
				if len(txInputDescItem.lgrTxoList[t].id) == 0 {
					return nil, fmt.Errorf("TransferTxMLPGen: txInputDescs[%d].lgrTxoList[%d].id is nil/empty", i, t)
				}
				idString := hex.EncodeToString(txInputDescItem.lgrTxoList[t].id)
				if index, exists := lgrTxoIdsMap[idString]; exists {
					return nil, fmt.Errorf("TransferTxMLPGen: txInputDescs[%d].lgrTxoList contains repeated lgrTxoIds, say %d-th and %d-th", i, index, t)
				}
				lgrTxoIdsMap[idString] = t

				if txInputDescItem.lgrTxoList[t].txo == nil {
					return nil, fmt.Errorf("TransferTxMLPGen: txInputDescs[%d].lgrTxoList[%d].txo is nil", i, t)
				}
				coinAddressTypeInRingMember := txInputDescItem.lgrTxoList[t].txo.CoinAddressType()
				if coinAddressTypeInRingMember != coinAddressType {
					//	The case of (CoinAddressTypePublicKeyForRingPre, CoinAddressTypePublicKeyForRing) is allowed
					if (coinAddressTypeInRingMember == CoinAddressTypePublicKeyForRingPre && coinAddressType == CoinAddressTypePublicKeyForRing) ||
						(coinAddressTypeInRingMember == CoinAddressTypePublicKeyForRing && coinAddressType == CoinAddressTypePublicKeyForRingPre) {
						//	allowed
					} else {
						return nil, fmt.Errorf("TransferTxMLPGen: txInputDescs[%d].lgrTxoList[%d].txo has differnet coinAddressType from the coin-to-spend, say txInputDescs[%d].lgrTxoList[%d]", i, t, i, txInputDescItem.sidx)
					}
				}
			}

		} else if coinAddressType == CoinAddressTypePublicKeyHashForSingle {
			inForSingle += 1
			vInPublic += txInputDescItem.value

			//	for the CoinAddressTypePublicKeyHashForSingle, the ring must have size 1
			if len(txInputDescItem.lgrTxoList) != 1 {
				return nil, fmt.Errorf("TransferTxMLPGen: the coin to spend, say txInputDescs[%d].lgrTxoList[%d] has Pseudonym-Privacy, but the size of txInputDescs[%d].lgrTxoList is not 1", i, txInputDescItem.sidx, i)
			}

			//	check the keys
			//	coinSpendSecretKey        []byte
			//	coinSerialNumberSecretKey []byte	// 	this is skipped, to allow the caller to use a dummy one
			//	coinValuePublicKey        []byte	//	this is skipped, to allow the caller to use a dummy one
			//	coinValueSecretKey        []byte	//	this is skipped, to allow the caller to use a dummy one
			if len(txInputDescItem.coinSpendSecretKey) == 0 {
				return nil, fmt.Errorf("TransferTxMLPGen: for % -th the coin to spend, say txInputDescs[%d].lgrTxoList[%d], the corresponding coinSpendSecretKey, say txInputDescs[%d].coinSpendSecretKey, is nil", i, txInputDescItem.sidx, i)
			}
			validKey, err := pp.CoinAddressKeyForPKHSingleVerify(coinAddress, txInputDescItem.coinSpendSecretKey, txInputDescItem.coinDetectorKey)
			if err != nil {
				return nil, err
			}
			if !validKey {
				return nil, fmt.Errorf("TransferTxMLPGen: the coin to spend, say txInputDescs[%d].lgrTxoList[%d] and corresponding coinSpendSecretKey, say txInputDescs[%d].coinSpendSecretKey, do not match", i, txInputDescItem.sidx, i)
			}

			//	check the public value
			switch txoInstToSpend := lgrTxoToSpend.txo.(type) {
			case *TxoSDN:
				if txoInstToSpend.value != txInputDescItem.value {
					return nil, fmt.Errorf("TransferTxMLPGen: the coin to spend, say txInputDescs[%d].lgrTxoList[%d] has value=%d, but txInputDescs[%d].value is %d", i, txInputDescItem.sidx, txoInstToSpend.value, i, txInputDescItem.value)
				}
			default:
				return nil, fmt.Errorf("TransferTxMLPGen: the coin to spend, say txInputDescs[%d].lgrTxoList[%d] has CoinAddressTypePublicKeyHashForSingle, but it is not a TxoSDN", i, txInputDescItem.sidx)
			}

			//	collect the distinct coinAddress with CoinAddressTypePublicKeyHashForSingle
			coinAddressString := hex.EncodeToString(coinAddress)
			if _, exists := coinAddressSpendSecretKeyMap[coinAddressString]; !exists {
				coinAddressForSingleDistinctList = append(coinAddressForSingleDistinctList, coinAddress)
				coinAddressSpendSecretKeyMap[coinAddressString] = txInputDescItem.coinSpendSecretKey
				inForSingleDistinct += 1
			}

			//	As the ring size must be 1, and the only ring member is the one to spend,
			//	here we do not need to check:
			// In one ring,
			// (1) there should not be repeated lgrTxoId,
			// (2) the txos should have the 'same' coinAddressType (which imply the same privacy-level)

		} else {
			return nil, fmt.Errorf("TransferTxMLPGen: the coin to spend, say txInputDescs[%d].lgrTxoList[%d].txo's coinAddresses's coinAddressesType(%d) is not supported", i, txInputDescItem.sidx, coinAddressType)
		}
	}

	if len(cmtrs_in) != inForRing {
		//	assert
		return nil, fmt.Errorf("TransferTxMLPGen: it should not happen that the length of cmtrsIn (%d) is different from inForRing (%d)", len(cmtrs_in), inForRing)
	}

	if len(coinAddressForSingleDistinctList) != inForSingleDistinct {
		//	assert
		return nil, fmt.Errorf("TransferTxMLPGen: it should not happen that the length of coinAddressForSingleDistinctList (%d) is different from inForSingleDistinct (%d)", len(coinAddressForSingleDistinctList), inForSingleDistinct)
	}

	if len(coinAddressSpendSecretKeyMap) != inForSingleDistinct {
		//	assert
		return nil, fmt.Errorf("TransferTxMLPGen: it should not happen that the length of coinAddressSpendSecretKeyMap (%d) is different from inForSingleDistinct (%d)", len(coinAddressSpendSecretKeyMap), inForSingleDistinct)
	}

	if inForRing > int(pp.paramI) {
		return nil, fmt.Errorf("TransferTxMLPGen: the number of RingCT-privacy coins to be spent (%d) exceeds the allowed maximum value (%d)", inForRing, pp.paramI)
	}
	if inForSingle > int(pp.paramISingle) {
		return nil, fmt.Errorf("TransferTxMLPGen: the number of Pseudonym-privacy coins to be spent (%d) exceeds the allowed maximum value (%d)", inForSingle, pp.paramISingle)
	}
	if inForSingleDistinct > int(pp.paramISingleDistinct) {
		return nil, fmt.Errorf("TransferTxMLPGen: the number of distinct coin-addresses for Pseudonym-privacy coins to be spent (%d) exceeds the allowed maximum value (%d)", inForSingleDistinct, pp.paramISingleDistinct)
	}

	if vOutTotal != vInTotal {
		return nil, fmt.Errorf("TransferTxMLPGen: the total value on the output side (%d) is different that on the input side (%d)", vOutTotal, vInTotal)
	}

	vPublic := int64(vOutPublic) - int64(vInPublic) // Note that V << uint64.
	//	This is to have cmt_{in,1} + ... + cmt_{in,inForRing} = cmt_{out,1} + ... + cmt_{out,outForRing} + vPublic,
	//	where vPublic could be 0 or negative.
	//	(inForRing, outForRing, vPublic) will determine the balance proof type for the transaction.

	trTx := &TransferTxMLP{}
	trTx.txInputs = make([]*TxInputMLP, inputNum)
	trTx.txos = make([]TxoMLP, outputNum)
	trTx.fee = fee
	trTx.txMemo = txMemo
	// trTx.txWitness

	//	fill trTx.txos
	cmts_out := make([]*ValueCommitment, outForRing)
	cmtrs_out := make([]*PolyCNTTVec, outForRing)
	values_out := make([]uint64, outForRing)

	for j := 0; j < outputNum; j++ {
		txOutputDescItem := txOutputDescs[j]

		coinAddressType, err := pp.ExtractCoinAddressTypeFromCoinAddress(txOutputDescItem.coinAddress)
		if err != nil {
			return nil, err
		}

		switch coinAddressType {
		case CoinAddressTypePublicKeyForRingPre:
			txoRCTPre, cmtr, err := pp.txoRCTPreGen(txOutputDescItem.coinAddress, txOutputDescItem.coinValuePublicKey, txOutputDescItem.value)
			if err != nil {
				return nil, err
			}
			trTx.txos[j] = txoRCTPre
			cmts_out[j] = txoRCTPre.valueCommitment
			cmtrs_out[j] = cmtr
			values_out[j] = txOutputDescItem.value

		case CoinAddressTypePublicKeyForRing:
			txoRCT, cmtr, err := pp.txoRCTGen(txOutputDescItem.coinAddress, txOutputDescItem.coinValuePublicKey, txOutputDescItem.value)
			if err != nil {
				return nil, err
			}
			trTx.txos[j] = txoRCT
			cmts_out[j] = txoRCT.valueCommitment
			cmtrs_out[j] = cmtr
			values_out[j] = txOutputDescItem.value

		case CoinAddressTypePublicKeyHashForSingle:
			txoSDN, err := pp.txoSDNGen(txOutputDescItem.coinAddress, txOutputDescItem.value)
			if err != nil {
				return nil, err
			}
			trTx.txos[j] = txoSDN
			//cmts_out[j] = txoRCT.valueCommitment
			//cmtrs_out[j] = cmtr
			//values_out[j] = txOutputDescItem.value

		default:
			return nil, fmt.Errorf("TransferTxMLPGen: the %d -th coinAddresses of the input txOutputDescMLPs (%d) is not supported", j, coinAddressType)
		}
	}

	//	fill trTx.txInputs
	ma_ps := make([]*PolyANTT, inForRing)
	cmts_in_p := make([]*ValueCommitment, inForRing)
	cmtrs_in_p := make([]*PolyCNTTVec, inForRing)
	values_in := make([]uint64, inForRing)

	for i := 0; i < inForRing; i++ {
		txInputDescItem := txInputDescs[i]

		// serial Number
		// ma_ps
		// Note that for the case of TxoRCTPre, the generation of serial number must keep the same as that in pqringct.
		// m_a = m'_a + m_r
		m_r, err := pp.expandKIDRMLP(txInputDescItem.lgrTxoList[txInputDescItem.sidx])
		if err != nil {
			return nil, err
		}

		askSn, err := pp.coinSerialNumberSecretKeyForPKRingParse(txInputDescItem.coinSerialNumberSecretKey)
		ma_ps[i] = pp.PolyANTTAdd(askSn.ma, m_r)

		sn, err := pp.ledgerTxoSerialNumberComputeMLP(ma_ps[i])
		if err != nil {
			return nil, err
		}

		trTx.txInputs[i] = NewTxInputMLP(txInputDescItem.lgrTxoList, sn)

		// cmt_ps
		// cmtr_ps
		// msgs_in
		cmtr_p_poly, err := pp.sampleValueCmtRandomness()
		if err != nil {
			return nil, err
		}

		values_in[i] = txInputDescItem.value //	this has been checked during the sanity-check steps
		msg_in := pp.intToBinary(txInputDescItem.value)

		cmtrs_in_p[i] = pp.NTTPolyCVec(cmtr_p_poly)
		cmts_in_p[i] = &ValueCommitment{}
		cmts_in_p[i].b = pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, cmtrs_in_p[i], pp.paramKC, pp.paramLC)
		cmts_in_p[i].c = pp.PolyCNTTAdd(
			pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[0], cmtrs_in_p[i], pp.paramLC),
			&PolyCNTT{coeffs: msg_in},
		)
	}

	for i := inForRing; i < inputNum; i++ {
		txInputDescItem := txInputDescs[i]

		// serial Number
		// ma_ps
		// Note that for CoinAddressTypePublicKeyHashForSingle,
		// m'_a = m_a + m_r = m_r, since m_a is empty.
		m_r, err := pp.expandKIDRMLP(txInputDescItem.lgrTxoList[txInputDescItem.sidx])
		if err != nil {
			return nil, err
		}

		//askSn, err := pp.coinSerialNumberSecretKeyForPKRingParse(txInputDescItem.coinSerialNumberSecretKey)
		//ma_ps[i] = pp.PolyANTTAdd(askSn.ma, m_r)

		sn, err := pp.ledgerTxoSerialNumberComputeMLP(m_r)
		if err != nil {
			return nil, err
		}

		trTx.txInputs[i] = NewTxInputMLP(txInputDescItem.lgrTxoList, sn)
	}

	// trTxCon
	trTxCon, err := pp.SerializeTransferTxMLP(trTx, false)
	if err != nil {
		return nil, err
	}
	// extTrTxCon = trTxCon || cmt_p[0] || cmt_p[inForRing]
	extTrTxCon, err := pp.extendSerializedTransferTxContent(trTxCon, cmts_in_p)
	if err != nil {
		return nil, err
	}

	//	elrSignatureSign
	inRingSizes := make([]uint8, inForRing) //	This is used to collect the ring sizes.
	elrSigs := make([]*ElrSignatureMLP, inForRing)
	for i := 0; i < inForRing; i++ {
		txInputDescItem := txInputDescs[i]
		askSp, err := pp.coinSpendSecretKeyForPKRingParse(txInputDescItem.coinSpendSecretKey)
		if err != nil {
			return nil, err
		}
		askSp_ntt := pp.NTTPolyAVec(askSp.s)

		if len(txInputDescItem.lgrTxoList) > int(pp.paramRingSizeMax) {
			return nil, fmt.Errorf("TransferTxMLPGen: the %d -th input has ring size (%d) exceeding the allowd maximum value (%d) ", i, len(txInputDescItem.lgrTxoList), pp.paramRingSizeMax)
		}
		inRingSizes[i] = uint8(len(txInputDescItem.lgrTxoList))
		elrSigs[i], err = pp.elrSignatureMLPSign(txInputDescItem.lgrTxoList, ma_ps[i], cmts_in_p[i], extTrTxCon,
			txInputDescItem.sidx, askSp_ntt, cmtrs_in[i], cmtrs_in_p[i])
		if err != nil {
			return nil, fmt.Errorf("TransferTxMLPGen: fail to generate the extend linkable ring signature for the %d -th coin to spend", i)
		}
	}

	//	simpleSignatureSign
	addressPublicKeyForSingles := make([]*AddressPublicKeyForSingle, inForSingleDistinct)
	simpleSigs := make([]*SimpleSignatureMLP, inForSingleDistinct)
	for i := 0; i < inForSingleDistinct; i++ {
		coinAddress := coinAddressForSingleDistinctList[i]
		coinAddressString := hex.EncodeToString(coinAddress)
		coinSpendSecretKey, exists := coinAddressSpendSecretKeyMap[coinAddressString]
		if !exists {
			// just assert
			return nil, fmt.Errorf("TransferTxMLPGen: This should not happen, where a coinAddress with CoinAddressTypePublicKeyHashForSingle does not have corresponding coinSpendSecretKey")
		}
		apkForSingle, askSp, err := pp.coinSpendSecretKeyForPKHSingleParse(coinSpendSecretKey)
		if err != nil {
			return nil, err
		}

		addressPublicKeyForSingles[i] = apkForSingle

		askSp_ntt := pp.NTTPolyAVec(askSp.s)
		simpleSigs[i], err = pp.simpleSignatureSign(apkForSingle.t, extTrTxCon, askSp_ntt)
		if err != nil {
			return nil, fmt.Errorf("TransferTxMLPGen: fail to generate the simple signature for the %d -th coinAddress with CoinAddressTypePublicKeyHashForSingle", i)
		}
	}

	//	balance proof
	txCase, balanceProof, err := pp.genBalanceProofTrTx(extTrTxCon, uint8(inForRing), uint8(outForRing), cmts_in_p, cmts_out, vPublic, cmtrs_in_p, values_in, cmtrs_out, values_out)
	if err != nil {
		return nil, err
	}

	trTx.txWitness = &TxWitnessTrTx{
		txCase:                     txCase,
		inForRing:                  uint8(inForRing),
		inForSingle:                uint8(inForSingle),
		inForSingleDistinct:        uint8(inForSingleDistinct),
		inRingSizes:                inRingSizes,
		outForRing:                 uint8(outForRing),
		outForSingle:               uint8(outForSingle),
		vPublic:                    vPublic,
		ma_ps:                      ma_ps,
		cmts_in_p:                  cmts_in_p,
		elrSigs:                    elrSigs,
		addressPublicKeyForSingles: addressPublicKeyForSingles,
		simpleSigs:                 simpleSigs,
		balanceProof:               balanceProof,
	}

	return trTx, nil

}

// TransferTxMLPVerify verifies TransferTxMLP.
// reviewed on 2023.12.19
// todo: multi-round review
func (pp *PublicParameter) TransferTxMLPVerify(trTx *TransferTxMLP) (bool, error) {
	if trTx == nil ||
		len(trTx.txInputs) == 0 || len(trTx.txos) == 0 ||
		trTx.txWitness == nil {
		return false, nil
	}

	V := uint64(1)<<pp.paramN - 1

	if trTx.fee > V {
		return false, nil
	}

	inputNum := len(trTx.txInputs)
	outputNum := len(trTx.txos)

	//	the following check will make use the txWitness,
	//	conduct sanity-check on txWitness here
	if trTx.txWitness.outForRing > pp.paramJ || trTx.txWitness.outForSingle > pp.paramJSingle {
		return false, nil
	}
	if int(trTx.txWitness.outForRing)+int(trTx.txWitness.outForSingle) != outputNum {
		return false, nil
	}

	if trTx.txWitness.inForRing > pp.paramI || trTx.txWitness.inForSingle > pp.paramISingle || trTx.txWitness.inForSingleDistinct > pp.paramISingleDistinct {
		return false, nil
	}
	if trTx.txWitness.inForSingleDistinct > trTx.txWitness.inForSingle {
		return false, nil
	}
	if int(trTx.txWitness.inForRing)+int(trTx.txWitness.inForSingle) != inputNum {
		return false, nil
	}

	if len(trTx.txWitness.inRingSizes) != int(trTx.txWitness.inForRing) ||
		len(trTx.txWitness.ma_ps) != int(trTx.txWitness.inForRing) ||
		len(trTx.txWitness.cmts_in_p) != int(trTx.txWitness.inForRing) ||
		len(trTx.txWitness.elrSigs) != int(trTx.txWitness.inForRing) {
		return false, nil
	}

	if len(trTx.txWitness.addressPublicKeyForSingles) != int(trTx.txWitness.inForSingleDistinct) ||
		len(trTx.txWitness.simpleSigs) != int(trTx.txWitness.inForSingleDistinct) {
		return false, nil
	}

	addressPublicKeyForSingleMap := make(map[string]int)
	if trTx.txWitness.inForSingleDistinct > 0 {
		//	prepare addressPublicKeyForSingleMap, which will be used later to guarantee the spent-coins with pseudonym have corresponding signature
		for i := 0; i < int(trTx.txWitness.inForSingleDistinct); i++ {
			serializedApk, err := pp.serializeAddressPublicKeyForSingle(trTx.txWitness.addressPublicKeyForSingles[i])
			if err != nil {
				return false, err
			}
			apkHash, err := Hash(serializedApk) //	This computation is the same as that in CoinAddressKeyForPKHSingleGen
			apkHashString := hex.EncodeToString(apkHash)
			if _, exists := addressPublicKeyForSingleMap[apkHashString]; exists {
				return false, fmt.Errorf("TransferTxMLPVerify: there are repated addressPublicKeyForSingles in trTx.txWitness.addressPublicKeyForSingles")
			} else {
				addressPublicKeyForSingleMap[apkHashString] = 0 // the count = 0 will be used later to count the appearing times
			}
		}

		if len(addressPublicKeyForSingleMap) != int(trTx.txWitness.inForSingleDistinct) {
			//	just assert
			return false, fmt.Errorf("TransferTxMLPVerify: This should not happen, where len(addressPublicKeyForSingleMap)(%d) != int(trTx.txWitness.inForSingleDistinct) (%d)", len(addressPublicKeyForSingleMap), trTx.txWitness.inForSingleDistinct)
		}
	}

	//	check the txos
	vOutPublic := trTx.fee
	cmts_out := make([]*ValueCommitment, trTx.txWitness.outForRing)
	for j := 0; j < outputNum; j++ {
		txo := trTx.txos[j]
		coinAddressType := txo.CoinAddressType()

		if j < int(trTx.txWitness.outForRing) {
			//	outForRing
			if coinAddressType != CoinAddressTypePublicKeyForRingPre && coinAddressType != CoinAddressTypePublicKeyForRing {
				return false, fmt.Errorf("TransferTxMLPVerify: the fisrt %d txo should have RingCT-privacy, but %d-th does not", trTx.txWitness.outForRing, j)
			}
			switch txoInst := txo.(type) {
			case *TxoRCTPre:
				if txoInst.coinAddressType != CoinAddressTypePublicKeyForRingPre {
					return false, fmt.Errorf("TransferTxMLPVerify: the %d -th txo is TxoRCTPre, but the coinAddressType(%d) is not CoinAddressTypePublicKeyForRingPre", j, coinAddressType)
				}
				cmts_out[j] = txoInst.valueCommitment

			case *TxoRCT:
				if txoInst.coinAddressType != CoinAddressTypePublicKeyForRing {
					return false, fmt.Errorf("TransferTxMLPVerify: the %d -th txo is TxoRCT, but the coinAddressType(%d) is not CoinAddressTypePublicKeyForRing", j, coinAddressType)
				}
				cmts_out[j] = txoInst.valueCommitment

			default:
				//	just assert
				return false, fmt.Errorf("TransferTxMLPVerify: This should not happen, where the %d -th txo is not TxoRCTPre or TxoRCT", j)
			}

		} else {
			//	outForSingle
			if coinAddressType != CoinAddressTypePublicKeyHashForSingle {
				return false, fmt.Errorf("TransferTxMLPVerify: the %d-th txo should have Pseudonym-privacy, but it does not", j)
			}
			switch txoInst := txo.(type) {
			case *TxoSDN:
				if txoInst.value > V {
					return false, nil
				}
				vOutPublic += txoInst.value
				if vOutPublic > V {
					return false, nil
				}

			default:
				//	just assert
				return false, fmt.Errorf("TransferTxMLPVerify: This should not happen, where the %d -th txo is not TxoSDN", j)
			}
		}
	}

	// check the txInputs
	// prepare trTxCon which will be used in signature verifications and balance proof verifications
	trTxCon, err := pp.SerializeTransferTxMLP(trTx, false)
	if err != nil {
		return false, err
	}
	// extTrTxCon = trTxCon || cmt_p[0] || cmt_p[inForRing]
	extTrTxCon, err := pp.extendSerializedTransferTxContent(trTxCon, trTx.txWitness.cmts_in_p)
	if err != nil {
		return false, err
	}

	vInPublic := uint64(0)
	spentCoinSerialNumberMap := make(map[string]int) // There should not be double spending in one transaction.

	for i := 0; i < inputNum; i++ {
		txInput := trTx.txInputs[i]

		//	serialNumber (double-spending) check inside the transaction
		if len(txInput.serialNumber) == 0 {
			return false, nil
		}
		snString := hex.EncodeToString(txInput.serialNumber)
		if index, exists := spentCoinSerialNumberMap[snString]; exists {
			return false, fmt.Errorf("TransferTxMLPVerify: double-spending detected, the %d-th txInput and the %d -th txInput", i, index)
		}
		spentCoinSerialNumberMap[snString] = i

		//	sanity-check on the lgrTxoList
		//	Here we need to use the information in TxWitness, which is also a manner of double-check
		if len(txInput.lgrTxoList) == 0 {
			return false, nil
		}

		if i < int(trTx.txWitness.inForRing) {
			//	txInput.lgrTxoList should be a ring with ring member being RingCT-privacy
			//	in a ring, there should not be repeated lgrTxoId

			lgrTxoIdMap := make(map[string]int)
			for t := 0; t < len(txInput.lgrTxoList); t++ {
				if txInput.lgrTxoList[t].txo.CoinAddressType() != CoinAddressTypePublicKeyForRingPre &&
					txInput.lgrTxoList[t].txo.CoinAddressType() != CoinAddressTypePublicKeyForRing {
					return false, nil
				}

				if len(txInput.lgrTxoList[t].id) == 0 {
					return false, nil
				}
				lgrTxoIdString := hex.EncodeToString(txInput.lgrTxoList[t].id)
				if index, exists := lgrTxoIdMap[lgrTxoIdString]; exists {
					return false, fmt.Errorf("TransferTxMLPVerify: %d-th input contain repeated lgrtxo, the %d-th and the %d -th", i, t, index)
				}
				lgrTxoIdMap[lgrTxoIdString] = t
			}

			//	check ringSizes
			if len(txInput.lgrTxoList) != int(trTx.txWitness.inRingSizes[i]) {
				return false, nil
			}

			//	i-th serial number and elrSignature
			//	txInputs[i].serialNumber, trTx.txWitness.ma_ps[i], trTx.txWitness.cmts_in_p[i], extTrTxCon, trTx.txWitness.elrSigs[i]
			snFromKeyImg, err := pp.ledgerTxoSerialNumberComputeMLP(trTx.txWitness.ma_ps[i])
			if err != nil {
				return false, err
			}
			if bytes.Compare(snFromKeyImg, txInput.serialNumber) != 0 {
				return false, nil
			}
			valid, err := pp.elrSignatureMLPVerify(txInput.lgrTxoList, trTx.txWitness.ma_ps[i], trTx.txWitness.cmts_in_p[i], extTrTxCon, trTx.txWitness.elrSigs[i])
			if err != nil {
				return false, err
			}
			if valid == false {
				return false, nil
			}

		} else {
			//	txInput.lgrTxoList should be a ring with only one ring member, and the ring member should be pseudo-privacy
			//	collect the coin-value
			if len(txInput.lgrTxoList) != 1 {
				return false, nil
			}

			//	i-th serial number
			// Note that for CoinAddressTypePublicKeyHashForSingle,
			// m'_a = m_a + m_r = m_r, since m_a is empty.
			m_r, err := pp.expandKIDRMLP(txInput.lgrTxoList[0])
			if err != nil {
				return false, err
			}
			snFromLgrTxo, err := pp.ledgerTxoSerialNumberComputeMLP(m_r)
			if err != nil {
				return false, err
			}
			if bytes.Compare(snFromLgrTxo, txInput.serialNumber) != 0 {
				return false, nil
			}

			//	txo
			switch txoInst := txInput.lgrTxoList[0].txo.(type) {
			case *TxoSDN:
				if txoInst.coinAddressType != CoinAddressTypePublicKeyHashForSingle {
					return false, fmt.Errorf("TransferTxMLPVerify: the %d -th input is a TxoSDN, but it's coinAddressType is not CoinAddressTypePublicKeyHashForSingle", i)
				}

				//	value
				if txoInst.value > V {
					return false, nil
				}
				vInPublic = vInPublic + txoInst.value
				if vInPublic > V {
					return false, nil
				}

				//	addressPublicKeyForSingleHash shall have a corresponding addressPublicKeyForSingle in trTx.txWitness.addressPublicKeyForSingles
				apkHashString := hex.EncodeToString(txoInst.addressPublicKeyForSingleHash)
				if count, exists := addressPublicKeyForSingleMap[apkHashString]; exists {
					addressPublicKeyForSingleMap[apkHashString] = count + 1
				} else {
					return false, nil
				}

			default:
				return false, fmt.Errorf("TransferTxMLPVerify: the %d -th input should be a TxoSDN, but it is not", i)
			}
		}
	}

	//	To guarantee that there are no dummy addressPublicKeyForSingles in trTx.txWitness.addressPublicKeyForSingles
	for apkHashString, count := range addressPublicKeyForSingleMap {
		if count == 0 {
			return false, fmt.Errorf("TransferTxMLPVerify: the addressPublicKeyForSingle (with Hash = %s) in trTx.txWitness.addressPublicKeyForSingles does not have corresponding spent-coin", apkHashString)
		}
	}
	//	verify the simpleSignatures
	for i := 0; i < len(trTx.txWitness.addressPublicKeyForSingles); i++ {
		valid, err := pp.simpleSignatureVerify(trTx.txWitness.addressPublicKeyForSingles[i].t, extTrTxCon, trTx.txWitness.simpleSigs[i])
		if err != nil {
			return false, err
		}
		if valid == false {
			return false, nil
		}
	}

	vPublic := int64(vOutPublic) - int64(vInPublic)

	return pp.verifyBalanceProofTrTx(extTrTxCon, trTx.txWitness.inForRing, trTx.txWitness.outForRing, trTx.txWitness.cmts_in_p, cmts_out, vPublic, trTx.txWitness.txCase, trTx.txWitness.balanceProof)
}

//	TxWitness		begin

// GetTxWitnessCbTxSerializeSizeByDesc returns the serialize size for TxWitnessCbTx according to the input coinAddressList.
// reviewed on 2024.01.01, by Alice
func (pp *PublicParameter) GetTxWitnessCbTxSerializeSizeByDesc(coinAddressList [][]byte) (int, error) {
	if len(coinAddressList) == 0 {
		return 0, fmt.Errorf("GetTxWitnessCbTxSerializeSizeByDesc: the input coinAddressList is empty")
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
				return 0, fmt.Errorf("GetTxWitnessCbTxSerializeSizeByDesc: the coinAddresses for RingCT-Privacy should be at the fist successive positions")
			}
		} else if coinAddressType == CoinAddressTypePublicKeyHashForSingle {
			outForSingle += 1
		} else {
			return 0, fmt.Errorf("GetTxWitnessCbTxSerializeSizeByDesc: unsupported coinAddress type appears in coinAddressList")
		}
	}

	if outForRing > int(pp.paramJ) {
		return 0, fmt.Errorf("GetTxWitnessCbTxSerializeSizeByDesc: the number of output coins for RingCT-privacy exceeds the max allowed value: %d vs %d", outForRing, pp.paramJ)
	}

	if outForSingle > int(pp.paramJSingle) {
		return 0, fmt.Errorf("GetCbTxWitnessSerializeSizeByDesc: the number of output coins for Pseudonym-privacy exceeds the max allowed value: %d vs %d", outForSingle, pp.paramJSingle)
	}

	return pp.TxWitnessCbTxSerializeSize(uint8(outForRing))
}

//	TxWitness		end

//	TxInput		begin
//	TxInput		end

//	Serial Number	begin

// GetNullSerialNumberMLP returns null-serial-number.
// Note that this must keep the same as pqringct.GetNullSerialNumber.
// reviewed on 2023.12.07.
func (pp *PublicParameter) GetNullSerialNumberMLP() []byte {
	snSize := pp.ledgerTxoSerialNumberSerializeSizeMLP()
	nullSn := make([]byte, snSize)
	for i := 0; i < snSize; i++ {
		nullSn[i] = 0
	}
	return nullSn
}

// todo: review
func (pp *PublicParameter) GetSerialNumberSize() int {
	return pp.ledgerTxoSerialNumberSerializeSizeMLP()
}

// ledgerTxoSerialNumberSerializeSizeMLP returns serial size of null-serial-number.
// Note that this must keep the same as pqringct.ledgerTxoSerialNumberCompute.
// reviewed on 2023.12.07.
// reviewed on 2023.12.14
func (pp *PublicParameter) ledgerTxoSerialNumberSerializeSizeMLP() int {
	return HashOutputBytesLen
}

// ledgerTxoSerialNumberComputeMLP computes the serial number from the input m'_a.
// Note that m'_a is the actual unique coin-serial-number. To have better efficiency, we store H(m'_a) as the coin-serial-number.
// That's why we refer to it as a "compute" algorithm, rather than "Generate".
// Note that this must keep the same as pqringct.ledgerTxoSerialNumberCompute.
// reviewed on 2023.12.14
func (pp *PublicParameter) ledgerTxoSerialNumberComputeMLP(ma_p *PolyANTT) ([]byte, error) {
	if ma_p == nil {
		return nil, fmt.Errorf("ledgerTxoSerialNumberComputeMLP: the input ma_p is nil")
	}

	length := pp.PolyANTTSerializeSize()
	w := bytes.NewBuffer(make([]byte, 0, length))

	err := pp.writePolyANTT(w, ma_p)
	if err != nil {
		return nil, err
	}

	sn, err := Hash(w.Bytes())
	if err != nil {
		return nil, err
	}

	return sn, nil

	//tmp := make([]byte, pp.paramDA*8)
	//for k := 0; k < pp.paramDA; k++ {
	//	tmp = append(tmp, byte(a.coeffs[k]>>0))
	//	tmp = append(tmp, byte(a.coeffs[k]>>8))
	//	tmp = append(tmp, byte(a.coeffs[k]>>16))
	//	tmp = append(tmp, byte(a.coeffs[k]>>24))
	//	tmp = append(tmp, byte(a.coeffs[k]>>32))
	//	tmp = append(tmp, byte(a.coeffs[k]>>40))
	//	tmp = append(tmp, byte(a.coeffs[k]>>48))
	//	tmp = append(tmp, byte(a.coeffs[k]>>56))
	//}
	//res, err := Hash(tmp)
	//if err != nil {
	//	log.Fatalln("Error call Hash() in ledgerTxoSerialNumberCompute")
	//}
	//return res
}

// expandKIDRMLP expands the input LgrTxoMLP to a PolyANTT, named m_r, which will be used as a unique randomness for a LgrTxoMLP,
// since the caller will guarantee each LgrTxoMLP has a unique LgrTxoMLP.id.
// Note that for the case of the input lgrtxo.txo being a TxoRCTPre, this must keep the same as pqringct.expandKIDR.
// added on 2023.12.14
// reviewed on 2023.12.14
func (pp *PublicParameter) expandKIDRMLP(lgrtxo *LgrTxoMLP) (*PolyANTT, error) {
	if lgrtxo == nil {
		return nil, fmt.Errorf("expandKIDRMLP: the input lgrtxo is nil")
	}

	serializedLgrTxo, err := pp.SerializeLgrTxoMLP(lgrtxo)
	if err != nil {
		return nil, err
	}
	seed, err := Hash(serializedLgrTxo)
	if err != nil {
		return nil, err
	}

	coeffs, err := pp.randomDaIntegersInQa(seed)
	if err != nil {
		return nil, err
	}
	return &PolyANTT{coeffs}, nil

	//bitNum := 38
	//bound := pp.paramQA
	//xof := sha3.NewShake128()
	//xof.Reset()
	//length := pp.paramDA
	//coeffs := make([]int64, 0, length)
	//xof.Write(seed)
	//for len(coeffs) < length {
	//	expectedNum := length - len(coeffs)
	//	buf := make([]byte, (int64(bitNum*expectedNum)*(1<<bitNum)/bound+7)/8)
	//	xof.Read(buf)
	//	tmp := fillWithBoundOld(buf, expectedNum, bitNum, bound)
	//	coeffs = append(coeffs, tmp...)
	//}
	//for i := 0; i < length; i++ {
	//	coeffs[i] = reduceInt64(coeffs[i], pp.paramQA)
	//}
	//return &PolyANTT{coeffs: coeffs}, nil
}

//	Serial Number	end

//	LgrTxoMLP	begin

// LgrTxoMLPIdSerializeSize returns the serialize size of LgrTxoMLP.id.
// Note that this must keep the same as pqringct.LgrTxoIdSerializeSize.
// added on 2023.12.14
// reviewed on 2023.12.14
func (pp *PublicParameter) LgrTxoMLPIdSerializeSize() int {
	return HashOutputBytesLen
}

// LgrTxoMLPSerializeSize returns the serialize size of LgrTxoMLP.
// // Note that, for the case of lgrTxo.txo being a TxoRctPre, this must keep the same as pqringct.LgrTxoSerializeSize.
// added on 2023.12.14
// reviewed on 2023.12.14
func (pp *PublicParameter) lgrTxoMLPSerializeSize(lgrTxo *LgrTxoMLP) (int, error) {
	if lgrTxo == nil || lgrTxo.txo == nil || len(lgrTxo.id) == 0 {
		return 0, fmt.Errorf("LgrTxoMLPSerializeSize: there is nil/empty pointer in the input lgrTxo")
	}

	txoSerialize, err := pp.TxoMLPSerializeSize(lgrTxo.txo)
	if err != nil {
		return 0, err
	}

	return txoSerialize + pp.LgrTxoMLPIdSerializeSize(), nil
}

// SerializeLgrTxoMLP serializes the input LgrTxoMLP to []byte.
// Note that for the case of txoRCTPre, this must keep the same as pqringct.SerializeLgrTxo.
// added on 2023.12.14
// reviewed on 2023.12.14
func (pp *PublicParameter) SerializeLgrTxoMLP(lgrTxo *LgrTxoMLP) ([]byte, error) {

	if lgrTxo == nil || lgrTxo.txo == nil || len(lgrTxo.id) == 0 {
		return nil, errors.New("SerializeLgrTxoMLP: there is nil/empty pointer in LgrTxo")
	}

	length, err := pp.lgrTxoMLPSerializeSize(lgrTxo)
	if err != nil {
		return nil, err
	}
	w := bytes.NewBuffer(make([]byte, 0, length))

	//	txo: fixed length
	//  It is fixed length in pqringct, but not anymore in pqringctx.
	//	To keep back-compatible with pqringct, here we still use w.Write, as in pqringct.
	serializedTxo, err := pp.SerializeTxoMLP(lgrTxo.txo)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(serializedTxo)
	if err != nil {
		return nil, err
	}

	//	id: fixed-length
	_, err = w.Write(lgrTxo.id)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// DeserializeLgrTxoMLP deserialize the input []byte to a LgrTxoMLP.
// Note that for the case of txoRCTPre, this must keep the same as pqringct.DeserializeLgrTxo.
// added on 2023.12.14
// reviewed on 2023.12.14
// reviewed on 2023.12.20
func (pp *PublicParameter) DeserializeLgrTxoMLP(serializedLgrTxo []byte) (*LgrTxoMLP, error) {
	if len(serializedLgrTxo) == 0 {
		return nil, fmt.Errorf("DeserializeLgrTxoMLP: the input serializedLgrTxo is empty")
	}

	r := bytes.NewReader(serializedLgrTxo)

	// To be compatible with pqringct, we have to use this way to determine the bytes for the serializedTxo.
	// Note that this is based on the fact that pp.LgrTxoMLPIdSerializeSize() is a fixed length.
	serializedTxoLen := len(serializedLgrTxo) - pp.LgrTxoMLPIdSerializeSize()
	serializedTxo := make([]byte, serializedTxoLen)
	_, err := r.Read(serializedTxo)
	if err != nil {
		return nil, err
	}
	txo, err := pp.DeserializeTxoMLP(serializedTxo)
	if err != nil {
		return nil, err
	}

	id := make([]byte, pp.LgrTxoMLPIdSerializeSize())
	_, err = r.Read(id)
	if err != nil {
		return nil, err
	}

	return &LgrTxoMLP{
		txo: txo,
		id:  id,
	}, nil
}

//	LgrTxoMLP	end

// helper functions	begin

// genBalanceProofCbTx generates BalanceProofCbTx.
// reviewed on 2023.12.18
// reviewed on 2023.12.20
func (pp *PublicParameter) genBalanceProofCbTx(cbTxCon []byte, vL uint64, outForRing uint8, cmtRs []*ValueCommitment,
	cmtrRs []*PolyCNTTVec, vRs []uint64) (TxWitnessCbTxCase, BalanceProof, error) {

	//	generation algorithm does not conduct sanity-check on the inputs. This is because
	//	(1) the caller is supposed to have conducted these checks and then call this generation algorithm.
	//	(2) the corresponding verification algorithm will conduct all these checks.

	var err error
	var txCase TxWitnessCbTxCase
	var balanceProof BalanceProof
	if outForRing == 0 {
		txCase = TxWitnessCbTxCaseC0
		balanceProof, err = pp.genBalanceProofL0R0()
		if err != nil {
			return 0, nil, err
		}
	} else if outForRing == 1 {
		txCase = TxWitnessCbTxCaseC1
		balanceProof, err = pp.genBalanceProofL0R1(cbTxCon, vL, cmtRs[0], cmtrRs[0])
		if err != nil {
			return 0, nil, err
		}
	} else {
		//	outForRing >= 2
		txCase = TxWitnessCbTxCaseCn
		balanceProof, err = pp.genBalanceProofL0Rn(cbTxCon, outForRing, vL, cmtRs, cmtrRs, vRs)
		if err != nil {
			return 0, nil, err
		}
	}

	return txCase, balanceProof, nil
}

// verifyBalanceProofCbTx verifies the BalanceProofCbTx.
// reviewed on 2023.12.18
// reviewed on 2023.12.20
func (pp *PublicParameter) verifyBalanceProofCbTx(cbTxCon []byte, vL uint64, outForRing uint8, cmtRs []*ValueCommitment,
	txCase TxWitnessCbTxCase, balanceProof BalanceProof) (bool, error) {
	if len(cbTxCon) == 0 {
		return false, nil
	}

	V := uint64(1)<<pp.paramN - 1

	if vL > V {
		return false, nil
	}

	if outForRing > pp.paramJ {
		return false, nil
	}

	if len(cmtRs) != int(outForRing) {
		return false, nil
	}

	if balanceProof == nil {
		return false, nil
	}

	//	here only these simple sanity-checks are conducted. This is because
	//	verifyBalanceProofCbTx serves as a distributor, and will call concrete verifyBalanceProofXXYYZZ.

	switch bpfInst := balanceProof.(type) {
	case *BalanceProofL0R0:
		if txCase != TxWitnessCbTxCaseC0 {
			return false, fmt.Errorf("verifyBalanceProofCbTx: balanceProof is BalanceProofL0R0, but the txCase is not TxWitnessCbTxCaseC0")
		}
		if outForRing != 0 {
			return false, fmt.Errorf("verifyBalanceProofCbTx: balanceProof is BalanceProofL0R0, but the outForRing is not 0")
		}

		if vL != 0 {
			// balance is checked publicly.
			return false, nil
		}
		return pp.verifyBalanceProofL0R0(bpfInst)

	case *BalanceProofL0R1:
		if txCase != TxWitnessCbTxCaseC1 {
			return false, fmt.Errorf("verifyBalanceProofCbTx: balanceProof is BalanceProofL0R1, but the txCase is not TxWitnessCbTxCaseC1")
		}
		if outForRing != 1 {
			return false, fmt.Errorf("verifyBalanceProofCbTx: balanceProof is BalanceProofL0R1, but the outForRing is not 1")
		}
		return pp.verifyBalanceProofL0R1(cbTxCon, vL, cmtRs[0], bpfInst)

	case *BalanceProofLmRn:
		if txCase != TxWitnessCbTxCaseCn {
			return false, fmt.Errorf("verifyBalanceProofCbTx: balanceProof is BalanceProofLmRn, but the txCase is not TxWitnessCbTxCaseCn")
		}
		if outForRing < 2 {
			return false, fmt.Errorf("verifyBalanceProofCbTx: balanceProof is BalanceProofLmRn, but the outForRing is not >= 2")
		}
		return pp.verifyBalanceProofL0Rn(cbTxCon, outForRing, vL, cmtRs, bpfInst)
	}

	return false, nil
}

// balanceProofCbTxSerializeSize returns the serialize size for BalanceProofCbTx.
func (pp *PublicParameter) balanceProofCbTxSerializeSize(outForRing uint8) (int, error) {
	if outForRing == 0 {
		return pp.balanceProofL0R0SerializeSize(), nil
	} else if outForRing == 1 {
		return pp.balanceProofL0R1SerializeSize(), nil
	} else { //	outForRing >= 2
		return pp.balanceProofLmRnSerializeSizeByCommNum(0, outForRing)
	}
}

// extendSerializedTransferTxContent extend the serialized TransferTx Content by appending the cmt_ps.
// added on 2023.12.15
// reviewed on 2023.12.19
func (pp *PublicParameter) extendSerializedTransferTxContent(serializedTrTxCon []byte, cmts_in_p []*ValueCommitment) ([]byte, error) {

	length := len(serializedTrTxCon) + len(cmts_in_p)*pp.ValueCommitmentSerializeSize()

	rst := make([]byte, 0, length)

	//	trTxCon []byte
	rst = append(rst, serializedTrTxCon...)

	//	cmt_ps []*ValueCommitment
	for i := 0; i < len(cmts_in_p); i++ {
		serializedCmt, err := pp.SerializeValueCommitment(cmts_in_p[i])
		if err != nil {
			return nil, err
		}
		rst = append(rst, serializedCmt...)
	}

	return rst, nil
}

// genBalanceProofTrTx generates balanceProof for transferTx.
// reviewed on 2023.12.16
// reviewed on 2023.12.19
func (pp *PublicParameter) genBalanceProofTrTx(extTrTxCon []byte, inForRing uint8, outForRing uint8, cmts_in_p []*ValueCommitment, cmts_out []*ValueCommitment, vPublic int64,
	cmtrs_in_p []*PolyCNTTVec, values_in []uint64, cmtrs_out []*PolyCNTTVec, values_out []uint64) (TxWitnessTrTxCase, BalanceProof, error) {

	var txCase TxWitnessTrTxCase
	var balanceProof BalanceProof
	var err error

	if inForRing == 0 {
		if outForRing == 0 {
			if vPublic != 0 {
				// assert, the caller should have checked.
				return 0, nil, fmt.Errorf("genBalanceProofTrTx: this should not happen, where inForRing == 0 and outForRing == 0, but vPublic != 0")
			}
			txCase = TxWitnessTrTxCaseI0C0
			balanceProof, err = pp.genBalanceProofL0R0()
			if err != nil {
				return 0, nil, err
			}
		} else if outForRing == 1 {
			//	0 = cmt_{out,0} + vPublic
			if vPublic > 0 {
				// assert, since previous codes have checked.
				return 0, nil, fmt.Errorf("genBalanceProofTrTx: this should not happen, where inForRing == 0 and outForRing == 1, but vPublic > 0")
			}
			//  -vPublic = cmt_{out,0}
			txCase = TxWitnessTrTxCaseI0C1
			balanceProof, err = pp.genBalanceProofL0R1(extTrTxCon, uint64(-vPublic), cmts_out[0], cmtrs_out[0])
			if err != nil {
				return 0, nil, err
			}
		} else { //	outForRing >= 2
			//	0 = cmt_{out,0} + ... + cmt_{out, outForRing-1} + vPublic
			if vPublic > 0 {
				// assert, the caller should have checked.
				return 0, nil, fmt.Errorf("genBalanceProofTrTx: this should not happen, where inForRing == 0 and outForRing >= 2, but vPublic > 0")
			}

			//	(-vPublic) = cmt_{out,0} + ... + cmt_{out, outForRing-1}
			txCase = TxWitnessTrTxCaseI0Cn
			balanceProof, err = pp.genBalanceProofL0Rn(extTrTxCon, outForRing, uint64(-vPublic), cmts_out, cmtrs_out, values_out)
			if err != nil {
				return 0, nil, err
			}
		}
	} else if inForRing == 1 {
		if outForRing == 0 {
			//	cmt_{in,0} = vPublic
			if vPublic < 0 {
				// assert, the caller should have checked.
				return 0, nil, fmt.Errorf("genBalanceProofTrTx: this should not happen, where inForRing == 1 and outForRing == 0, but vPublic < 0")
			}

			//	vPublic = cmt_{in,0}
			txCase = TxWitnessTrTxCaseI1C0
			balanceProof, err = pp.genBalanceProofL0R1(extTrTxCon, uint64(vPublic), cmts_in_p[0], cmtrs_in_p[0])
			if err != nil {
				return 0, nil, err
			}
		} else if outForRing == 1 {
			//	cmt_{in,0} = cmt_{out,0} + vPublic
			if vPublic == 0 {
				//	cmt_{in,0} = cmt_{out,0}
				txCase = TxWitnessTrTxCaseI1C1Exact
				balanceProof, err = pp.genBalanceProofL1R1(extTrTxCon, cmts_in_p[0], cmts_out[0], cmtrs_in_p[0], cmtrs_out[0], values_out[0])
				if err != nil {
					return 0, nil, err
				}
			} else if vPublic > 0 {
				//	cmt_{in,0} = cmt_{out,0} + vPublic
				txCase = TxWitnessTrTxCaseI1C1CAdd
				balanceProof, err = pp.genBalanceProofL1Rn(extTrTxCon, 1, cmts_in_p[0], cmts_out, uint64(vPublic), cmtrs_in_p[0], values_in[0], cmtrs_out, values_out)
				if err != nil {
					return 0, nil, err
				}
			} else { // vPublic < 0
				//	cmt_{in,0} + (-vPublic) = cmt_{out,0}
				//	cmt_{out,0} = cmt_{in,0} + (-vPublic)
				txCase = TxWitnessTrTxCaseI1C1IAdd
				balanceProof, err = pp.genBalanceProofL1Rn(extTrTxCon, 1, cmts_out[0], cmts_in_p, uint64(-vPublic), cmtrs_out[0], values_out[0], cmtrs_in_p, values_in)
				if err != nil {
					return 0, nil, err
				}
			}
		} else { //	outForRing >= 2
			//	cmt_{in,0} = cmt_{out,0} + ...+ cmt_{out, outForRing-1} + vPublic
			if vPublic == 0 {
				//	cmt_{in,0} = cmt_{out,0} + ...+ cmt_{out, outForRing-1}
				txCase = TxWitnessTrTxCaseI1CnExact
				balanceProof, err = pp.genBalanceProofL1Rn(extTrTxCon, outForRing, cmts_in_p[0], cmts_out, 0, cmtrs_in_p[0], values_in[0], cmtrs_out, values_out)
				if err != nil {
					return 0, nil, err
				}
			} else if vPublic > 0 {
				//	cmt_{in,0} = cmt_{out,0} + ...+ cmt_{out, outForRing-1} + vPublic
				txCase = TxWitnessTrTxCaseI1CnCAdd
				balanceProof, err = pp.genBalanceProofL1Rn(extTrTxCon, outForRing, cmts_in_p[0], cmts_out, uint64(vPublic), cmtrs_in_p[0], values_in[0], cmtrs_out, values_out)
				if err != nil {
					return 0, nil, err
				}
			} else { // vPublic < 0
				//	cmt_{in,0} + (-vPublic) = cmt_{out,0} + ...+ cmt_{out, outForRing-1}
				//	cmt_{out,0} + ...+ cmt_{out, outForRing-1} = cmt_{in,0} + (-vPublic)
				txCase = TxWitnessTrTxCaseI1CnIAdd
				balanceProof, err = pp.genBalanceProofLmRn(extTrTxCon, outForRing, inForRing, cmts_out, cmts_in_p, uint64(-vPublic), cmtrs_out, values_out, cmtrs_in_p, values_in)
				if err != nil {
					return 0, nil, err
				}
			}
		}

	} else { //	inForRing >= 2
		if outForRing == 0 {
			//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = vPublic
			if vPublic < 0 {
				// assert, the caller should have checked.
				return 0, nil, fmt.Errorf("genBalanceProofTrTx: this should not happen, where inForRing >= 2 and outForRing == 0, but vPublic < 0")
			}

			//	vPublic = cmt_{in,0} + ... + cmt_{in, inForRing-1}
			txCase = TxWitnessTrTxCaseImC0
			balanceProof, err = pp.genBalanceProofL0Rn(extTrTxCon, inForRing, uint64(vPublic), cmts_in_p, cmtrs_in_p, values_in)
			if err != nil {
				return 0, nil, err
			}

		} else if outForRing == 1 {
			//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + vPublic
			if vPublic == 0 {
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0}
				//	cmt_{out,0} = cmt_{in,0} + ... + cmt_{in, inForRing-1}
				txCase = TxWitnessTrTxCaseImC1Exact
				balanceProof, err = pp.genBalanceProofL1Rn(extTrTxCon, inForRing, cmts_out[0], cmts_in_p, 0, cmtrs_out[0], values_out[0], cmtrs_in_p, values_in)
				if err != nil {
					return 0, nil, err
				}
			} else if vPublic > 0 {
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + vPublic
				txCase = TxWitnessTrTxCaseImC1CAdd
				balanceProof, err = pp.genBalanceProofLmRn(extTrTxCon, inForRing, outForRing, cmts_in_p, cmts_out, uint64(vPublic), cmtrs_in_p, values_in, cmtrs_out, values_out)
				if err != nil {
					return 0, nil, err
				}
			} else { // vPublic < 0
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} + (-vPublic) = cmt_{out,0}
				//	cmt_{out,0} = cmt_{in,0} + ... + cmt_{in, inForRing-1} + (-vPublic)
				txCase = TxWitnessTrTxCaseImC1IAdd
				balanceProof, err = pp.genBalanceProofL1Rn(extTrTxCon, inForRing, cmts_out[0], cmts_in_p, uint64(-vPublic), cmtrs_out[0], values_out[0], cmtrs_in_p, values_in)
				if err != nil {
					return 0, nil, err
				}
			}

		} else { // outForRing >= 2
			//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + ... + cmt_{out, outForRing-1} + vPublic
			if vPublic == 0 {
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + ... + cmt_{out, outForRing-1}
				txCase = TxWitnessTrTxCaseImCnExact
				balanceProof, err = pp.genBalanceProofLmRn(extTrTxCon, inForRing, outForRing, cmts_in_p, cmts_out, 0, cmtrs_in_p, values_in, cmtrs_out, values_out)
				if err != nil {
					return 0, nil, err
				}

			} else if vPublic > 0 {
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + ... + cmt_{out, outForRing-1} + vPublic
				txCase = TxWitnessTrTxCaseImCnCAdd
				balanceProof, err = pp.genBalanceProofLmRn(extTrTxCon, inForRing, outForRing, cmts_in_p, cmts_out, uint64(vPublic), cmtrs_in_p, values_in, cmtrs_out, values_out)
				if err != nil {
					return 0, nil, err
				}

			} else { // vPublic < 0
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} + (-vPublic) = cmt_{out,0} + ... + cmt_{out, outForRing-1}
				//	cmt_{out,0} + ... + cmt_{out, outForRing-1} = cmt_{in,0} + ... + cmt_{in, inForRing-1} + (-vPublic)
				txCase = TxWitnessTrTxCaseImCnIAdd
				balanceProof, err = pp.genBalanceProofLmRn(extTrTxCon, outForRing, inForRing, cmts_out, cmts_in_p, uint64(-vPublic), cmtrs_out, values_out, cmtrs_in_p, values_in)
				if err != nil {
					return 0, nil, err
				}
			}
		}
	}

	return txCase, balanceProof, nil
}

// verifyBalanceProofTrTx verifies BalanceProofTrTx
// reviewed on 2023.12.19
func (pp *PublicParameter) verifyBalanceProofTrTx(extTrTxCon []byte, inForRing uint8, outForRing uint8, cmts_in_p []*ValueCommitment, cmts_out []*ValueCommitment, vPublic int64,
	txCase TxWitnessTrTxCase, balcenProof BalanceProof) (bool, error) {

	if len(extTrTxCon) == 0 {
		return false, nil
	}

	if inForRing > pp.paramI || outForRing > pp.paramJ {
		return false, nil
	}

	if len(cmts_in_p) != int(inForRing) || len(cmts_out) != int(outForRing) {
		return false, nil
	}

	V := uint64(1)<<pp.paramN - 1

	if vPublic > int64(V) || vPublic < -int64(V) {
		return false, nil
	}

	//	here we do not conduct sanity-check on the (cmts_in_p, cmts_out),
	//	since verifyBalanceProofTrTx serves as a distributor, and will call concrete verifyBalanceProofXXYYZZ.

	if inForRing == 0 {
		if outForRing == 0 {
			if vPublic != 0 {
				return false, nil
			}
			if txCase != TxWitnessTrTxCaseI0C0 {
				return false, nil
			}
			switch bpfInst := balcenProof.(type) {
			case *BalanceProofL0R0:
				return pp.verifyBalanceProofL0R0(bpfInst)
			default:
				return false, fmt.Errorf("verifyBalanceProofTrTx: (inForRing = 0, outForRing = 0), but the input balance proof is not BalanceProofL0R0")
			}

		} else if outForRing == 1 {
			//	0 = cmt_{out,0} + vPublic
			if vPublic > 0 {
				return false, nil
			}
			//  -vPublic = cmt_{out,0}
			if txCase != TxWitnessTrTxCaseI0C1 {
				return false, nil
			}
			switch bpfInst := balcenProof.(type) {
			case *BalanceProofL0R1:
				return pp.verifyBalanceProofL0R1(extTrTxCon, uint64(-vPublic), cmts_out[0], bpfInst)
			default:
				return false, fmt.Errorf("verifyBalanceProofTrTx: (inForRing = 0, outForRing = 1), but the input balance proof is not BalanceProofL0R1")
			}

		} else { //	outForRing >= 2
			//	0 = cmt_{out,0} + ... + cmt_{out, outForRing-1} + vPublic
			if vPublic > 0 {
				return false, nil
			}

			//	(-vPublic) = cmt_{out,0} + ... + cmt_{out, outForRing-1}
			if txCase != TxWitnessTrTxCaseI0Cn {
				return false, nil
			}
			switch bpfInst := balcenProof.(type) {
			case *BalanceProofLmRn:
				return pp.verifyBalanceProofL0Rn(extTrTxCon, outForRing, uint64(-vPublic), cmts_out, bpfInst)
			default:
				return false, fmt.Errorf("verifyBalanceProofTrTx: (inForRing = 0, outForRing >= 2), but the input balance proof is not BalanceProofLmRn")
			}
		}
	} else if inForRing == 1 {
		if outForRing == 0 {
			//	cmt_{in,0} = vPublic
			if vPublic < 0 {
				return false, nil
			}

			//	vPublic = cmt_{in,0}
			if txCase != TxWitnessTrTxCaseI1C0 {
				return false, nil
			}
			switch bpfInst := balcenProof.(type) {
			case *BalanceProofL0R1:
				return pp.verifyBalanceProofL0R1(extTrTxCon, uint64(vPublic), cmts_in_p[0], bpfInst)
			default:
				return false, fmt.Errorf("verifyBalanceProofTrTx: (inForRing = 1, outForRing = 0), but the input balance proof is not BalanceProofL0R1")
			}
		} else if outForRing == 1 {
			//	cmt_{in,0} = cmt_{out,0} + vPublic
			if vPublic == 0 {
				//	cmt_{in,0} = cmt_{out,0}
				if txCase != TxWitnessTrTxCaseI1C1Exact {
					return false, nil
				}
				switch bpfInst := balcenProof.(type) {
				case *BalanceProofL1R1:
					return pp.verifyBalanceProofL1R1(extTrTxCon, cmts_in_p[0], cmts_out[0], bpfInst)
				default:
					return false, fmt.Errorf("verifyBalanceProofTrTx: (inForRing = 1, outForRing = 1, vPublic = 0), but the input balance proof is not BalanceProofL1R1")
				}
			} else if vPublic > 0 {
				//	cmt_{in,0} = cmt_{out,0} + vPublic
				if txCase != TxWitnessTrTxCaseI1C1CAdd {
					return false, nil
				}
				switch bpfInst := balcenProof.(type) {
				case *BalanceProofLmRn:
					return pp.verifyBalanceProofL1Rn(extTrTxCon, 1, cmts_in_p[0], cmts_out, uint64(vPublic), bpfInst)
				default:
					return false, fmt.Errorf("verifyBalanceProofTrTx: (inForRing = 1, outForRing = 1, vPublic > 0), but the input balance proof is not BalanceProofLmRn")
				}

			} else { // vPublic < 0
				//	cmt_{in,0} + (-vPublic) = cmt_{out,0}
				//	cmt_{out,0} = cmt_{in,0} + (-vPublic)
				if txCase != TxWitnessTrTxCaseI1C1IAdd {
					return false, nil
				}
				switch bpfInst := balcenProof.(type) {
				case *BalanceProofLmRn:
					return pp.verifyBalanceProofL1Rn(extTrTxCon, 1, cmts_out[0], cmts_in_p, uint64(-vPublic), bpfInst)
				default:
					return false, fmt.Errorf("verifyBalanceProofTrTx: (inForRing = 1, outForRing = 1, vPublic < 0), but the input balance proof is not BalanceProofLmRn")
				}
			}
		} else { //	outForRing >= 2
			//	cmt_{in,0} = cmt_{out,0} + ...+ cmt_{out, outForRing-1} + vPublic
			if vPublic == 0 {
				//	cmt_{in,0} = cmt_{out,0} + ...+ cmt_{out, outForRing-1}
				if txCase != TxWitnessTrTxCaseI1CnExact {
					return false, nil
				}
				switch bpfInst := balcenProof.(type) {
				case *BalanceProofLmRn:
					return pp.verifyBalanceProofL1Rn(extTrTxCon, outForRing, cmts_in_p[0], cmts_out, 0, bpfInst)
				default:
					return false, fmt.Errorf("verifyBalanceProofTrTx: (inForRing = 1, outForRing >= 2 , vPublic = 0), but the input balance proof is not BalanceProofLmRn")
				}

			} else if vPublic > 0 {
				//	cmt_{in,0} = cmt_{out,0} + ...+ cmt_{out, outForRing-1} + vPublic
				if txCase != TxWitnessTrTxCaseI1CnCAdd {
					return false, nil
				}
				switch bpfInst := balcenProof.(type) {
				case *BalanceProofLmRn:
					return pp.verifyBalanceProofL1Rn(extTrTxCon, outForRing, cmts_in_p[0], cmts_out, uint64(vPublic), bpfInst)
				default:
					return false, fmt.Errorf("verifyBalanceProofTrTx: (inForRing = 1, outForRing >= 2 , vPublic > 0), but the input balance proof is not BalanceProofLmRn")
				}
			} else { // vPublic < 0
				//	cmt_{in,0} + (-vPublic) = cmt_{out,0} + ...+ cmt_{out, outForRing-1}
				//	cmt_{out,0} + ...+ cmt_{out, outForRing-1} = cmt_{in,0} + (-vPublic)
				if txCase != TxWitnessTrTxCaseI1CnIAdd {
					return false, nil
				}
				switch bpfInst := balcenProof.(type) {
				case *BalanceProofLmRn:
					return pp.verifyBalanceProofLmRn(extTrTxCon, outForRing, inForRing, cmts_out, cmts_in_p, uint64(-vPublic), bpfInst)
				default:
					return false, fmt.Errorf("verifyBalanceProofTrTx: (inForRing = 1, outForRing >= 2 , vPublic < 0), but the input balance proof is not BalanceProofLmRn")
				}
			}
		}

	} else { //	inForRing >= 2
		if outForRing == 0 {
			//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = vPublic
			if vPublic < 0 {
				return false, nil
			}

			//	vPublic = cmt_{in,0} + ... + cmt_{in, inForRing-1}
			if txCase != TxWitnessTrTxCaseImC0 {
				return false, nil
			}
			switch bpfInst := balcenProof.(type) {
			case *BalanceProofLmRn:
				return pp.verifyBalanceProofL0Rn(extTrTxCon, inForRing, uint64(vPublic), cmts_in_p, bpfInst)
			default:
				return false, fmt.Errorf("verifyBalanceProofTrTx: (inForRing >= 2, outForRing = 0 ), but the input balance proof is not BalanceProofLmRn")
			}

		} else if outForRing == 1 {
			//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + vPublic
			if vPublic == 0 {
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0}
				//	cmt_{out,0} = cmt_{in,0} + ... + cmt_{in, inForRing-1}
				if txCase != TxWitnessTrTxCaseImC1Exact {
					return false, nil
				}
				switch bpfInst := balcenProof.(type) {
				case *BalanceProofLmRn:
					return pp.verifyBalanceProofL1Rn(extTrTxCon, inForRing, cmts_out[0], cmts_in_p, 0, bpfInst)
				default:
					return false, fmt.Errorf("verifyBalanceProofTrTx: (inForRing >= 2, outForRing = 1, vPublic = 0 ), but the input balance proof is not BalanceProofLmRn")
				}

			} else if vPublic > 0 {
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + vPublic
				if txCase != TxWitnessTrTxCaseImC1CAdd {
					return false, nil
				}
				switch bpfInst := balcenProof.(type) {
				case *BalanceProofLmRn:
					return pp.verifyBalanceProofLmRn(extTrTxCon, inForRing, outForRing, cmts_in_p, cmts_out, uint64(vPublic), bpfInst)
				default:
					return false, fmt.Errorf("verifyBalanceProofTrTx: (inForRing >= 2, outForRing = 1, vPublic > 0 ), but the input balance proof is not BalanceProofLmRn")
				}

			} else { // vPublic < 0
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} + (-vPublic) = cmt_{out,0}
				//	cmt_{out,0} = cmt_{in,0} + ... + cmt_{in, inForRing-1} + (-vPublic)
				if txCase != TxWitnessTrTxCaseImC1IAdd {
					return false, nil
				}
				switch bpfInst := balcenProof.(type) {
				case *BalanceProofLmRn:
					return pp.verifyBalanceProofL1Rn(extTrTxCon, inForRing, cmts_out[0], cmts_in_p, uint64(-vPublic), bpfInst)
				default:
					return false, fmt.Errorf("verifyBalanceProofTrTx: (inForRing >= 2, outForRing = 1, vPublic < 0 ), but the input balance proof is not BalanceProofLmRn")
				}

			}

		} else { // outForRing >= 2
			//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + ... + cmt_{out, outForRing-1} + vPublic
			if vPublic == 0 {
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + ... + cmt_{out, outForRing-1}
				if txCase != TxWitnessTrTxCaseImCnExact {
					return false, nil
				}
				switch bpfInst := balcenProof.(type) {
				case *BalanceProofLmRn:
					return pp.verifyBalanceProofLmRn(extTrTxCon, inForRing, outForRing, cmts_in_p, cmts_out, 0, bpfInst)
				default:
					return false, fmt.Errorf("verifyBalanceProofTrTx: (inForRing >= 2, outForRing > 1, vPublic = 0 ), but the input balance proof is not BalanceProofLmRn")
				}

			} else if vPublic > 0 {
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + ... + cmt_{out, outForRing-1} + vPublic
				if txCase != TxWitnessTrTxCaseImCnCAdd {
					return false, nil
				}
				switch bpfInst := balcenProof.(type) {
				case *BalanceProofLmRn:
					return pp.verifyBalanceProofLmRn(extTrTxCon, inForRing, outForRing, cmts_in_p, cmts_out, uint64(vPublic), bpfInst)
				default:
					return false, fmt.Errorf("verifyBalanceProofTrTx: (inForRing >= 2, outForRing > 1, vPublic > 0 ), but the input balance proof is not BalanceProofLmRn")
				}
			} else { // vPublic < 0
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} + (-vPublic) = cmt_{out,0} + ... + cmt_{out, outForRing-1}
				//	cmt_{out,0} + ... + cmt_{out, outForRing-1} = cmt_{in,0} + ... + cmt_{in, inForRing-1} + (-vPublic)
				if txCase != TxWitnessTrTxCaseImCnIAdd {
					return false, nil
				}
				switch bpfInst := balcenProof.(type) {
				case *BalanceProofLmRn:
					return pp.verifyBalanceProofLmRn(extTrTxCon, outForRing, inForRing, cmts_out, cmts_in_p, uint64(-vPublic), bpfInst)
				default:
					return false, fmt.Errorf("verifyBalanceProofTrTx: (inForRing >= 2, outForRing > 1, vPublic < 0 ), but the input balance proof is not BalanceProofLmRn")
				}
			}
		}
	}

}

// balanceProofTrTxSerializeSize returns the serialize for the BalanceProof for TxWitnessTrTx, according to the input (inForRing uint8, outForRing uint8, vPublic int64).
// reviewed on 2023.12.19
func (pp *PublicParameter) balanceProofTrTxSerializeSize(inForRing uint8, outForRing uint8, vPublic int64) (int, error) {

	if inForRing == 0 {
		if outForRing == 0 {
			if vPublic != 0 {
				//	assert
				return 0, fmt.Errorf("balanceProofTrTxSerializeSize: this should not happen, where inForRing == 0 and outForRing == 0, but vPublic != 0")
			}

			return pp.balanceProofL0R0SerializeSize(), nil

		} else if outForRing == 1 {
			//	0 = cmt_{out,0} + vPublic
			if vPublic > 0 {
				//	assert
				return 0, fmt.Errorf("balanceProofTrTxSerializeSize: this should not happen, where inForRing == 0 and outForRing == 1, but vPublic > 0")
			}
			//  -vPublic = cmt_{out,0}
			return pp.balanceProofL0R1SerializeSize(), nil

		} else { //	outForRing >= 2
			//	0 = cmt_{out,0} + ... + cmt_{out, outForRing-1} + vPublic
			if vPublic > 0 {
				// assert
				return 0, fmt.Errorf("balanceProofTrTxSerializeSize: this should not happen, where inForRing == 0 and outForRing >= 2, but vPublic > 0")
			}

			//	(-vPublic) = cmt_{out,0} + ... + cmt_{out, outForRing-1}
			return pp.balanceProofLmRnSerializeSizeByCommNum(0, outForRing)

		}
	} else if inForRing == 1 {
		if outForRing == 0 {
			//	cmt_{in,0} = vPublic
			if vPublic < 0 {
				// assert
				return 0, fmt.Errorf("balanceProofTrTxSerializeSize: this should not happen, where inForRing == 1 and outForRing == 0, but vPublic < 0")
			}

			//	vPublic = cmt_{in,0}
			return pp.balanceProofL0R1SerializeSize(), nil

		} else if outForRing == 1 {
			//	cmt_{in,0} = cmt_{out,0} + vPublic
			if vPublic == 0 {
				//	cmt_{in,0} = cmt_{out,0}
				return pp.balanceProofL1R1SerializeSize(), nil
			} else if vPublic > 0 {
				//	cmt_{in,0} = cmt_{out,0} + vPublic
				return pp.balanceProofLmRnSerializeSizeByCommNum(inForRing, outForRing)
			} else { // vPublic < 0
				//	cmt_{in,0} + (-vPublic) = cmt_{out,0}
				//	cmt_{out,0} = cmt_{in,0} + (-vPublic)
				return pp.balanceProofLmRnSerializeSizeByCommNum(outForRing, inForRing)
			}
		} else { //	outForRing >= 2
			//	cmt_{in,0} = cmt_{out,0} + ...+ cmt_{out, outForRing-1} + vPublic
			if vPublic == 0 {
				//	cmt_{in,0} = cmt_{out,0} + ...+ cmt_{out, outForRing-1}
				return pp.balanceProofLmRnSerializeSizeByCommNum(inForRing, outForRing)
			} else if vPublic > 0 {
				//	cmt_{in,0} = cmt_{out,0} + ...+ cmt_{out, outForRing-1} + vPublic
				return pp.balanceProofLmRnSerializeSizeByCommNum(inForRing, outForRing)
			} else { // vPublic < 0
				//	cmt_{in,0} + (-vPublic) = cmt_{out,0} + ...+ cmt_{out, outForRing-1}
				//	cmt_{out,0} + ...+ cmt_{out, outForRing-1} = cmt_{in,0} + (-vPublic)
				return pp.balanceProofLmRnSerializeSizeByCommNum(outForRing, inForRing)
			}
		}

	} else { //	inForRing >= 2
		if outForRing == 0 {
			//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = vPublic
			if vPublic < 0 {
				// assert
				return 0, fmt.Errorf("balanceProofTrTxSerializeSize: this should not happen, where inForRing >= 2 and outForRing == 0, but vPublic < 0")
			}

			//	vPublic = cmt_{in,0} + ... + cmt_{in, inForRing-1}
			return pp.balanceProofLmRnSerializeSizeByCommNum(0, inForRing)

		} else if outForRing == 1 {
			//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + vPublic
			if vPublic == 0 {
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0}
				//	cmt_{out,0} = cmt_{in,0} + ... + cmt_{in, inForRing-1}
				return pp.balanceProofLmRnSerializeSizeByCommNum(outForRing, inForRing)
			} else if vPublic > 0 {
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + vPublic
				return pp.balanceProofLmRnSerializeSizeByCommNum(inForRing, outForRing)
			} else { // vPublic < 0
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} + (-vPublic) = cmt_{out,0}
				//	cmt_{out,0} = cmt_{in,0} + ... + cmt_{in, inForRing-1} + (-vPublic)
				return pp.balanceProofLmRnSerializeSizeByCommNum(outForRing, inForRing)
			}

		} else { // outForRing >= 2
			//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + ... + cmt_{out, outForRing-1} + vPublic
			if vPublic == 0 {
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + ... + cmt_{out, outForRing-1}
				return pp.balanceProofLmRnSerializeSizeByCommNum(inForRing, outForRing)

			} else if vPublic > 0 {
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + ... + cmt_{out, outForRing-1} + vPublic
				return pp.balanceProofLmRnSerializeSizeByCommNum(inForRing, outForRing)

			} else { // vPublic < 0
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} + (-vPublic) = cmt_{out,0} + ... + cmt_{out, outForRing-1}
				//	cmt_{out,0} + ... + cmt_{out, outForRing-1} = cmt_{in,0} + ... + cmt_{in, inForRing-1} + (-vPublic)
				return pp.balanceProofLmRnSerializeSizeByCommNum(outForRing, inForRing)
			}
		}
	}
}

//	helper functions	end
