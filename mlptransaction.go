package pqringctx

// Application Layer Convention:
// 1. The RingCT-Privacy TXO must appear continuously starting from the first position regardless of input or output, and the number does not exceed pp.paramJ
// 2. The Pseudonym-Privacy TXO can appear any position but cannot break continuity of the above constraints, and the number does not exceed pp.paramJSingle
// 3. ...

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

// The rules on 0-value coin (namely, 0-value-coin-rule) are defined as below,
// where a basic principle is that the system will avoid 0-value coin as much as possible.
// 1. For coinbaseTx, let Vin = block reward + transaction_fee,
//	(1) Case 1 (Vin = 0):	there must be only ONE Pseudonym-Address output Txo and its value is 0.
//                          (Since multiple coins with value 0 (either public value or commitment) is unnecessary.)
//							Note that this rule requires that, when subsidy (say block reward) becomes 0,
//							the mining module needs to improve its block template generation,
//							so that when there is not any transferTx in the block,
//							it should use a Pseudonym-Address as the coinbase coin address.
//	(2) Case 2 (Vin > 0): 	(a) the value on Pseudonym-Address output Txo must > 0;
//     						(b) Let vL := Vin - sum of (public values on Pseudonym-Address output Txo),
//								if vL < the number of RingCT-Address-output, the transaction is rejected,
//								since it can de deduced that at one least commitment has value 0.
// 2. For transferTx,
//							(a) the value on Pseudonym-Address output Txo must > 0;
//							(b) If it can be deduced that the sum of the committed values on RingCT-Address is smaller than
//								the number of RingCT-Address-output Txo, the transaction is rejected,
//								since it can de deduced that at one least commitment has value 0.
// Note: The 0-value-coin-rule is imposed on the transaction layer, including Witness Layer, not deep into BalanceProof Layer.

// CoinbaseTxMLPGen generates a coinbase transaction.
// reviewed on 2023.12.07
// reviewed on 2023.12.19
// reviewed on 2023.12.20
// REVIEWED on 2023/12/31
// reviewed by Alice, 2024.07.06
func (pp *PublicParameter) CoinbaseTxMLPGen(vin uint64, txOutputDescMLPs []*TxOutputDescMLP, txMemo []byte) (*CoinbaseTxMLP, error) {

	if int64(len(txMemo)) > int64(MaxAllowedTxMemoMLPSize) {
		return nil, fmt.Errorf("CoinbaseTxMLPGen: the input txMemo []byte has a size (%v) larger than the allowed maximum value", len(txMemo))
	}

	V := (uint64(1) << pp.paramN) - 1

	if vin > V {
		return nil, fmt.Errorf("CoinbaseTxMLPGen: vin (%d) is not in [0, V= %d]", vin, V)
	}

	if vin == 0 {
		//	The special case for 0-value coin applies.
		if len(txOutputDescMLPs) != 1 {
			return nil, fmt.Errorf("CoinbaseTxMLPGen: vin = 0, but len(txOutputDescMLPs) (%d) is not 1", len(txOutputDescMLPs))
		}

		coinAddressType, err := pp.ExtractCoinAddressTypeFromCoinAddress(txOutputDescMLPs[0].coinAddress)
		if err != nil {
			return nil, err
		}
		if coinAddressType != CoinAddressTypePublicKeyHashForSingle {
			return nil, fmt.Errorf("CoinbaseTxMLPGen: vin = 0, but txOutputDescMLPs[0].coinAddressType (%d) is not CoinAddressTypePublicKeyHashForSingle", coinAddressType)
		}

		if txOutputDescMLPs[0].value != 0 {
			return nil, fmt.Errorf("CoinbaseTxMLPGen: vin = 0, but txOutputDescMLPs[0].value (%v) is not 0", txOutputDescMLPs[0].value)
		}
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

			if len(txOutputDescMLPs[i].coinValuePublicKey) == 0 {
				return nil, fmt.Errorf("CoinbaseTxMLPGen: the coinAddresses for RingCT-Privacy should have coinValuePublicKey, but the %d -th one does not", i)
			}

		} else if coinAddressType == CoinAddressTypePublicKeyHashForSingle {
			outForSingle += 1

			// skip the nil-check on coinValuePublicKey, to allow the caller to use a dummy coinValuePublicKey

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
			if txOutputDescMLP.value == 0 {
				if vin != 0 {
					// 0-value-coin-rule applies:
					// Only if vin == 0, output Txo could have value = 0
					return nil, fmt.Errorf("CoinbaseTxMLPGen: txOutputDescMLPs[%d] has coinAddressType=CoinAddressTypePublicKeyHashForSingle, but the value is 0", j)
				}
			}

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

	// 0-value-coin-rule applies:
	if vL < uint64(outForRing) {
		//	It can be deduced that at least one of the value-commitments on the output coins have value 0.
		//	It is banned by 0-value-coin-rule.
		return nil, fmt.Errorf("CoinbaseTxMLPGen: it attempting to generate RCT-Privacy coin with value 0")
	}

	//	TxWitness
	serializedCbTxCon, err := pp.SerializeCoinbaseTxMLP(retCbTx, false)
	if err != nil {
		return nil, err
	}
	//	use digest as the message to be authenticated
	cbTxConDigest, err := Hash(serializedCbTxCon)
	if err != nil {
		return nil, err
	}

	txCase, balanceProof, err := pp.genBalanceProofCbTx(cbTxConDigest, vL, uint8(outForRing), cmts, cmtrs, vRs)
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
// refactored on 2024.01.08, using err == nil or not to denote valid or invalid
// refactored and reviewed by Alice, 2024.07.06
// todo: review by 2024.07
func (pp *PublicParameter) CoinbaseTxMLPVerify(cbTx *CoinbaseTxMLP) error {

	if !pp.CoinbaseTxMLPSanityCheck(cbTx, true) {
		return fmt.Errorf("CoinbaseTxMLPVerify: the input cbTx *CoinbaseTxMLP is not well-form")
	}

	// As it has passed the above sanity-check, here only needs to collect the cmts_out.
	// Note that the TxoRCTPre and TxoRCT Txos are the first outForRing ones.
	cmts_out := make([]*ValueCommitment, cbTx.txWitness.outForRing)
	for j := 0; j < int(cbTx.txWitness.outForRing); j++ {
		switch txoInst := cbTx.txos[j].(type) {
		case *TxoRCTPre:
			cmts_out[j] = txoInst.valueCommitment

		case *TxoRCT:
			cmts_out[j] = txoInst.valueCommitment

		default:
			//	just assert
			//	should not happen
			return fmt.Errorf("CoinbaseTxMLPVerify: the input cbTx *CoinbaseTxMLP pass the sanity check and has outForRing (%d), but the %d-th one is not TxoRCTPre or TxoRCT",
				cbTx.txWitness.outForRing, j)
		}
	}

	serializedCbTxConOriginal, err := pp.SerializeCoinbaseTxMLP(cbTx, false)
	if err != nil {
		return err
	}

	if len(serializedCbTxConOriginal) == 0 {
		return fmt.Errorf("CoinbaseTxMLPVerify: serializedCbTxCon is empty/nil")
	}

	//	use digest as the message to be authenticated
	cbTxConDigest, err := Hash(serializedCbTxConOriginal)
	if err != nil {
		return err
	}

	//	verify the witness
	err = pp.verifyBalanceProofCbTx(cbTxConDigest, cbTx.txWitness.vL, cbTx.txWitness.outForRing, cmts_out, cbTx.txWitness.txCase, cbTx.txWitness.balanceProof)
	if err != nil {
		return err
	}

	return nil
}

// TransferTxMLPGen generates TransferTxMLP.
// reviewed 2023.12.19
// refactored and reviewed by Alice, 2024.07.07
// todo: review by 2024.07
// todo: review pp.CoinValueKeyVerify
func (pp *PublicParameter) TransferTxMLPGen(txInputDescs []*TxInputDescMLP, txOutputDescs []*TxOutputDescMLP, fee uint64, txMemo []byte) (*TransferTxMLP, error) {

	//	check the well-form of the inputs and outputs
	inputNum := len(txInputDescs)
	outputNum := len(txOutputDescs)
	if inputNum == 0 || outputNum == 0 {
		return nil, fmt.Errorf("TransferTxMLPGen: neither txInputDescs or txOutputDescs could be empty")
	}
	if inputNum > int(pp.paramI)+int(pp.paramISingle) {
		return nil, fmt.Errorf("TransferTxMLPGen: The input txInputDescs []*TxInputDescMLP has a size (%d) exceeds the allowed maximum value (%d)", inputNum, int(pp.paramI)+int(pp.paramISingle))
	}

	if outputNum > int(pp.paramJ)+int(pp.paramJSingle) {
		return nil, fmt.Errorf("TransferTxMLPGen: The input txInputDescs []*TxInputDescMLP has a size (%d) exceeds the allowed maximum value (%d)", outputNum, int(pp.paramJ)+int(pp.paramJSingle))
	}

	V := (uint64(1) << pp.paramN) - 1

	//	check the fee is simple, check it first
	if fee > V {
		return nil, fmt.Errorf("TransferTxMLPGen: the transaction fee (%d) is not in the scope[0, V (%d)]", fee, V)
	}

	if int64(len(txMemo)) > int64(MaxAllowedTxMemoMLPSize) {
		return nil, fmt.Errorf("TransferTxMLPGen: the input txMemo has a size (%v) not in the allowed scope", len(txMemo))
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
				// The coinValuePublicKey for RingCT-Privacy output could not be nil.
				return nil, fmt.Errorf("TransferTxMLPGen: txOutputDescs[%d].coinAddress has coinAddressType=%d, but txOutputDescs[%d].coinValuePublicKey is nil/empty", j, coinAddressType, j)
			}

			// For RCT-privacy coin, we do not apply the 0-value-coin-rule here,
			// and only apply it by public information.

		} else if coinAddressType == CoinAddressTypePublicKeyHashForSingle {
			outForSingle += 1
			vOutPublic += txOutputDescItem.value

			// skip the check on coinValuePublicKey, to allow the caller uses dummy one for some reason, e.g., safety.

			// apply the 0-value-coin-rule.
			if txOutputDescItem.value == 0 {
				return nil, fmt.Errorf("TransferTxMLPGen: txOutputDescs[%d].coinAddress has coinAddressType=%d, but txOutputDescs[%d].value is 0", j, coinAddressType, j)
			}

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

	// check the txInputDescs
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

		//	check the lgrTxoList
		//	Note that here we do not know this is a ring for ring or pseudonym-ring.
		if !pp.LgrTxoRingForSingleSanityCheck(txInputDescItem.lgrTxoList) &&
			!pp.LgrTxoRingForRingSanityCheck(txInputDescItem.lgrTxoList) {
			return nil, fmt.Errorf("TransferTxMLPGen: txInputDescs[%d].lgrTxoList is not well-form", i)
		}

		//	check the sidx
		if int(txInputDescItem.sidx) >= len(txInputDescItem.lgrTxoList) {
			return nil, fmt.Errorf("TransferTxMLPGen: txInputDescs[%d].sidx is %d, while the length of txInputDescs[%d].lgrTxoList is %d", i, txInputDescItem.sidx, i, len(txInputDescItem.lgrTxoList))
		}

		lgrTxoToSpend := txInputDescItem.lgrTxoList[txInputDescItem.sidx]
		//	Note that the previous sanity-check guarantee that lgrTxoToSpend is well-form.

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
				return nil, fmt.Errorf("TransferTxMLPGen: on the input side, the coins-to-spend with RingCT-Privacy should be at the first successive positions, but the %d -th one is not", i)
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
			copiedCoinValueSecretKey := make([]byte, len(txInputDescItem.coinValueSecretKey))
			copy(copiedCoinValueSecretKey, txInputDescItem.coinValueSecretKey)
			validValueKey, hints := pp.CoinValueKeyVerify(txInputDescItem.coinValuePublicKey, copiedCoinValueSecretKey)
			if !validValueKey {
				return nil, fmt.Errorf("TransferTxMLPGen: the coin value key pair for %d-th coin to spend, say txInputDescs[%d].coinValuePublicKey and txInputDescs[%d].coinValueSecretKey, does not match. Hints = %s", i, i, i, hints)
			}

			//	Check the value-commitment and value-ciphertext
			copy(copiedCoinValueSecretKey, txInputDescItem.coinValueSecretKey)
			valueInCmt, cmtr, err := pp.ExtractValueAndRandFromTxoMLP(lgrTxoToSpend.txo, txInputDescItem.coinValuePublicKey, copiedCoinValueSecretKey)
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
			// Note that these checks are conducted in previous pp.LgrTxoRingForRingSanityCheck(txInputDescItem.lgrTxoList).
			//lgrTxoIdsMap := make(map[string]int)
			//for t := 0; t < len(txInputDescItem.lgrTxoList); t++ {
			//	if len(txInputDescItem.lgrTxoList[t].id) == 0 {
			//		return nil, fmt.Errorf("TransferTxMLPGen: txInputDescs[%d].lgrTxoList[%d].id is nil/empty", i, t)
			//	}
			//	idString := hex.EncodeToString(txInputDescItem.lgrTxoList[t].id)
			//	if index, exists := lgrTxoIdsMap[idString]; exists {
			//		return nil, fmt.Errorf("TransferTxMLPGen: txInputDescs[%d].lgrTxoList contains repeated lgrTxoIds, say %d-th and %d-th", i, index, t)
			//	}
			//	lgrTxoIdsMap[idString] = t
			//
			//	if txInputDescItem.lgrTxoList[t].txo == nil {
			//		return nil, fmt.Errorf("TransferTxMLPGen: txInputDescs[%d].lgrTxoList[%d].txo is nil", i, t)
			//	}
			//	coinAddressTypeInRingMember := txInputDescItem.lgrTxoList[t].txo.CoinAddressType()
			//	if coinAddressTypeInRingMember != coinAddressType {
			//		//	The case of (CoinAddressTypePublicKeyForRingPre, CoinAddressTypePublicKeyForRing) is allowed
			//		if (coinAddressTypeInRingMember == CoinAddressTypePublicKeyForRingPre && coinAddressType == CoinAddressTypePublicKeyForRing) ||
			//			(coinAddressTypeInRingMember == CoinAddressTypePublicKeyForRing && coinAddressType == CoinAddressTypePublicKeyForRingPre) {
			//			//	allowed
			//		} else {
			//			return nil, fmt.Errorf("TransferTxMLPGen: txInputDescs[%d].lgrTxoList[%d].txo has differnet coinAddressType from the coin-to-spend, say txInputDescs[%d].lgrTxoList[%d]", i, t, i, txInputDescItem.sidx)
			//		}
			//	}
			//}

		} else if coinAddressType == CoinAddressTypePublicKeyHashForSingle {
			inForSingle += 1
			vInPublic += txInputDescItem.value

			////	for the CoinAddressTypePublicKeyHashForSingle, the ring must have size 1
			//if len(txInputDescItem.lgrTxoList) != 1 {
			//	return nil, fmt.Errorf("TransferTxMLPGen: the coin to spend, say txInputDescs[%d].lgrTxoList[%d] has Pseudonym-Privacy, but the size of txInputDescs[%d].lgrTxoList is not 1", i, txInputDescItem.sidx, i)
			//}

			//	check the keys
			//	coinSpendSecretKey        []byte
			//	coinSerialNumberSecretKey []byte	// 	this is skipped, to allow the caller to use a dummy one
			//	coinValuePublicKey        []byte	//	this is skipped, to allow the caller to use a dummy one
			//	coinValueSecretKey        []byte	//	this is skipped, to allow the caller to use a dummy one
			if len(txInputDescItem.coinSpendSecretKey) == 0 {
				return nil, fmt.Errorf("TransferTxMLPGen: for %d-th the coin to spend, say txInputDescs[%d].lgrTxoList[%d], the corresponding coinSpendSecretKey, say txInputDescs[%d].coinSpendSecretKey, is nil", i, i, txInputDescItem.sidx, i)
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

	//	Defer the 0-value-coin-rule to the later generation of witness.

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
		if err != nil {
			return nil, err
		}
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
	extTrTxConOriginal, err := pp.extendSerializedTransferTxContent(trTxCon, cmts_in_p)
	if err != nil {
		return nil, err
	}

	// use extTrTxConDigest
	extTrTxConDigest, err := Hash(extTrTxConOriginal)
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

		//if len(txInputDescItem.lgrTxoList) > int(pp.paramRingSizeMax) {
		//	return nil, fmt.Errorf("TransferTxMLPGen: the %d -th input has ring size (%d) exceeding the allowd maximum value (%d) ", i, len(txInputDescItem.lgrTxoList), pp.paramRingSizeMax)
		//}
		inRingSizes[i] = uint8(len(txInputDescItem.lgrTxoList)) // Note that the previous sanity-checks guarantee len(txInputDescItem.lgrTxoList) in the scope of uint8.
		elrSigs[i], err = pp.elrSignatureMLPSign(txInputDescItem.lgrTxoList, ma_ps[i], cmts_in_p[i], extTrTxConDigest,
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
		simpleSigs[i], err = pp.simpleSignatureSign(apkForSingle.t, extTrTxConDigest, askSp_ntt)
		if err != nil {
			return nil, fmt.Errorf("TransferTxMLPGen: fail to generate the simple signature for the %d -th coinAddress with CoinAddressTypePublicKeyHashForSingle", i)
		}
	}

	//	balance proof
	txCase, balanceProof, err := pp.genBalanceProofTrTx(extTrTxConDigest, uint8(inForRing), uint8(outForRing), cmts_in_p, cmts_out, vPublic, cmtrs_in_p, values_in, cmtrs_out, values_out)
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
// refactored on 2024.01.07, using err == nil or not to denote valid or invalid
// refactored and reviewed by Alice, 2024.07.07
// todo: review by 2024.07
// todo: multi-round review
func (pp *PublicParameter) TransferTxMLPVerify(trTx *TransferTxMLP) error {

	err := pp.TransferTxMLPSanityCheck(trTx, true)
	if err != nil {
		return fmt.Errorf("TransferTxMLPVerify: the input trTx *TransferTxMLP is not well-form: %s", err)
	}

	//	collect cmts_out
	cmts_out := make([]*ValueCommitment, trTx.txWitness.outForRing)
	for j := 0; j < int(trTx.txWitness.outForRing); j++ {
		switch txoInst := trTx.txos[j].(type) {
		case *TxoRCTPre:
			cmts_out[j] = txoInst.valueCommitment
		case *TxoRCT:
			cmts_out[j] = txoInst.valueCommitment
		default:
			return fmt.Errorf("TransferTxMLPVerify: This should not happen, where the %d -th (< outForRing (%d)) txo is not TxoRCTPre or TxoRCT", j, trTx.txWitness.outForRing)
		}
	}

	// prepare trTxCon which will be used in signature verifications and balance proof verifications
	trTxCon, err := pp.SerializeTransferTxMLP(trTx, false)
	if err != nil {
		return err
	}
	if len(trTxCon) == 0 {
		return fmt.Errorf("TransferTxMLPVerify: the serialzied trTxCon is empty")
	}
	// extTrTxConOriginal = trTxCon || cmt_p[0] || cmt_p[inForRing]
	extTrTxConOriginal, err := pp.extendSerializedTransferTxContent(trTxCon, trTx.txWitness.cmts_in_p)
	if err != nil {
		return err
	}
	// use extTrTxConDigest
	extTrTxConDigest, err := Hash(extTrTxConOriginal)
	if err != nil {
		return err
	}

	//	prepare addressPublicKeyForSingleMap,
	//	which will be used later to check whether the spent Pseudonym-Privacy Txos have corresponding addressPublicKeys.
	//	Also guarantee there is not addressPublicKey in txWitness.addressPublicKeyForSingles.
	addressPublicKeyForSingleMap := make(map[string]int)
	if trTx.txWitness.inForSingleDistinct > 0 {
		for i := 0; i < int(trTx.txWitness.inForSingleDistinct); i++ {
			serializedApk, err := pp.serializeAddressPublicKeyForSingle(trTx.txWitness.addressPublicKeyForSingles[i])
			if err != nil {
				return err
			}
			apkHash, err := Hash(serializedApk) //	This computation is the same as that in CoinAddressKeyForPKHSingleGen
			if err != nil {
				return err
			}
			apkHashString := hex.EncodeToString(apkHash)
			if _, exists := addressPublicKeyForSingleMap[apkHashString]; exists {
				return fmt.Errorf("TransferTxMLPVerify: there are repated addressPublicKeyForSingles in trTx.txWitness.addressPublicKeyForSingles")
			} else {
				addressPublicKeyForSingleMap[apkHashString] = 0 // the count = 0 will be used later to count the appearing times
			}
		}

		if len(addressPublicKeyForSingleMap) != int(trTx.txWitness.inForSingleDistinct) {
			//	just assert
			return fmt.Errorf("TransferTxMLPVerify: This should not happen, where len(addressPublicKeyForSingleMap)(%d) != int(trTx.txWitness.inForSingleDistinct) (%d)", len(addressPublicKeyForSingleMap), trTx.txWitness.inForSingleDistinct)
		}
	}

	//	Verify the inputs:
	//	(1) For RCT-Privacy Txo:
	//		(a) check its serial number is from the corresponding ma_ps[i]
	//		(b) verify the elsSignature
	//	(2) For the Pseudonym-Privacy Txo:
	//		(a) check its serial number is from the corresponding lgrTxo.
	//		(b) check whether the addressPublicKeyForSingleHash has corresponding addressPublicKey in txWitness.addressPublicKeyForSingles,
	//		by making use of the previous map.
	//		Note that the simpleSignature will be checked later using the distinct txWitness.addressPublicKeyForSingles.
	spentCoinSerialNumberMap := make(map[string]int) // There should not be double spending in one transaction.
	for i := 0; i < len(trTx.txInputs); i++ {

		//	serialNumber (double-spending) check inside the transaction
		snString := hex.EncodeToString(trTx.txInputs[i].serialNumber)
		if index, exists := spentCoinSerialNumberMap[snString]; exists {
			return fmt.Errorf("TransferTxMLPVerify: double-spending detected, the %d-th txInput and the %d -th txInput", i, index)
		}
		spentCoinSerialNumberMap[snString] = i

		//	sanity-check on the lgrTxoList
		//	Here we need to use the information in TxWitness, which is also a manner of double-check
		if i < int(trTx.txWitness.inForRing) {
			//	i-th serial number and elrSignature
			//	txInputs[i].serialNumber, trTx.txWitness.ma_ps[i], trTx.txWitness.cmts_in_p[i], extTrTxConDigest, trTx.txWitness.elrSigs[i]
			snFromKeyImg, err := pp.ledgerTxoSerialNumberComputeMLP(trTx.txWitness.ma_ps[i])
			if err != nil {
				return err
			}
			if bytes.Compare(snFromKeyImg, trTx.txInputs[i].serialNumber) != 0 {
				return fmt.Errorf("TransferTxMLPVerify: for the %d -th input, the computed serialNumber is different from trTx.txInputs[%d].serialNumber",
					i, i)
			}

			//	elrSignature
			err = pp.elrSignatureMLPVerify(trTx.txInputs[i].lgrTxoList, trTx.txWitness.ma_ps[i], trTx.txWitness.cmts_in_p[i], extTrTxConDigest, trTx.txWitness.elrSigs[i])
			if err != nil {
				return err
			}

		} else {
			//	i-th serial number
			// Note that for CoinAddressTypePublicKeyHashForSingle,
			// m'_a = m_a + m_r = m_r, since m_a is empty.
			m_r, err := pp.expandKIDRMLP(trTx.txInputs[i].lgrTxoList[0])
			if err != nil {
				return err
			}
			snFromLgrTxo, err := pp.ledgerTxoSerialNumberComputeMLP(m_r)
			if err != nil {
				return err
			}
			if bytes.Compare(snFromLgrTxo, trTx.txInputs[i].serialNumber) != 0 {
				return fmt.Errorf("TransferTxMLPVerify: for the %d -th input, the computed serialNumber is different from trTx.txInputs[%d].serialNumber",
					i, i)
			}

			//	txo
			switch txoInst := trTx.txInputs[i].lgrTxoList[0].txo.(type) {
			case *TxoSDN:
				//	addressPublicKeyForSingleHash shall have a corresponding addressPublicKeyForSingle in trTx.txWitness.addressPublicKeyForSingles
				apkHashString := hex.EncodeToString(txoInst.addressPublicKeyForSingleHash)
				if count, exists := addressPublicKeyForSingleMap[apkHashString]; exists {
					addressPublicKeyForSingleMap[apkHashString] = count + 1
				} else {
					return fmt.Errorf("TransferTxMLPVerify: the %d -th input is pseudonym-privacy, but there is not corresponding public key in trTx.txWitness.addressPublicKeyForSingles", i)
				}

			default:
				return fmt.Errorf("TransferTxMLPVerify: (should not happen) the %d -th input should be a TxoSDN, but it is not", i)
			}
		}
	}

	//	To guarantee that there are no dummy addressPublicKeyForSingles in trTx.txWitness.addressPublicKeyForSingles
	for apkHashString, count := range addressPublicKeyForSingleMap {
		if count == 0 {
			return fmt.Errorf("TransferTxMLPVerify: the addressPublicKeyForSingle (with Hash = %s) in trTx.txWitness.addressPublicKeyForSingles does not have corresponding spent-coin", apkHashString)
		}
	}
	//	verify the simpleSignatures
	for i := 0; i < len(trTx.txWitness.addressPublicKeyForSingles); i++ {
		err = pp.simpleSignatureVerify(trTx.txWitness.addressPublicKeyForSingles[i].t, extTrTxConDigest, trTx.txWitness.simpleSigs[i])
		if err != nil {
			return err
		}
	}

	err = pp.verifyBalanceProofTrTx(extTrTxConDigest, trTx.txWitness.inForRing, trTx.txWitness.outForRing, trTx.txWitness.cmts_in_p, cmts_out, trTx.txWitness.vPublic, trTx.txWitness.txCase, trTx.txWitness.balanceProof)
	if err != nil {
		return err
	}

	return nil
}

//	TxWitness		begin

// GetTxWitnessCbTxSerializeSizeByDesc returns the serialize size for TxWitnessCbTx according to the input coinAddressList.
// reviewed on 2024.01.01, by Alice
// reviewed by Alice, 2024.07.07
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

// GetTxWitnessTrTxSerializeSizeByDesc returns the serialize size for TxWitnessTrTx according to the input description information, say (inForRing, inForSingleDistinct, outForRing, inRingSizes, vPublic).
// reviewed by Alice, 2024.07.07
// todo: review
func (pp *PublicParameter) GetTxWitnessTrTxSerializeSizeByDesc(inForRing uint8, inForSingleDistinct uint8, outForRing uint8, inRingSizes []uint8, vPublic int64) (int, error) {
	if inForRing > pp.paramI {
		return 0, fmt.Errorf("GetTxWitnessTrTxSerializeSizeByDesc: the input inForRing (%d) exceeds the allowed maximum value (%d)", inForRing, pp.paramI)
	}

	if inForSingleDistinct > pp.paramISingleDistinct {
		return 0, fmt.Errorf("GetTxWitnessTrTxSerializeSizeByDesc: the input inForSingleDistinct (%d) exceeds the allowed maximum value (%d)", inForSingleDistinct, pp.paramISingleDistinct)
	}

	if outForRing > pp.paramJ {
		return 0, fmt.Errorf("GetTxWitnessTrTxSerializeSizeByDesc: the input outForRing (%d) exceeds the allowed maximum value (%d)", outForRing, pp.paramJ)
	}

	if len(inRingSizes) != int(inForRing) {
		return 0, fmt.Errorf("GetTxWitnessTrTxSerializeSizeByDesc: the leng of input inRingSizes (%d) does not equal the input inForRing (%d)", len(inRingSizes), inForRing)
	}

	for i := uint8(0); i < inForRing; i++ {
		if inRingSizes[i] > pp.paramRingSizeMax {
			return 0, fmt.Errorf("GetTxWitnessTrTxSerializeSizeByDesc: inRingSizes[%d] (%d) exceeds allowed maximum value", i, inRingSizes[i])
		}
	}

	return pp.TxWitnessTrTxSerializeSize(inForRing, inForSingleDistinct, outForRing, inRingSizes, vPublic)
}

//	TxWitness		end

//	TxInput		begin
//	TxInput		end

//	Serial Number	begin

// GetNullSerialNumberMLP returns null-serial-number.
// Note that this must keep the same as pqringct.GetNullSerialNumber.
// reviewed on 2023.12.07.
// reviewed by Alice, 2024.07.07
func (pp *PublicParameter) GetNullSerialNumberMLP() []byte {
	snSize := pp.ledgerTxoSerialNumberSerializeSizeMLP()
	nullSn := make([]byte, snSize)
	for i := 0; i < snSize; i++ {
		nullSn[i] = 0
	}
	return nullSn
}

// GetSerialNumberSerializeSize
// reviewed by Alice, 2024.07.07
func (pp *PublicParameter) GetSerialNumberSerializeSize() int {
	return pp.ledgerTxoSerialNumberSerializeSizeMLP()
}

//	Serial Number	end

// helper functions	begin

// genBalanceProofCbTx generates BalanceProofCbTx.
// reviewed on 2023.12.18
// reviewed on 2023.12.20
// refactored and reviewed by Alice, 2024.07.06
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
// refactored on 2024.01.08, using err == nil or not to denote valid or invalid
// refactored and reviewed by Alice, 2024.07.06
// todo: review
func (pp *PublicParameter) verifyBalanceProofCbTx(cbTxCon []byte, vL uint64, outForRing uint8, cmtRs []*ValueCommitment,
	txCase TxWitnessCbTxCase, balanceProof BalanceProof) error {
	if len(cbTxCon) == 0 {
		return fmt.Errorf("verifyBalanceProofCbTx: the input cbTxCon is nil/empty")
	}

	V := (uint64(1) << pp.paramN) - 1

	if vL > V {
		return fmt.Errorf("verifyBalanceProofCbTx: the input vL (%v) exceeds the allowed maximum value (%v)", vL, V)
	}

	if outForRing > pp.paramJ {
		return fmt.Errorf("verifyBalanceProofCbTx: the input outForRing (%d) exceeds the allowed maximum value (%d)", outForRing, pp.paramJ)
	}

	//	The 0-value-coin-rule is imposed on the transaction layer, including Witness Layer, not deep into BalanceProof Layer.
	if vL < uint64(outForRing) {
		return fmt.Errorf("verifyBalanceProofCbTx: the input vL (%v) < outForRing (%d) implies that at least one of the RCT-privacy coin has value 0", vL, outForRing)
	}

	if len(cmtRs) != int(outForRing) {
		return fmt.Errorf("verifyBalanceProofCbTx: len(cmtRs) (%d) != outForRing (%d)", len(cmtRs), outForRing)
	}
	// Here we do not conduct the ValueCommitmentSanityCheck on cmtRs[j], since it will be conducted in BalanceProof.
	//for j := 0; j < int(outForRing); j++ {
	//	if !pp.ValueCommitmentSanityCheck(cmtRs[j]) {
	//		return fmt.Errorf("verifyBalanceProofCbTx: the input cmtRs[%d] is not well-form", j)
	//	}
	//}

	if !pp.BalanceProofSanityCheck(balanceProof) {
		return fmt.Errorf("verifyBalanceProofCbTx: the input balanceProof BalanceProof is not well-form")
	}

	//	here only these simple sanity-checks are conducted. This is because
	//	verifyBalanceProofCbTx serves as a distributor, and will call concrete verifyBalanceProofXXYYZZ.

	switch bpfInst := balanceProof.(type) {
	case *BalanceProofL0R0:
		if txCase != TxWitnessCbTxCaseC0 {
			return fmt.Errorf("verifyBalanceProofCbTx: balanceProof is BalanceProofL0R0, but the txCase is not TxWitnessCbTxCaseC0")
		}
		if outForRing != 0 {
			return fmt.Errorf("verifyBalanceProofCbTx: balanceProof is BalanceProofL0R0, but the outForRing is not 0")
		}

		if vL != 0 {
			// balance is checked publicly.
			return fmt.Errorf("verifyBalanceProofCbTx: balanceProof is BalanceProofL0R0, but vL (%v) != 0", vL)
		}
		return pp.verifyBalanceProofL0R0(bpfInst)

	case *BalanceProofL0R1:
		if txCase != TxWitnessCbTxCaseC1 {
			return fmt.Errorf("verifyBalanceProofCbTx: balanceProof is BalanceProofL0R1, but the txCase is not TxWitnessCbTxCaseC1")
		}
		if outForRing != 1 {
			return fmt.Errorf("verifyBalanceProofCbTx: balanceProof is BalanceProofL0R1, but the outForRing is not 1")
		}
		return pp.verifyBalanceProofL0R1(cbTxCon, vL, cmtRs[0], bpfInst)

	case *BalanceProofLmRnGeneral:
		if txCase != TxWitnessCbTxCaseCn {
			return fmt.Errorf("verifyBalanceProofCbTx: balanceProof is BalanceProofLmRn, but the txCase is not TxWitnessCbTxCaseCn")
		}
		if outForRing < 2 {
			return fmt.Errorf("verifyBalanceProofCbTx: balanceProof is BalanceProofLmRn, but the outForRing is not >= 2")
		}
		return pp.verifyBalanceProofL0Rn(cbTxCon, outForRing, vL, cmtRs, bpfInst)

	default:
		return fmt.Errorf("verifyBalanceProofCbTx: the input balanceProof is not BalanceProofL0R0, BalanceProofL0R1, or BalanceProofLmRn")
	}

	return nil
}

// extendSerializedTransferTxContent extend the serialized TransferTxMLP Content by appending the cmt_ps.
// added on 2023.12.15
// reviewed on 2023.12.19
// reviewed by Alice, 2024.07.07
// todo: review by 2024.07.07
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
// reviewed by Alice, 2024.07.07
// todo: review by 2024.07
func (pp *PublicParameter) genBalanceProofTrTx(extTrTxCon []byte, inForRing uint8, outForRing uint8,
	cmts_in_p []*ValueCommitment, cmts_out []*ValueCommitment, vPublic int64,
	cmtrs_in_p []*PolyCNTTVec, values_in []uint64, cmtrs_out []*PolyCNTTVec, values_out []uint64) (TxWitnessTrTxCase, BalanceProof, error) {

	//	generation algorithm does not conduct sanity-check on the inputs. This is because
	//	(1) the caller is supposed to have conducted these checks and then call this generation algorithm.
	//	(2) the corresponding verification algorithm will conduct all these checks.

	var txCase TxWitnessTrTxCase
	var balanceProof BalanceProof
	var err error

	if inForRing == 0 {
		if outForRing == 0 {
			if vPublic != 0 {
				return 0, nil, fmt.Errorf("genBalanceProofTrTx: invalid case (inForRing == 0 and outForRing == 0, but vPublic != 0)")
			}
			txCase = TxWitnessTrTxCaseI0C0
			balanceProof, err = pp.genBalanceProofL0R0()
			if err != nil {
				return 0, nil, err
			}
		} else if outForRing == 1 {
			//	0 = cmt_{out,0} + vPublic
			if vPublic > 0 {
				return 0, nil, fmt.Errorf("genBalanceProofTrTx: banned case (inForRing == 0 and outForRing == 1, but vPublic > 0)")
			}
			if vPublic == 0 {
				return 0, nil, fmt.Errorf("genBalanceProofTrTx: banned case (inForRing == 0 and outForRing == 1, but vPublic == 0)")
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
				return 0, nil, fmt.Errorf("genBalanceProofTrTx: invalid case(inForRing == 0 and outForRing >= 2, but vPublic > 0)")
			}

			if vPublic == 0 {
				return 0, nil, fmt.Errorf("genBalanceProofTrTx: banned case (inForRing == 0 and outForRing >= 2, but vPublic == 0)")
			}

			// Now vPublic < 0
			if (-vPublic) < int64(outForRing) {
				return 0, nil, fmt.Errorf("genBalanceProofTrTx: banned case (inForRing == 0 and outForRing >= 2, but vPublic < 0 AND (-vPublic) < int64(outForRing))")
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
				return 0, nil, fmt.Errorf("genBalanceProofTrTx: invalid case (inForRing >= 2 and outForRing == 0, but vPublic < 0)")
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
// refactored on 2024.01.08, using err == nil or not to denote valid or invalid
// reviewed by Alice, 2024.07.07
// todo: review by 2024.07
func (pp *PublicParameter) verifyBalanceProofTrTx(extTrTxCon []byte, inForRing uint8, outForRing uint8, cmts_in_p []*ValueCommitment, cmts_out []*ValueCommitment, vPublic int64,
	txCase TxWitnessTrTxCase, balcenProof BalanceProof) error {

	//	sanity-checks	begin
	if len(extTrTxCon) == 0 {
		return fmt.Errorf("verifyBalanceProofTrTx: the input extTrTxCon is nil/empty")
	}

	if inForRing > pp.paramI {
		return fmt.Errorf("verifyBalanceProofTrTx: the input inForRing (%d) exceeds the allowed maximum value (%d)", inForRing, pp.paramI)
	}
	if outForRing > pp.paramJ {
		return fmt.Errorf("verifyBalanceProofTrTx: the input outForRing (%d) exceeds the allowed maximum value (%d)", outForRing, pp.paramJ)
	}

	if len(cmts_in_p) != int(inForRing) {
		return fmt.Errorf("verifyBalanceProofTrTx: len(cmts_in_p) (%d) is different from inForRing (%d)", len(cmts_in_p), inForRing)
	}
	// Here we do not conduct ValueCommitmentSanityCheck on cmts_in_p[i], since it will be conducted in later balanceProof.
	//for i := 0; i < int(inForRing); i++ {
	//	if !pp.ValueCommitmentSanityCheck(cmts_in_p[i]) {
	//		return fmt.Errorf("verifyBalanceProofTrTx: cmts_in_p[%d] is not well-form", i)
	//	}
	//}

	if len(cmts_out) != int(outForRing) {
		return fmt.Errorf("verifyBalanceProofTrTx: len(cmts_out) (%d) is different from outForRing (%d)", len(cmts_out), outForRing)
	}
	// Here we do not conduct ValueCommitmentSanityCheck on cmts_out[j], since it will be conducted in later balanceProof.
	//for j := 0; j < int(outForRing); j++ {
	//	if !pp.ValueCommitmentSanityCheck(cmts_out[j]) {
	//		return fmt.Errorf("verifyBalanceProofTrTx: cmts_out[%d] is not well-form", j)
	//	}
	//}

	V := uint64(1)<<pp.paramN - 1

	if vPublic > int64(V) || vPublic < -int64(V) {
		return fmt.Errorf("verifyBalanceProofTrTx: the input vPublic (%d) is not in the allowed range [-%v, %v]", vPublic, V, V)
	}

	//	sanity-checks	end

	//	Here we only conduct simple checks,
	//	since verifyBalanceProofTrTx serves as a distributor, and will call concrete verifyBalanceProofXXYYZZ.

	if inForRing == 0 {
		if outForRing == 0 {
			if vPublic != 0 {
				return fmt.Errorf("verifyBalanceProofTrTx: the case is (inForRing, outForRing) = (%d, %d), but vPublic (%d) != 0", inForRing, outForRing, vPublic)
			}
			if txCase != TxWitnessTrTxCaseI0C0 {
				return fmt.Errorf("verifyBalanceProofTrTx: the case is (inForRing, outForRing) = (%d, %d), but txCase (%d) != TxWitnessTrTxCaseI0C0", inForRing, outForRing, txCase)
			}
			switch bpfInst := balcenProof.(type) {
			case *BalanceProofL0R0:
				return pp.verifyBalanceProofL0R0(bpfInst)
			default:
				return fmt.Errorf("verifyBalanceProofTrTx: (inForRing = 0, outForRing = 0), but the input balance proof is not BalanceProofL0R0")
			}

		} else if outForRing == 1 {
			//	0 = cmt_{out,0} + vPublic
			if vPublic > 0 {
				return fmt.Errorf("verifyBalanceProofTrTx: the case is (inForRing, outForRing) = (%d, %d), but vPublic (%d) > 0", inForRing, outForRing, vPublic)
			}
			if vPublic == 0 {
				return fmt.Errorf("verifyBalanceProofTrTx: the case is banned as(inForRing, outForRing) = (%d, %d), but vPublic (%d) == 0", inForRing, outForRing, vPublic)
			}
			//  -vPublic = cmt_{out,0}
			if txCase != TxWitnessTrTxCaseI0C1 {
				return fmt.Errorf("verifyBalanceProofTrTx: the case is (inForRing, outForRing) = (%d, %d), but txCase (%d) != TxWitnessTrTxCaseI0C1", inForRing, outForRing, txCase)
			}
			switch bpfInst := balcenProof.(type) {
			case *BalanceProofL0R1:
				return pp.verifyBalanceProofL0R1(extTrTxCon, uint64(-vPublic), cmts_out[0], bpfInst)
			default:
				return fmt.Errorf("verifyBalanceProofTrTx: (inForRing = 0, outForRing = 1), but the input balance proof is not BalanceProofL0R1")
			}

		} else { //	outForRing >= 2
			//	0 = cmt_{out,0} + ... + cmt_{out, outForRing-1} + vPublic
			if vPublic > 0 {
				return fmt.Errorf("verifyBalanceProofTrTx: the case is (inForRing, outForRing) = (%d, %d), but vPublic (%d) > 0", inForRing, outForRing, vPublic)
			}

			if vPublic == 0 {
				return fmt.Errorf("verifyBalanceProofTrTx: the case is banned as (inForRing, outForRing) = (%d, %d), but vPublic (%d) > 0", inForRing, outForRing, vPublic)
			}

			if (-vPublic) < int64(outForRing) {
				return fmt.Errorf("verifyBalanceProofTrTx: the case is banned as (inForRing, outForRing, vPublic) = (%d, %d, %v), but (-vPublic) < int64(outForRing)", inForRing, outForRing, vPublic)
			}

			//	(-vPublic) = cmt_{out,0} + ... + cmt_{out, outForRing-1}
			if txCase != TxWitnessTrTxCaseI0Cn {
				return fmt.Errorf("verifyBalanceProofTrTx: the case is (inForRing, outForRing) = (%d, %d), but txCase (%d) != TxWitnessTrTxCaseI0Cn", inForRing, outForRing, txCase)
			}
			switch bpfInst := balcenProof.(type) {
			case *BalanceProofLmRnGeneral:
				return pp.verifyBalanceProofL0Rn(extTrTxCon, outForRing, uint64(-vPublic), cmts_out, bpfInst)
			default:
				return fmt.Errorf("verifyBalanceProofTrTx: (inForRing = 0, outForRing >= 2), but the input balance proof is not BalanceProofLmRn")
			}
		}
	} else if inForRing == 1 {
		if outForRing == 0 {
			//	cmt_{in,0} = vPublic
			if vPublic < 0 {
				return fmt.Errorf("verifyBalanceProofTrTx: the case is (inForRing, outForRing) = (%d, %d), but vPublic (%d) < 0", inForRing, outForRing, vPublic)
			}

			//	vPublic = cmt_{in,0}
			if txCase != TxWitnessTrTxCaseI1C0 {
				return fmt.Errorf("verifyBalanceProofTrTx: the case is (inForRing, outForRing) = (%d, %d), but txCase (%d) != TxWitnessTrTxCaseI1C0", inForRing, outForRing, txCase)
			}
			switch bpfInst := balcenProof.(type) {
			case *BalanceProofL0R1:
				return pp.verifyBalanceProofL0R1(extTrTxCon, uint64(vPublic), cmts_in_p[0], bpfInst)
			default:
				return fmt.Errorf("verifyBalanceProofTrTx: (inForRing = 1, outForRing = 0), but the input balance proof is not BalanceProofL0R1")
			}
		} else if outForRing == 1 {
			//	cmt_{in,0} = cmt_{out,0} + vPublic
			if vPublic == 0 {
				//	cmt_{in,0} = cmt_{out,0}
				if txCase != TxWitnessTrTxCaseI1C1Exact {
					return fmt.Errorf("verifyBalanceProofTrTx: the case is (inForRing, outForRing, vPublic) = (%d, %d, %v), but txCase (%d) != TxWitnessTrTxCaseI1C1Exact", inForRing, outForRing, vPublic, txCase)
				}
				switch bpfInst := balcenProof.(type) {
				case *BalanceProofL1R1:
					return pp.verifyBalanceProofL1R1(extTrTxCon, cmts_in_p[0], cmts_out[0], bpfInst)
				default:
					return fmt.Errorf("verifyBalanceProofTrTx: (inForRing = 1, outForRing = 1, vPublic = 0), but the input balance proof is not BalanceProofL1R1")
				}
			} else if vPublic > 0 {
				//	cmt_{in,0} = cmt_{out,0} + vPublic
				if txCase != TxWitnessTrTxCaseI1C1CAdd {
					return fmt.Errorf("verifyBalanceProofTrTx: the case is (inForRing, outForRing, vPublic) = (%d, %d, %v), but txCase (%d) != TxWitnessTrTxCaseI1C1CAdd", inForRing, outForRing, vPublic, txCase)
				}
				switch bpfInst := balcenProof.(type) {
				case *BalanceProofLmRnGeneral:
					return pp.verifyBalanceProofL1Rn(extTrTxCon, 1, cmts_in_p[0], cmts_out, uint64(vPublic), bpfInst)
				default:
					return fmt.Errorf("verifyBalanceProofTrTx: (inForRing = 1, outForRing = 1, vPublic > 0), but the input balance proof is not BalanceProofLmRn")
				}

			} else { // vPublic < 0
				//	cmt_{in,0} + (-vPublic) = cmt_{out,0}
				//	cmt_{out,0} = cmt_{in,0} + (-vPublic)
				if txCase != TxWitnessTrTxCaseI1C1IAdd {
					return fmt.Errorf("verifyBalanceProofTrTx: the case is (inForRing, outForRing, vPublic) = (%d, %d, %v), but txCase (%d) != TxWitnessTrTxCaseI1C1IAdd", inForRing, outForRing, vPublic, txCase)
				}
				switch bpfInst := balcenProof.(type) {
				case *BalanceProofLmRnGeneral:
					return pp.verifyBalanceProofL1Rn(extTrTxCon, 1, cmts_out[0], cmts_in_p, uint64(-vPublic), bpfInst)
				default:
					return fmt.Errorf("verifyBalanceProofTrTx: (inForRing = 1, outForRing = 1, vPublic < 0), but the input balance proof is not BalanceProofLmRn")
				}
			}
		} else { //	outForRing >= 2
			//	cmt_{in,0} = cmt_{out,0} + ...+ cmt_{out, outForRing-1} + vPublic
			if vPublic == 0 {
				//	cmt_{in,0} = cmt_{out,0} + ...+ cmt_{out, outForRing-1}
				if txCase != TxWitnessTrTxCaseI1CnExact {
					return fmt.Errorf("verifyBalanceProofTrTx: the case is (inForRing, outForRing, vPublic) = (%d, %d, %v), but txCase (%d) != TxWitnessTrTxCaseI1CnExact", inForRing, outForRing, vPublic, txCase)
				}
				switch bpfInst := balcenProof.(type) {
				case *BalanceProofLmRnGeneral:
					return pp.verifyBalanceProofL1Rn(extTrTxCon, outForRing, cmts_in_p[0], cmts_out, 0, bpfInst)
				default:
					return fmt.Errorf("verifyBalanceProofTrTx: (inForRing = 1, outForRing >= 2 , vPublic = 0), but the input balance proof is not BalanceProofLmRn")
				}

			} else if vPublic > 0 {
				//	cmt_{in,0} = cmt_{out,0} + ...+ cmt_{out, outForRing-1} + vPublic
				if txCase != TxWitnessTrTxCaseI1CnCAdd {
					return fmt.Errorf("verifyBalanceProofTrTx: the case is (inForRing, outForRing, vPublic) = (%d, %d, %v), but txCase (%d) != TxWitnessTrTxCaseI1CnCAdd", inForRing, outForRing, vPublic, txCase)
				}
				switch bpfInst := balcenProof.(type) {
				case *BalanceProofLmRnGeneral:
					return pp.verifyBalanceProofL1Rn(extTrTxCon, outForRing, cmts_in_p[0], cmts_out, uint64(vPublic), bpfInst)
				default:
					return fmt.Errorf("verifyBalanceProofTrTx: (inForRing = 1, outForRing >= 2 , vPublic > 0), but the input balance proof is not BalanceProofLmRn")
				}
			} else { // vPublic < 0
				//	cmt_{in,0} + (-vPublic) = cmt_{out,0} + ...+ cmt_{out, outForRing-1}
				//	cmt_{out,0} + ...+ cmt_{out, outForRing-1} = cmt_{in,0} + (-vPublic)
				if txCase != TxWitnessTrTxCaseI1CnIAdd {
					return fmt.Errorf("verifyBalanceProofTrTx: the case is (inForRing, outForRing, vPublic) = (%d, %d, %v), but txCase (%d) != TxWitnessTrTxCaseI1CnIAdd", inForRing, outForRing, vPublic, txCase)
				}
				switch bpfInst := balcenProof.(type) {
				case *BalanceProofLmRnGeneral:
					return pp.verifyBalanceProofLmRn(extTrTxCon, outForRing, inForRing, cmts_out, cmts_in_p, uint64(-vPublic), bpfInst)
				default:
					return fmt.Errorf("verifyBalanceProofTrTx: (inForRing = 1, outForRing >= 2 , vPublic < 0), but the input balance proof is not BalanceProofLmRn")
				}
			}
		}

	} else { //	inForRing >= 2
		if outForRing == 0 {
			//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = vPublic
			if vPublic < 0 {
				return fmt.Errorf("verifyBalanceProofTrTx: the case is (inForRing, outForRing) = (%d, %d), but vPublic (%d) < 0", inForRing, outForRing, vPublic)
			}

			//	vPublic = cmt_{in,0} + ... + cmt_{in, inForRing-1}
			if txCase != TxWitnessTrTxCaseImC0 {
				return fmt.Errorf("verifyBalanceProofTrTx: the case is (inForRing, outForRing, vPublic) = (%d, %d, %v), but txCase (%d) != TxWitnessTrTxCaseImC0", inForRing, outForRing, vPublic, txCase)
			}
			switch bpfInst := balcenProof.(type) {
			case *BalanceProofLmRnGeneral:
				return pp.verifyBalanceProofL0Rn(extTrTxCon, inForRing, uint64(vPublic), cmts_in_p, bpfInst)
			default:
				return fmt.Errorf("verifyBalanceProofTrTx: (inForRing >= 2, outForRing = 0 ), but the input balance proof is not BalanceProofLmRn")
			}

		} else if outForRing == 1 {
			//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + vPublic
			if vPublic == 0 {
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0}
				//	cmt_{out,0} = cmt_{in,0} + ... + cmt_{in, inForRing-1}
				if txCase != TxWitnessTrTxCaseImC1Exact {
					return fmt.Errorf("verifyBalanceProofTrTx: the case is (inForRing, outForRing, vPublic) = (%d, %d, %v), but txCase (%d) != TxWitnessTrTxCaseImC1Exact", inForRing, outForRing, vPublic, txCase)
				}
				switch bpfInst := balcenProof.(type) {
				case *BalanceProofLmRnGeneral:
					return pp.verifyBalanceProofL1Rn(extTrTxCon, inForRing, cmts_out[0], cmts_in_p, 0, bpfInst)
				default:
					return fmt.Errorf("verifyBalanceProofTrTx: (inForRing >= 2, outForRing = 1, vPublic = 0 ), but the input balance proof is not BalanceProofLmRn")
				}

			} else if vPublic > 0 {
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + vPublic
				if txCase != TxWitnessTrTxCaseImC1CAdd {
					return fmt.Errorf("verifyBalanceProofTrTx: the case is (inForRing, outForRing, vPublic) = (%d, %d, %v), but txCase (%d) != TxWitnessTrTxCaseImC1CAdd", inForRing, outForRing, vPublic, txCase)
				}
				switch bpfInst := balcenProof.(type) {
				case *BalanceProofLmRnGeneral:
					return pp.verifyBalanceProofLmRn(extTrTxCon, inForRing, outForRing, cmts_in_p, cmts_out, uint64(vPublic), bpfInst)
				default:
					return fmt.Errorf("verifyBalanceProofTrTx: (inForRing >= 2, outForRing = 1, vPublic > 0 ), but the input balance proof is not BalanceProofLmRn")
				}

			} else { // vPublic < 0
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} + (-vPublic) = cmt_{out,0}
				//	cmt_{out,0} = cmt_{in,0} + ... + cmt_{in, inForRing-1} + (-vPublic)
				if txCase != TxWitnessTrTxCaseImC1IAdd {
					return fmt.Errorf("verifyBalanceProofTrTx: the case is (inForRing, outForRing, vPublic) = (%d, %d, %v), but txCase (%d) != TxWitnessTrTxCaseImC1IAdd", inForRing, outForRing, vPublic, txCase)
				}
				switch bpfInst := balcenProof.(type) {
				case *BalanceProofLmRnGeneral:
					return pp.verifyBalanceProofL1Rn(extTrTxCon, inForRing, cmts_out[0], cmts_in_p, uint64(-vPublic), bpfInst)
				default:
					return fmt.Errorf("verifyBalanceProofTrTx: (inForRing >= 2, outForRing = 1, vPublic < 0 ), but the input balance proof is not BalanceProofLmRn")
				}

			}

		} else { // outForRing >= 2
			//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + ... + cmt_{out, outForRing-1} + vPublic
			if vPublic == 0 {
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + ... + cmt_{out, outForRing-1}
				if txCase != TxWitnessTrTxCaseImCnExact {
					return fmt.Errorf("verifyBalanceProofTrTx: the case is (inForRing, outForRing, vPublic) = (%d, %d, %v), but txCase (%d) != TxWitnessTrTxCaseImCnExact", inForRing, outForRing, vPublic, txCase)
				}
				switch bpfInst := balcenProof.(type) {
				case *BalanceProofLmRnGeneral:
					return pp.verifyBalanceProofLmRn(extTrTxCon, inForRing, outForRing, cmts_in_p, cmts_out, 0, bpfInst)
				default:
					return fmt.Errorf("verifyBalanceProofTrTx: (inForRing >= 2, outForRing > 1, vPublic = 0 ), but the input balance proof is not BalanceProofLmRn")
				}

			} else if vPublic > 0 {
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + ... + cmt_{out, outForRing-1} + vPublic
				if txCase != TxWitnessTrTxCaseImCnCAdd {
					return fmt.Errorf("verifyBalanceProofTrTx: the case is (inForRing, outForRing, vPublic) = (%d, %d, %v), but txCase (%d) != TxWitnessTrTxCaseImCnCAdd", inForRing, outForRing, vPublic, txCase)
				}
				switch bpfInst := balcenProof.(type) {
				case *BalanceProofLmRnGeneral:
					return pp.verifyBalanceProofLmRn(extTrTxCon, inForRing, outForRing, cmts_in_p, cmts_out, uint64(vPublic), bpfInst)
				default:
					return fmt.Errorf("verifyBalanceProofTrTx: (inForRing >= 2, outForRing > 1, vPublic > 0 ), but the input balance proof is not BalanceProofLmRn")
				}
			} else { // vPublic < 0
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} + (-vPublic) = cmt_{out,0} + ... + cmt_{out, outForRing-1}
				//	cmt_{out,0} + ... + cmt_{out, outForRing-1} = cmt_{in,0} + ... + cmt_{in, inForRing-1} + (-vPublic)
				if txCase != TxWitnessTrTxCaseImCnIAdd {
					return fmt.Errorf("verifyBalanceProofTrTx: the case is (inForRing, outForRing, vPublic) = (%d, %d, %v), but txCase (%d) != TxWitnessTrTxCaseImCnIAdd", inForRing, outForRing, vPublic, txCase)
				}
				switch bpfInst := balcenProof.(type) {
				case *BalanceProofLmRnGeneral:
					return pp.verifyBalanceProofLmRn(extTrTxCon, outForRing, inForRing, cmts_out, cmts_in_p, uint64(-vPublic), bpfInst)
				default:
					return fmt.Errorf("verifyBalanceProofTrTx: (inForRing >= 2, outForRing > 1, vPublic < 0 ), but the input balance proof is not BalanceProofLmRn")
				}
			}
		}
	}

}

//	helper functions	end

//	Sanity-Check functions	begin
//
// CoinbaseTxMLPSanityCheck checks whether the input cbTx *CoinbaseTxMLP is well-from:
// (1) cbTx is not nil;
// (2) cbTx.vin is in the allowed scope;
// (3) 0-value-coin-rule is obeyed;
// (4) cbTx.txMemo has the size in the allowed scope;
// (5) cbTx.txWitness is well-form.
// added by Alice, 2024.07.06
// todo: review by 2024.07
func (pp *PublicParameter) CoinbaseTxMLPSanityCheck(cbTx *CoinbaseTxMLP, withWitness bool) bool {
	if cbTx == nil {
		return false
	}

	V := (uint64(1) << pp.paramN) - 1

	if cbTx.vin > V {
		return false
	}

	if cbTx.vin == 0 {
		//	The special case for 0-value coin applies.
		if len(cbTx.txos) != 1 {
			return false
		}

		switch txoInst := cbTx.txos[0].(type) {
		case *TxoSDN:
			if !pp.TxoSDNSanityCheck(txoInst) {
				return false
			}

			if txoInst.value != 0 {
				return false
			}
		default:
			return false
		}
	}

	if len(cbTx.txos) == 0 || len(cbTx.txos) > int(pp.paramJ)+int(pp.paramJSingle) {
		return false
	}

	vOutPublic := uint64(0)
	outForRing := 0
	outForSingle := 0
	for i := 0; i < len(cbTx.txos); i++ {
		if !pp.TxoMLPSanityCheck(cbTx.txos[i]) {
			return false
		}
		// Conduct the sanity-check firstly, to make the following codes run normally.

		switch txoInst := cbTx.txos[i].(type) {
		case *TxoRCTPre:
			if i == outForRing {
				outForRing += 1
			} else {
				//	The coinAddresses for RingCT-Privacy should be at the fist successive positions.
				return false
			}

		case *TxoRCT:
			if i == outForRing {
				outForRing += 1
			} else {
				//	The coinAddresses for RingCT-Privacy should be at the fist successive positions.
				return false
			}

		case *TxoSDN:
			outForSingle += 1

			if txoInst.value > V {
				return false
			}
			if txoInst.value == 0 {
				if cbTx.vin != 0 {
					return false
				}
			}
			vOutPublic = vOutPublic + txoInst.value
			if vOutPublic > V {
				return false
			}

		default:
			return false
		}
	}

	if outForRing > int(pp.paramJ) {
		return false
	}

	if outForSingle > int(pp.paramJSingle) {
		return false
	}

	if outForRing+outForSingle != len(cbTx.txos) {
		return false
	}

	if cbTx.vin < vOutPublic {
		return false
	}

	//	Now cbTx.vin >= voutPublic
	vL := cbTx.vin - vOutPublic
	if vL < uint64(outForRing) {
		return false
	}

	if int64(len(cbTx.txMemo)) > int64(MaxAllowedTxMemoMLPSize) {
		return false
	}

	if withWitness {
		if !pp.TxWitnessCbTxSanityCheck(cbTx.txWitness) {
			return false
		}

		if cbTx.txWitness.vL != vL {
			return false
		}

		if int(cbTx.txWitness.outForRing) != outForRing ||
			int(cbTx.txWitness.outForSingle) != outForSingle {
			return false
		}
	}

	return true
}

// TransferTxMLPSanityCheck checks whether the input trTx *TransferTxMLP is well-from:
// (1) cbTx is not nil;
// (2) cbTx.vin is in the allowed scope;
// (3) 0-value-coin-rule is obeyed;
// (4) cbTx.txMemo has the size in the allowed scope;
// (5) cbTx.txWitness is well-form.
// added by Alice, 2024.07.07
// todo: review by 2024.07
func (pp *PublicParameter) TransferTxMLPSanityCheck(trTx *TransferTxMLP, withWitness bool) error {
	if trTx == nil {
		return fmt.Errorf("TransferTxMLPSanityCheck: the input trTx *TransferTxMLP is nil")
	}

	//	check the well-form of the inputs and outputs
	inputNum := len(trTx.txInputs)
	outputNum := len(trTx.txos)
	if inputNum == 0 {
		return fmt.Errorf("TransferTxMLPSanityCheck: the input trTx.txInputs is nil/empty")
	}

	if outputNum == 0 {
		return fmt.Errorf("TransferTxMLPSanityCheck: the input trTx.txos is nil/empty")
	}

	if inputNum > int(pp.paramI)+int(pp.paramISingle) {
		return fmt.Errorf("TransferTxMLPSanityCheck: the input trTx.txInputs has size (%d) exceeding the allowed maximum value pp.paramI + pp.paramISingle", inputNum)
	}

	if outputNum > int(pp.paramJ)+int(pp.paramJSingle) {
		return fmt.Errorf("TransferTxMLPSanityCheck: the input trTx.txos has size (%d) exceeding the allowed maximum value pp.paramJ + pp.paramJSingle", outputNum)
	}

	V := (uint64(1) << pp.paramN) - 1

	//	check the fee is simple, check it first
	if trTx.fee > V {
		return fmt.Errorf("TransferTxMLPSanityCheck: the input trTx.fee (%v) exceeds the allowed maximum value (%v)", trTx.fee, V)
	}

	if int64(len(trTx.txMemo)) > int64(MaxAllowedTxMemoMLPSize) {
		return fmt.Errorf("TransferTxMLPSanityCheck: the input trTx.txMemo has a size (%v) exceeds the allowed maximum value", len(trTx.txMemo))
	}

	//	check on the txOutputDescs
	outForRing := 0
	outForSingle := 0
	vOutPublic := trTx.fee
	for j := 0; j < outputNum; j++ {

		if !pp.TxoMLPSanityCheck(trTx.txos[j]) {
			return fmt.Errorf("TransferTxMLPSanityCheck: the input trTx.txos[%d] is not well-form", j)
		}
		//	Conduct the sanity-check firstly, to make the following codes run normally.

		switch txoInst := trTx.txos[j].(type) {
		case *TxoRCTPre:
			if j == outForRing {
				outForRing += 1
			} else {
				//	The coinAddresses for RingCT-Privacy should be at the fist successive positions.
				return fmt.Errorf("TransferTxMLPSanityCheck: the input trTx.txos[%d] is TxoRCTPre, but TxoSDN appeared previously", j)
			}

		case *TxoRCT:
			if j == outForRing {
				outForRing += 1
			} else {
				//	The coinAddresses for RingCT-Privacy should be at the fist successive positions.
				return fmt.Errorf("TransferTxMLPSanityCheck: the input trTx.txos[%d] is TxoRCT, but TxoSDN appeared previously", j)
			}

		case *TxoSDN:
			outForSingle += 1

			if txoInst.value > V {
				return fmt.Errorf("TransferTxMLPSanityCheck: the input trTx.txos[%d] is TxoSDN, but its value (%v) exceeds the allowed maximum value (%v)", j, txoInst.value, V)
			}
			if txoInst.value == 0 {
				// For TransferTx, the coin on pseudonym address could not use 0-value.
				return fmt.Errorf("TransferTxMLPSanityCheck: the input trTx.txos[%d] is TxoSDN, but its value is 0", j)
			}

			vOutPublic = vOutPublic + txoInst.value
			if vOutPublic > V {
				return fmt.Errorf("TransferTxMLPSanityCheck: the vOutPublic before and trTx.txos[%d] exceeds the allowed maximum value (%v)", j, V)
			}

		default:
			return fmt.Errorf("TransferTxMLPSanityCheck: the input trTx.txos[%d] is not TxoRCTPre, TxoRCT, or TxoSDN", j)
		}
	}

	if outForRing > int(pp.paramJ) {
		return fmt.Errorf("TransferTxMLPSanityCheck: outForRing (%d) exceeds the allowed maximum value (%d)", outForRing, pp.paramJ)
	}
	if outForSingle > int(pp.paramJSingle) {
		return fmt.Errorf("TransferTxMLPSanityCheck: outForSingle (%d) exceeds the allowed maximum value (%d)", outForRing, pp.paramJSingle)
	}
	if outForRing+outForSingle != outputNum {
		// assert
		return fmt.Errorf("TransferTxMLPSanityCheck: (shoud not happen) outForRing (%d) + outForSingle (%d) != outputNum (%d)", outForRing, outForSingle, outputNum)
	}

	// check the txInputDescs
	inForRing := 0
	inForSingle := 0
	inForSingleDistinct := 0
	vInPublic := uint64(0)
	spentCoinSerialNumberMap := make(map[string]int) // There should not be double spending in one transaction.
	//addressPublicKeyForSingleHashDistinctList := make([][]byte, 0, inputNum) // This is used to collect the list of distinct addressPublicKeyForSingleHash for the coin-to-spend in outForSingle, in order.
	addressPublicKeyForSingleHashMap := make(map[string]int) // This is used to help collect addressPublicKeyForSingleHashDistinctList, detecting the repeated ones.
	for i := 0; i < inputNum; i++ {
		if !pp.TxInputMLPSanityCheck(trTx.txInputs[i]) {
			return fmt.Errorf("TransferTxMLPSanityCheck: the input trTx.txInputs[%d] is not well-form", i)
		}

		//	double-spending check by serialNumber
		snString := hex.EncodeToString(trTx.txInputs[i].serialNumber)
		if index, exists := spentCoinSerialNumberMap[snString]; exists {
			return fmt.Errorf("TransferTxMLPSanityCheck: the input trTx.txInputs[%d].serialNumber is the same as that of trTx.txInputs[%d]", i, index)
		}
		spentCoinSerialNumberMap[snString] = i

		coinAddressType := trTx.txInputs[i].lgrTxoList[0].txo.CoinAddressType()
		// Note that the previous TxInputMLPSanityCheck can guarantee this line code run normally.
		if coinAddressType == CoinAddressTypePublicKeyForRingPre || coinAddressType == CoinAddressTypePublicKeyForRing {
			if i == inForRing {
				inForRing += 1
			} else {
				//	The coinAddresses for RingCT-Privacy should be at the fist successive positions.
				return fmt.Errorf("TransferTxMLPSanityCheck: the input trTx.txInputs[%d] is a ring, but pseudo-ring appeared before that", i)
			}

		} else if coinAddressType == CoinAddressTypePublicKeyHashForSingle {
			inForSingle += 1

			switch txoInst := trTx.txInputs[i].lgrTxoList[0].txo.(type) {
			case *TxoSDN:
				if txoInst.value > V {
					return fmt.Errorf("TransferTxMLPSanityCheck: (should not happen) the input trTx.txInputs[%d] is a TxoSDN, and its value (%v) exceeds tha allowed maximum value (%v)", i, txoInst.value, V)
				}
				vInPublic += txoInst.value
				if vInPublic > V {
					return fmt.Errorf("TransferTxMLPSanityCheck: the vInPublic (%v) before and trTx.txInputs[%d] exceeds tha allowed maximum value (%v)", vInPublic, V)
				}

				// collect the addressPublicKeyForSingleHashMap
				apkHashString := hex.EncodeToString(txoInst.addressPublicKeyForSingleHash)
				if _, exists := addressPublicKeyForSingleHashMap[apkHashString]; !exists {
					inForSingleDistinct = inForSingleDistinct + 1
					addressPublicKeyForSingleHashMap[apkHashString] = i
					//addressPublicKeyForSingleHashDistinctList = append(addressPublicKeyForSingleHashDistinctList, txoInst.addressPublicKeyForSingleHash)
				}

			default:
				// should not happen
				return fmt.Errorf("TransferTxMLPSanityCheck: (should not happen) the input trTx.txInputs[%d] has coinAddressType = CoinAddressTypePublicKeyHashForSingle, but it is not TxoSDN", i)
			}

		} else {
			// should not happen
			return fmt.Errorf("TransferTxMLPSanityCheck: (should not happen) the input trTx.txInputs[%d] is a not TxoRCTPre, TxoRCT, or TxoSDN", i)
		}
	}

	if inForRing > int(pp.paramI) {
		return fmt.Errorf("TransferTxMLPSanityCheck: inForRing (%d) exceeds the allowed maximum value (%d)", inForRing, pp.paramI)
	}

	if inForSingle > int(pp.paramISingle) {
		return fmt.Errorf("TransferTxMLPSanityCheck: inForSingle (%d) exceeds the allowed maximum value (%d)", inForSingle, pp.paramISingle)
	}

	if inForSingleDistinct > int(pp.paramISingleDistinct) {
		return fmt.Errorf("TransferTxMLPSanityCheck: inForSingleDistinct (%d) exceeds the allowed maximum value (%d)", inForSingleDistinct, pp.paramISingleDistinct)
	}

	if inForRing+inForSingle != inputNum {
		// assert
		return fmt.Errorf("TransferTxMLPSanityCheck: (should not happen) inForRing (%d) + inForSingle (%d) != inputNum (%d)", inForRing, inForSingle, inputNum)
	}
	if inForSingleDistinct > inForSingle {
		// assert
		return fmt.Errorf("TransferTxMLPSanityCheck: (should not happen) inForSingleDistinct (%d) > inForSingle (%d)", inForSingleDistinct, inForSingle)
	}
	//if len(addressPublicKeyForSingleHashDistinctList) != inForSingleDistinct {
	//	// assert
	//	return fmt.Errorf("TransferTxMLPSanityCheck: len(addressPublicKeyForSingleHashDistinctList) (%d) != inForSingleDistinct (%d)", len(addressPublicKeyForSingleHashDistinctList), inForSingleDistinct)
	//}

	//	defer the 0-value-coin-rule to later witness sanity-check

	if withWitness {
		vPublic := int64(vOutPublic) - int64(vInPublic) // Note that V << uint64.
		//	This is to have cmt_{in,1} + ... + cmt_{in,inForRing} = cmt_{out,1} + ... + cmt_{out,outForRing} + vPublic,
		//	where vPublic could be 0 or negative.
		//	(inForRing, outForRing, vPublic) will determine the balance proof type for the transaction.

		if !pp.TxWitnessTrTxSanityCheck(trTx.txWitness) {
			return fmt.Errorf("TransferTxMLPSanityCheck: trTx.txWitness is not well-form")
		}

		if int(trTx.txWitness.inForRing) != inForRing {
			return fmt.Errorf("TransferTxMLPSanityCheck: int(trTx.txWitness.inForRing) != inForRing")
		}

		if int(trTx.txWitness.inForSingle) != inForSingle {
			return fmt.Errorf("TransferTxMLPSanityCheck: int(trTx.txWitness.inForSingle) != inForSingle")
		}

		if int(trTx.txWitness.inForSingleDistinct) != inForSingleDistinct {
			return fmt.Errorf("TransferTxMLPSanityCheck: int(trTx.txWitness.inForSingleDistinct) != inForSingleDistinct")
		}

		if int(trTx.txWitness.outForRing) != outForRing {
			return fmt.Errorf("TransferTxMLPSanityCheck: int(trTx.txWitness.outForRing) != outForRing")
		}

		if int(trTx.txWitness.outForSingle) != outForSingle {
			return fmt.Errorf("TransferTxMLPSanityCheck: int(trTx.txWitness.outForSingle) != outForSingle")
		}

		if trTx.txWitness.vPublic != vPublic {
			return fmt.Errorf("TransferTxMLPSanityCheck: trTx.txWitness.vPublic != vPublic")
		}

		for i := 0; i < inForRing; i++ {
			//	Note that previous sanity-check guarantees the following check makes sense.
			if len(trTx.txInputs[i].lgrTxoList) != int(trTx.txWitness.inRingSizes[i]) {
				return fmt.Errorf("TransferTxMLPSanityCheck: len(trTx.txInputs[%d].lgrTxoList) != int(trTx.txWitness.inRingSizes[%d])", i, i)
			}
		}

	}

	return nil
}

// TxInputMLPSanityCheck checks whether the input txInputMLP *TxInputMLP is well-form:
// (1) txInputMLP is not nil;
// (2) txInputMLP.serialNumber has correct length;
// (3) txInputMLP.lgrTxoList is either a single-member-ring-for-pseudonym or a normal ring.
// added by Alice, 2024.07.07
// todo: review by 2024.07
func (pp *PublicParameter) TxInputMLPSanityCheck(txInputMLP *TxInputMLP) bool {
	if txInputMLP == nil {
		return false
	}

	if len(txInputMLP.serialNumber) != pp.ledgerTxoSerialNumberSerializeSizeMLP() {
		return false
	}

	//	txInputMLP.lgrTxoList is either a single-member-ring-for-pseudonym or a normal ring.
	if pp.LgrTxoRingForSingleSanityCheck(txInputMLP.lgrTxoList) {
		return true
	} else if pp.LgrTxoRingForRingSanityCheck(txInputMLP.lgrTxoList) {
		return true
	} else {
		return false
	}
}

//	Sanity-Check functions	end
