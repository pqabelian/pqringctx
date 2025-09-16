package pqringctx

// Application Layer Convention:
// 1. The RingCT-Privacy TXO must appear continuously starting from the first position regardless of input or output, and the number does not exceed pp.paramJ
// 2. The Pseudonym-Privacy TXO can appear any position but cannot break continuity of the above constraints, and the number does not exceed pp.paramJSingle
// 3. ...

import (
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

// CtxCoinbaseTxGen generates a CtxCoinbaseTx.
func (pp *PublicParameter) CtxCoinbaseTxGen(vin uint64, txOutputDescs []*CtxTxOutputDesc) (*CtxCoinbaseTx, error) {

	V := (uint64(1) << pp.paramN) - 1

	if vin == 0 || vin > V {
		return nil, fmt.Errorf("CtxCoinbaseTxGen: vin (%d) is not in (0, V= %d]", vin, V)
	}

	if len(txOutputDescs) == 0 || len(txOutputDescs) > int(pp.paramJ)+int(pp.paramJSingle) {
		return nil, fmt.Errorf("CtxCoinbaseTxGen: the number of outputs (%d) is not in [1, %d]", len(txOutputDescs), int(pp.paramJ)+int(pp.paramJSingle))
	}

	// identify the J_ring
	outForRing := 0   // outForHidden
	outForSingle := 0 // outForPublic
	for i := 0; i < len(txOutputDescs); i++ {
		ctxTxoType := txOutputDescs[i].ctxTxoType
		if ctxTxoType == CtxTxoTypeHidden {
			if i == outForRing {
				outForRing += 1
			} else {
				//	The CtxTxOutputDesc for CtxTxoHidden should be at the fist successive positions.
				return nil, fmt.Errorf("CtxCoinbaseTxGen: the CtxTxOutputDesc for CtxTxoHidden should be at the fist successive positions, but the %d -th one is not", i)
			}

			if len(txOutputDescs[i].coinValuePublicKey) == 0 {
				return nil, fmt.Errorf("CtxCoinbaseTxGen: the CtxTxOutputDesc for CtxTxoHidden should have coinValuePublicKey, but the %d -th one does not", i)
			}

		} else if ctxTxoType == CtxTxoTypePublic {
			outForSingle += 1

			// skip the nil-check on coinValuePublicKey, to allow the caller to use a dummy coinValuePublicKey

			// apply the 0-value-coin-rule.
			if txOutputDescs[i].value == 0 {
				return nil, fmt.Errorf("CtxCoinbaseTxGen: txOutputDescs[%d] has ctxTxoType=%d, but the value is 0", i, ctxTxoType)
			}

		} else {
			return nil, fmt.Errorf("CtxCoinbaseTxGen: the ctxTxoType of the %d -th input ctxTxOutputDescs (%d) is not supported", i, ctxTxoType)
		}
	}
	if outForRing > int(pp.paramJ) {
		return nil, fmt.Errorf("CtxCoinbaseTxGen: the number of CtxTxoTypeHidden in the input ctxTxOutputDescs %d exceeds the allowd maxumim %d", outForRing, pp.paramJ)
	}

	if outForSingle > int(pp.paramJSingle) {
		return nil, fmt.Errorf("CtxCoinbaseTxGen: the number of CtxTxoTypePublic in the input ctxTxOutputDescs %d exceeds the allowd maxumim %d", outForSingle, pp.paramJSingle)
	}

	retCbTx := &CtxCoinbaseTx{}
	retCbTx.vin = vin
	retCbTx.txos = make([]CtxTxo, len(txOutputDescs))

	cmts := make([]*ValueCommitment, outForRing)
	cmtrs := make([]*PolyCNTTVec, outForRing)
	vRs := make([]uint64, outForRing)

	vout := uint64(0)
	voutPublic := uint64(0)
	// generate the output using txoGen
	for j, txOutputDescItem := range txOutputDescs {
		if txOutputDescItem.value > V {
			return nil, fmt.Errorf("CtxCoinbaseTxGen: txOutputDescs[%d].value (%d) is not in [0, %d]", j, txOutputDescItem.value, V)
		}
		vout += txOutputDescItem.value
		if vout > V {
			return nil, fmt.Errorf("CtxCoinbaseTxGen: the total output value of the fist %d output is not in [0, %d]", j+1, V)
		}

		switch txOutputDescItem.ctxTxoType {
		case CtxTxoTypeHidden:
			txoHidden, cmtr, err := pp.ctxTxoHiddenGen(txOutputDescItem.coinValuePublicKey, txOutputDescItem.value)
			if err != nil {
				return nil, err
			}
			retCbTx.txos[j] = txoHidden
			cmts[j] = txoHidden.valueCommitment
			cmtrs[j] = cmtr
			vRs[j] = txOutputDescItem.value

		case CtxTxoTypePublic:
			if txOutputDescItem.value == 0 {
				return nil, fmt.Errorf("CtxCoinbaseTxGen: txOutputDescs[%d] has ctxTxoType=CtxTxoTypePublic, but the value is 0", j)
			}

			txoPublic, err := pp.ctxTxoPublicGen(txOutputDescItem.value)
			if err != nil {
				return nil, err
			}
			retCbTx.txos[j] = txoPublic
			//cmts[j] = txoHidden.valueCommitment
			//cmtrs[j] = cmtr
			//vRs[j] = txOutputDesc.value

			voutPublic += txOutputDescItem.value

		default:
			return nil, fmt.Errorf("CtxCoinbaseTxGen: the CtxTxoType of the %d -th input txOutputDescs (%d) is not supported", j, txOutputDescItem.ctxTxoType)
		}
	}
	if vout != vin {
		return nil, fmt.Errorf("CtxCoinbaseTxGen: the total output value (%d) and the toal input value (%d) are not equal", vout, vin)
	}
	vL := vin - voutPublic //	note that vout == vin above implies vL >= 0 here.

	// 0-value-coin-rule applies:
	if vL < uint64(outForRing) {
		//	It can be deduced that at least one of the value-commitments on the output coins have value 0.
		//	It is banned by 0-value-coin-rule.
		return nil, fmt.Errorf("CtxCoinbaseTxGen: it attempting to generate CtxTxoPublic with value 0")
	}

	//	TxWitness
	serializedCbTxCon, err := pp.SerializeCtxCoinbaseTx(retCbTx, false)
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

	retCbTx.txWitness = &CtxTxWitnessCbTx{
		txCase:       txCase,
		vL:           vL,
		outForRing:   uint8(outForRing),
		outForSingle: uint8(outForSingle),
		balanceProof: balanceProof,
	}

	return retCbTx, nil
}

// CtxCoinbaseTxVerify verifies the input CtxCoinbaseTx.
func (pp *PublicParameter) CtxCoinbaseTxVerify(cbTx *CtxCoinbaseTx) error {

	if !pp.CtxCoinbaseTxSanityCheck(cbTx, true) {
		return fmt.Errorf("CtxCoinbaseTxVerify: the input cbTx *CtxCoinbaseTx is not well-form")
	}
	// Note that CtxCoinbaseTxSanityCheck has guaranteed that the data in CtxCoinbaseTx.txWitness are
	// consistent with CtxCoinbaseTx.

	// As it has passed the above sanity-check, here only needs to collect the cmts_out.
	// Note that the CtxTxoHidden Txos are the first outForRing ones.
	cmts_out := make([]*ValueCommitment, cbTx.txWitness.outForRing)
	for j := 0; j < int(cbTx.txWitness.outForRing); j++ {
		switch txoInst := cbTx.txos[j].(type) {

		case *CtxTxoHidden:
			cmts_out[j] = txoInst.valueCommitment

		default:
			//	just assert
			//	should not happen
			return fmt.Errorf("CtxCoinbaseTxVerify: the input cbTx *CtxCoinbaseTx pass the sanity check and has outForRing (%d), but the %d-th one is not CtxTxoHidden",
				cbTx.txWitness.outForRing, j)
		}
	}

	serializedCbTxConOriginal, err := pp.SerializeCtxCoinbaseTx(cbTx, false)
	if err != nil {
		return err
	}

	if len(serializedCbTxConOriginal) == 0 {
		return fmt.Errorf("CtxCoinbaseTxVerify: serializedCbTxCon is empty/nil")
	}

	//	use digest as the message to be authenticated
	cbTxConDigest, err := Hash(serializedCbTxConOriginal)
	if err != nil {
		return err
	}

	//	verify the witness
	// Note that CtxCoinbaseTxSanityCheck has guaranteed that the data in CtxCoinbaseTx.txWitness are
	// consistent with CtxCoinbaseTx.
	err = pp.verifyBalanceProofCbTx(cbTxConDigest, cbTx.txWitness.vL, cbTx.txWitness.outForRing, cmts_out, cbTx.txWitness.txCase, cbTx.txWitness.balanceProof)
	if err != nil {
		return err
	}

	return nil
}

// CtxTransferTxGen generates CtxTransferTx.
func (pp *PublicParameter) CtxTransferTxGen(txInputDescs []*CtxTxInputDesc, txOutputDescs []*CtxTxOutputDesc) (*CtxTransferTx, error) {

	//	check the well-form of the inputs and outputs
	inputNum := len(txInputDescs)
	outputNum := len(txOutputDescs)
	if inputNum == 0 || outputNum == 0 {
		return nil, fmt.Errorf("CtxTransferTxGen: neither txInputDescs or txOutputDescs could be empty")
	}
	if inputNum > int(pp.paramI)+int(pp.paramISingle) {
		return nil, fmt.Errorf("CtxTransferTxGen: The input txInputDescs []*CtxTxInputDesc has a size (%d) exceeds the allowed maximum value (%d)", inputNum, int(pp.paramI)+int(pp.paramISingle))
	}

	if outputNum > int(pp.paramJ)+int(pp.paramJSingle) {
		return nil, fmt.Errorf("CtxTransferTxGen: The input txInputDescs []*CtxTxOutputDesc has a size (%d) exceeds the allowed maximum value (%d)", outputNum, int(pp.paramJ)+int(pp.paramJSingle))
	}

	V := (uint64(1) << pp.paramN) - 1

	//	check on the txOutputDescs
	outForRing := 0
	outForSingle := 0
	vOutTotal := uint64(0)
	vOutPublic := uint64(0)
	for j := 0; j < outputNum; j++ {
		txOutputDescItem := txOutputDescs[j]
		if txOutputDescItem.value > V {
			return nil, fmt.Errorf("CtxTransferTxGen: txOutputDescs[%d].value (%d) is not in the scope [0,V(%d)]", j, txOutputDescItem.value, V)
		}
		vOutTotal += txOutputDescItem.value
		if vOutTotal > V {
			return nil, fmt.Errorf("CtxTransferTxGen: the vOutTotal of the first %d txOutputDescs[].value, say %d, exceeds V(%d)", j+1, vOutTotal, V)
		}

		if txOutputDescItem.ctxTxoType == CtxTxoTypeHidden {
			if j == outForRing {
				outForRing += 1
			} else {
				//	The CtxTxoTypeHidden should be at the fist successive positions.
				return nil, fmt.Errorf("CtxTransferTxGen: on the output side, the CtxTxoTypeHidden should be at the fist successive positions, but the %d -th one is not", j)
			}

			if len(txOutputDescItem.coinValuePublicKey) == 0 {
				// The coinValuePublicKey for CtxTxoTypeHidden could not be nil.
				return nil, fmt.Errorf("CtxTransferTxGen: txOutputDescs[%d].ctxTxoType = %d, but the coinValuePublicKey is nil/empty", j, txOutputDescItem.ctxTxoType)
			}

			// For CtxTxoTypeHidden, we do not apply the 0-value-coin-rule here,
			// and only apply it by public information.

		} else if txOutputDescItem.ctxTxoType == CtxTxoTypePublic {
			outForSingle += 1
			vOutPublic += txOutputDescItem.value

			// skip the check on coinValuePublicKey, to allow the caller uses dummy one for some reason, e.g., safety.

			// apply the 0-value-coin-rule.
			if txOutputDescItem.value == 0 {
				return nil, fmt.Errorf("CtxTransferTxGen: txOutputDescs[%d].ctxTxoType =%d, but the value is 0", j, txOutputDescItem.ctxTxoType)
			}

		} else {
			return nil, fmt.Errorf("CtxTransferTxGen: txOutputDescs[%d].ctxTxoType (%d) is not supported", j, txOutputDescItem.ctxTxoType)
		}
	}

	if outForRing > int(pp.paramJ) {
		return nil, fmt.Errorf("CtxTransferTxGen: outForRing (%d) exceeds the allowed maximum value (%d)", outForRing, pp.paramJ)
	}
	if outForSingle > int(pp.paramJSingle) {
		return nil, fmt.Errorf("CtxTransferTxGen: outForSingle (%d) exceeds the the allowed maximum value (%d)", outForSingle, pp.paramJSingle)
	}

	// check the txInputDescs
	inForRing := 0
	inForSingle := 0

	cmts_in := make([]*ValueCommitment, 0, inputNum) // This is used to collect the cmt for the coin-to-spend in inForRing.
	cmtrs_in := make([]*PolyCNTTVec, 0, inputNum)    // This is used to collect the cmtr for the coin-to-spend in inForRing.
	values_in := make([]uint64, 0, inputNum)         // This is used to collect the value for the coin-to-spend in inForRing.

	vInTotal := uint64(0)
	vInPublic := uint64(0)
	for i := 0; i < inputNum; i++ {
		txInputDescItem := txInputDescs[i]

		//	check the value
		if txInputDescItem.value > V {
			return nil, fmt.Errorf("CtxTransferTxGen: txInputDescs[%d].value (%d) is not in the scope [0, V(%d)]", i, txInputDescItem.value, V)
		}
		vInTotal += txInputDescItem.value
		if vInTotal > V {
			return nil, fmt.Errorf("CtxTransferTxGen: the vInTotal of the first %d txInputDescs[].value, say %d, exceeds V (%d)", i+1, vInTotal, V)
		}

		//	Note that here we do not know this is a ring for ring or pseudonym-ring.
		if !pp.CtxTxoSanityCheck(txInputDescItem.ctxTxo) {
			return nil, fmt.Errorf("CtxTransferTxGen: txInputDescs[%d].ctxTxo is not well-form", i)
		}

		//	identify inForRing, inForSingle

		inCtxTxoType := txInputDescItem.ctxTxo.CtxTxoType()
		if inCtxTxoType == CtxTxoTypeHidden {
			if i == inForRing {
				inForRing += 1
			} else {
				//	The CtxTxoTypeHidden should be at the fist successive positions.
				return nil, fmt.Errorf("CtxTransferTxGen: on the input side, the CtxTxoTypeHidden coins-to-spend should be at the first successive positions, but the %d -th one is not", i)
			}

			//	To spend a CtxTxoTypeHidden coin, none of the (coinValuePublicKey, coinValueSecretKey) could be nil.
			if len(txInputDescItem.coinValuePublicKey) == 0 || len(txInputDescItem.coinValueSecretKey) == 0 {
				return nil, fmt.Errorf("CtxTransferTxGen: txInputDescs[%d].ctxTxoType is CtxTxoTypeHidden, but there is nil in (coinValuePublicKey, coinValueSecretKey)", i)
			}

			//	Check the validity of (coinValuePublicKey, coinValueSecretKey)
			copiedCoinValueSecretKey := make([]byte, len(txInputDescItem.coinValueSecretKey))
			copy(copiedCoinValueSecretKey, txInputDescItem.coinValueSecretKey)
			validValueKey, hints := pp.CoinValueKeyVerify(txInputDescItem.coinValuePublicKey, copiedCoinValueSecretKey)
			if !validValueKey {
				return nil, fmt.Errorf("CtxTransferTxGen: the coin value key pair for %d-th coin to spend does not match. Hints = %s", i, hints)
			}

			//	Check the value-commitment and value-ciphertext
			copy(copiedCoinValueSecretKey, txInputDescItem.coinValueSecretKey)
			valueInCmt, cmtr, cmt, err := pp.ExtractValueAndRandFromCtxTxo(txInputDescItem.ctxTxo, txInputDescItem.coinValuePublicKey, copiedCoinValueSecretKey)
			if err != nil {
				return nil, err
			}
			if valueInCmt != txInputDescItem.value {
				return nil, fmt.Errorf("CtxTransferTxGen: txInputDescs[%d].value (%d) is different from the extratced value from the commitment (%d)",
					i, txInputDescs[i].value, valueInCmt)
			}

			//	collect the cmt, randomness, value for coin-to-spend in inForRing
			cmts_in = append(cmts_in, cmt)
			cmtrs_in = append(cmtrs_in, cmtr)
			values_in = append(values_in, valueInCmt)

		} else if inCtxTxoType == CtxTxoTypePublic {
			inForSingle += 1
			vInPublic += txInputDescItem.value

			//	coinValuePublicKey        []byte	//	this is skipped, to allow the caller to use a dummy one
			//	coinValueSecretKey        []byte	//	this is skipped, to allow the caller to use a dummy one

			//	check the public value
			value, _, _, err := pp.ExtractValueAndRandFromCtxTxo(txInputDescItem.ctxTxo, nil, nil)
			if err != nil {
				return nil, err
			}
			if value != txInputDescItem.value {
				return nil, fmt.Errorf("CtxTransferTxGen: txInputDescs[%d].value (%d) does not mathc that in txInputDescs[%d].ctxTxo (%d)",
					i, txInputDescItem.value, i, value)
			}

		} else {
			return nil, fmt.Errorf("CtxTransferTxGen: txInputDescs[%d].ctxTxo's CtxTxoType(%d) is not supported", i, inCtxTxoType)
		}
	}

	if len(cmts_in) != inForRing || len(cmtrs_in) != inForRing || len(values_in) != inForRing {
		//	assert
		return nil, fmt.Errorf("CtxTransferTxGen: it should not happen that the length of cmtrsIn (%d), values_in (%d), cmts_in (%d) is different from inForRing (%d)",
			len(cmtrs_in), len(values_in), len(cmts_in), inForRing)
	}

	if inForRing > int(pp.paramI) {
		return nil, fmt.Errorf("CtxTransferTxGen: the number of CtxTxoHidden coins to be spent (%d) exceeds the allowed maximum value (%d)", inForRing, pp.paramI)
	}
	if inForSingle > int(pp.paramISingle) {
		return nil, fmt.Errorf("CtxTransferTxGen: the number of CtxTxoPublic coins to be spent (%d) exceeds the allowed maximum value (%d)", inForSingle, pp.paramISingle)
	}

	if vOutTotal != vInTotal {
		return nil, fmt.Errorf("CtxTransferTxGen: the total value on the output side (%d) is different that on the input side (%d)", vOutTotal, vInTotal)
	}

	vPublic := int64(vOutPublic) - int64(vInPublic) // Note that V << uint64.
	//	This is to have cmt_{in,1} + ... + cmt_{in,inForRing} = cmt_{out,1} + ... + cmt_{out,outForRing} + vPublic,
	//	where vPublic could be 0 or negative.
	//	(inForRing, outForRing, vPublic) will determine the balance proof type for the transaction.

	//	Defer the 0-value-coin-rule to the later generation of witness.

	trTx := &CtxTransferTx{}
	trTx.txInputs = make([]CtxTxo, inputNum)
	trTx.txos = make([]CtxTxo, outputNum)
	// trTx.txWitness

	//	fill trTx.txos
	cmts_out := make([]*ValueCommitment, outForRing)
	cmtrs_out := make([]*PolyCNTTVec, outForRing)
	values_out := make([]uint64, outForRing)

	for j := 0; j < outputNum; j++ {
		txOutputDescItem := txOutputDescs[j]

		switch txOutputDescItem.ctxTxoType {
		case CtxTxoTypeHidden:
			txoHidden, cmtr, err := pp.ctxTxoHiddenGen(txOutputDescItem.coinValuePublicKey, txOutputDescItem.value)
			if err != nil {
				return nil, err
			}
			trTx.txos[j] = txoHidden

			cmts_out[j] = txoHidden.valueCommitment
			cmtrs_out[j] = cmtr
			values_out[j] = txOutputDescItem.value

		case CtxTxoTypePublic:
			txoPublic, err := pp.ctxTxoPublicGen(txOutputDescItem.value)
			if err != nil {
				return nil, err
			}
			trTx.txos[j] = txoPublic
			//cmts_out[j] = txoHidden.valueCommitment
			//cmtrs_out[j] = cmtr
			//values_out[j] = txOutputDescItem.value

		default:
			return nil, fmt.Errorf("CtxTransferTxGen: txOutputDescs[%d].ctxTxoType (%d) is not supported",
				j, txOutputDescItem.ctxTxoType)
		}
	}

	//	fill trTx.txInputs
	for i := 0; i < inputNum; i++ {
		trTx.txInputs[i] = txInputDescs[i].ctxTxo
	}

	cmts_in_p := cmts_in[0:inForRing]
	cmtrs_in_p := cmtrs_in[0:inForRing]
	values_in = values_in[0:inForRing]

	// trTxCon
	trTxCon, err := pp.SerializeCtxTransferTx(trTx, false)
	if err != nil {
		return nil, err
	}

	// use extTrTxConDigest
	trTxConDigest, err := Hash(trTxCon)
	if err != nil {
		return nil, err
	}

	//	balance proof
	txCase, balanceProof, err := pp.genBalanceProofTrTx(trTxConDigest, uint8(inForRing), uint8(outForRing), cmts_in_p, cmts_out, vPublic, cmtrs_in_p, values_in, cmtrs_out, values_out)
	if err != nil {
		return nil, err
	}

	trTx.txWitness = &CtxTxWitnessTrTx{
		txCase:       txCase,
		inForRing:    uint8(inForRing),
		inForSingle:  uint8(inForSingle),
		outForRing:   uint8(outForRing),
		outForSingle: uint8(outForSingle),
		vPublic:      vPublic,
		balanceProof: balanceProof,
	}

	return trTx, nil

}

// CtxTransferTxVerify verifies CtxTransferTx.
func (pp *PublicParameter) CtxTransferTxVerify(trTx *CtxTransferTx) error {

	err := pp.CtxTransferTxSanityCheck(trTx, true)
	if err != nil {
		return fmt.Errorf("CtxTransferTxVerify: the input trTx *CtxTransferTx is not well-form: %s", err)
	}

	// Note that CtxTransferTxSanityCheck has guaranteed that trTx.txWitness has data
	// that are consistent with trTx, e.g., inForRing.

	//	collect cmts_in
	cmts_in_p := make([]*ValueCommitment, trTx.txWitness.inForRing)
	for i := 0; i < int(trTx.txWitness.inForRing); i++ {
		switch txoInst := trTx.txInputs[i].(type) {
		case *CtxTxoHidden:
			cmts_in_p[i] = txoInst.valueCommitment
		default:
			return fmt.Errorf("CtxTransferTxVerify: This should not happen, where the %d -th (< inForRing (%d)) txo is not CtxTxoHidden", i, trTx.txWitness.inForRing)
		}
	}

	//	collect cmts_out
	cmts_out := make([]*ValueCommitment, trTx.txWitness.outForRing)
	for j := 0; j < int(trTx.txWitness.outForRing); j++ {
		switch txoInst := trTx.txos[j].(type) {
		case *CtxTxoHidden:
			cmts_out[j] = txoInst.valueCommitment
		default:
			return fmt.Errorf("CtxTransferTxVerify: This should not happen, where the %d -th (< outForRing (%d)) txo is not CtxTxoPublic", j, trTx.txWitness.outForRing)
		}
	}

	// prepare trTxCon which will be used in signature verifications and balance proof verifications
	trTxCon, err := pp.SerializeCtxTransferTx(trTx, false)
	if err != nil {
		return err
	}
	if len(trTxCon) == 0 {
		return fmt.Errorf("CtxTransferTxVerify: the serialzied trTxCon is empty")
	}

	// use trTxConDigest
	trTxConDigest, err := Hash(trTxCon)
	if err != nil {
		return err
	}

	// Note that the validity between trTx.txWitness's fields and trTx's fields have been checked in CtxTransferTxSanityCheck.
	err = pp.verifyBalanceProofTrTx(trTxConDigest, trTx.txWitness.inForRing, trTx.txWitness.outForRing, cmts_in_p, cmts_out, trTx.txWitness.vPublic, trTx.txWitness.txCase, trTx.txWitness.balanceProof)
	if err != nil {
		return err
	}

	return nil
}

//	TxWitness		begin
//	TxWitness		end

//	helper functions	begin
//	helper functions	end

//	Sanity-Check functions	begin
//
// CtxCoinbaseTxSanityCheck checks whether the input cbTx *CtxCoinbaseTx is well-from:
// (1) cbTx is not nil;
// (2) cbTx.vin is in the allowed scope;
// (3) 0-value-coin-rule is obeyed;
// (4) cbTx.txWitness is well-form.
func (pp *PublicParameter) CtxCoinbaseTxSanityCheck(cbTx *CtxCoinbaseTx, withWitness bool) bool {
	if cbTx == nil {
		return false
	}

	V := (uint64(1) << pp.paramN) - 1

	if cbTx.vin == 0 || cbTx.vin > V {
		return false
	}

	if len(cbTx.txos) == 0 || len(cbTx.txos) > int(pp.paramJ)+int(pp.paramJSingle) {
		return false
	}

	vOutPublic := uint64(0)
	outForRing := 0
	outForSingle := 0
	for i := 0; i < len(cbTx.txos); i++ {
		if !pp.CtxTxoSanityCheck(cbTx.txos[i]) {
			return false
		}
		// Conduct the sanity-check firstly, to make the following codes run normally.

		switch txoInst := cbTx.txos[i].(type) {
		case *CtxTxoHidden:
			if i == outForRing {
				outForRing += 1
			} else {
				//	The coinAddresses for RingCT-Privacy should be at the fist successive positions.
				return false
			}

		case *CtxTxoPublic:
			outForSingle += 1

			if txoInst.value > V || txoInst.value == 0 {
				return false
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

	if withWitness {
		if !pp.CtxTxWitnessCbTxSanityCheck(cbTx.txWitness) {
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

// CtxTransferTxSanityCheck checks whether the input trTx *CtxTransferTx is well-from:
// (1) trTx is not nil;
// (2) trTx.txInputs is well-form;
// (3) trTx.txos is well-form;
// (4) trTx.txWitness is well-form.
func (pp *PublicParameter) CtxTransferTxSanityCheck(trTx *CtxTransferTx, withWitness bool) error {
	if trTx == nil {
		return fmt.Errorf("CtxTransferTxSanityCheck: the input trTx *CtxTransferTx is nil")
	}

	//	check the well-form of the inputs and outputs
	inputNum := len(trTx.txInputs)
	outputNum := len(trTx.txos)
	if inputNum == 0 {
		return fmt.Errorf("CtxTransferTxSanityCheck: the input trTx.txInputs is nil/empty")
	}

	if outputNum == 0 {
		return fmt.Errorf("CtxTransferTxSanityCheck: the input trTx.txos is nil/empty")
	}

	if inputNum > int(pp.paramI)+int(pp.paramISingle) {
		return fmt.Errorf("CtxTransferTxSanityCheck: the input trTx.txInputs has size (%d) exceeding the allowed maximum value pp.paramI + pp.paramISingle", inputNum)
	}

	if outputNum > int(pp.paramJ)+int(pp.paramJSingle) {
		return fmt.Errorf("CtxTransferTxSanityCheck: the input trTx.txos has size (%d) exceeding the allowed maximum value pp.paramJ + pp.paramJSingle", outputNum)
	}

	V := (uint64(1) << pp.paramN) - 1

	//	check on the txos []CtxTxo
	outForRing := 0
	outForSingle := 0
	vOutPublic := uint64(0)
	for j := 0; j < outputNum; j++ {

		if !pp.CtxTxoSanityCheck(trTx.txos[j]) {
			return fmt.Errorf("CtxTransferTxSanityCheck: the input trTx.txos[%d] is not well-form", j)
		}
		//	Conduct the sanity-check firstly, to make the following codes run normally.

		switch txoInst := trTx.txos[j].(type) {
		case *CtxTxoHidden:
			if j == outForRing {
				outForRing += 1
			} else {
				//	The CtxTxoHidden should be at the fist successive positions.
				return fmt.Errorf("CtxTransferTxSanityCheck: the input trTx.txos[%d] is CtxTxoHidden, but CtxTxoPublic appeared previously", j)
			}

		case *CtxTxoPublic:
			outForSingle += 1

			if txoInst.value > V || txoInst.value == 0 {
				return fmt.Errorf("CtxTransferTxSanityCheck: the input trTx.txos[%d] is CtxTxoPublic, but its value (%v) is not in the allowed scope [1, %d]", j, txoInst.value, V)
			}

			vOutPublic = vOutPublic + txoInst.value
			if vOutPublic > V {
				return fmt.Errorf("CtxTransferTxSanityCheck: the vOutPublic before and trTx.txos[%d] exceeds the allowed maximum value (%v)", j, V)
			}

		default:
			return fmt.Errorf("CtxTransferTxSanityCheck: the input trTx.txos[%d] is not CtxTxoHidden or CtxTxoPublic", j)
		}
	}

	if outForRing > int(pp.paramJ) {
		return fmt.Errorf("CtxTransferTxSanityCheck: outForRing (%d) exceeds the allowed maximum value (%d)", outForRing, pp.paramJ)
	}
	if outForSingle > int(pp.paramJSingle) {
		return fmt.Errorf("CtxTransferTxSanityCheck: outForSingle (%d) exceeds the allowed maximum value (%d)", outForSingle, pp.paramJSingle)
	}
	if outForRing+outForSingle != outputNum {
		// assert
		return fmt.Errorf("CtxTransferTxSanityCheck: (shoud not happen) outForRing (%d) + outForSingle (%d) != outputNum (%d)", outForRing, outForSingle, outputNum)
	}

	// check the txInputs []CtxTxo
	inForRing := 0
	inForSingle := 0
	vInPublic := uint64(0)
	for i := 0; i < inputNum; i++ {
		if !pp.CtxTxoSanityCheck(trTx.txInputs[i]) { // note that the CtxTxoType is checked in SanityCheck.
			return fmt.Errorf("CtxTransferTxSanityCheck: the input trTx.txInputs[%d] is not well-form", i)
		}

		switch txoInst := trTx.txInputs[i].(type) {
		case *CtxTxoHidden:
			if i == inForRing {
				inForRing += 1
			} else {
				//	The CtxTxoHidden should be at the fist successive positions.
				return fmt.Errorf("CtxTransferTxSanityCheck: the input trTx.txInputs[%d] is a CtxTxoHidden, but CtxTxoPublic appeared before that", i)
			}

		case *CtxTxoPublic:
			inForSingle += 1

			if txoInst.value > V || txoInst.value == 0 {
				return fmt.Errorf("CtxTransferTxSanityCheck: (should not happen) trTx.txInputs[%d] value (%d) is not in the allowed scope [1, %d]", i, txoInst.value, V)
			}

			vInPublic += txoInst.value
			if vInPublic > V {
				return fmt.Errorf("CtxTransferTxSanityCheck: the vInPublic (%v) before and trTx.txInputs[%d] exceeds tha allowed maximum value (%v)", vInPublic, i, V)
			}

		default:
			// should not happen
			return fmt.Errorf("CtxTransferTxSanityCheck: (should not happen) the input trTx.txInputs[%d] is a not CtxTxoHidden or CtxTxoPublic", i)
		}
	}

	if inForRing > int(pp.paramI) {
		return fmt.Errorf("CtxTransferTxSanityCheck: inForRing (%d) exceeds the allowed maximum value (%d)", inForRing, pp.paramI)
	}

	if inForSingle > int(pp.paramISingle) {
		return fmt.Errorf("CtxTransferTxSanityCheck: inForSingle (%d) exceeds the allowed maximum value (%d)", inForSingle, pp.paramISingle)
	}

	if inForRing+inForSingle != inputNum {
		// assert
		return fmt.Errorf("CtxTransferTxSanityCheck: (should not happen) inForRing (%d) + inForSingle (%d) != inputNum (%d)", inForRing, inForSingle, inputNum)
	}

	//	defer the 0-value-coin-rule to later witness sanity-check

	if withWitness {
		vPublic := int64(vOutPublic) - int64(vInPublic) // Note that V << uint64.
		//	This is to have cmt_{in,1} + ... + cmt_{in,inForRing} = cmt_{out,1} + ... + cmt_{out,outForRing} + vPublic,
		//	where vPublic could be 0 or negative.
		//	(inForRing, outForRing, vPublic) will determine the balance proof type for the transaction.

		if !pp.CtxTxWitnessTrTxSanityCheck(trTx.txWitness) {
			return fmt.Errorf("CtxTransferTxSanityCheck: trTx.txWitness is not well-form")
		}

		if int(trTx.txWitness.inForRing) != inForRing {
			return fmt.Errorf("CtxTransferTxSanityCheck: int(trTx.txWitness.inForRing) != inForRing")
		}

		if int(trTx.txWitness.inForSingle) != inForSingle {
			return fmt.Errorf("CtxTransferTxSanityCheck: int(trTx.txWitness.inForSingle) != inForSingle")
		}

		if int(trTx.txWitness.outForRing) != outForRing {
			return fmt.Errorf("CtxTransferTxSanityCheck: int(trTx.txWitness.outForRing) != outForRing")
		}

		if int(trTx.txWitness.outForSingle) != outForSingle {
			return fmt.Errorf("CtxTransferTxSanityCheck: int(trTx.txWitness.outForSingle) != outForSingle")
		}

		if trTx.txWitness.vPublic != vPublic {
			return fmt.Errorf("CtxTransferTxSanityCheck: trTx.txWitness.vPublic != vPublic")
		}

	}

	return nil
}

//	Sanity-Check functions	end
