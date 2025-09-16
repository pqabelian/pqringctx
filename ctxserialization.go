package pqringctx

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Tx Serialization	begin

// CtxCoinbaseTxSerializeSize compute the serializedSize for CtxCoinbaseTx.
func (pp *PublicParameter) CtxCoinbaseTxSerializeSize(cbTx *CtxCoinbaseTx, withWitness bool) (int, error) {

	if !pp.CtxCoinbaseTxSanityCheck(cbTx, withWitness) {
		return 0, fmt.Errorf("CtxCoinbaseTxSerializeSize: the input cbTx *CoinbaseTxMLP is not well-form")
	}

	var length int

	// Vin uint64
	length = 8

	//txos []CtxTxo
	outputNum := len(cbTx.txos)
	length += VarIntSerializeSize(uint64(outputNum))
	for i := 0; i < outputNum; i++ {
		txoLen, err := pp.CtxTxoSerializeSize(cbTx.txos[i])
		if err != nil {
			return 0, err
		}
		length += VarIntSerializeSize(uint64(txoLen)) + txoLen
	}

	// TxWitness
	if withWitness {
		if cbTx.txWitness == nil {
			return 0, fmt.Errorf("CtxCoinbaseTxSerializeSize: withWitness = true while cbTx.txWitness is nil")
		}
		witnessLen, err := pp.CtxTxWitnessCbTxSerializeSize(cbTx.txWitness.outForRing)
		if err != nil {
			return 0, err
		}
		length += VarIntSerializeSize(uint64(witnessLen)) + witnessLen
	}

	return length, nil
}

// SerializeCtxCoinbaseTx serialize the input CtxCoinbaseTx to []byte.
func (pp *PublicParameter) SerializeCtxCoinbaseTx(cbTx *CtxCoinbaseTx, withWitness bool) ([]byte, error) {

	//// As CtxCoinbaseTxSerializeSize will call CtxCoinbaseTxSanityCheck, here we can skip CtxCoinbaseTxSanityCheck safely.
	//if !pp.CtxCoinbaseTxSanityCheck(cbTx, withWitness) {
	//	return nil, fmt.Errorf("SerializeCtxCoinbaseTx: the input cbTx *CtxCoinbaseTx is not well-form")
	//}

	length, err := pp.CtxCoinbaseTxSerializeSize(cbTx, withWitness)
	if err != nil {
		return nil, err
	}
	w := bytes.NewBuffer(make([]byte, 0, length))

	// vin     uint64
	binarySerializer.PutUint64(w, binary.LittleEndian, cbTx.vin)

	//	txos []CtxTxo
	outputNum := len(cbTx.txos)
	err = WriteVarInt(w, uint64(outputNum))
	if err != nil {
		return nil, err
	}
	for i := 0; i < outputNum; i++ {
		serializedTxo, err := pp.SerializeCtxTxo(cbTx.txos[i])
		if err != nil {
			return nil, err
		}
		err = writeVarBytes(w, serializedTxo)
		if err != nil {
			return nil, err
		}
	}

	//	txWitness *TxWitnessCbTx
	if withWitness {
		if cbTx.txWitness == nil {
			return nil, fmt.Errorf("SerializeCoinbaseTxMLP: withWitness = true while cbTx.txWitness is nil")
		}
		serializedTxWitness, err := pp.SerializeCtxTxWitnessCbTx(cbTx.txWitness)
		if err != nil {
			return nil, err
		}

		err = writeVarBytes(w, serializedTxWitness)
		if err != nil {
			return nil, err
		}
	}

	return w.Bytes(), nil
}

// DeserializeCtxCoinbaseTx deserialize []byte to CtxCoinbaseTx.
func (pp *PublicParameter) DeserializeCtxCoinbaseTx(serializedCtxCoinbaseTx []byte, withWitness bool) (*CtxCoinbaseTx, error) {
	if len(serializedCtxCoinbaseTx) == 0 {
		return nil, fmt.Errorf("DeserializeCtxCoinbaseTx: the input serializedCtxCoinbaseTx is empty")
	}

	r := bytes.NewReader(serializedCtxCoinbaseTx)

	// vin     uint64
	vin, err := binarySerializer.Uint64(r, littleEndian)
	if err != nil {
		return nil, err
	}

	//	txos      []CtxTxo
	outputNum, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if outputNum > uint64(pp.paramJ)+uint64(pp.paramJSingle) {
		return nil, fmt.Errorf("DeserializeCtxCoinbaseTx: the outputNum (%d) exceeds the allowed maximum value (%d)", outputNum, uint64(pp.paramJ)+uint64(pp.paramJSingle))
	}
	txos := make([]CtxTxo, outputNum)
	for i := 0; i < int(outputNum); i++ {
		serializedTxo, err := readVarBytes(r, MaxAllowedCtxTxoSize, "CtxCoinbaseTx.txos")
		if err != nil {
			return nil, err
		}
		txos[i], err = pp.DeserializeCtxTxo(serializedTxo)
		if err != nil {
			return nil, err
		}
	}

	//	txWitness *TxWitnessCbTx
	var txWitness *CtxTxWitnessCbTx
	if withWitness {
		serializedTxWitness, err := readVarBytes(r, MaxAllowedCtxTxWitnessCbTxSize, "CtxTxWitnessCbTx.txWitness")
		if err != nil {
			return nil, err
		}

		txWitness, err = pp.DeserializeCtxTxWitnessCbTx(serializedTxWitness)
		if err != nil {
			return nil, err
		}
		//	an assert/double-check
		expectedTxWitnessLen, err1 := pp.TxWitnessCbTxSerializeSize(txWitness.outForRing)
		if err1 != nil {
			return nil, err1
		}
		if len(serializedTxWitness) != expectedTxWitnessLen {
			return nil, fmt.Errorf("DeserializeCtxCoinbaseTx: serializedTxWitness from serializedCtxCoinbaseTx has length %d, while the obtained txWitness has length %d", len(serializedTxWitness), expectedTxWitnessLen)
		}
	} else {
		txWitness = nil
	}

	cbTx := &CtxCoinbaseTx{
		vin:       vin,
		txos:      txos,
		txWitness: txWitness,
	}

	if !pp.CtxCoinbaseTxSanityCheck(cbTx, withWitness) {
		return nil, fmt.Errorf("DeserializeCtxCoinbaseTx: the deserialzed CtxCoinbaseTx is not well-form")
	}

	return cbTx, nil
}

// CtxTransferTxSerializeSize returns the serialize size for the input CtxTransferTx.
func (pp *PublicParameter) CtxTransferTxSerializeSize(trTx *CtxTransferTx, withWitness bool) (int, error) {
	err := pp.CtxTransferTxSanityCheck(trTx, withWitness)
	if err != nil {
		return 0, fmt.Errorf("CtxTransferTxSerializeSize: the input trTx *CtxTransferTx is not well-form: %s", err)
	}
	// This sanity-check can guarantee the following codes run normally.

	var length = 0

	//	txInputs  []CtxTxo
	inputNum := len(trTx.txInputs)
	length = length + VarIntSerializeSize(uint64(inputNum))
	for i := 0; i < inputNum; i++ {
		txoLen, err := pp.CtxTxoSerializeSize(trTx.txInputs[i])
		if err != nil {
			return 0, err
		}
		length += VarIntSerializeSize(uint64(txoLen)) + txoLen
	}

	//	txos      []CtxTxo
	outputNum := len(trTx.txos)
	length += VarIntSerializeSize(uint64(outputNum))
	for i := 0; i < outputNum; i++ {
		txoLen, err := pp.CtxTxoSerializeSize(trTx.txos[i])
		if err != nil {
			return 0, err
		}
		length += VarIntSerializeSize(uint64(txoLen)) + txoLen
	}

	//	txWitness *CtxTxWitnessTrTx
	if withWitness {
		if trTx.txWitness == nil {
			return 0, fmt.Errorf("CtxTransferTxSerializeSize: withWitness = true while trTx.txWitness is nil")
		}
		witnessLen, err := pp.CtxTxWitnessTrTxSerializeSize(trTx.txWitness.inForRing, trTx.txWitness.outForRing, trTx.txWitness.vPublic)
		if err != nil {
			return 0, err
		}
		//	Although the witnessLen can be computed from some description information,
		//	note that when deserialization extracting these description may cause inefficiency,
		//	here we use var bytes
		length += VarIntSerializeSize(uint64(witnessLen)) + witnessLen
	}

	return length, nil
}

// SerializeCtxTransferTx serialize the input CtxTransferTx to []byte.
func (pp *PublicParameter) SerializeCtxTransferTx(trTx *CtxTransferTx, withWitness bool) ([]byte, error) {

	//// As CtxTransferTxSerializeSize will call CtxTransferTxSanityCheck, here we skip CtxTransferTxSanityCheck safely.
	//err := pp.CtxTransferTxSanityCheck(trTx, withWitness)
	//if err != nil {
	//	return nil, fmt.Errorf("SerializeCtxTransferTx: the input trTx *CtxTransferTx it not well-form: %s", err)
	//}
	////	The sanity-check here can guarantee the following codes run normally.

	length, err := pp.CtxTransferTxSerializeSize(trTx, withWitness)
	if err != nil {
		return nil, err
	}

	w := bytes.NewBuffer(make([]byte, 0, length))

	//	txInputs  []CtxTxo
	inputNum := len(trTx.txInputs)
	err = WriteVarInt(w, uint64(inputNum))
	if err != nil {
		return nil, err
	}
	for i := 0; i < inputNum; i++ {
		serializedTxo, err := pp.SerializeCtxTxo(trTx.txInputs[i])
		if err != nil {
			return nil, err
		}
		err = writeVarBytes(w, serializedTxo)
		if err != nil {
			return nil, err
		}
	}

	//	txos      []CtxTxo
	outputNum := len(trTx.txos)
	err = WriteVarInt(w, uint64(outputNum))
	if err != nil {
		return nil, err
	}
	for i := 0; i < outputNum; i++ {
		serializedTxo, err := pp.SerializeCtxTxo(trTx.txos[i])
		if err != nil {
			return nil, err
		}
		err = writeVarBytes(w, serializedTxo)
		if err != nil {
			return nil, err
		}
	}

	//	txWitness *CtxTxWitnessTrTx
	if withWitness {
		if trTx.txWitness == nil {
			return nil, fmt.Errorf("SerializeCtxTransferTx: withWitness = true while trTx.txWitness is nil")
		}

		serializedWitness, err := pp.SerializeCtxTxWitnessTrTx(trTx.txWitness)
		if err != nil {
			return nil, err
		}

		err = writeVarBytes(w, serializedWitness)
		if err != nil {
			return nil, err
		}
	}

	return w.Bytes(), nil
}

// DeserializeCtxTransferTx deserialize []byte to CtxTransferTx.
func (pp *PublicParameter) DeserializeCtxTransferTx(serializedCtxTransferTx []byte, withWitness bool) (*CtxTransferTx, error) {
	if len(serializedCtxTransferTx) == 0 {
		return nil, fmt.Errorf("DeserializeCtxTransferTx: the input serializedCtxTransferTx is empty")
	}

	r := bytes.NewReader(serializedCtxTransferTx)

	//	txInputs  []CtxTxo
	inputNum, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if inputNum > uint64(pp.paramI)+uint64(pp.paramISingle) {
		return nil, fmt.Errorf("DeserializeCtxTransferTx: the inputNum (%d) exceeds the allowed maximum value (%d)", inputNum, uint64(pp.paramI)+uint64(pp.paramISingle))
	}

	txInputs := make([]CtxTxo, inputNum)
	for i := 0; i < int(inputNum); i++ {
		serializedTxInput, err := readVarBytes(r, MaxAllowedCtxTxoSize, "CtxTransferTx.txInputs")
		if err != nil {
			return nil, err
		}
		txInputs[i], err = pp.DeserializeCtxTxo(serializedTxInput)
		if err != nil {
			return nil, err
		}
	}

	//	txos      []CtxTxo
	outputNum, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if outputNum > uint64(pp.paramJ)+uint64(pp.paramJSingle) {
		return nil, fmt.Errorf("DeserializeCtxTransferTx: the outputNum (%d) exceeds the allowed maximum value (%d)", outputNum, uint64(pp.paramJ)+uint64(pp.paramJSingle))
	}
	txos := make([]CtxTxo, outputNum)
	for i := 0; i < int(outputNum); i++ {
		serializedTxo, err := readVarBytes(r, MaxAllowedCtxTxoSize, "CtxTransferTx.txos")
		if err != nil {
			return nil, err
		}
		txos[i], err = pp.DeserializeCtxTxo(serializedTxo)
		if err != nil {
			return nil, err
		}
	}

	//	txWitness *TxWitnessTrTx
	var txWitness *CtxTxWitnessTrTx
	if withWitness {
		serializedTxWitness, err := readVarBytes(r, MaxAllowedCtxTxWitnessTrTxSize, "CtxTransferTx.txWitness")
		if err != nil {
			return nil, err
		}

		txWitness, err = pp.DeserializeCtxTxWitnessTrTx(serializedTxWitness)
		if err != nil {
			return nil, err
		}
		//	an assert/double-check
		expectedTxWitnessLen, err1 := pp.CtxTxWitnessTrTxSerializeSize(txWitness.inForRing, txWitness.outForRing, txWitness.vPublic)
		if err1 != nil {
			return nil, err1
		}
		if len(serializedTxWitness) != expectedTxWitnessLen {
			return nil, fmt.Errorf("DeserializeCtxTransferTx: readed serializedTxWitness from serializedCtxTransferTx has length %d, while the obtained txWitness has length %d", len(serializedTxWitness), expectedTxWitnessLen)
		}
	}

	transferTx := &CtxTransferTx{
		txInputs:  txInputs,
		txos:      txos,
		txWitness: txWitness,
	}

	err = pp.CtxTransferTxSanityCheck(transferTx, withWitness)
	if err != nil {
		return nil, fmt.Errorf("DeserializeCtxTransferTx: the deserialized CtxTransferTx is not well-form, %s", err)
	}

	return transferTx, nil
}

//	Tx Serialization	end
