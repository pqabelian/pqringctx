package pqringctx

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Tx Serialization	begin

// CoinbaseTxMLPSerializeSize compute the serializedSize for CoinbaseTxMLP.
// reviewed on 2023.12.04
// reviewed on 2023.12.07
// todo: refactor to have the same architecture with trTx
func (pp *PublicParameter) CoinbaseTxMLPSerializeSize(tx *CoinbaseTxMLP, withWitness bool) (int, error) {
	var length int

	// Vin uint64
	length = 8

	//txos []*txoMLP
	length += VarIntSerializeSize(uint64(len(tx.txos)))
	for i := 0; i < len(tx.txos); i++ {
		txoLen, err := pp.TxoMLPSerializeSize(tx.txos[i])
		if err != nil {
			return 0, nil
		}
		length += VarIntSerializeSize(uint64(txoLen)) + txoLen
	}

	//TxMemo []byte
	length += VarIntSerializeSize(uint64(len(tx.txMemo))) + len(tx.txMemo)

	// TxWitness
	if withWitness {
		witnessLen := pp.TxWitnessCbTxSerializeSize(tx.txWitness.outForRing)
		length += VarIntSerializeSize(uint64(witnessLen)) + witnessLen
	}

	return length, nil
}

// SerializeCoinbaseTxMLP serialize the input CoinbaseTxMLP to []byte.
// reviewed on 2023.12.07
// reviewed on 2023.12.14
// todo: refactor to have the same architecture with trTx
func (pp *PublicParameter) SerializeCoinbaseTxMLP(tx *CoinbaseTxMLP, withWitness bool) ([]byte, error) {
	if tx == nil || len(tx.txos) == 0 {
		return nil, fmt.Errorf("SerializeCoinbaseTxMLP: there is nil pointer in the input CoinbaseTxMLP")
	}

	length, err := pp.CoinbaseTxMLPSerializeSize(tx, withWitness)
	if err != nil {
		return nil, err
	}
	w := bytes.NewBuffer(make([]byte, 0, length))

	// Vin     uint64
	binarySerializer.PutUint64(w, binary.LittleEndian, tx.vin)

	//txos []*txo
	err = WriteVarInt(w, uint64(len(tx.txos)))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(tx.txos); i++ {
		serializedTxo, err := pp.SerializeTxoMLP(tx.txos[i])
		if err != nil {
			return nil, err
		}
		err = writeVarBytes(w, serializedTxo)
		if err != nil {
			return nil, err
		}
	}

	//TxMemo []byte
	err = writeVarBytes(w, tx.txMemo)
	if err != nil {
		return nil, err
	}

	if withWitness {

		serializedTxWitness, err := pp.SerializeTxWitnessCbTx(tx.txWitness)
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

// TxInputMLPSerializeSize returns the serialize size of the input TxInputMLP.
// added on 2023.12.14
// reviewed onn2023.12.19
// reviewed onn2023.12.20
func (pp *PublicParameter) TxInputMLPSerializeSize(txInput *TxInputMLP) (int, error) {
	if txInput == nil || len(txInput.lgrTxoList) == 0 || len(txInput.serialNumber) == 0 {
		return 0, fmt.Errorf("TxInputMLPSerializeSize: there is nil pointer in the input TxInputMLP")
	}

	var length = 0
	//	lgrTxoList   []*LgrTxoMLP
	lgrTxoNum := len(txInput.lgrTxoList)
	// length = VarIntSerializeSize(uint64(lgrTxoNum))
	if len(txInput.lgrTxoList) > int(pp.paramRingSizeMax) {
		// we shall check the ring size, to resist memory exhaustion attack.
		return 0, fmt.Errorf("TxInputMLPSerializeSize: txInput.lgrTxoList has a length(%d) exceeds the maximum supported value (%d)", len(txInput.lgrTxoList))
	}
	length = length + 1
	for i := 0; i < lgrTxoNum; i++ {
		lgrTxoSerializeSize, err := pp.lgrTxoMLPSerializeSize(txInput.lgrTxoList[i])
		if err != nil {
			return 0, nil
		}
		length = length + VarIntSerializeSize(uint64(lgrTxoSerializeSize)) + lgrTxoSerializeSize
	}

	//	serialNumber []byte
	//	serialNumber is fixed-length
	// length = length + VarIntSerializeSize(uint64(len(txInput.serialNumber))) + len(txInput.serialNumber)
	length = length + pp.ledgerTxoSerialNumberSerializeSizeMLP()

	return length, nil
}

// serializeTxInputMLP serializes the input TxInputMLP to []byte.
// serializeTxInputMLP is called only SerializeTransferTxMLP() to prepare TrTxCon to be authenticated.
// added on 2023.12.14
// reviewed on 2023.12.19
// reviewed on 2023.12.20
func (pp *PublicParameter) serializeTxInputMLP(txInput *TxInputMLP) ([]byte, error) {
	if txInput == nil || len(txInput.lgrTxoList) == 0 || len(txInput.serialNumber) == 0 {
		return nil, fmt.Errorf("serializeTxInputMLP: there is nil pointer in the input TxInputMLP")
	}

	length, err := pp.TxInputMLPSerializeSize(txInput)
	if err != nil {
		return nil, err
	}
	w := bytes.NewBuffer(make([]byte, 0, length))

	//	lgrTxoList   []*LgrTxoMLP
	// err = WriteVarInt(w, uint64(len(txInput.lgrTxoList)))
	if len(txInput.lgrTxoList) > int(pp.paramRingSizeMax) {
		// we shall check the ring size, to resist memory exhaustion attack.
		return nil, fmt.Errorf("serializeTxInputMLP: txInput.lgrTxoList has a length(%d) exceeds the maximum supported value (%d)", len(txInput.lgrTxoList))
	}
	err = w.WriteByte(uint8(len(txInput.lgrTxoList)))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(txInput.lgrTxoList); i++ {
		serializedLgrTxo, err := pp.SerializeLgrTxoMLP(txInput.lgrTxoList[i])
		if err != nil {
			return nil, err
		}
		err = writeVarBytes(w, serializedLgrTxo)
		if err != nil {
			return nil, err
		}
	}

	//	serialNumber []byte
	if len(txInput.serialNumber) != pp.ledgerTxoSerialNumberSerializeSize() {
		return nil, fmt.Errorf("serializeTxInputMLP: txInput.serialNumber has a length(%d) different from the expected one(%d)", len(txInput.serialNumber), pp.ledgerTxoSerialNumberSerializeSize())
	}
	//err = writeVarBytes(w, txInput.serialNumber)
	_, err = w.Write(txInput.serialNumber)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// deserializeTxInputMLP deserializes the input []byte to a TxInputMLP.
// added on 2023.12.14
// reviewed on 2023.12.19
// reviewed on 2023.12.20
func (pp *PublicParameter) deserializeTxInputMLP(serializedTxInputMLP []byte) (*TxInputMLP, error) {

	r := bytes.NewReader(serializedTxInputMLP)

	//	lgrTxoList   []*LgrTxoMLP
	count, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	lgrTxoList := make([]*LgrTxoMLP, count)
	for i := uint8(0); i < count; i++ {
		serializedLgrTxo, err := readVarBytes(r, MaxAllowedLgrTxoMLPSize, "TxInputMLP.lgrTxoList[]")
		if err != nil {
			return nil, err
		}
		lgrTxoList[i], err = pp.DeserializeLgrTxoMLP(serializedLgrTxo)
		if err != nil {
			return nil, err
		}
	}

	//	serialNumber []byte
	//var serialNumber []byte
	//serialNumber, err = readVarBytes(r, MaxAllowedSerialNumberSize, "TxInputMLP.serialNumber")
	serialNumber := make([]byte, pp.ledgerTxoSerialNumberSerializeSizeMLP())
	_, err = r.Read(serialNumber)
	if err != nil {
		return nil, err
	}

	return &TxInputMLP{
		lgrTxoList:   lgrTxoList,
		serialNumber: serialNumber,
	}, nil
}

// TransferTxMLPSerializeSize returns the serialize size for the input TransferTxMLP.
// todo: review
func (pp *PublicParameter) TransferTxMLPSerializeSize(trTx *TransferTxMLP, withWitness bool) (int, error) {
	var length int

	//	txInputs  []*TxInputMLP
	inputNum := len(trTx.txInputs)
	if inputNum > pp.paramI+pp.paramISingle {
		return 0, fmt.Errorf("TransferTxMLPSerializeSize: the inputNum (%d) exceeds the allowed maximum value (%d)", inputNum, pp.paramI+pp.paramISingle)
	}
	length = VarIntSerializeSize(uint64(inputNum))
	for i := 0; i < len(trTx.txInputs); i++ {
		txInputLen, err := pp.TxInputMLPSerializeSize(trTx.txInputs[i])
		if err != nil {
			return 0, err
		}
		length += VarIntSerializeSize(uint64(txInputLen)) + txInputLen
	}

	//	txos      []TxoMLP
	outputNum := len(trTx.txos)
	if outputNum > pp.paramJ+pp.paramJSingle {
		return 0, fmt.Errorf("TransferTxMLPSerializeSize: the outputNum (%d) exceeds the allowed maximum value (%d)", outputNum, pp.paramJ+pp.paramJSingle)
	}
	length += VarIntSerializeSize(uint64(len(trTx.txos)))
	for i := 0; i < len(trTx.txos); i++ {
		txoLen, err := pp.TxoMLPSerializeSize(trTx.txos[i])
		if err != nil {
			return 0, err
		}
		length += VarIntSerializeSize(uint64(txoLen)) + txoLen
	}

	//	fee       uint64
	length += 8

	//	txMemo    []byte
	length += VarIntSerializeSize(uint64(len(trTx.txMemo))) + len(trTx.txMemo)

	//	txWitness *TxWitnessTrTx
	if withWitness {
		if trTx.txWitness == nil {
			return 0, fmt.Errorf("TransferTxMLPSerializeSize: withWitness = true while trTx.txWitness is nil")
		}
		witnessLen, err := pp.TxWitnessTrTxSerializeSize(trTx.txWitness.inForRing, trTx.txWitness.inForSingleDistinct, trTx.txWitness.outForRing, trTx.txWitness.inRingSizes, trTx.txWitness.vPublic)
		if err != nil {
			return 0, err
		}
		//	Although the witnessLen can be computed from some description information, note that when deserialization extracting these description may cause inefficiency,
		//	here we use var bytes
		length += VarIntSerializeSize(uint64(witnessLen)) + witnessLen
	}

	return length, nil
}

// SerializeTransferTxMLP serialize the input TransferTxMLP to []byte.
// Note that SerializeTransferTxMLP serializes the details bytes of the input and out Txos.
// reviewed on 2023.12.19
// reviewed on 2023.12.20
func (pp *PublicParameter) SerializeTransferTxMLP(trTx *TransferTxMLP, withWitness bool) ([]byte, error) {

	if trTx == nil || len(trTx.txInputs) == 0 || len(trTx.txos) == 0 {
		return nil, fmt.Errorf("SerializeTransferTxMLP: there is nil pointer in the input TransferTxMLP")
	}

	length, err := pp.TransferTxMLPSerializeSize(trTx, withWitness)
	if err != nil {
		return nil, err
	}

	w := bytes.NewBuffer(make([]byte, 0, length))

	//	txInputs  []*TxInputMLP
	inputNum := len(trTx.txInputs)
	if inputNum > pp.paramI+pp.paramISingle {
		return nil, fmt.Errorf("SerializeTransferTxMLP: the inputNum (%d) exceeds the allowed maximum value (%d)", inputNum, pp.paramI+pp.paramISingle)
	}
	err = WriteVarInt(w, uint64(inputNum))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(trTx.txInputs); i++ {
		serializedTxInput, err := pp.serializeTxInputMLP(trTx.txInputs[i])
		if err != nil {
			return nil, err
		}
		err = writeVarBytes(w, serializedTxInput)
		if err != nil {
			return nil, err
		}
	}

	//	txos      []TxoMLP
	outputNum := len(trTx.txos)
	if outputNum > pp.paramJ+pp.paramJSingle {
		return nil, fmt.Errorf("SerializeTransferTxMLP: the outputNum (%d) exceeds the allowed maximum value (%d)", outputNum, pp.paramJ+pp.paramJSingle)
	}
	err = WriteVarInt(w, uint64(outputNum))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(trTx.txos); i++ {
		serializedTxo, err := pp.SerializeTxoMLP(trTx.txos[i])
		if err != nil {
			return nil, err
		}
		err = writeVarBytes(w, serializedTxo)
		if err != nil {
			return nil, err
		}
	}

	//	fee       uint64
	err = binarySerializer.PutUint64(w, binary.LittleEndian, trTx.fee)
	if err != nil {
		return nil, err
	}

	//	txMemo    []byte
	err = writeVarBytes(w, trTx.txMemo)
	if err != nil {
		return nil, err
	}

	//	txWitness *TxWitnessTrTx
	if withWitness {
		serializedWitness, err := pp.SerializeTxWitnessTrTx(trTx.txWitness)
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

// DeserializeTransferTxMLP deserialize []byte to TransferTxMLP.
// todo: review
func (pp *PublicParameter) DeserializeTransferTxMLP(serializedTransferTxMLP []byte, withWitness bool) (*TransferTxMLP, error) {
	if len(serializedTransferTxMLP) == 0 {
		return nil, fmt.Errorf("DeserializeTransferTxMLP: the input serializedTransferTxMLP is empty")
	}

	r := bytes.NewReader(serializedTransferTxMLP)

	//	txInputs  []*TxInputMLP
	inputNum, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if int(inputNum) > pp.paramI+pp.paramISingle {
		return nil, fmt.Errorf("DeserializeTransferTxMLP: the inputNum (%d) exceeds the allowed maximum value (%d)", inputNum, pp.paramI+pp.paramISingle)
	}

	txInputs := make([]*TxInputMLP, inputNum)
	for i := 0; i < int(inputNum); i++ {
		serializedTxInput, err := readVarBytes(r, MaxAllowedTxInputMLPSize, "TransferTxMLP.txInputs")
		if err != nil {
			return nil, err
		}
		txInputs[i], err = pp.deserializeTxInputMLP(serializedTxInput)
		if err != nil {
			return nil, err
		}
	}

	//	txos      []TxoMLP
	outputNum, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if int(outputNum) > pp.paramJ+pp.paramJSingle {
		return nil, fmt.Errorf("DeserializeTransferTxMLP: the outputNum (%d) exceeds the allowed maximum value (%d)", outputNum, pp.paramJ+pp.paramJSingle)
	}
	txos := make([]TxoMLP, outputNum)
	for i := 0; i < int(outputNum); i++ {
		serializedTxo, err := readVarBytes(r, MaxAllowedTxoMLPSize, "TransferTxMLP.txos")
		txos[i], err = pp.DeserializeTxoMLP(serializedTxo)
		if err != nil {
			return nil, err
		}
	}

	//	fee       uint64
	fee, err := binarySerializer.Uint64(r, littleEndian)
	if err != nil {
		return nil, err
	}

	//	txMemo    []byte
	txMemo, err := readVarBytes(r, MaxAllowedTxMemoMLPSize, "TransferTxMLP.txMemo")
	if err != nil {
		return nil, err
	}

	//	txWitness *TxWitnessTrTx
	var txWitness *TxWitnessTrTx
	if withWitness {
		serializedWitness, err := readVarBytes(r, MaxAllowedTxWitnessTrTxSize, "")
		if err != nil {
			return nil, err
		}

		txWitness, err = pp.DeserializeTxWitnessTrTx(serializedWitness)
		if err != nil {
			return nil, err
		}
		//	an assert/double-check
		expectedWitnessLen, err1 := pp.TxWitnessTrTxSerializeSize(txWitness.inForRing, txWitness.inForSingleDistinct, txWitness.outForRing, txWitness.inRingSizes, txWitness.vPublic)
		if err1 != nil {
			return nil, err1
		}
		if len(serializedWitness) != expectedWitnessLen {
			return nil, fmt.Errorf("DeserializeTransferTxMLP: readed serializedWitness from serializedTransferTxMLP has length %d, while the obtained txWitness has length %d", len(serializedWitness), expectedWitnessLen)
		}
	}

	return &TransferTxMLP{
		txInputs:  txInputs,
		txos:      txos,
		fee:       fee,
		txMemo:    txMemo,
		txWitness: txWitness,
	}, nil
}

//	Tx Serialization	end
