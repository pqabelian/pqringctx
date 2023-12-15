package pqringctx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// Tx Serialization	begin

// CoinbaseTxMLPSerializeSize compute the serializedSize for CoinbaseTxMLP.
// reviewed on 2023.12.04
// reviewed on 2023.12.07
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
// todo: review
func (pp *PublicParameter) TxInputMLPSerializeSize(txInput *TxInputMLP) (int, error) {
	if txInput == nil || len(txInput.lgrTxoList) == 0 || len(txInput.serialNumber) == 0 {
		return 0, fmt.Errorf("TxInputMLPSerializeSize: there is nil pointer in the input TxInputMLP")
	}

	var length = 0
	//	lgrTxoList   []*LgrTxoMLP
	lgrTxoNum := len(txInput.lgrTxoList)
	length = VarIntSerializeSize(uint64(lgrTxoNum))
	for i := 0; i < lgrTxoNum; i++ {
		lgrTxoSerializeSize, err := pp.lgrTxoMLPSerializeSize(txInput.lgrTxoList[i])
		if err != nil {
			return 0, nil
		}
		length = length + VarIntSerializeSize(uint64(lgrTxoSerializeSize)) + lgrTxoSerializeSize
	}

	//	serialNumber []byte
	length = length + VarIntSerializeSize(uint64(len(txInput.serialNumber))) + len(txInput.serialNumber)

	return length, nil
}

// serializeTxInputMLP serializes the input TxInputMLP to []byte.
// serializeTxInputMLP is called only SerializeTransferTxMLP() to prepare TrTxCon to be authenticated.
// added on 2023.12.14
// todo: review
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
	err = WriteVarInt(w, uint64(len(txInput.lgrTxoList)))
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
	err = writeVarBytes(w, txInput.serialNumber)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// deserializeTxInputMLP deserializes the input []byte to a TxInputMLP.
// added on 2023.12.14
// todo: review
func (pp *PublicParameter) deserializeTxInputMLP(serializedTxInputMLP []byte) (*TxInputMLP, error) {

	r := bytes.NewReader(serializedTxInputMLP)

	//	lgrTxoList   []*LgrTxoMLP
	var lgrTxoList []*LgrTxoMLP
	count, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		lgrTxoList = make([]*LgrTxoMLP, count)
		for i := uint64(0); i < count; i++ {
			serializedLgrTxo, err := readVarBytes(r, MaxAllowedLgrTxoMLPSize, "TxInputMLP.lgrTxoList[]")
			if err != nil {
				return nil, err
			}
			lgrTxoMLP, err := pp.DeserializeLgrTxoMLP(serializedLgrTxo)
			if err != nil {
				return nil, err
			}
			lgrTxoList[i] = lgrTxoMLP
		}
	} else {
		lgrTxoList = nil
	}

	//	serialNumber []byte
	var serialNumber []byte
	serialNumber, err = readVarBytes(r, MaxAllowedSerialNumberSize, "TxInputMLP.serialNumber")
	if err != nil {
		return nil, err
	}

	return &TxInputMLP{
		lgrTxoList:   lgrTxoList,
		serialNumber: serialNumber,
	}, nil
}

// TransferTxMLPSerializeSize returns the serialize size for the input TransferTxMLP.
// todo: implement pp.TxWitnessTrTxSerializeSize
func (pp *PublicParameter) TransferTxMLPSerializeSize(trTx *TransferTxMLP, withWitness bool) (int, error) {
	var length int

	//	txInputs  []*TxInputMLP
	length = VarIntSerializeSize(uint64(len(trTx.txInputs)))
	for i := 0; i < len(trTx.txInputs); i++ {
		txInputLen, err := pp.TxInputMLPSerializeSize(trTx.txInputs[i])
		if err != nil {
			return 0, err
		}
		length += VarIntSerializeSize(uint64(txInputLen)) + txInputLen
	}

	//	txos      []TxoMLP
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
		// todo
		witnessLen := pp.TxWitnessTrTxSerializeSize()
		length += VarIntSerializeSize(uint64(witnessLen)) + witnessLen
	}

	return length, nil
}

// SerializeTransferTxMLP serialize the input TransferTxMLP to []byte.
// Note that SerializeTransferTxMLP serializes the details bytes of the input and out Txos.
// todo: pp.SerializeTxWitnessTrTx
func (pp *PublicParameter) SerializeTransferTxMLP(trTx *TransferTxMLP, withWitness bool) ([]byte, error) {

	if trTx == nil || len(trTx.txInputs) == 0 || len(trTx.txos) == 0 {
		return nil, errors.New("SerializeTransferTxMLP: there is nil pointer in the input TransferTxMLP")
	}

	length, err := pp.TransferTxMLPSerializeSize(trTx, withWitness)
	if err != nil {
		return nil, err
	}

	w := bytes.NewBuffer(make([]byte, 0, length))

	//	txInputs  []*TxInputMLP
	err = WriteVarInt(w, uint64(len(trTx.txInputs)))
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
	err = WriteVarInt(w, uint64(len(trTx.txos)))
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
		// todo:
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

//	Tx Serialization	end
