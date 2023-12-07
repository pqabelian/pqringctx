package pqringctx

import (
	"bytes"
	"encoding/binary"
	"errors"
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
func (pp *PublicParameter) SerializeCoinbaseTxMLP(tx *CoinbaseTxMLP, withWitness bool) ([]byte, error) {
	if tx == nil || len(tx.txos) == 0 {
		return nil, errors.New("SerializeCoinbaseTxMLP: there is nil pointer in CoinbaseTx")
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

//	Tx Serialization	end
