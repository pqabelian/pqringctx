package pqringctx

type CtxTxoType uint8

const (
	CtxTxoTypeHidden CtxTxoType = 0
	CtxTxoTypePublic CtxTxoType = 1
)

// CtxCoinbaseTx is defined for CtxCoinbaseTx.
// review done 2025.12.21
type CtxCoinbaseTx struct {
	vin       uint64
	txos      []CtxTxo
	txWitness *CtxTxWitnessCbTx
}

// CtxTransferTx handles only the balance proof between the input side and output side.
// review done 2025.12.21
type CtxTransferTx struct {
	txInputs  []CtxTxo
	txos      []CtxTxo
	txWitness *CtxTxWitnessTrTx
}

// CtxTxOutputDesc describes the information for generating CtxTxo,
// for generating CtxCoinbaseTx and CtxTransferTx.
// As the generated CtxTxo will have CtxTxoType, CtxTxOutputDesc is uniform for multi-privacy-levels.
// In particular, to generate a CtxTxoPublic, the coinValuePublicKey could be nil.
// review done 2025.12.21
// todo: 2025.12.21 future, adjust the position of value to the second
type CtxTxOutputDesc struct {
	ctxTxoType         CtxTxoType
	coinValuePublicKey []byte //	This is optional, could be nil
	value              uint64
}

// CtxTxInputDesc describe the information for a CtxTxo to be consumed, for generating CtxTransferTx.
// As the consumed CtxTxo may have different privacy-levels, CtxTxInputDesc is uniform for multi-privacy-levels.
// In particular, if the CtxTxo to consumed is CtxTxoPublic,
// the coinSerialNumberSecretKey, coinValuePK, and coinValueSK will be nil.
// review done 2025.12.21
// todo: 2025.12.21 future, adjust the position of value to the second
type CtxTxInputDesc struct {
	ctxTxo             CtxTxo
	coinValuePublicKey []byte //	This is optional, could be nil
	coinValueSecretKey []byte //	This is optional, could be nil
	value              uint64
}

// New functions for TxInputDesc and TxOutputDesc 	begin

// NewCtxTxOutputDesc constructs a new CtxTxOutputDesc from the input (ctxTxoType, coinValuePK, value).
// review done 2025.12.21
func NewCtxTxOutputDesc(ctxTxoType CtxTxoType, coinValuePublicKey []byte, value uint64) *CtxTxOutputDesc {
	return &CtxTxOutputDesc{
		ctxTxoType:         ctxTxoType,
		coinValuePublicKey: coinValuePublicKey,
		value:              value,
	}
}

// NewCtxTxInputDesc constructs a new CtxTxInputDesc from the input (ctxTxo, coinValuePK, coinValueSecretKey, value).
// review done 2025.12.21
func NewCtxTxInputDesc(ctxTxo CtxTxo, coinValuePublicKey []byte, coinValueSecretKey []byte, value uint64) *CtxTxInputDesc {
	return &CtxTxInputDesc{
		ctxTxo:             ctxTxo,
		coinValuePublicKey: coinValuePublicKey,
		coinValueSecretKey: coinValueSecretKey,
		value:              value,
	}
}

//	New functions for TxInputDesc and TxOutputDesc 	end

// New and Get functions for Transactions	begin

// NewCtxCoinbaseTx constructs a new CtxCoinbaseTx using the input (vin uint64, txos []CtxTxo, txWitnessCbTx *CtxTxWitnessCbTx).
// review done 2025.12.21
func NewCtxCoinbaseTx(vin uint64, txos []CtxTxo, txWitnessCbTx *CtxTxWitnessCbTx) *CtxCoinbaseTx {
	return &CtxCoinbaseTx{
		vin:       vin,
		txos:      txos,
		txWitness: txWitnessCbTx,
	}
}

// NewCtxTransferTx constructs a new CtxTransferTx using the input
// (txInputs []CtxTxo, txos []CtxTxo, txWitnessTrTx *CtxTxWitnessTrTx).
// review done 2025.12.21
func NewCtxTransferTx(txInputs []CtxTxo, txos []CtxTxo, txWitnessTrTx *CtxTxWitnessTrTx) *CtxTransferTx {
	return &CtxTransferTx{
		txInputs:  txInputs,
		txos:      txos,
		txWitness: txWitnessTrTx,
	}
}

// GetTxos returns the handler CtxCoinbaseTx's txos.
// review done 2025.12.21
func (ctxCoinbaseTx *CtxCoinbaseTx) GetTxos() []CtxTxo {
	return ctxCoinbaseTx.txos
}

// GetTxWitness returns the handler CtxCoinbaseTx's txWitness.
// review done 2025.12.21
func (ctxCoinbaseTx *CtxCoinbaseTx) GetTxWitness() *CtxTxWitnessCbTx {
	return ctxCoinbaseTx.txWitness
}

// GetTxos returns the txos of CtxTransferTx.
// review done 2025.12.21
func (ctxTransferTx *CtxTransferTx) GetTxos() []CtxTxo {
	return ctxTransferTx.txos
}

// GetTxWitness returns the txWitness of CtxTransferTx.
// review done 2025.12.21
func (ctxTransferTx *CtxTransferTx) GetTxWitness() *CtxTxWitnessTrTx {
	return ctxTransferTx.txWitness
}

//	New and Get functions for Transactions	end

// ctx review done 2025.12.21
