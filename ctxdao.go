package pqringctx

type CtxTxoType uint8

const (
	CtxTxoTypeHidden CtxTxoType = 0
	CtxTxoTypePublic CtxTxoType = 1
)

// CoinbaseTxMLP is defined for coinbaseTx.
type CtxCoinbaseTx struct {
	vin       uint64
	txos      []CtxTxo
	txWitness *CtxTxWitnessCbTx
}

// CtxTransferTx handles only the balance proof between the input side and output side.
type CtxTransferTx struct {
	//	Version uint32	//	crypto-layer does not care the (actually does not have the concept of) version of transferTx.
	txInputs  []CtxTxo
	txos      []CtxTxo
	txWitness *CtxTxWitnessTrTx
}

// TxOutputDescMLP describes the information for generating TxoMLP, for generating CoinbaseTxMLP and TransferTxMLP.
// As the generated TxoMLP will have privacy-level based on the coinAddress, TxOutputDescMLP is uniform for multi-privacy-levels.
// In particular, to generate a coin on pseudonym-privacy address, the coinValuePublicKey could be nil.
type CtxTxOutputDesc struct {
	ctxTxoType         CtxTxoType
	coinValuePublicKey []byte //	This is optional, could be nil
	value              uint64
}

// TxInputDescMLP describe the information for a coin to be consumed, for generating TransferTxMLP.
// As the consumed coin may have different privacy-levels, TxInputDescMLP is uniform for multi-privacy-levels.
// In particular, if the coin to consumed is on pseudonym-privacy-level,
// the coinSerialNumberSecretKey, coinValuePK, and coinValueSK will be nil.
type CtxTxInputDesc struct {
	ctxTxo             CtxTxo
	coinValuePublicKey []byte //	This is optional, could be nil
	coinValueSecretKey []byte //	This is optional, could be nil
	value              uint64
}

// New functions for TxInputDesc and TxOutputDesc 	begin

// NewTxOutputDescMLP constructs a new TxOutputDescMLP from the input (coinAddress, coinValuePK, value).
func NewCtxTxOutputDesc(ctxTxoType CtxTxoType, coinValuePublicKey []byte, value uint64) *CtxTxOutputDesc {
	return &CtxTxOutputDesc{
		ctxTxoType:         ctxTxoType,
		coinValuePublicKey: coinValuePublicKey,
		value:              value,
	}
}

// NewTxInputDescMLP constructs a new TxOutputDescMLP from the input (coinAddress, coinValuePK, value).
// reviewed on 2023.12.07
// reviewed by Alice, 2024.07.06
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

// NewTransferTxMLP constructs a new TransferTxMLP using the input (txInputs []*TxInputMLP, txos []TxoMLP, fee uint64, txMemo []byte, txWitness *TxWitnessTrTx).
func NewCtxCoinbaseTx(vin uint64, txos []CtxTxo, txWitnessCbTx *CtxTxWitnessCbTx) *CtxCoinbaseTx {
	return &CtxCoinbaseTx{
		vin:       vin,
		txos:      txos,
		txWitness: txWitnessCbTx,
	}
}

// NewTransferTxMLP constructs a new TransferTxMLP using the input (txInputs []*TxInputMLP, txos []TxoMLP, fee uint64, txMemo []byte, txWitness *TxWitnessTrTx).
func NewCtxTransferTx(txInputs []CtxTxo, txos []CtxTxo, txWitnessTrTx *CtxTxWitnessTrTx) *CtxTransferTx {
	return &CtxTransferTx{
		txInputs:  txInputs,
		txos:      txos,
		txWitness: txWitnessTrTx,
	}
}

// GetTxos returns the handler CoinbaseTxMLP's txos.
func (ctxCoinbaseTx *CtxCoinbaseTx) GetTxos() []CtxTxo {
	return ctxCoinbaseTx.txos
}

// GetTxWitness returns the handler CoinbaseTxMLP's txWitness.
func (ctxCoinbaseTx *CtxCoinbaseTx) GetTxWitness() *CtxTxWitnessCbTx {
	return ctxCoinbaseTx.txWitness
}

// GetTxos returns the txos of TransferTxMLP.
func (ctxTransferTx *CtxTransferTx) GetTxos() []CtxTxo {
	return ctxTransferTx.txos
}

// GetTxWitness returns the txWitness of TransferTxMLP.
func (ctxTransferTx *CtxTransferTx) GetTxWitness() *CtxTxWitnessTrTx {
	return ctxTransferTx.txWitness
}

//	New and Get functions for Transactions	end
