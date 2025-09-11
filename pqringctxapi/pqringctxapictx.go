package pqringctxapi

import "github.com/cryptosuite/pqringctx"

// CtxTxoType is defined for the types of CtxTxo.
type CtxTxoType = pqringctx.CtxTxoType

const (
	CtxTxoTypeHidden = pqringctx.CtxTxoTypeHidden
	CtxTxoTypePublic = pqringctx.CtxTxoTypePublic
)

// TxOutputDescMLP is used to collect output information
// To support Multi-Level Privacy (MLP), the value public key field can be nil
type CtxTxOutputDesc = pqringctx.CtxTxOutputDesc

// TxInputDescMLP is used to collect input information which include:
// - reference data which used to protect privacy
// - information which would be transferred
type CtxTxInputDesc = pqringctx.CtxTxInputDesc

// TxoMLP is exported to represent a TXO defined by pqringctx
type CtxTxo = pqringctx.CtxTxo

// CoinbaseTxMLP defined the coinbase transaction
type CtxCoinbaseTx = pqringctx.CtxCoinbaseTx

// TransferTxMLP defined the transfer transaction
type CtxTransferTx = pqringctx.CtxTransferTx

// TxWitnessCbTx / TxWitnessTrTx is witness for difference type of transaction
type CtxTxWitnessCbTx = pqringctx.CtxTxWitnessCbTx
type CtxTxWitnessTrTx = pqringctx.CtxTxWitnessTrTx

// NewTxOutputDescMLP constructs a new TxOutputDescMLP from the input coinAddress, serializedVPK, and value.
// To support Multi-Level Privacy (MLP), the value public key field can be nil
// reviewed on 2023.12.07
func NewCtxTxOutputDesc(ctxTxoType CtxTxoType, coinValuePublicKey []byte, value uint64) *CtxTxOutputDesc {
	return pqringctx.NewCtxTxOutputDesc(ctxTxoType, coinValuePublicKey, value)
}

// CoinbaseTxGen generates CoinbaseTx.
// As the caller may decompose the components of the generated CoinbaseTx
// to make a chain-layer transaction,
// CoinbaseTxGen outputs a CoinbaseTxMLP, rather than a serialized Tx.
// reviewed on 2023.12.07
func CtxCoinbaseTxGen(pp *PublicParameter, vin uint64, txOutputDescs []*CtxTxOutputDesc) (cbTx *CtxCoinbaseTx, err error) {
	return pp.CtxCoinbaseTxGen(vin, txOutputDescs)
}

// NewCoinbaseTxMLP constructs a new CoinbaseTxMLP from the input (vin uint64, txos []TxoMLP, txMemo []byte, txWitnessCbTx *TxWitnessCbTx).
// reviewed on 2023.12.07
func NewCtxCoinbaseTx(vin uint64, txos []CtxTxo, txWitnessCbTx *CtxTxWitnessCbTx) (cbTx *CtxCoinbaseTx) {
	return pqringctx.NewCtxCoinbaseTx(vin, txos, txWitnessCbTx)
}

// CoinbaseTxVerify verify whether the input CoinbaseTxMLP is valid.
// todo: review
func CtxCoinbaseTxVerify(pp *PublicParameter, cbTx *CtxCoinbaseTx) error {
	return pp.CtxCoinbaseTxVerify(cbTx)
}

// NewTxInputDescMLP constructs a TxInputDescMLP, using the same inputs.
// reviewed on 2023.12.21
func NewCtxTxInputDesc(ctxTxo CtxTxo, coinValuePublicKey []byte, coinValueSecretKey []byte, value uint64) *CtxTxInputDesc {
	return pqringctx.NewCtxTxInputDesc(ctxTxo, coinValuePublicKey, coinValueSecretKey, value)
}

// TransferTxGen generates TransferTxMLP.
// As the caller may decompose the components of the generated TransferTx
// to make a chain-layer transaction,
// TransferTxGen outputs a pqringctxapidao.TransferTxMLP, rather than a serialized Tx.
func CtxTransferTxGen(pp *PublicParameter, txInputDescs []*CtxTxInputDesc, txOutputDescs []*CtxTxOutputDesc) (trTx *CtxTransferTx, err error) {
	return pp.CtxTransferTxGen(txInputDescs, txOutputDescs)
}

// NewTransferTxMLP constructs a new TransferTxMLP using the input (txInputs []*TxInputMLP, txos []TxoMLP, fee uint64, txMemo []byte, txWitnessTrTx *TxWitnessTrTx).
func NewCtxTransferTx(txInputs []CtxTxo, txos []CtxTxo, txWitnessTrTx *CtxTxWitnessTrTx) (trTx *CtxTransferTx) {
	return pqringctx.NewCtxTransferTx(txInputs, txos, txWitnessTrTx)
}

// TransferTxVerify verifies TransferTxMLP.
func CtxTransferTxVerify(pp *PublicParameter, trTx *CtxTransferTx) error {
	return pp.CtxTransferTxVerify(trTx)
}

// APIs	for Txo	begin
//func GetTxoSerializeSizeWithCoinAddressType(pp *PublicParameter, coinAddressType CoinAddressType) (int, error) {
//	return pp.GetTxoMLPSerializeSizeByCoinAddressType(coinAddressType)
//}

// GetTxoSerializeSize return the size of a Txo on the input coinAddress.
// Note that the Txos on coinAddresses with different types may have different formats and sizes.
// reviewed on 2023.12.07
func GetCtxTxoSerializeSize(pp *PublicParameter, ctxTxoType CtxTxoType) (int, error) {
	return pp.GetCtxTxoSerializeSizeByCtxTxoType(ctxTxoType)
}

// SerializeTxo serializes the input TxoMLP to []byte.
func SerializeCtxTxo(pp *PublicParameter, txo CtxTxo) ([]byte, error) {
	return pp.SerializeCtxTxo(txo)
}

// DeserializeTxo deserialize the input []byte to a TxoMLP.
// reviewed on 2023.12.07
func DeserializeCtxTxo(pp *PublicParameter, serializedTxo []byte) (CtxTxo, error) {
	return pp.DeserializeCtxTxo(serializedTxo)
}

// TxoCoinReceive
// todo: review
func ExtractValueFromCtxTxo(pp *PublicParameter, txo CtxTxo, coinValuePublicKey []byte, coinValueSecretKey []byte) (value uint64, err error) {
	value, _, _, err = pp.ExtractValueAndRandFromCtxTxo(txo, coinValuePublicKey, coinValueSecretKey)
	return value, err
}

// PseudonymTxoCoinParse parses the input (Pseudonym-Privacy) TxoMLP to its (coinAddress, coinValue) pair, and
// return an err if it is not a Pseudonym-Privacy Txo.
// todo: review
func PseudonymCtxTxoCoinParse(pp *PublicParameter, txo TxoMLP) (coinAddress []byte, value uint64, err error) {
	return pp.PseudonymTxoCoinParse(txo)
}

// APIs	for Txo	end

// APIs for Witness 	begin

// GetTxWitnessCbTxSerializeSizeByDesc return the accurate size of the TxWitness for a coinbaseTx, according to the coinAddressListPayTo.
// reviewed on 2024.01.01, by Alice
func GetCtxTxWitnessCbTxSerializeSizeByDesc(pp *PublicParameter, outNumForHidde uint8) (int, error) {
	return pp.GetCtxTxWitnessCbTxSerializeSizeByDesc(outNumForHidde)
}

// SerializeTxWitnessCbTx serializes the input TxWitnessCbTx into []byte.
// reviewed on 2023.12.07
func SerializeCtxTxWitnessCbTx(pp *PublicParameter, txWitness *CtxTxWitnessCbTx) ([]byte, error) {
	return pp.SerializeCtxTxWitnessCbTx(txWitness)
}

// DeserializeTxWitnessCbTx deserializes the input []byte to a TxWitnessCbTx.
// reviewed on 2023.12.07
func DeserializeCtxTxWitnessCbTx(pp *PublicParameter, serializedTxWitness []byte) (*CtxTxWitnessCbTx, error) {
	return pp.DeserializeCtxTxWitnessCbTx(serializedTxWitness)
}

// GetTxWitnessTrTxSerializeSizeByDesc returns the serialize size for TxWitnessTrTx according to the input description information, say (inForRing, inForSingleDistinct, outForRing, inRingSizes, vPublic).
// todo: vPublic = (sum of public value for out) - (sum of public value for in)
func GetCtxTxWitnessTrTxSerializeSizeByDesc(pp *PublicParameter, inNumForHidden uint8, outNumForHidden uint8, vPublic int64) (int, error) {
	return pp.GetCtxTxWitnessTrTxSerializeSizeByDesc(inNumForHidden, outNumForHidden, vPublic)
}

// SerializeTxWitnessTrTx serializes TxWitnessTrTx to []byte.
// reviewed on 2023.12.21
func SerializeCtxTxWitnessTrTx(pp *PublicParameter, txWitness *CtxTxWitnessTrTx) ([]byte, error) {
	return pp.SerializeCtxTxWitnessTrTx(txWitness)
}

// DeserializeTxWitnessTrTx deserializes the input []byte to a TxWitnessTrTx.
// todo: review
func DeserializeCtxTxWitnessTrTx(pp *PublicParameter, serializedTxWitness []byte) (*CtxTxWitnessTrTx, error) {
	return pp.DeserializeCtxTxWitnessTrTx(serializedTxWitness)
}

// APIs for Witness 	end

// Get functions of Transactions	begin

// GetCbTxTxos
func GetCtxCoinbaseTxTxos(cbTx *CtxCoinbaseTx) []CtxTxo {
	return cbTx.GetTxos()
}

// GetCbTxTxWitness
func GetCtxCoinbaseTxTxWitness(cbTx *CtxCoinbaseTx) *CtxTxWitnessCbTx {
	return cbTx.GetTxWitness()
}

// GetTrTxTxos
func GetCtxTransferTxTxos(trTx *CtxTransferTx) []CtxTxo {
	return trTx.GetTxos()
}

// GetTrTxWitness
func GetCtxTransferTxTxWitness(trTx *CtxTransferTx) *CtxTxWitnessTrTx {
	return trTx.GetTxWitness()
}

//	Get functions of Transactions	end
