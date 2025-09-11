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
func NewCoinbaseTxMLP(vin uint64, txos []TxoMLP, txMemo []byte, txWitnessCbTx *TxWitnessCbTx) (cbTx *CoinbaseTxMLP) {
	return pqringctx.NewCoinbaseTxMLP(vin, txos, txMemo, txWitnessCbTx)
}

// CoinbaseTxVerify verify whether the input CoinbaseTxMLP is valid.
// todo: review
func CoinbaseTxVerify(pp *PublicParameter, cbTx *CoinbaseTxMLP) error {
	return pp.CoinbaseTxMLPVerify(cbTx)
}

// NewTxInputDescMLP constructs a TxInputDescMLP, using the same inputs.
// reviewed on 2023.12.21
func NewTxInputDescMLP(lgrTxoList []*LgrTxoMLP, sidx uint8, coinSpendSecretKey []byte, coinSerialNumberSecretKey []byte,
	coinValuePublicKey []byte, coinValueSecretKey []byte, coinDetectorKey []byte, value uint64) *TxInputDescMLP {
	return pqringctx.NewTxInputDescMLP(lgrTxoList, sidx, coinSpendSecretKey, coinSerialNumberSecretKey, coinValuePublicKey, coinValueSecretKey, coinDetectorKey, value)
}

// TransferTxGen generates TransferTxMLP.
// As the caller may decompose the components of the generated TransferTx
// to make a chain-layer transaction,
// TransferTxGen outputs a pqringctxapidao.TransferTxMLP, rather than a serialized Tx.
// reviewed on 2023.12.21
func TransferTxGen(pp *PublicParameter, txInputDescs []*TxInputDescMLP, txOutputDescs []*TxOutputDescMLP, fee uint64, txMemo []byte) (trTx *TransferTxMLP, err error) {
	return pp.TransferTxMLPGen(txInputDescs, txOutputDescs, fee, txMemo)
}

// NewTxInputMLP constructs a new TxInputMLP using the input (lgrTxoList []*LgrTxoMLP, serialNumber []byte).
// reviewed on 2023.12.21
func NewTxInputMLP(lgrTxoList []*LgrTxoMLP, serialNumber []byte) (txInputMLP *TxInputMLP) {
	return pqringctx.NewTxInputMLP(lgrTxoList, serialNumber)
}

// NewTransferTxMLP constructs a new TransferTxMLP using the input (txInputs []*TxInputMLP, txos []TxoMLP, fee uint64, txMemo []byte, txWitnessTrTx *TxWitnessTrTx).
// reviewed on 2023.12.21
func NewTransferTxMLP(txInputs []*TxInputMLP, txos []TxoMLP, fee uint64, txMemo []byte, txWitnessTrTx *TxWitnessTrTx) (trTx *TransferTxMLP) {
	return pqringctx.NewTransferTxMLP(txInputs, txos, fee, txMemo, txWitnessTrTx)
}

// TransferTxVerify verifies TransferTxMLP.
// todo: review
func TransferTxVerify(pp *PublicParameter, trTx *TransferTxMLP) error {
	return pp.TransferTxMLPVerify(trTx)
}

// APIs	for Txo	begin
//func GetTxoSerializeSizeWithCoinAddressType(pp *PublicParameter, coinAddressType CoinAddressType) (int, error) {
//	return pp.GetTxoMLPSerializeSizeByCoinAddressType(coinAddressType)
//}

// GetTxoSerializeSize return the size of a Txo on the input coinAddress.
// Note that the Txos on coinAddresses with different types may have different formats and sizes.
// reviewed on 2023.12.07
func GetTxoSerializeSize(pp *PublicParameter, coinAddress []byte) (int, error) {
	coinAddressType, err := pp.ExtractCoinAddressTypeFromCoinAddress(coinAddress)
	if err != nil {
		return 0, err
	}
	return pp.GetTxoMLPSerializeSizeByCoinAddressType(coinAddressType)
}

// SerializeTxo serializes the input TxoMLP to []byte.
// reviewed on 2023.12.07
func SerializeTxo(pp *PublicParameter, txo TxoMLP) ([]byte, error) {
	return pp.SerializeTxoMLP(txo)
}

// DeserializeTxo deserialize the input []byte to a TxoMLP.
// reviewed on 2023.12.07
func DeserializeTxo(pp *PublicParameter, serializedTxo []byte) (TxoMLP, error) {
	return pp.DeserializeTxoMLP(serializedTxo)
}

// TxoCoinReceive
// todo: review
func TxoCoinReceive(pp *PublicParameter, txo TxoMLP, coinAddress []byte, coinValuePublicKey []byte, coinValueSecretKey []byte) (valid bool, value uint64, err error) {
	return pp.TxoMLPCoinReceive(txo, coinAddress, coinValuePublicKey, coinValueSecretKey)
}

// PseudonymTxoCoinParse parses the input (Pseudonym-Privacy) TxoMLP to its (coinAddress, coinValue) pair, and
// return an err if it is not a Pseudonym-Privacy Txo.
// todo: review
func PseudonymTxoCoinParse(pp *PublicParameter, txo TxoMLP) (coinAddress []byte, value uint64, err error) {
	return pp.PseudonymTxoCoinParse(txo)
}

// APIs	for Txo	end

// APIs for Witness 	begin

// GetTxWitnessCbTxSerializeSizeByDesc return the accurate size of the TxWitness for a coinbaseTx, according to the coinAddressListPayTo.
// reviewed on 2024.01.01, by Alice
func GetTxWitnessCbTxSerializeSizeByDesc(pp *PublicParameter, coinAddressListPayTo [][]byte) (int, error) {
	return pp.GetTxWitnessCbTxSerializeSizeByDesc(coinAddressListPayTo)
}

// SerializeTxWitnessCbTx serializes the input TxWitnessCbTx into []byte.
// reviewed on 2023.12.07
func SerializeTxWitnessCbTx(pp *PublicParameter, txWitness *TxWitnessCbTx) ([]byte, error) {
	return pp.SerializeTxWitnessCbTx(txWitness)
}

// DeserializeTxWitnessCbTx deserializes the input []byte to a TxWitnessCbTx.
// reviewed on 2023.12.07
func DeserializeTxWitnessCbTx(pp *PublicParameter, serializedTxWitness []byte) (*TxWitnessCbTx, error) {
	return pp.DeserializeTxWitnessCbTx(serializedTxWitness)
}

// GetTxWitnessTrTxSerializeSizeByDesc returns the serialize size for TxWitnessTrTx according to the input description information, say (inForRing, inForSingleDistinct, outForRing, inRingSizes, vPublic).
// todo: review
func GetTxWitnessTrTxSerializeSizeByDesc(pp *PublicParameter, inForRing uint8, inForSingleDistinct uint8, outForRing uint8, inRingSizes []uint8, vPublic int64) (int, error) {
	return pp.GetTxWitnessTrTxSerializeSizeByDesc(inForRing, inForSingleDistinct, outForRing, inRingSizes, vPublic)
}

// SerializeTxWitnessTrTx serializes TxWitnessTrTx to []byte.
// reviewed on 2023.12.21
func SerializeTxWitnessTrTx(pp *PublicParameter, txWitness *TxWitnessTrTx) ([]byte, error) {
	return pp.SerializeTxWitnessTrTx(txWitness)
}

// DeserializeTxWitnessTrTx deserializes the input []byte to a TxWitnessTrTx.
// todo: review
func DeserializeTxWitnessTrTx(pp *PublicParameter, serializedTxWitness []byte) (*TxWitnessTrTx, error) {
	return pp.DeserializeTxWitnessTrTx(serializedTxWitness)
}

// APIs for Witness 	end

// Get functions of Transactions	begin

// GetCbTxTxos
// added by Alice, 2024.07.06
// todo: review
func GetCbTxTxos(cbTx *CoinbaseTxMLP) []TxoMLP {
	return cbTx.GetTxos()
}

// GetCbTxTxWitness
// added by Alice, 2024.07.06
// todo: review
func GetCbTxTxWitness(cbTx *CoinbaseTxMLP) *TxWitnessCbTx {
	return cbTx.GetTxWitness()
}

// GetTrTxTxos
// added by Alice, 2024.07.06
// todo: review
func GetTrTxTxos(trTx *TransferTxMLP) []TxoMLP {
	return trTx.GetTxos()
}

// GetTrTxTxInputs
// added by Alice, 2024.07.06
// todo: review
func GetTrTxTxInputs(trTx *TransferTxMLP) []*TxInputMLP {
	return trTx.GetTxInputs()
}

// GetTrTxWitness
// added by Alice, 2024.07.06
// todo: review
func GetTrTxWitness(trTx *TransferTxMLP) *TxWitnessTrTx {
	return trTx.GetTxWitness()
}

//	Get functions of Transactions	end
