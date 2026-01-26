package pqringctxapi

import "github.com/pqabelian/pqringctx"

// CtxTxoType is defined for the types of CtxTxo.
// review done 2025.12.21
type CtxTxoType = pqringctx.CtxTxoType

// review done 2025.12.21
const (
	CtxTxoTypeHidden = pqringctx.CtxTxoTypeHidden
	CtxTxoTypePublic = pqringctx.CtxTxoTypePublic
)

// CtxTxOutputDesc is used to collect output information
// To support Multi-Level Privacy (MLP), the value public key field can be nil
// review done 2025.12.21
type CtxTxOutputDesc = pqringctx.CtxTxOutputDesc

// CtxTxInputDesc is used to collect input information which include:
// - information which would be transferred
// review done 2025.12.21
type CtxTxInputDesc = pqringctx.CtxTxInputDesc

// CtxTxo is exported to represent a CtxTxo defined by pqringctx
// review done 2025.12.21
type CtxTxo = pqringctx.CtxTxo

// CtxCoinbaseTx defined the confidentialTx coinbase transaction
// review done 2025.12.21
type CtxCoinbaseTx = pqringctx.CtxCoinbaseTx

// CtxTransferTx defined the confidentialTx transfer transaction
// review done 2025.12.21
type CtxTransferTx = pqringctx.CtxTransferTx

// CtxTxWitnessCbTx / CtxTxWitnessTrTx is witness for difference type of transaction
// review done 2025.12.21
type CtxTxWitnessCbTx = pqringctx.CtxTxWitnessCbTx
type CtxTxWitnessTrTx = pqringctx.CtxTxWitnessTrTx

// NewCtxTxOutputDesc constructs a new CtxTxOutputDesc from the input ctxTxoType, serializedVPK, and value.
// To support Multi-Level Privacy (MLP), the value public key field can be nil
// review done 2025.12.21
func NewCtxTxOutputDesc(ctxTxoType CtxTxoType, coinValuePublicKey []byte, value uint64) *CtxTxOutputDesc {
	return pqringctx.NewCtxTxOutputDesc(ctxTxoType, coinValuePublicKey, value)
}

// CtxCoinbaseTxGen generates CtxCoinbaseTx.
// As the caller may decompose the components of the generated CtxCoinbaseTx to make a chain-layer transaction,
// CtxCoinbaseTxGen outputs a CtxCoinbaseTx, rather than a serialized Tx.
// review done 2025.12.21
func CtxCoinbaseTxGen(pp *PublicParameter, vin uint64, txOutputDescs []*CtxTxOutputDesc) (cbTx *CtxCoinbaseTx, err error) {
	return pp.CtxCoinbaseTxGen(vin, txOutputDescs)
}

// NewCtxCoinbaseTx constructs a new CtxCoinbaseTx from the input (vin uint64, txos []CtxTxo, txWitnessCbTx *CtxTxWitnessCbTx).
// review done 2025.12.21
func NewCtxCoinbaseTx(vin uint64, txos []CtxTxo, txWitnessCbTx *CtxTxWitnessCbTx) (cbTx *CtxCoinbaseTx) {
	return pqringctx.NewCtxCoinbaseTx(vin, txos, txWitnessCbTx)
}

// CtxCoinbaseTxVerify verifies whether the input CtxCoinbaseTx is valid.
// review done 2025.12.21
func CtxCoinbaseTxVerify(pp *PublicParameter, cbTx *CtxCoinbaseTx) error {
	return pp.CtxCoinbaseTxVerify(cbTx)
}

// NewCtxTxInputDesc constructs a CtxTxInputDesc.
// review done 2025.12.21
func NewCtxTxInputDesc(ctxTxo CtxTxo, coinValuePublicKey []byte, coinValueSecretKey []byte, value uint64) *CtxTxInputDesc {
	return pqringctx.NewCtxTxInputDesc(ctxTxo, coinValuePublicKey, coinValueSecretKey, value)
}

// CtxTransferTxGen generates CtxTransferTx.
// As the caller may decompose the components of the generated CtxTransferTx to make a chain-layer transaction,
// CtxTransferTxGen outputs a CtxTransferTx, rather than a serialized Tx.
// review done 2025.12.21
func CtxTransferTxGen(pp *PublicParameter, txInputDescs []*CtxTxInputDesc, txOutputDescs []*CtxTxOutputDesc) (trTx *CtxTransferTx, err error) {
	return pp.CtxTransferTxGen(txInputDescs, txOutputDescs)
}

// NewCtxTransferTx constructs a new CtxTransferTx using the input (txInputs []CtxTxo, txos []CtxTxo, txWitnessTrTx *CtxTxWitnessTrTx).
// review done 2025.12.21
func NewCtxTransferTx(txInputs []CtxTxo, txos []CtxTxo, txWitnessTrTx *CtxTxWitnessTrTx) (trTx *CtxTransferTx) {
	return pqringctx.NewCtxTransferTx(txInputs, txos, txWitnessTrTx)
}

// CtxTransferTxVerify verifies CtxTransferTx.
// review done 2025.12.21
func CtxTransferTxVerify(pp *PublicParameter, trTx *CtxTransferTx) error {
	return pp.CtxTransferTxVerify(trTx)
}

// APIs	for Txo	begin

// GetCtxTxoSerializeSizeByCtxTxoType return the serialized size of a CtxTxo with the input CtxTxoType.
// review done 2025.12.21
func GetCtxTxoSerializeSizeByCtxTxoType(pp *PublicParameter, ctxTxoType CtxTxoType) (int, error) {
	return pp.GetCtxTxoSerializeSizeByCtxTxoType(ctxTxoType)
}

// SerializeCtxTxo serializes the input CtxTxo to []byte.
// review done 2025.12.21
func SerializeCtxTxo(pp *PublicParameter, txo CtxTxo) ([]byte, error) {
	return pp.SerializeCtxTxo(txo)
}

// DeserializeCtxTxo deserialize the input []byte to a CtxTxo.
// review done 2025.12.21
func DeserializeCtxTxo(pp *PublicParameter, serializedTxo []byte) (CtxTxo, error) {
	return pp.DeserializeCtxTxo(serializedTxo)
}

// ExtractValueFromCtxTxo extracts the value of the input CtxTxo.
// review done 2025.12.21
func ExtractValueFromCtxTxo(pp *PublicParameter, txo CtxTxo, coinValuePublicKey []byte, coinValueSecretKey []byte) (value uint64, err error) {
	value, _, _, err = pp.ExtractValueAndRandFromCtxTxo(txo, coinValuePublicKey, coinValueSecretKey)
	return value, err
}

// APIs	for Txo	end

// APIs for Witness 	begin

// GetCtxTxWitnessCbTxSerializeSizeByDesc return the accurate size of the CtxTxWitnessCbTx,
// according to the input outNumForHidden.
// review done 2025.12.21
func GetCtxTxWitnessCbTxSerializeSizeByDesc(pp *PublicParameter, outNumForHidden uint8) (int, error) {
	return pp.CtxTxWitnessCbTxSerializeSizeByDesc(outNumForHidden)
}

// SerializeCtxTxWitnessCbTx serializes the input CtxTxWitnessCbTx into []byte.
// review done 2025.12.21
func SerializeCtxTxWitnessCbTx(pp *PublicParameter, txWitness *CtxTxWitnessCbTx) ([]byte, error) {
	return pp.SerializeCtxTxWitnessCbTx(txWitness)
}

// DeserializeCtxTxWitnessCbTx deserializes the input []byte to a CtxTxWitnessCbTx.
// review done 2025.12.21
func DeserializeCtxTxWitnessCbTx(pp *PublicParameter, serializedTxWitness []byte) (*CtxTxWitnessCbTx, error) {
	return pp.DeserializeCtxTxWitnessCbTx(serializedTxWitness)
}

// GetCtxTxWitnessTrTxSerializeSizeByDesc returns the serialize size for CtxTxWitnessTrTx,
// according to the input description information, say (inNumForHidden, outNumForHidden, vPublic),
// where vPublic = (sum of public value for out) - (sum of public value for in).
// review done 2025.12.21
func GetCtxTxWitnessTrTxSerializeSizeByDesc(pp *PublicParameter, inNumForHidden uint8, outNumForHidden uint8, vPublic int64) (int, error) {
	return pp.CtxTxWitnessTrTxSerializeSizeByDesc(inNumForHidden, outNumForHidden, vPublic)
}

// SerializeCtxTxWitnessTrTx serializes CtxTxWitnessTrTx to []byte.
// review done 2025.12.21
func SerializeCtxTxWitnessTrTx(pp *PublicParameter, txWitness *CtxTxWitnessTrTx) ([]byte, error) {
	return pp.SerializeCtxTxWitnessTrTx(txWitness)
}

// DeserializeCtxTxWitnessTrTx deserializes the input []byte to a CtxTxWitnessTrTx.
// review done 2025.12.21
func DeserializeCtxTxWitnessTrTx(pp *PublicParameter, serializedTxWitness []byte) (*CtxTxWitnessTrTx, error) {
	return pp.DeserializeCtxTxWitnessTrTx(serializedTxWitness)
}

// APIs for Witness 	end

// Get functions of Transactions	begin

// GetCtxCoinbaseTxTxos returns the Txos of the input CtxCoinbaseTx.
// review done 2025.12.21
func GetCtxCoinbaseTxTxos(cbTx *CtxCoinbaseTx) []CtxTxo {
	return cbTx.GetTxos()
}

// GetCtxCoinbaseTxTxWitness returns the TxWitness of CtxTxWitnessCbTx.
// review done 2025.12.21
func GetCtxCoinbaseTxTxWitness(cbTx *CtxCoinbaseTx) *CtxTxWitnessCbTx {
	return cbTx.GetTxWitness()
}

// GetCtxTransferTxTxos returns the Txos of the input CtxTransferTx.
// review done 2025.12.21
func GetCtxTransferTxTxos(trTx *CtxTransferTx) []CtxTxo {
	return trTx.GetTxos()
}

// GetCtxTransferTxTxWitness returns the TxWitness of CtxTxWitnessTrTx.
// review done 2025.12.21
func GetCtxTransferTxTxWitness(trTx *CtxTransferTx) *CtxTxWitnessTrTx {
	return trTx.GetTxWitness()
}

//	Get functions of Transactions	end

// end of codes

// ctx review done 2025.12.21
