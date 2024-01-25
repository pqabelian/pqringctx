package pqringctxapi

import (
	"github.com/cryptosuite/pqringctx"
)

// PublicParameter is defined the alias of pqringctx.PublicParameter,
// to enable the caller only need to import pqringctxapi and pqringctxapidao.
type PublicParameter = pqringctx.PublicParameter

// CoinAddressType is defined to explicit distinguish different type
// To support Multi-Level Privacy (MLP) and compatible with previous addresses
type CoinAddressType = pqringctx.CoinAddressType

const (
	CoinAddressTypePublicKeyForRingPre    = pqringctx.CoinAddressTypePublicKeyForRingPre
	CoinAddressTypePublicKeyForRing       = pqringctx.CoinAddressTypePublicKeyForRing
	CoinAddressTypePublicKeyHashForSingle = pqringctx.CoinAddressTypePublicKeyHashForSingle
)

// TxOutputDescMLP is used to collect output information
// To support Multi-Level Privacy (MLP), the value public key field can be nil
type TxOutputDescMLP = pqringctx.TxOutputDescMLP

// TxInputDescMLP is used to collect input information which include:
// - reference data which used to protect privacy
// - information which would be transferred
type TxInputDescMLP = pqringctx.TxInputDescMLP

// TxInputMLP is used to reference a TXO defined by pqringctx
type TxInputMLP = pqringctx.TxInputMLP

// TxoMLP is exported to represent a TXO defined by pqringctx
type TxoMLP = pqringctx.TxoMLP

// CoinbaseTxMLP defined the coinbase transaction
type CoinbaseTxMLP = pqringctx.CoinbaseTxMLP

// TransferTxMLP defined the transfer transaction
type TransferTxMLP = pqringctx.TransferTxMLP

// auxiliary struct

// LgrTxoMLP is exported to auxiliary TxInputDescMLP
type LgrTxoMLP = pqringctx.LgrTxoMLP

// TxWitnessCbTx / TxWitnessTrTx is witness for difference type of transaction
type TxWitnessCbTx = pqringctx.TxWitnessCbTx
type TxWitnessTrTx = pqringctx.TxWitnessTrTx

// InitializePQRingCTX is the init function, it must be called explicitly when using this PQRingCTX.
// After calling this initialization, the caller can use the returned PublicParameter to call PQRingCTX's API.
func InitializePQRingCTX(parameterSeedString []byte) *PublicParameter {
	return pqringctx.Initialize(parameterSeedString)
}

// CoinAddressKeyForPKRingGen generates coinAddress, coinSpendKey, and coinSnKey
// for the key which will be used to host the coins with full-privacy.
// Note that keys are purely in cryptography, we export bytes,
// and packages the cryptographic details in pqringctx.
// reviewed on 2023.12.07
// reviewed on 2023.12.30
func CoinAddressKeyForPKRingGen(pp *PublicParameter,
	coinSpendKeyRandSeed []byte, coinSerialNumberKeyRandSeed []byte,
	coinDetectorKey []byte, publicRand []byte) (coinAddress []byte, coinSpendSecretKey []byte, coinSerialNumberSecretKey []byte, err error) {
	return pp.CoinAddressKeyForPKRingGen(coinSpendKeyRandSeed, coinSerialNumberKeyRandSeed, coinDetectorKey, publicRand)
}

// CoinAddressKeyForPKHSingleGen generates coinAddress and coinSpendKey
// for the key which will be used to host the coins with pseudonym-privacy.
// Note that keys are purely in cryptography, we export bytes,
// and packages the cryptographic details in pqringctx.
// reviewed on 2023.12.07
// reviewed on 2023.12.30
func CoinAddressKeyForPKHSingleGen(pp *PublicParameter, coinSpendKeyRandSeed []byte, coinDetectorKey []byte, publicRand []byte) (coinAddress []byte, coinSpendSecretKey []byte, err error) {
	return pp.CoinAddressKeyForPKHSingleGen(coinSpendKeyRandSeed, coinDetectorKey, publicRand)
	//	return nil, nil, err
}

// CoinValueKeyGen generates serializedValuePublicKey and serializedValueSecretKey,
// which will be used to transmit the (value, randomness) pair of the value-commitment to the coin owner.
// Note that by default, pqringctx transmits the (value, randomness) pair by on-chain data,
// i.e., the ciphertexts are included in Txo.
// As the encryption/transmit of (value, randomness) pair is independent of the coinAddress part,
// we use a standalone ValueKeyGen algorithm to generate these keys.
func CoinValueKeyGen(pp *PublicParameter, randSeed []byte) (coinValuePublicKey []byte, coinValueSecretKey []byte, err error) {
	return pp.CoinValueKeyGen(randSeed)
}

// NewTxOutputDescMLP constructs a new TxOutputDescMLP from the input coinAddress, serializedVPK, and value.
// To support Multi-Level Privacy (MLP), the value public key field can be nil
// reviewed on 2023.12.07
func NewTxOutputDescMLP(coinAddress []byte, coinValuePublicKey []byte, value uint64) *TxOutputDescMLP {
	return pqringctx.NewTxOutputDescMLP(coinAddress, coinValuePublicKey, value)
}

// CoinbaseTxGen generates CoinbaseTx.
// As the caller may decompose the components of the generated CoinbaseTx
// to make a chain-layer transaction,
// CoinbaseTxGen outputs a CoinbaseTxMLP, rather than a serialized Tx.
// reviewed on 2023.12.07
func CoinbaseTxGen(pp *PublicParameter, vin uint64, txOutputDescs []*TxOutputDescMLP, txMemo []byte) (cbTx *CoinbaseTxMLP, err error) {
	return pp.CoinbaseTxMLPGen(vin, txOutputDescs, txMemo)
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

// API for AddressKeys	begin

// ExtractCoinAddressTypeFromCoinAddress extracts the CoinAddressType from the input coinAddress,
// which was generated by CoinAddressKeyForPKRingGen or CoinAddressKeyForPKHSingleGen, or by the abecrypto module (for back-compatability).
// reviewed on 2023.12.12.
func ExtractCoinAddressTypeFromCoinAddress(pp *PublicParameter, coinAddress []byte) (CoinAddressType, error) {
	return pp.ExtractCoinAddressTypeFromCoinAddress(coinAddress)
}

// ExtractPublicRandFromCoinAddress extracts PublicRand from the input coinAddress.
// reviewed on 2023.12.30
func ExtractPublicRandFromCoinAddress(pp *PublicParameter, coinAddress []byte) ([]byte, error) {
	return pp.ExtractPublicRandFromCoinAddress(coinAddress)
}

// ExtractCoinAddressTypeFromCoinSpendSecretKey extracts the CoinAddressType from the input coinSpendSecretKey.
// reviewed on 2023.12.12.
func ExtractCoinAddressTypeFromCoinSpendSecretKey(pp *PublicParameter, coinSpendSecretKey []byte) (CoinAddressType, error) {
	return pp.ExtractCoinAddressTypeFromCoinSpendSecretKey(coinSpendSecretKey)
}

// ExtractCoinAddressTypeFromCoinSerialNumberSecretKey extracts the CoinAddressType from the input coinSerialNumberSecretKey.
// // reviewed on 2023.12.12
func ExtractCoinAddressTypeFromCoinSerialNumberSecretKey(pp *PublicParameter, coinSerialNumberSecretKey []byte) (CoinAddressType, error) {
	return pp.ExtractCoinAddressTypeFromCoinSerialNumberSecretKey(coinSerialNumberSecretKey)
}

func GetCoinAddressSize(pp *PublicParameter, coinAddressType CoinAddressType) (int, error) {
	return pp.GetCoinAddressSize(coinAddressType)
}

// CoinAddressSizeByCoinAddressKeyForPKRingGen returns the CoinAddress size, which is determined by the underlying CoinAddressKeyForRingGen algorithm.
// reviewed on 2023.12.07
// reviewed on 2023.12.12
// refactor function name, 2024.01.24
func CoinAddressSizeByCoinAddressKeyForPKRingGen(pp *PublicParameter) (int, error) {
	return pp.GetCoinAddressSize(pqringctx.CoinAddressTypePublicKeyForRing)
}

// CoinAddressSizeByCoinAddressKeyForPKHSingleGen returns the CoinAddress size, which is determined by the underlying CoinAddressKeyForSingleGen algorithm.
// reviewed on 2023.12.07
// reviewed on 2023.12.12
// refactor function name, 2024.01.24
func CoinAddressSizeByCoinAddressKeyForPKHSingleGen(pp *PublicParameter) (int, error) {
	return pp.GetCoinAddressSize(pqringctx.CoinAddressTypePublicKeyHashForSingle)
}

// CoinSpendSecretKeySizeByCoinAddressKeyForPKRingGen returns the size of CoinSpendSecretKey,
// which was generated by CoinAddressKeyForPKRingGen.
// reviewed on 2023.12.12
// refactor function name on 2024.01.24
func CoinSpendSecretKeySizeByCoinAddressKeyForPKRingGen(pp *PublicParameter) (int, error) {
	return pp.GetCoinSpendSecretKeySize(pqringctx.CoinAddressTypePublicKeyForRing)
}

// CoinSpendSecretKeySizeByCoinAddressKeyForPKHSingleGen returns the size of CoinSpendSecretKey,
// which was generated by CoinAddressKeyForPKHSingleGen.
// reviewed on 2023.12.12
// refactor function name on 2024.01.24
func CoinSpendSecretKeySizeByCoinAddressKeyForPKHSingleGen(pp *PublicParameter) (int, error) {
	return pp.GetCoinSpendSecretKeySize(pqringctx.CoinAddressTypePublicKeyHashForSingle)
}

// CoinSerialNumberSecretKeySizeByCoinAddressKeyForPKRingGen returns the size of CoinSerialNumberSecretKey,
// which was generated by CoinAddressKeyForPKRingGen.
// reviewed on 2023.12.12
// refactor function name on 2024.01.24
func CoinSerialNumberSecretKeySizeByCoinAddressKeyForPKRingGen(pp *PublicParameter) (int, error) {
	return pp.GetCoinSerialNumberSecretKeySize(pqringctx.CoinAddressTypePublicKeyForRing)
}

// GetCoinValuePublicKeySize returns the CoinValuePublicKey size.
// reviewed on 2023.12.07
// reviewed on 2023.12.12
func GetCoinValuePublicKeySize(pp *PublicParameter) int {
	return pp.GetCoinValuePublicKeySize()
}

// todo: review
func GetCoinValueSecretKeySize(pp *PublicParameter) int {
	return pp.GetCoinValueSecretKeySize()
}

//	API for AddressKeys	end

// API for CryptoSchemeParams	begin
// reviewed on 2023.12.07
func GetParamSeedBytesLen(pp *PublicParameter) int {
	return pp.GetParamSeedBytesLen()
}

// GetParamKeyGenPublicRandBytesLen returns the ParamKeyGenPublicRandBytesLen.
// reviewed on 2023.12.30
func GetParamKeyGenPublicRandBytesLen(pp *PublicParameter) int {
	return pp.GetParamKeyGenPublicRandBytesLen()
}

// GetParamMACKeyBytesLen returns the ParamMACKeyBytesLen.
// reviewed on 2023.12.30
func GetParamMACKeyBytesLen(pp *PublicParameter) int {
	return pp.GetParamMACKeyBytesLen()
}

func GetParamMACOutputBytesLen(pp *PublicParameter) int {
	return pp.GetParamMACOutputBytesLen()
}

// API for CryptoSchemeParams	end

// APIs	for Tx-Params	begin

// GetTxInputMaxNum returns the allowed maximum number of TxInputs.
// reviewed on 2024.01.01
func GetTxInputMaxNum(pp *PublicParameter) int {
	return int(pp.GetTxInputMaxNumForRing()) + int(pp.GetTxInputMaxNumForSingle())
}

// GetTxOutputMaxNum returns the allowed maximum number of TxOutputs.
// reviewed on 2024.01.01
func GetTxOutputMaxNum(pp *PublicParameter) int {
	return int(pp.GetTxOutputMaxNumForRing()) + int(pp.GetTxOutputMaxNumForSingle())
}

// APIs	for Tx-Params	end

// APIs	for TxIn	begin

// GetNullSerialNumber returns the null-serial-number.
// reviewed on 2023.12.07
func GetNullSerialNumber(pp *PublicParameter) []byte {
	return pp.GetNullSerialNumberMLP()
}

func GetSerialNumberSize(pp *PublicParameter) int {
	return pp.GetSerialNumberSize()
}

// APIs	for TxIn	end

// APIs	for Txo	begin
func GetTxoSerializeSizeWithCoinAddressType(pp *PublicParameter, coinAddressType CoinAddressType) (int, error) {
	return pp.GetTxoMLPSerializeSizeByCoinAddressType(coinAddressType)
}

// GetTxoSerializeSize return the size of a Txo on the input coinAddress.
// Note that the Txos on coinAddresses with different types may have different formats and sizes.
// reviewed on 2023.12.07
func GetTxoSerializeSize(pp *PublicParameter, coinAddress []byte) (int, error) {
	coinAddressType, err := pp.ExtractCoinAddressTypeFromCoinAddress(coinAddress)
	if err != nil {
		return 0, nil
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

// ExtractCoinAddressFromSerializedTxo extracts the coinAddress from a serializedTxo, which was generated by SerializeTxo.
// reviewed on 2023.12.12
func ExtractCoinAddressFromSerializedTxo(pp *PublicParameter, serializedTxo []byte) ([]byte, error) {
	return pp.ExtractCoinAddressFromSerializedTxo(serializedTxo)
}

// GetCoinAddressFromTxo returns the coinAddress from TxoMLP.
// NOTE: this function provides the same functionality as ExtractCoinAddressFromSerializedTxo, but takes a TxoMLP as input.
// The caller can call GetCoinAddressFromTxo or ExtractCoinAddressFromSerializedTxo as he needs,
// depending on whether he needs to deserialize serializedTxo []byte to TxoMLP before the calling, for other uses.
// todo: review
func GetCoinAddressFromTxo(pp *PublicParameter, txo TxoMLP) ([]byte, error) {
	return pp.GetCoinAddressFromTxoMLP(txo)
}

// DetectCoinAddress
// todo: review
func DetectCoinAddress(pp *PublicParameter, coinAddress []byte, coinDetectorKey []byte) (bool, error) {
	return pp.DetectCoinAddress(coinAddress, coinDetectorKey)
}

// TxoCoinReceive
// todo: review
func TxoCoinReceive(pp *PublicParameter, txo TxoMLP, coinAddress []byte, coinValuePublicKey []byte, coinValueSecretKey []byte) (valid bool, value uint64, err error) {
	return pp.TxoMLPCoinReceive(txo, coinAddress, coinValuePublicKey, coinValueSecretKey)
}

// NewLgrTxo constructs a new LgrTxoMLP.
// reviewed on 2023.12.08
func NewLgrTxo(txo TxoMLP, id []byte) *LgrTxoMLP {
	return pqringctx.NewLgrTxoMLP(txo, id)
}

//func TxoCoinReceive(pp *PublicParameter, txo TxoMLP, coinAddress []byte, coinValuePublicKey []byte, coinValueSecretKey []byte) (valid bool, v uint64, err error) {
//	bl, value, err := pp.TxoMLPCoinReceive(txo, coinAddress, coinValuePublicKey, coinValueSecretKey)
//
//	if err != nil {
//		return false, 0, err
//	}
//	return bl, value, nil
//}

func TxoCoinSerialNumberGen(pp *PublicParameter, lgrTxo *LgrTxoMLP, coinSerialNumberSecretKey []byte) ([]byte, error) {
	return pp.TxoCoinSerialNumberGen(lgrTxo, coinSerialNumberSecretKey)
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

func GetTxWitnessTrTxSerializeSizeByDesc(pp *PublicParameter, inForRing uint8, inForSingleDistinct uint8, outForRing uint8, inRingSizes []uint8, vPublic int64) (int, error) {
	return pp.TxWitnessTrTxSerializeSize(inForRing, inForSingleDistinct, outForRing, inRingSizes, vPublic)
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
