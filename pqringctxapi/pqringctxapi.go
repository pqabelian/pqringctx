package pqringctxapi

import (
	"github.com/cryptosuite/pqringctx"
)

// PublicParameter is defined the alias of pqringctx.PublicParameter,
// to enable the caller only need to import pqringctxapi and pqringctxapidao.
type PublicParameter = pqringctx.PublicParameter
type CoinAddressType = pqringctx.CoinAddressType

type TxOutputDescMLP = pqringctx.TxOutputDescMLP
type TxInputDescMLP = pqringctx.TxInputDescMLP
type LgrTxoMLP = pqringctx.LgrTxoMLP

type CoinbaseTxMLP = pqringctx.CoinbaseTxMLP
type TransferTxMLP = pqringctx.TransferTxMLP

type TxoMLP = pqringctx.TxoMLP
type TxInputMLP = pqringctx.TxInputMLP
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
func CoinAddressKeyForPKRingGen(pp *PublicParameter, randSeed []byte) (coinAddress []byte, coinSpendSecretKey []byte, coinSerialNumberSecretKey []byte, err error) {
	return pp.CoinAddressKeyForPKRingGen(randSeed)
}

// CoinAddressKeyForPKHSingleGen generates coinAddress and coinSpendKey
// for the key which will be used to host the coins with pseudonym-privacy.
// Note that keys are purely in cryptography, we export bytes,
// and packages the cryptographic details in pqringctx.
// reviewed on 2023.12.07
func CoinAddressKeyForPKHSingleGen(pp *PublicParameter, randSeed []byte) (coinAddress []byte, coinSpendSecretKey []byte, err error) {
	return pp.CoinAddressKeyForPKHSingleGen(randSeed)
	//	return nil, nil, err
}

// CoinValueKeyGen generates serializedValuePublicKey and serializedValueSecretKey,
// which will be used to transmit the (value, randomness) pair of the value-commitment to the coin owner.
// Note that by default, pqringctx transmits the (value, randomness) pair by on-chain data,
// i.e., the ciphertexts are included in Txo.
// As the encryption/transmit of (value, randomness) pair is independent from the coinAddress part,
// we use a standalone ValueKeyGen algorithm to generate these keys.
func CoinValueKeyGen(pp *PublicParameter, randSeed []byte) (coinValuePublicKey []byte, coinValueSecretKey []byte, err error) {
	return pp.CoinValueKeyGen(randSeed)
}

// NewTxOutputDescMLP constructs a new TxOutputDescMLP from the input coinAddress, serializedVPK, and value.
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

// NewCoinbaseTxMLP constructs a new CoinbaseTxMLP from the input (vin uint64, txos []TxoMLP, txMemo []byte, txWitness *TxWitnessCbTx).
// reviewed on 2023.12.07
func NewCoinbaseTxMLP(vin uint64, txos []TxoMLP, txMemo []byte, txWitness *TxWitnessCbTx) (cbTx *CoinbaseTxMLP) {
	return pqringctx.NewCoinbaseTxMLP(vin, txos, txMemo, txWitness)
}

// CoinbaseTxVerify verify whether the input CoinbaseTxMLP is valid.
// todo: review
func CoinbaseTxVerify(pp *PublicParameter, cbTx *CoinbaseTxMLP) (bool, error) {
	return pp.CoinbaseTxMLPVerify(cbTx)
}

func NewTxInputDescMLP(lgrTxoList []*LgrTxoMLP, sidx uint8, coinSpendSecretKey []byte,
	coinSerialNumberSecretKey []byte, coinValuePublicKey []byte, coinValueSecretKey []byte, value uint64) *TxInputDescMLP {
	return pqringctx.NewTxInputDescMLP(lgrTxoList, sidx, coinSpendSecretKey, coinSerialNumberSecretKey, coinValuePublicKey, coinValueSecretKey, value)
}

// TransferTxGen generates TransferTx.
// As the caller may decompose the components of the generated TransferTx
// to make a chain-layer transaction,
// TransferTxGen outputs a pqringctxapidao.TransferTxMLP, rather than a serialized Tx.
// todo: review
func TransferTxGen(pp *PublicParameter, txInputDescs []*TxInputDescMLP, txOutputDescs []*TxOutputDescMLP, fee uint64, txMemo []byte) (trTx *TransferTxMLP, err error) {
	return pp.TransferTxMLPGen(txInputDescs, txOutputDescs, fee, txMemo)
}

func TransferTxVerify(pp *PublicParameter, trTx *TransferTxMLP) (bool, error) {
	return false, nil
}

// API for AddressKeys	begin

// ExtractCoinAddressTypeFromCoinAddress extracts the CoinAddressType from the input coinAddress,
// which was generated by CoinAddressKeyForPKRingGen or CoinAddressKeyForPKHSingleGen, or by the abecrypto module (for back-compatability).
// reviewed on 2023.12.12.
func ExtractCoinAddressTypeFromCoinAddress(pp *PublicParameter, coinAddress []byte) (CoinAddressType, error) {
	return pp.ExtractCoinAddressTypeFromCoinAddress(coinAddress)
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

// GetCoinAddressSizeByCoinAddressKeyForPKRingGen returns the CoinAddress size, which is determined by the underlying CoinAddressKeyForRingGen algorithm.
// reviewed on 2023.12.07
// reviewed on 2023.12.12
func GetCoinAddressSizeByCoinAddressKeyForPKRingGen(pp *PublicParameter) (int, error) {
	return pp.GetCoinAddressSize(pqringctx.CoinAddressTypePublicKeyForRing)
}

// GetCoinAddressSizeByCoinAddressKeyForPKHSingleGen returns the CoinAddress size, which is determined by the underlying CoinAddressKeyForSingleGen algorithm.
// reviewed on 2023.12.07
// reviewed on 2023.12.12
func GetCoinAddressSizeByCoinAddressKeyForPKHSingleGen(pp *PublicParameter) (int, error) {
	return pp.GetCoinAddressSize(pqringctx.CoinAddressTypePublicKeyHashForSingle)
}

// GetCoinSpendSecretKeySizeByCoinAddressKeyForPKRingGen returns the size of CoinSpendSecretKey,
// which was generated by CoinAddressKeyForPKRingGen.
// reviewed on 2023.12.12
func GetCoinSpendSecretKeySizeByCoinAddressKeyForPKRingGen(pp *PublicParameter) (int, error) {
	return pp.GetCoinSpendSecretKeySize(pqringctx.CoinAddressTypePublicKeyForRing)
}

// GetCoinSpendSecretKeySizeByCoinAddressKeyForPKHSingleGen returns the size of CoinSpendSecretKey,
// which was generated by CoinAddressKeyForPKHSingleGen.
// reviewed on 2023.12.12
func GetCoinSpendSecretKeySizeByCoinAddressKeyForPKHSingleGen(pp *PublicParameter) (int, error) {
	return pp.GetCoinSpendSecretKeySize(pqringctx.CoinAddressTypePublicKeyHashForSingle)
}

// GetCoinSerialNumberSecretKeySizeByCoinAddressKeyForPKRingGen returns the size of CoinSerialNumberSecretKey,
// which was generated by CoinAddressKeyForPKRingGen.
// reviewed on 2023.12.12
func GetCoinSerialNumberSecretKeySizeByCoinAddressKeyForPKRingGen(pp *PublicParameter) (int, error) {
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

// API for CryptoSchemeParams	end

// APIs	for TxIn	begin

// GetNullSerialNumber returns the null-serial-number.
// reviewed on 2023.12.07
func GetNullSerialNumber(pp *PublicParameter) []byte {
	return pp.GetNullSerialNumberMLP()
}

// APIs	for TxIn	end

// APIs	for Txo	begin

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

// NewLgrTxo constructs a new LgrTxoMLP.
// reviewed on 2023.12.08
func NewLgrTxo(txo TxoMLP, id []byte) *LgrTxoMLP {
	return pqringctx.NewLgrTxoMLP(txo, id)
}

// APIs	for Txo	end

// APIs for Witness 	begin

// GetCbTxWitnessSerializeSizeByDesc return the accurate size of the TxWitness for a coinbaseTx, according to the coinAddressListPayTo.
func GetCbTxWitnessSerializeSizeByDesc(pp *PublicParameter, coinAddressListPayTo [][]byte) (int, error) {
	return pp.GetCbTxWitnessSerializeSizeByDesc(coinAddressListPayTo)
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

// todo: review
func SerializeTxWitnessTrTx(pp *PublicParameter, txWitness *TxWitnessTrTx) ([]byte, error) {
	return pp.SerializeTxWitnessTrTx(txWitness)
}

// APIs for Witness 	end
