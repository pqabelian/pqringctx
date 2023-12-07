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

type CoinbaseTxMLP = pqringctx.CoinbaseTxMLP
type TransferTxMLP = pqringctx.TransferTxMLP

type TxoMLP = pqringctx.TxoMLP
type TxWitnessCbTx = pqringctx.TxWitnessCbTx
type TxWitnessTrTx = pqringctx.TxWitnessTrTx

// InitializePQRingCTX is the init function, it must be called explicitly when using this PQRingCTX.
// After calling this initialization, the caller can use the returned PublicParameter to call PQRingCTX's API.
func InitializePQRingCTX(parameterSeedString []byte) *PublicParameter {
	return pqringctx.Initialize(parameterSeedString)
}

// AddressKeyForRingGen generates coinAddress, coinSpendKey, and coinSnKey
// for the key which will be used to host the coins with full-privacy.
// Note that keys are purely in cryptography, we export bytes,
// and packages the cryptographic details in pqringctx.
func CoinAddressKeyForRingGen(pp *PublicParameter, randSeed []byte) (coinAddress []byte, coinSpendKey []byte, coinSnKey []byte, err error) {
	return pp.CoinAddressKeyForRingGen(randSeed)
}

// AddressKeyGenForSingle generates coinAddress and coinSpendKey
// for the key which will be used to host the coins with pseudonym-privacy.
// Note that keys are purely in cryptography, we export bytes,
// and packages the cryptographic details in pqringctx.
func CoinAddressKeyForSingleGen(pp *PublicParameter, randSeed []byte) (coinAddress []byte, coinSpendKey []byte, err error) {
	return pp.CoinAddressKeyForSingleGen(randSeed)
	//	return nil, nil, err
}

// CoinValueKeyGen generates serializedValuePublicKey and serializedValueSecretKey,
// which will be used to transmit the (value, randomness) pair of the value-commitment to the coin owner.
// Note that by default, pqringctx transmits the (value, randomness) pair by on-chain data,
// i.e., the ciphertexts are included in Txo.
// As the encryption/transmit of (value, randomness) pair is independent from the coinAddress part,
// we use a standalone ValueKeyGen algorithm to generate these keys.
func CoinValueKeyGen(pp *PublicParameter, randSeed []byte) (serializedValuePublicKey []byte, serializedValueSecretKey []byte, err error) {
	return pp.CoinValueKeyGen(randSeed)
}

func NewTxOutputDescMLP(coinAddress []byte, serializedVPK []byte, value uint64) *TxOutputDescMLP {
	return pqringctx.NewTxOutputDescMLP(coinAddress, serializedVPK, value)
}

// CoinbaseTxGen generates CoinbaseTx.
// As the caller may decompose the components of the generated CoinbaseTx
// to make a chain-layer transaction,
// CoinbaseTxGen outputs a CoinbaseTxMLP, rather than a serialized Tx.
func CoinbaseTxGen(pp *PublicParameter, vin uint64, txOutputDescs []*TxOutputDescMLP, txMemo []byte) (cbTx *CoinbaseTxMLP, err error) {
	return pp.CoinbaseTxGenMLP(vin, txOutputDescs, txMemo)
}

func NewCoinbaseTxMLP(vin uint64, txos []TxoMLP, txMemo []byte, txWitness *TxWitnessCbTx) (cbTx *CoinbaseTxMLP) {
	return pqringctx.NewCoinbaseTxMLP(vin, txos, txMemo, txWitness)
}

func CoinbaseTxVerify(pp *PublicParameter, cbTx *CoinbaseTxMLP) (bool, error) {
	return false, nil
}

// TransferTxGen generates TransferTx.
// As the caller may decompose the components of the generated TransferTx
// to make a chain-layer transaction,
// TransferTxGen outputs a pqringctxapidao.TransferTxMLP, rather than a serialized Tx.
func TransferTxGen(pp *PublicParameter, inputDescs []*TxInputDescMLP, outputDescs []*TxOutputDescMLP, fee uint64, txMemo []byte) (trTx *TransferTxMLP, err error) {
	return nil, err
}

func TransferTxVerify(pp *PublicParameter, trTx *TransferTxMLP) (bool, error) {
	return false, nil
}

// API for AddressKeys	begin
func ExtractCoinAddressTypeFromCoinAddress(pp *PublicParameter, coinAddress []byte) (CoinAddressType, error) {
	return pp.ExtractCoinAddressTypeFromCoinAddress(coinAddress)
}

func GetCoinAddressSize(pp *PublicParameter, coinAddressType CoinAddressType) (int, error) {
	return pp.GetCoinAddressSize(coinAddressType)
}

// GetCoinAddressSizeByCoinAddressKeyForRingGen returns the CoinAddress size, which is determined by the underlying CoinAddressKeyForRingGen algorithm.
// reviewed on 2023.12.07
func GetCoinAddressSizeByCoinAddressKeyForRingGen(pp *PublicParameter) (int, error) {
	return pp.GetCoinAddressSize(pqringctx.CoinAddressTypePublicKeyForRing)
}

// GetCoinAddressSizeByCoinAddressKeyForSingleGen returns the CoinAddress size, which is determined by the underlying CoinAddressKeyForSingleGen algorithm.
// reviewed on 2023.12.07
func GetCoinAddressSizeByCoinAddressKeyForSingleGen(pp *PublicParameter) (int, error) {
	return pp.GetCoinAddressSize(pqringctx.CoinAddressTypePublicKeyHashForSingle)
}

// GetCoinValuePublicKeySize returns the CoinValuePublicKey size.
// reviewed on 2023.12.07
func GetCoinValuePublicKeySize(pp *PublicParameter) int {
	return pp.GetCoinValuePublicKeySize()
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

func SerializeTxo(pp *PublicParameter, txo TxoMLP) ([]byte, error) {
	return pp.SerializeTxoMLP(txo)
}

func DeserializeTxo(pp *PublicParameter, serializedTxo []byte) (TxoMLP, error) {
	return pp.DeserializeTxoMLP(serializedTxo)
}

// APIs	for Txo	end

// APIs for Witness 	begin

// GetCbTxWitnessSerializeSizeByDesc return the accurate size of the TxWitness for a coinbaseTx, according to the coinAddressListPayTo.
func GetCbTxWitnessSerializeSizeByDesc(pp *PublicParameter, coinAddressListPayTo [][]byte) (int, error) {
	return pp.GetCbTxWitnessSerializeSizeByDesc(coinAddressListPayTo)
}

func SerializeTxWitnessCbTx(pp *PublicParameter, txWitness *TxWitnessCbTx) ([]byte, error) {
	return pp.SerializeTxWitnessCbTx(txWitness)
}

func DeserializeTxWitnessCbTx(pp *PublicParameter, serializedTxWitness []byte) (*TxWitnessCbTx, error) {
	return pp.DeserializeTxWitnessCbTx(serializedTxWitness)
}

// APIs for Witness 	end
