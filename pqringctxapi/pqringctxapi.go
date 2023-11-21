package pqringctxapi

import (
	"github.com/cryptosuite/pqringctx"
	"github.com/cryptosuite/pqringctx/pqringctxapidao"
)

// InitializePQRingCTX is the init function, it must be called explicitly when using this PQRingCTX.
// After calling this initialization, the caller can use the returned PublicParameter to call PQRingCTX's API.
func InitializePQRingCTX(parameterSeedString []byte) *pqringctxapidao.PublicParameter {
	return pqringctx.Initialize(parameterSeedString)
}

// AddressKeyGenForRing generates coinAddress, coinSpendKey, and coinSnKey
// for the key which will be used to host the coins with full-privacy.
// Note that keys are purely in cryptography, we export bytes,
// and packages the cryptographic details in pqringctx.
func AddressKeyGenForRing(pp *pqringctx.PublicParameter, seed []byte) (coinAddress []byte, coinSpendKey []byte, coinSnKey []byte, err error) {
	return nil, nil, nil, err
}

// AddressKeyGenForSingle generates coinAddress and coinSpendKey
// for the key which will be used to host the coins with pseudonym-privacy.
// Note that keys are purely in cryptography, we export bytes,
// and packages the cryptographic details in pqringctx.
func AddressKeyGenForSingle(pp *pqringctx.PublicParameter, seed []byte) (coinAddress []byte, coinSpendKey []byte, err error) {
	return nil, nil, err
}

// ValueKeyGen generates serializedValuePublicKey and serializedValueSecretKey,
// which will be used to transmit the (value, randomness) pair of the value-commitment to the coin owner.
// Note that by default, pqringctx transmits the (value, randomness) pair by on-chain data,
// i.e., the ciphertexts are included in Txo.
// As the encryption/transmit of (value, randomness) pair is independent from the coinAddress part,
// we use a standalone ValueKeyGen algorithm to generate these keys.
func ValueKeyGen(pp *pqringctx.PublicParameter, seed []byte) (serializedValuePublicKey []byte, serializedValueSecretKey []byte, err error) {
	return nil, nil, err
}

// CoinbaseTxGen generates CoinbaseTx.
// As the caller may decompose the components of the generated CoinbaseTx
// to make a chain-layer transaction,
// CoinbaseTxGen outputs an pqringctxapidao.CoinbaseTxMLP, rather than a serialized Tx.
func CoinbaseTxGen(pp *pqringctx.PublicParameter, vin uint64, txOutputDescs []*pqringctxapidao.TxOutputDescMLP, txMemo []byte) (cbTx *pqringctxapidao.CoinbaseTxMLP, err error) {
	return nil, err
}

func CoinbaseTxVerify(pp *pqringctx.PublicParameter, cbTx *pqringctxapidao.CoinbaseTxMLP) (bool, error) {
	return false, nil
}

// TransferTxGen generates TransferTx.
// As the caller may decompose the components of the generated TransferTx
// to make a chain-layer transaction,
// TransferTxGen outputs a pqringctxapidao.TransferTxMLP, rather than a serialized Tx.
func TransferTxGen(pp *pqringctx.PublicParameter, inputDescs []*pqringctxapidao.TxInputDescMLP, outputDescs []*pqringctxapidao.TxOutputDescMLP, fee uint64, txMemo []byte) (trTx *pqringctxapidao.TransferTxMLP, err error) {
	return nil, err
}

func TransferTxVerify(pp *pqringctx.PublicParameter, trTx *pqringctxapidao.TransferTxMLP) (bool, error) {
	return false, nil
}
