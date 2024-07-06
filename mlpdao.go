package pqringctx

type CoinAddressType uint8

const (
	CoinAddressTypePublicKeyForRingPre    CoinAddressType = 0
	CoinAddressTypePublicKeyForRing       CoinAddressType = 1
	CoinAddressTypePublicKeyHashForSingle CoinAddressType = 2
)

// LgrTxoMLP consists of a TxoMLP and a txoId-in-ledger, which is the unique identifier of a TxoMLP in the ledger/blockchain/database.
// TxoId-in-ledger is determined by the ledger layer.
// In other words, a TxoMLP becomes a coin (i.e., LgrTxoMLP) only when it is assigned a unique txoId-in-ledger.
// reviewed by Alice, 2024.07.06
type LgrTxoMLP struct {
	txo TxoMLP
	id  []byte
}

// TxInputMLP is used as a component object for TransferTxMLP, to describe the consumed coins.
// While the consumed coins may have different privacy-levels, TxInputMLP is uniform for the consumed coins on multi-privacy-levels.
// In particular, if the consumed coin is on pseudonym-privacy-level,
// the lgrTxoList will have size 1.
// reviewed by Alice, 2024.07.06
type TxInputMLP struct {
	lgrTxoList   []*LgrTxoMLP
	serialNumber []byte
}

// CoinbaseTxMLP is defined for coinbaseTx.
// reviewed by Alice, 2024.07.06
type CoinbaseTxMLP struct {
	vin       uint64
	txos      []TxoMLP
	txMemo    []byte
	txWitness *TxWitnessCbTx
}

// TransferTxMLP is defined for transferTx.
// reviewed by Alice, 2024.07.06
type TransferTxMLP struct {
	//	Version uint32	//	crypto-layer does not care the (actually does not have the concept of) version of transferTx.
	txInputs  []*TxInputMLP
	txos      []TxoMLP
	fee       uint64
	txMemo    []byte
	txWitness *TxWitnessTrTx
}

// TxOutputDescMLP describes the information for generating TxoMLP, for generating CoinbaseTxMLP and TransferTxMLP.
// As the generated TxoMLP will have privacy-level based on the coinAddress, TxOutputDescMLP is uniform for multi-privacy-levels.
// In particular, to generate a coin on pseudonym-privacy address, the coinValuePublicKey could be nil.
// reviewed on 2023.12.07
// reviewed by Alice, 2024.07.06
type TxOutputDescMLP struct {
	coinAddress        []byte
	coinValuePublicKey []byte //	This is optional, could be nil
	value              uint64
}

// TxInputDescMLP describe the information for a coin to be consumed, for generating TransferTxMLP.
// As the consumed coin may have different privacy-levels, TxInputDescMLP is uniform for multi-privacy-levels.
// In particular, if the coin to consumed is on pseudonym-privacy-level,
// the coinSerialNumberSecretKey, coinValuePK, and coinValueSK will be nil.
// reviewed by Alice, 2024.07.06
type TxInputDescMLP struct {
	lgrTxoList                []*LgrTxoMLP
	sidx                      uint8 //	consumed LgrTxoMLP index
	coinSpendSecretKey        []byte
	coinSerialNumberSecretKey []byte //	This is optional, could be nil
	coinValuePublicKey        []byte //	This is optional, could be nil
	coinValueSecretKey        []byte //	This is optional, could be nil
	coinDetectorKey           []byte
	value                     uint64
}

// New functions for TxInputDesc and TxOutputDesc 	begin

// NewTxOutputDescMLP constructs a new TxOutputDescMLP from the input (coinAddress, coinValuePK, value).
// reviewed on 2023.12.07
// reviewed by Alice, 2024.07.06
func NewTxOutputDescMLP(coinAddress []byte, coinValuePublicKey []byte, value uint64) *TxOutputDescMLP {
	return &TxOutputDescMLP{
		coinAddress:        coinAddress,
		coinValuePublicKey: coinValuePublicKey,
		value:              value,
	}
}

// NewTxInputDescMLP constructs a new TxOutputDescMLP from the input (coinAddress, coinValuePK, value).
// reviewed on 2023.12.07
// reviewed by Alice, 2024.07.06
func NewTxInputDescMLP(lgrTxoList []*LgrTxoMLP, sidx uint8, coinSpendSecretKey []byte,
	coinSerialNumberSecretKey []byte, coinValuePublicKey []byte, coinValueSecretKey []byte, coinDetectorKey []byte, value uint64) *TxInputDescMLP {
	return &TxInputDescMLP{
		lgrTxoList:                lgrTxoList,
		sidx:                      sidx,
		coinSpendSecretKey:        coinSpendSecretKey,
		coinSerialNumberSecretKey: coinSerialNumberSecretKey,
		coinValuePublicKey:        coinValuePublicKey,
		coinValueSecretKey:        coinValueSecretKey,
		coinDetectorKey:           coinDetectorKey,
		value:                     value,
	}
}

// NewLgrTxoMLP constructs a new LgrTxoMLP.
// reviewed on 2023.12.08
// reviewed by Alice, 2024.07.06
func NewLgrTxoMLP(txo TxoMLP, id []byte) *LgrTxoMLP {
	return &LgrTxoMLP{
		txo: txo,
		id:  id,
	}
}

//	New functions for TxInputDesc and TxOutputDesc 	end

// New and Get functions for Transactions	begin

// NewCoinbaseTxMLP constructs a new CoinbaseTxMLP from the input (vin uint64, txos []TxoMLP, txMemo []byte, txWitness *TxWitnessCbTx).
// reviewed on 2023.12.07
// reviewed by Alice, 2024.07.06
func NewCoinbaseTxMLP(vin uint64, txos []TxoMLP, txMemo []byte, txWitnessCbTx *TxWitnessCbTx) *CoinbaseTxMLP {
	return &CoinbaseTxMLP{
		vin:       vin,
		txos:      txos,
		txMemo:    txMemo,
		txWitness: txWitnessCbTx,
	}
}

// NewTxInputMLP constructs a new TxInputMLP using the input (lgrTxoList []*LgrTxoMLP, serialNumber []byte).
// reviewed on 2023.12.21
// reviewed by Alice, 2024.07.06
func NewTxInputMLP(lgrTxoList []*LgrTxoMLP, serialNumber []byte) *TxInputMLP {
	return &TxInputMLP{
		lgrTxoList:   lgrTxoList,
		serialNumber: serialNumber,
	}
}

// NewTransferTxMLP constructs a new TransferTxMLP using the input (txInputs []*TxInputMLP, txos []TxoMLP, fee uint64, txMemo []byte, txWitness *TxWitnessTrTx).
// reviewed by Alice, 2024.07.06
func NewTransferTxMLP(txInputs []*TxInputMLP, txos []TxoMLP, fee uint64, txMemo []byte, txWitnessTrTx *TxWitnessTrTx) *TransferTxMLP {
	return &TransferTxMLP{
		txInputs:  txInputs,
		txos:      txos,
		fee:       fee,
		txMemo:    txMemo,
		txWitness: txWitnessTrTx,
	}
}

// GetTxos returns the handler CoinbaseTxMLP's txos.
// reviewed on 2023.12.07
// reviewed by Alice, 2024.07.06
func (cbTx *CoinbaseTxMLP) GetTxos() []TxoMLP {
	return cbTx.txos
}

// GetTxWitness returns the handler CoinbaseTxMLP's txWitness.
// reviewed on 2023.12.07
// reviewed by Alice, 2024.07.06
func (cbTx *CoinbaseTxMLP) GetTxWitness() *TxWitnessCbTx {
	return cbTx.txWitness
}

// GetTxos returns the txos of TransferTxMLP.
// reviewed on 2023.12.21
// reviewed by Alice, 2024.07.06
func (trTx *TransferTxMLP) GetTxos() []TxoMLP {
	return trTx.txos
}

// GetTxInputs returns the txInputs of TransferTxMLP.
// reviewed by Alice, 2024.07.06
func (trTx *TransferTxMLP) GetTxInputs() []*TxInputMLP {
	return trTx.txInputs
}

// GetTxWitness returns the txWitness of TransferTxMLP.
// reviewed on 2023.12.21
// reviewed by Alice, 2024.07.06
func (trTx *TransferTxMLP) GetTxWitness() *TxWitnessTrTx {
	return trTx.txWitness
}

// GetSerialNumber returns the serial number of TxInputMLP.
// reviewed on 2023.12.21
// reviewed by Alice, 2024.07.06
func (txInput *TxInputMLP) GetSerialNumber() []byte {
	return txInput.serialNumber
}

//	New and Get functions for Transactions	end
