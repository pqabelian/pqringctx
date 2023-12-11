package pqringctx

type CoinAddressType uint8

const (
	CoinAddressTypePublicKeyForRingPre    CoinAddressType = 0
	CoinAddressTypePublicKeyForRing       CoinAddressType = 1
	CoinAddressTypePublicKeyHashForSingle CoinAddressType = 2
)

// LgrTxoMLP consists of a Txo and a txoId-in-ledger, which is the unique identifier of a Txo in the ledger/blockchain/database.
// TxoId-in-ledger is determined by the ledger layer.
// In other words, a Txo becomes a coin (i.e., LgrTxo) only when it is assigned a unique txoId-in-ledger.
type LgrTxoMLP struct {
	txo TxoMLP
	id  []byte
}

// TxInputMLP is used as a component object for TransferTxMLP, to describe the consumed coins.
// While the consumed coins may have different privacy-levels, TxInputMLP is uniform for the consumed coins on multi-privacy-levels.
// In particular, if the consumed coin is on pseudonym-privacy-level,
// the lgrTxoList will have size 1, and the serialNumber will be nil.
type TxInputMLP struct {
	lgrTxoList   []*LgrTxoMLP
	serialNumber []byte
}

// CoinbaseTxMLP is defined for coinbaseTx.
type CoinbaseTxMLP struct {
	vin       uint64
	txos      []TxoMLP
	txMemo    []byte
	txWitness *TxWitnessCbTx
}

// TransferTxMLP is defined for transferTx.
type TransferTxMLP struct {
	//	Version uint32	//	crypto-layer does not care the (actually does not have the concept of) version of transferTx.
	txInputs  []*TxInputMLP
	txos      []TxoMLP
	fee       uint64
	txMemo    []byte
	txWitness *TxWitnessTrTx
}

// TxOutputDescMLP describes the information for generating Txo, for generating CoinbaseTx and TransferTx.
// As the generated Txo will have privacy-level based on the coinAddress, TxOutputDescMLP is uniform for multi-privacy-levels.
// In particular, to generate a coin on pseudonym-privacy address, the serializedVPK could be nil.
// reviewed on 2023.12.07
type TxOutputDescMLP struct {
	coinAddress        []byte
	coinValuePublicKey []byte //	This is optional, could be nil
	value              uint64
}

// TxInputDescMLP describe the information for a coin to be consumed, for generating TransferTx.
// As the consumed coin may have different privacy-levels, TxInputDescMLP is uniform for multi-privacy-levels.
// In particular, if the coin to consumed is on pseudonym-privacy-level,
// the coinSerialNumberSecretKey, coinValuePK, and coinValueSK will be nil.
type TxInputDescMLP struct {
	lgrTxoList                []*LgrTxoMLP
	sidx                      uint8 //	consumed LgrTxo index
	coinSpendSecretKey        []byte
	coinSerialNumberSecretKey []byte //	This is optional, could be nil
	coinValuePublicKey        []byte //	This is optional, could be nil
	coinValueSecretKey        []byte //	This is optional, could be nil
	value                     uint64
}

// New functions for TxInputDesc and TxOutputDesc 	begin

// NewTxOutputDescMLP constructs a new TxOutputDescMLP from the input (coinAddress, coinValuePK, value).
// reviewed on 2023.12.07
func NewTxOutputDescMLP(coinAddress []byte, coinValuePublicKey []byte, value uint64) *TxOutputDescMLP {
	return &TxOutputDescMLP{
		coinAddress:        coinAddress,
		coinValuePublicKey: coinValuePublicKey,
		value:              value,
	}
}

// NewTxOutputDescMLP constructs a new TxOutputDescMLP from the input (coinAddress, coinValuePK, value).
// reviewed on 2023.12.07
func NewTxInputDescMLP(lgrTxoList []*LgrTxoMLP, sidx uint8, coinSpendSecretKey []byte,
	coinSerialNumberSecretKey []byte, coinValuePublicKey []byte, coinValueSecretKey []byte, value uint64) *TxInputDescMLP {
	return &TxInputDescMLP{
		lgrTxoList:                lgrTxoList,
		sidx:                      sidx,
		coinSpendSecretKey:        coinSpendSecretKey,
		coinSerialNumberSecretKey: coinSerialNumberSecretKey,
		coinValuePublicKey:        coinValuePublicKey,
		coinValueSecretKey:        coinValueSecretKey,
		value:                     value,
	}
}

// NewLgrTxoMLP constructs a new LgrTxoMLP.
// reviewed on 2023.12.08
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
func NewCoinbaseTxMLP(vin uint64, txos []TxoMLP, txMemo []byte, txWitness *TxWitnessCbTx) *CoinbaseTxMLP {
	return &CoinbaseTxMLP{
		vin:       vin,
		txos:      txos,
		txMemo:    txMemo,
		txWitness: txWitness,
	}
}

// GetTxos returns the handler CoinbaseTxMLP's txos.
// reviewed on 2023.12.07
func (cbTx *CoinbaseTxMLP) GetTxos() []TxoMLP {
	return cbTx.txos
}

// GetTxWitness returns the handler CoinbaseTxMLP's txWitness.
// reviewed on 2023.12.07
func (cbTx *CoinbaseTxMLP) GetTxWitness() *TxWitnessCbTx {
	return cbTx.txWitness
}

// todo: review
func (trTx *TransferTxMLP) GetTxos() []TxoMLP {
	return trTx.txos
}

// todo: review
func (trTx *TransferTxMLP) GetTxInputs() []*TxInputMLP {
	return trTx.txInputs
}

// todo: review
func (trTx *TransferTxMLP) GetTxWitness() *TxWitnessTrTx {
	return trTx.txWitness
}

func (txInput *TxInputMLP) GetSerialNumber() []byte {
	return txInput.serialNumber
}

//	New and Get functions for Transactions	end

// Signatures	begin
type elrsSignatureMLP struct {
	seeds [][]byte //	length ringSize, each (seed[]) for a ring member.
	//	z_as, as the responses, need to have the infinite normal ina scope, say [-(eta_a - beta_a), (eta_a - beta_a)].
	//	z_cs, z_cps, as the responses, need to have the infinite normal ina scope, say [-(eta_c - beta_c), (eta_c - beta_c)].
	//	That is why we use PolyAVec (resp. PolyCVec), rather than PolyANTTVec (resp. PolyCNTTVec).
	z_as  []*PolyAVec   // length ringSize, each for a ring member. Each element lies in (S_{eta_a - beta_a})^{L_a}.
	z_cs  [][]*PolyCVec // length ringSize, each length paramK. Each element lies (S_{eta_c - beta_c})^{L_c}.
	z_cps [][]*PolyCVec // length ringSize, each length paramK. Each element lies (S_{eta_c - beta_c})^{L_c}.
}

type simpsSignatureMLP struct {
	seed []byte
	//	z_a, as the responses, need to have the infinite normal ina scope, say [-(eta_a - beta_a), (eta_a - beta_a)].
	//	That is why we use PolyAVec, rather than PolyANTTVec.
	z_a *PolyAVec // lies in (S_{eta_a - beta_a})^{L_a}.

}

//	Signatures	end
