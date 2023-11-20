package apidao

type TxoAddressType uint8

const (
	TxoAddressTypePublicKeyForRing       TxoAddressType = 0
	TxoAddressTypePublicKeyHashForSingle TxoAddressType = 1
)

// TxoMLP is used as a component object for CoinbaseTxMLP and TransferTxMLP.
// As the Txos in one CoinbaseTxMLP/TransferTxMLP could be hosted on addresses for different privacy-levels
// and consequently have different structures,
// here we use []byte to denote Txo (in its serialized form).
// type TxoMLP []byte
// Note: We do not define standalone structure for Txo.
// 		Instead, we directly use []byte in Txs to denote Txo, rather than using a structure.
//		This is because:
//		Txo is purely at the cryptography layer, and the caller of PQRINGCTX does not need to learn the details of Txo.
//		PQRINGCTX will be responsible for generating Txo and providing service/API on the generated Txo.

// TxWitnessMLP is used as a component object for CoinbaseTxMLP and TransferTxMLP.
// As the TxWitnessMLP for different CoinbaseTxMLP/TransferTxMLP instances could have different structures,
// here we use []byte to denote Txo (in its serialized form).
// type TxWitnessMLP []byte
// Note: We do not define standalone structure for TxWitness.
//		This is because:
//		TxWitness is purely at the cryptography layer, and the caller of PQRINGCTX does not need to learn the details of TxWitness.
//		PQRINGCTX will be responsible for generating TxWitness and providing service/API on the generated TxWitness.

// LgrTxoMLP consists of a Txo and a txoId-in-ledger, which is the unique identifier of a Txo in the ledger/blockchain/database.
// TxoId-in-ledger is determined by the ledger layer.
// In other words, a Txo becomes a coin (i.e., LgrTxo) only when it is assigned a unique txoId-in-ledger.
type LgrTxoMLP struct {
	txo []byte // we directly use []byte to denote Txo, rather than using a structure.
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
	txos      [][]byte
	txMemo    []byte
	txWitness []byte
}

// TransferTxMLP is defined for transferTx.
type TransferTxMLP struct {
	//	Version uint32	//	crypto-layer does not care the (actually does not have the concept of) version of transferTx.
	inputs    []*TxInputMLP
	txos      [][]byte
	fee       uint64
	txMemo    []byte
	txWitness []byte
}

// TxOutputDescMLP describes the information for generating Txo, for generating CoinbaseTx and TransferTx.
// As the generated Txo will have privacy-level based on the coinAddress, TxOutputDescMLP is uniform for multi-privacy-levels.
// In particular, to generate a coin on pseudonym-privacy address, the serializedVPK could be nil.
type TxOutputDescMLP struct {
	coinAddress   []byte
	serializedVPK []byte //	This is optional, could be nil
	value         uint64
}

// TxInputDescMLP describe the information for a coin to be consumed, for generating TransferTx.
// As the consumed coin may have different privacy-levels, TxInputDescMLP is uniform for multi-privacy-levels.
// In particular, if the coin to consumed is on pseudonym-privacy-level,
// the coinSnKey, serializedVPk, and serializedVSk will be nil.
type TxInputDescMLP struct {
	lgrTxoList    []*LgrTxoMLP
	sidx          uint8 //	consumed LgrTxo index
	coinSpendKey  []byte
	coinSnKey     []byte //	This is optional, could be nil
	serializedVPk []byte //	This is optional, could be nil
	serializedVSk []byte //	This is optional, could be nil
	value         uint64
}

/*type TxoOnPKForRing struct {
	*pqringctx.AddressPublicKey
	*pqringctx.ValueCommitment
	Vct             []byte //	value ciphertext
	CtKemSerialized []byte //  ciphertext for kem
}

type TxoOnPKHForSingle struct {
	*pqringctx.AddressPublicKey
	*pqringctx.ValueCommitment
	Vct             []byte //	value ciphertext
	CtKemSerialized []byte //  ciphertext for kem
}*/

/*
type TxoAddress struct {
	addressType TxoAddressType
}

type AddressPublicKeyForRing struct {
	t *PolyANTTVec // directly in NTT form
	e *PolyANTT
}

type TxoForRing struct {
	AddressPublicKey *AddressPublicKeyForRing
}

type TxoForSingle struct {
	addressPublicKeyHash []byte
	value                uint64
}*/
