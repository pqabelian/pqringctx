package pqringctx

type CoinAddressType uint8

const (
	CoinAddressTypePublicKeyForRingPre    CoinAddressType = 0
	CoinAddressTypePublicKeyForRing       CoinAddressType = 1
	CoinAddressTypePublicKeyHashForSingle CoinAddressType = 2
)

type TxCase uint8

const (
	TxCaseCbTxI0C0 = 0
	TxCaseCbTxI0C1 = 1
	TxCaseCbTxI0Cn = 2
)

type BalanceProofCase uint8

const (
	BalanceProofCaseL0R1 = 0
	BalanceProofCaseL1R1 = 1
	BalanceProofCaseLmRn = 2
)

// TxoMLP is used as a component object for CoinbaseTxMLP and TransferTxMLP.
// As the Txos in one CoinbaseTxMLP/TransferTxMLP could be hosted on addresses for different privacy-levels
// and consequently have different structures,
// here we use []byte to denote Txo (in its serialized form).
// type TxoMLP []byte
// Note: We do not define standalone structure for Txo.
//
//	Instead, we directly use []byte in Txs to denote Txo, rather than using a structure.
//	This is because:
//	Txo is purely at the cryptography layer, and the caller of PQRINGCTX does not need to learn the details of Txo.
//	PQRINGCTX will be responsible for generating Txo and providing service/API on the generated Txo.
type TxoMLP interface {
	CoinAddressType() CoinAddressType
}

type TxoRCTPre struct {
	coinAddressType         CoinAddressType
	addressPublicKeyForRing *AddressPublicKeyForRing
	valueCommitment         *ValueCommitment
	vct                     []byte //	value ciphertext
	ctKemSerialized         []byte //  ciphertext for kem
}

func (txoRCTPre *TxoRCTPre) CoinAddressType() CoinAddressType {
	return txoRCTPre.coinAddressType
}

type TxoRCT struct {
	coinAddressType         CoinAddressType
	addressPublicKeyForRing *AddressPublicKeyForRing
	valueCommitment         *ValueCommitment
	vct                     []byte //	value ciphertext
	ctKemSerialized         []byte //  ciphertext for kem
}

func (txoRCT *TxoRCT) CoinAddressType() CoinAddressType {
	return txoRCT.coinAddressType
}

type TxoSDN struct {
	coinAddressType               CoinAddressType
	addressPublicKeyForSingleHash []byte
	value                         uint64
}

func (txoSDN *TxoSDN) CoinAddressType() CoinAddressType {
	return txoSDN.coinAddressType
}

// TxWitnessMLP is used as a component object for CoinbaseTxMLP and TransferTxMLP.
// As the TxWitnessMLP for different CoinbaseTxMLP/TransferTxMLP instances could have different structures,
// here we use []byte to denote Txo (in its serialized form).
// type TxWitnessMLP []byte
// Note: We do not define standalone structure for TxWitness.
//
//	This is because:
//	TxWitness is purely at the cryptography layer, and the caller of PQRINGCTX does not need to learn the details of TxWitness.
//	PQRINGCTX will be responsible for generating TxWitness and providing service/API on the generated TxWitness.
type TxWitnessMLP interface {
	TxCase() TxCase
}

type TxWitnessCbTxI0C0 struct {
	txCase TxCase
}

func (txWitness *TxWitnessCbTxI0C0) TxCase() TxCase {
	return txWitness.txCase
}

type TxWitnessCbTxI0C1 struct {
	txCase       TxCase
	balanceProof *balanceProofL0R1
}

func (txWitness *TxWitnessCbTxI0C1) TxCase() TxCase {
	return txWitness.txCase
}

type TxWitnessCbTxI0Cn struct {
	txCase       TxCase
	balanceProof *balanceProofLmRn
}

func (txWitness *TxWitnessCbTxI0Cn) TxCase() TxCase {
	return txWitness.txCase
}

type TxWitnessTrTx struct {
	txCase                     TxCase
	ma_ps                      []*PolyANTT                  // length I_ring, each for one RingCT-privacy Input. The key-image of the signing key, and is the pre-image of SerialNumber.
	cmt_ps                     []*ValueCommitment           // length I_ring, each for one RingCT-privacy Input. It commits the same value as the consumed Txo.
	elrsSigs                   []*elrsSignatureMLP          // length I_ring, each for one RingCT-privacy Input.
	addressPublicKeyForSingles []*AddressPublicKeyForSingle // length I_single_distinct, each for one distinct CoinAddress in pseudonym-privacy Inputs.
	simpsSigs                  []*simpsSignatureMLP         // length I_single_distinct, each for one distinct CoinAddress in pseudonym-privacy Inputs.
	b_hat                      *PolyCNTTVec
	c_hats                     []*PolyCNTT //	length n_2: n_2 = I+J+2 for I=1, and n_2 = I+J+4 for I >= 2.
	u_p                        []int64     // carry vector range proof, length paramDc, each lies in scope [-(eta_f-beta_f), (eta_f-beta_f)], where beta_f = D_c (J+1) for I=1 and beta_f = D_c (I+J+1) for I >= 2.
	rpulpproof                 *rpulpProofMLP
}

func (txWitness *TxWitnessTrTx) TxCase() TxCase {
	return txWitness.txCase
}

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
	txWitness TxWitnessMLP
}

// TransferTxMLP is defined for transferTx.
type TransferTxMLP struct {
	//	Version uint32	//	crypto-layer does not care the (actually does not have the concept of) version of transferTx.
	inputs    []*TxInputMLP
	txos      []TxoMLP
	fee       uint64
	txMemo    []byte
	txWitness TxWitnessMLP
}

// TxOutputDesc describes the information for generating Txo, for generating CoinbaseTx and TransferTx.
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

// New functions for TxInputDesc and TxOutputDesc 	begin
func NewTxOutputDescMLP(coinAddress []byte, serializedVPK []byte, value uint64) *TxOutputDescMLP {
	return &TxOutputDescMLP{
		coinAddress:   coinAddress,
		serializedVPK: serializedVPK,
		value:         value,
	}
}

//	New functions for TxInputDesc and TxOutputDesc 	end

// New and Get functions for Transactions	begin
func NewCoinbaseTxMLP(vin uint64, txos []TxoMLP, txMemo []byte, txWitness TxWitnessMLP) *CoinbaseTxMLP {
	return &CoinbaseTxMLP{
		vin:       vin,
		txos:      txos,
		txMemo:    txMemo,
		txWitness: txWitness,
	}
}

func (cbTx *CoinbaseTxMLP) GetTxos() []TxoMLP {
	return cbTx.txos
}

func (cbTx *CoinbaseTxMLP) GetTxWitness() TxWitnessMLP {
	return cbTx.txWitness
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

// BPFs	begin
type rpulpProofMLP struct {
	c_waves []*PolyCNTT //	lenth n
	c_hat_g *PolyCNTT
	psi     *PolyCNTT
	phi     *PolyCNTT
	chseed  []byte
	//	cmt_zs and zs, as the responses, need to have the infinite normal in a scope, say [-(eta_c-beta_c), (eta_c-beta_c)].
	//	That is why here we use PolyCVec rather than PolyCNTTVec.
	cmt_zs [][]*PolyCVec //	length n (J for CbTxWitnessJ2, I+J for TrTxWitness), each length paramK, each in (S_{eta_c - beta_c})^{L_c}
	zs     []*PolyCVec   //	length paramK, each in (S_{eta_c - beta_c})^{L_c}
}

type balanceProof interface {
	BalanceProofCase() BalanceProofCase
	LeftCommNum() int
	RightCommNum() int
}

type balanceProofL0R1 struct {
	balanceProofCase BalanceProofCase
	leftCommNum      int
	rightCommNum     int
	// bpf
	chseed []byte
	// zs, as the response, need to have infinite normal in a scopr, say [-(eta_c - beta_c), (eta_c - beta_c)].
	// That is why we use PolyCVec rather than PolyCNTTVec.
	zs []*PolyCVec //	length paramK, each in (S_{eta_c - beta_c})^{L_c}
}

func (bpf *balanceProofL0R1) BalanceProofCase() BalanceProofCase {
	return bpf.balanceProofCase
}
func (bpf *balanceProofL0R1) LeftCommNum() int {
	return bpf.leftCommNum
}
func (bpf *balanceProofL0R1) RightCommNum() int {
	return bpf.rightCommNum
}

type balanceProofL1R1 struct {
	balanceProofCase BalanceProofCase
	leftCommNum      int
	rightCommNum     int
	// bpf
	psi    *PolyCNTT
	chseed []byte
	//	zs1 and zs2, as the responses, need to have the infinite normal in a scope, say [-(eta_c-beta_c), (eta_c-beta_c)].
	//	That is why here we use PolyCVec rather than PolyCNTTVec.
	zs1 []*PolyCVec //	length paramK, each in (S_{eta_c - beta_c})^{L_c}
	zs2 []*PolyCVec //	length paramK, each in (S_{eta_c - beta_c})^{L_c}
}

func (bpf *balanceProofL1R1) BalanceProofCase() BalanceProofCase {
	return bpf.balanceProofCase
}
func (bpf *balanceProofL1R1) LeftCommNum() int {
	return bpf.leftCommNum
}
func (bpf *balanceProofL1R1) RightCommNum() int {
	return bpf.rightCommNum
}

type balanceProofLmRn struct {
	balanceProofCase BalanceProofCase
	leftCommNum      int
	rightCommNum     int
	// bpf
	b_hat      *PolyCNTTVec
	c_hats     []*PolyCNTT // length J+2
	u_p        []int64     // carry vector range proof, length paramDc, each lies in scope [-(eta_f-beta_f), (eta_f-beta_f)], where beta_f = D_c J.
	rpulpproof *rpulpProof
}

func (bpf *balanceProofLmRn) BalanceProofCase() BalanceProofCase {
	return bpf.balanceProofCase
}
func (bpf *balanceProofLmRn) LeftCommNum() int {
	return bpf.leftCommNum
}
func (bpf *balanceProofLmRn) RightCommNum() int {
	return bpf.rightCommNum
}

//	BPFs	end
