package pqringct

//const (
//	//	PQRingCT, 2022.03.31
//	TxoSerializeSizeMaxAllowed          = 1048576 //1024*1024*1, 1M bytes
//	SerialNumberSerializeSizeMaxAllowed = 128     // 128 bytes
//	TxMemoSerializeSizeMaxAllowed       = 1024    // 1024 bytes
//	TxWitnessSerializeSizeMaxAllowed    = 8388608 //1024*1024*8, 8M bytes
//)

// Put these serialization-related constants here, since the caller may need to know these constants.
const (
	MAXALLOWED                  uint32 = 4294967295 // 2^32-1
	MaxAllowedKemCiphertextSize uint32 = 1048576    // 2^20
	MaxAllowedTxMemoSize        uint32 = 1024       // bytes
	MaxAllowedSerialNumberSize  uint32 = 64         // 512 bits = 64 bytes
	MaxAllowedChallengeSeedSize uint32 = 64         // use SHA512 to generate the challenge seed
	MaxAllowedRpulpProofSize    uint32 = 8388608    // 2^23, 8M bytes
	MaxAllowedTxWitnessSize     uint32 = 16777216   // 2^24, 16M bytes
	MaxAllowedElrsSignatureSize uint32 = 8388608    // 2^23, 8M bytes
	MaxAllowedTrTxInputSize     uint32 = 8388608    // 2^23, 8M bytes
)

func AddressKeyGen(pp *PublicParameter, seed []byte) ([]byte, []byte, []byte, error) {
	apk, ask, err := pp.addressKeyGen(seed)
	if err != nil {
		return nil, nil, nil, err
	}

	serializedAPk, err := pp.SerializeAddressPublicKey(apk)
	if err != nil {
		return nil, nil, nil, err
	}

	serializedASksp, err := pp.SerializeAddressSecretKeySp(ask.AddressSecretKeySp)
	if err != nil {
		return nil, nil, nil, err
	}
	serializedASksn, err := pp.SerializeAddressSecretKeySn(ask.AddressSecretKeySn)
	if err != nil {
		return nil, nil, nil, err
	}
	return serializedAPk, serializedASksp, serializedASksn, nil
}

func AddressKeyVerify(pp *PublicParameter, serialzedAPk []byte, serializedASksp []byte, serializedASksn []byte) (valid bool, hints string) {
	apk, err := pp.DeserializeAddressPublicKey(serialzedAPk)
	if err != nil {
		return false, err.Error()
	}

	asksp, err := pp.DeserializeAddressSecretKeySp(serializedASksp)
	if err != nil {
		return false, err.Error()
	}

	asksn, err := pp.DeserializeAddressSecretKeySn(serializedASksn)
	if err != nil {
		return false, err.Error()
	}

	ask := &AddressSecretKey{
		AddressSecretKeySp: asksp,
		AddressSecretKeySn: asksn,
	}

	return pp.addressKeyVerify(apk, ask)
}

// ask = (s, m_a), apk = (t = As, e = <a,s>+m_a). s is asksp, m_a is asksn
func ValueKeyGen(pp *PublicParameter, seed []byte) ([]byte, []byte, error) {
	vpk, vsk, err := pp.valueKeyGen(seed)
	if err != nil {
		return nil, nil, err
	}
	return vpk, vsk, nil
}

func ValueKeyVerify(pp *PublicParameter, serialzedVPk []byte, serializedVsp []byte) (valid bool, hints string) {
	//	From the caller, (serialzedVPk, serializedVsp) was obtained by call ValueKeyGen(pp *PublicParameter, seed []byte).
	return pp.valueKeyVerify(serialzedVPk, serializedVsp)
}

func CoinbaseTxGen(pp *PublicParameter, vin uint64, txOutputDescs []*TxOutputDesc, txMemo []byte) (cbTx *CoinbaseTx, err error) {
	return pp.coinbaseTxGen(vin, txOutputDescs, txMemo)
}
func CoinbaseTxVerify(pp *PublicParameter, cbTx *CoinbaseTx) (bool, error) {
	return pp.coinbaseTxVerify(cbTx)
}

func TransferTxGen(pp *PublicParameter, inputDescs []*TxInputDesc, outputDescs []*TxOutputDesc, fee uint64, txMemo []byte) (trTx *TransferTx, err error) {
	return pp.transferTxGen(inputDescs, outputDescs, fee, txMemo)
}
func TransferTxVerify(pp *PublicParameter, trTx *TransferTx) (bool, error) {
	return pp.transferTxVerify(trTx)
}
func TxoCoinReceive(pp *PublicParameter, txo *Txo, address []byte, serializedVPk []byte, serializedVSk []byte) (valid bool, v uint64, err error) {
	bl, value, err := pp.txoCoinReceive(txo, address, serializedVPk, serializedVSk)

	if err != nil {
		return false, 0, err
	}
	return bl, value, nil
}

// LedgerTxoSerialNumberGen() generates the Serial Number for a LgrTxo.
func LedgerTxoSerialNumberGen(pp *PublicParameter, lgrTxo *LgrTxo, serializedAsksn []byte) ([]byte, error) {
	sn, err := pp.ledgerTXOSerialNumberGen(lgrTxo, serializedAsksn)
	if err != nil {
		return nil, err
	}
	return sn, nil
}

//func LedgerTxoIdCompute(pp *PublicParameter, identifier []byte) ([]byte, error) {
//	lgrTxoId, err := Hash(identifier)
//	if err != nil {
//		return nil, err
//	}
//	return lgrTxoId, nil
//}

//	Data structures for Transaction generation/verify	begin

func NewTxOutputDescv2(pp *PublicParameter, serializedAPk []byte, serializedVPk []byte, value uint64) *TxOutputDesc {
	//return newTxOutputDescv2(serializedAPk, serializedVPk, value)
	return &TxOutputDesc{
		serializedAPk: serializedAPk,
		serializedVPk: serializedVPk,
		value:         value,
	}
}

func NewTxInputDescv2(pp *PublicParameter, lgrTxoList []*LgrTxo, sidx uint8, serializedASksp []byte, serializedASksn []byte, serializedVPk []byte, serializedVSk []byte, value uint64) *TxInputDesc {
	//return newTxInputDescv2(lgrTxoList, sidx, serializedASksn, serializedASksp, serializedVPk, serializedVSk, value)
	return &TxInputDesc{
		lgrTxoList:      lgrTxoList,
		sidx:            sidx,
		serializedASksp: serializedASksp,
		serializedASksn: serializedASksn,
		serializedVPk:   serializedVPk,
		serializedVSk:   serializedVSk,
		value:           value,
	}
}

func NewLgrTxo(txo *Txo, id []byte) *LgrTxo {
	return &LgrTxo{
		txo: txo,
		id:  id,
	}
}

//	Data structures for Transaction generation/verify	end

// serialize APIs	begin
func SerializeTxo(pp *PublicParameter, txo *Txo) ([]byte, error) {
	serialized, err := pp.SerializeTxo(txo)
	if err != nil {
		return nil, err
	}
	return serialized, nil
}

func DeserializeTxo(pp *PublicParameter, serializedTxo []byte) (*Txo, error) {
	txo, err := pp.DeserializeTxo(serializedTxo)
	if err != nil {
		return nil, err
	}
	return txo, nil
}

func SerializeCbTxWitnessJ1(pp *PublicParameter, witness *CbTxWitnessJ1) ([]byte, error) {
	serialized, err := pp.SerializeCbTxWitnessJ1(witness)
	if err != nil {
		return nil, err
	}
	return serialized, nil
}

func DeserializeCbTxWitnessJ1(pp *PublicParameter, serializedWitness []byte) (*CbTxWitnessJ1, error) {
	witness, err := pp.DeserializeCbTxWitnessJ1(serializedWitness)
	if err != nil {
		return nil, err
	}
	return witness, nil
}

func SerializeCbTxWitnessJ2(pp *PublicParameter, witness *CbTxWitnessJ2) ([]byte, error) {
	serialized, err := pp.SerializeCbTxWitnessJ2(witness)
	if err != nil {
		return nil, err
	}
	return serialized, nil
}

func DeserializeCbTxWitnessJ2(pp *PublicParameter, serializedWitness []byte) (*CbTxWitnessJ2, error) {
	witness, err := pp.DeserializeCbTxWitnessJ2(serializedWitness)
	if err != nil {
		return nil, err
	}
	return witness, nil
}

//	serialize APIs	end

//	sizes begin

func GetParamSeedBytesLen(pp *PublicParameter) int {
	return pp.paramKeyGenSeedBytesLen
}

func GetAddressPublicKeySerializeSize(pp *PublicParameter) int {
	return pp.AddressPublicKeySerializeSize()
}

func GetValuePublicKeySerializeSize(pp *PublicParameter) int {
	return 1188
}

func GetTxInputMaxNum(pp *PublicParameter) int {
	return pp.paramI
}
func GetTxOutputMaxNum(pp *PublicParameter) int {
	return pp.paramJ
}

func GetSerialNumberSerializeSize(pp *PublicParameter) int {
	return pp.ledgerTxoSerialNumberSerializeSize()
}

func GetNullSerialNumber(pp *PublicParameter) []byte {
	snSize := pp.ledgerTxoSerialNumberSerializeSize()
	nullSn := make([]byte, snSize)
	for i := 0; i < snSize; i++ {
		nullSn[i] = 0
	}
	return nullSn
}

//	sizes end

// approximate Size begin
func GetTxoSerializeSizeApprox(pp *PublicParameter) int {
	return pp.TxoSerializeSize()
}

func GetCbTxWitnessSerializeSizeApprox(pp *PublicParameter, outTxoNum int) int {
	if outTxoNum == 0 {
		return 0
	}

	if outTxoNum == 1 {
		return pp.CbTxWitnessJ1SerializeSizeApprox()
	}

	if outTxoNum > 1 {
		return pp.CbTxWitnessJ2SerializeSizeApprox(outTxoNum)
	}

	return 0
}

func GetTrTxWitnessSerializeSizeApprox(pp *PublicParameter, inputRingSizes []int, outputTxoNum int) int {
	return pp.TrTxWitnessSerializeSizeApprox(inputRingSizes, outputTxoNum)
}

//	approximate Size end
