package pqringctx

import (
	"bytes"
	"fmt"
)

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
	outForRing   uint8
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

// TxWitness Serialization	begin

// todo
func (pp *PublicParameter) TxWitnessMLPSerializeSizeByDesc() (int, error) {
	return 0, nil
}

// TxWitnessMLPSerializeSize returns the serialized size for the input TxWitnessMLP.
// reviewed on 2023.12.04 todo
func (pp *PublicParameter) TxWitnessMLPSerializeSize(txWitnessMLP TxWitnessMLP) (int, error) {
	if txWitnessMLP == nil {
		return 0, errors.New("TxWitnessMLPSerializeSize: the input txWitnessMLP is nil")
	}

	switch txWitnessInst := txWitnessMLP.(type) {
	case *TxWitnessCbTxI0C0:
		if txWitnessMLP.TxCase() != TxCaseCbTxI0C0 {
			errStr := fmt.Sprintf("TxWitnessMLPSerializeSize: the input txWitnessMLP is TxWitnessCbTxI0C0, but the TxCase %d does not match", txWitnessMLP.TxCase())
			return 0, errors.New(errStr)
		}
		return pp.TxWitnessCbTxI0C0SerializeSize(), nil

	case *TxWitnessCbTxI0C1:
		if txWitnessMLP.TxCase() != TxCaseCbTxI0C1 {
			errStr := fmt.Sprintf("TxWitnessMLPSerializeSize: the input txWitnessMLP is TxWitnessCbTxI0C1, but the TxCase %d does not match", txWitnessMLP.TxCase())
			return 0, errors.New(errStr)
		}
		return pp.TxWitnessCbTxI0C1SerializeSize(), nil

	case *TxWitnessCbTxI0Cn:
		if txWitnessMLP.TxCase() != TxCaseCbTxI0Cn {
			errStr := fmt.Sprintf("TxWitnessMLPSerializeSize: the input txWitnessMLP is TxWitnessCbTxI0Cn, but the TxCase %d does not match", txWitnessMLP.TxCase())
			return 0, errors.New(errStr)
		}
		return pp.TxWitnessCbTxI0CnSerializeSize(txWitnessInst.balanceProof.RightCommNum()), nil

		// todo: more cases

	default:
		return 0, errors.New("TxoMLPSerializeSize: the input TxoMLP is not TxoRCTPre, TxoRCT, TxoSDN")
	}
}

// todo(MLP): to finish and review, 2023.12.04
func (pp *PublicParameter) SerializeTxWitnessMLP(txWitnessMLP TxWitnessMLP) (serializedTxWitness []byte, err error) {
	if txWitnessMLP == nil {
		return nil, errors.New("SerializeTxWitness: the input TxWitnessMLP is nil")
	}

	switch txWitnessInst := txWitnessMLP.(type) {
	case *TxWitnessCbTxI0C0:
		if txWitnessInst.TxCase() != TxCaseCbTxI0C0 {
			errStr := fmt.Sprintf("SerializeTxWitness: the input TxWitnessMLP is TxWitnessCbTxI0C0, but the TxCase %d does not match", txWitnessInst.TxCase())
			return nil, errors.New(errStr)
		}
		return pp.serializeTxWitnessCbTxI0C0(txWitnessInst)

	case *TxWitnessCbTxI0C1:
		if txWitnessInst.TxCase() != TxCaseCbTxI0C1 {
			errStr := fmt.Sprintf("SerializeTxWitness: the input TxWitnessMLP is TxWitnessCbTxI0C1, but the TxCase %d does not match", txWitnessInst.TxCase())
			return nil, errors.New(errStr)
		}
		return pp.serializeTxWitnessCbTxI0C1(txWitnessInst)

	case *TxWitnessCbTxI0Cn:
		if txWitnessInst.TxCase() != TxCaseCbTxI0Cn {
			errStr := fmt.Sprintf("SerializeTxWitness: the input TxWitnessMLP is TxWitnessCbTxI0Cn, but the TxCase %d does not match", txWitnessInst.TxCase())
			return nil, errors.New(errStr)
		}
		return pp.serializeTxWitnessCbTxI0Cn(txWitnessInst)

		// todo(MLP): more cases

	default:
		return nil, errors.New("SerializeTxWitness: the input TxWitnessMLP is not in the supported TxCases")
	}
}

func (pp *PublicParameter) extractTxCaseFromSerializedTxWitnessMLP(serializedTxWitness []byte) (TxCase, error) {
	if len(serializedTxWitness) <= 0 {
		return 0, errors.New("extractTxCaseFromSerializedTxWitnessMLP: the input serializedTxWitness is nil or empty")
	}

	txCase := TxCase(serializedTxWitness[0])

	return txCase, nil

}

func (pp *PublicParameter) DeserializeTxWitnessMLP(serializedTxWitness []byte) (txWitnessMLP TxWitnessMLP, err error) {
	n := len(serializedTxWitness)

	if n <= 0 {
		return nil, errors.New("DeserializeTxWitnessMLP: the input serializedTxWitness is nil or empty")
	}

	txCase, err := pp.extractTxCaseFromSerializedTxWitnessMLP(serializedTxWitness)
	if err != nil {
		return nil, err
	}

	switch txCase {
	case TxCaseCbTxI0C0:
		return pp.deserializeTxWitnessCbTxI0C0(serializedTxWitness)
	case TxCaseCbTxI0C1:
		return pp.deserializeTxWitnessCbTxI0C1(serializedTxWitness)
	case TxCaseCbTxI0Cn:
		return pp.deserializeTxWitnessCbTxI0Cn(serializedTxWitness)
	default:
		return nil, errors.New("DeserializeTxWitnessMLP: the input serializedTxWitness has a TxCase that is not supported")
	}
}

// TxWitnessCbTxI0C0SerializeSize returns the serialized size for TxWitnessCbTxI0C0.
// reviewed on 2023.12.04
func (pp *PublicParameter) TxWitnessCbTxI0C0SerializeSize() int {
	// TxWitnessCbTxI0C0 actually does not contain any witness, and only contain its TxCase.
	return 1
}

// serializeTxWitnessCbTxI0C0 serializes the input txWitnessCbTxI0C0.
// reviewed on 2023.12.04
func (pp *PublicParameter) serializeTxWitnessCbTxI0C0(txWitnessCbTxI0C0 *TxWitnessCbTxI0C0) ([]byte, error) {
	if txWitnessCbTxI0C0 == nil {
		return nil, errors.New("serializeTxWitnessCbTxI0C0: the input txWitnessCbTxI0C0 is nil")
	}

	if txWitnessCbTxI0C0.txCase != TxCaseCbTxI0C0 {
		return nil, fmt.Errorf("serializeTxWitnessCbTxI0C0: the TxCase of input txWitnessCbTxI0C0 is %d rather than the expected TxCaseCbTxI0C0 (%d)", txWitnessCbTxI0C0.txCase, TxCaseCbTxI0C0)
	}

	w := bytes.NewBuffer(make([]byte, 0, 1))

	// txWitnessCbTxI0C0.txCase is fixed-length, say 1 byte
	err := w.WriteByte(byte(txWitnessCbTxI0C0.txCase))
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// deserializeTxWitnessCbTxI0C0 deserializes the input []byte to a txWitnessCbTxI0C0.
// reviewed on 2023.12.04
func (pp *PublicParameter) deserializeTxWitnessCbTxI0C0(serializedTxWitnessCbTxI0C0 []byte) (*TxWitnessCbTxI0C0, error) {
	r := bytes.NewReader(serializedTxWitnessCbTxI0C0)

	txCase, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if txCase != byte(TxCaseCbTxI0C0) {
		return nil, errors.New("deserializeTxWitnessCbTxI0C0: the deserialized TxCase is not TxCaseCbTxI0C0")
	}

	return &TxWitnessCbTxI0C0{
		txCase: TxCaseCbTxI0C0,
	}, nil
}

// TxWitnessCbTxI0C1SerializeSize returns the serilaized size for TxWitnessCbTxI0C1.
// Finished and reviewed on 2023.12.04.
func (pp *PublicParameter) TxWitnessCbTxI0C1SerializeSize() int {
	n := 1 + //	txCase       TxCase
		pp.balanceProofL0R1SerializeSize() //	balanceProof *balanceProofL0R1
	return n
}

// serializeTxWitnessCbTxI0C1 serialize the input txWitnessCbTxI0C1.
// Finished and reviewed on 2023.12.04.
func (pp *PublicParameter) serializeTxWitnessCbTxI0C1(txWitnessCbTxI0C1 *TxWitnessCbTxI0C1) ([]byte, error) {
	if txWitnessCbTxI0C1 == nil {
		return nil, errors.New("serializeTxWitnessCbTxI0C1: the input txWitnessCbTxI0C1 is nil")
	}

	if txWitnessCbTxI0C1.txCase != TxCaseCbTxI0C1 {
		return nil, fmt.Errorf("serializeTxWitnessCbTxI0C1: the TxCase of input txWitnessCbTxI0C1 is %d rather than the expected TxCaseCbTxI0C0 (%d)", txWitnessCbTxI0C1.txCase, TxCaseCbTxI0C1)
	}

	w := bytes.NewBuffer(make([]byte, 0, pp.TxWitnessCbTxI0C1SerializeSize()))

	// txWitnessCbTxI0C0.txCase is fixed-length, say 1 byte
	err := w.WriteByte(byte(txWitnessCbTxI0C1.txCase))
	if err != nil {
		return nil, err
	}

	//  balanceProof *balanceProofL0R1
	serializedBpf, err := pp.serializeBalanceProofL0R1(txWitnessCbTxI0C1.balanceProof)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(serializedBpf)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// deserializeTxWitnessCbTxI0C1 deserialize the input serializedTxWitnessCbTxI0C1 into a txWitnessCbTxI0C1.
// Finished and reviewed on 2023.12.04.
func (pp *PublicParameter) deserializeTxWitnessCbTxI0C1(serializedTxWitnessCbTxI0C1 []byte) (*TxWitnessCbTxI0C1, error) {
	r := bytes.NewReader(serializedTxWitnessCbTxI0C1)

	txCase, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if txCase != byte(TxCaseCbTxI0C1) {
		return nil, errors.New("deserializeTxWitnessCbTxI0C1: the deserialized TxCase is not TxCaseCbTxI0C1")
	}

	serializedBpf := make([]byte, pp.balanceProofL0R1SerializeSize())
	_, err = r.Read(serializedBpf)
	if err != nil {
		return nil, err
	}
	bpf, err := pp.deserializeBalanceProofL0R1(serializedBpf)
	if err != nil {
		return nil, err
	}

	return &TxWitnessCbTxI0C1{
		txCase:       TxCaseCbTxI0C1,
		balanceProof: bpf,
	}, nil
}

// TxWitnessCbTxI0CnSerializeSizeByDesc returns the serialized size of TxWitnessCbTxI0Cn, according to the number of RingCT-privacy coins at the output side.
func (pp *PublicParameter) TxWitnessCbTxI0CnSerializeSize(outForRing uint8) int {
	n := 1 + //	txCase       TxCase
		1 + // outForRing uint8
		pp.balanceProofLmRnSerializeSizeByCommNum(0, outForRing) //	balanceProof *balanceProofLmRn
	return n
}

func (pp *PublicParameter) serializeTxWitnessCbTxI0Cn(txWitnessCbTxI0Cn *TxWitnessCbTxI0Cn) ([]byte, error) {
	if txWitnessCbTxI0Cn == nil {
		return nil, errors.New("serializeTxWitnessCbTxI0Cn: the input txWitnessCbTxI0Cn is nil")
	}

	if txWitnessCbTxI0Cn.txCase != TxCaseCbTxI0Cn {
		return nil, fmt.Errorf("serializeTxWitnessCbTxI0Cn: the TxCase of input txWitnessCbTxI0Cn is %d rather than the expected TxCaseCbTxI0Cn (%d)", txWitnessCbTxI0Cn.txCase, TxCaseCbTxI0Cn)
	}

	w := bytes.NewBuffer(make([]byte, 0, pp.TxWitnessCbTxI0CnSerializeSize(txWitnessCbTxI0Cn.outForRing)))

	// txCase       TxCase
	err := w.WriteByte(byte(txWitnessCbTxI0Cn.txCase))
	if err != nil {
		return nil, err
	}

	// outForRing   uint8
	err = w.WriteByte(txWitnessCbTxI0Cn.outForRing)
	if err != nil {
		return nil, err
	}

	//  balanceProof *balanceProofL0Rn
	serializedBpf, err := pp.serializeBalanceProofLmRn(txWitnessCbTxI0Cn.balanceProof)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(serializedBpf)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}
func (pp *PublicParameter) deserializeTxWitnessCbTxI0Cn(serializedTxWitnessCbTxI0Cn []byte) (*TxWitnessCbTxI0Cn, error) {
	r := bytes.NewReader(serializedTxWitnessCbTxI0Cn)

	txCase, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if txCase != byte(TxCaseCbTxI0Cn) {
		return nil, errors.New("deserializeTxWitnessCbTxI0Cn: the deserialized TxCase is not TxCaseCbTxI0Cn")
	}

	outForRing, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	serializedBpf := make([]byte, pp.balanceProofLmRnSerializeSizeByCommNum(0, outForRing))
	_, err = r.Read(serializedBpf)
	if err != nil {
		return nil, err
	}
	bpf, err := pp.deserializeBalanceProofLmRn(serializedBpf)
	if err != nil {
		return nil, err
	}

	return &TxWitnessCbTxI0Cn{
		txCase:       TxCaseCbTxI0Cn,
		outForRing:   outForRing,
		balanceProof: bpf,
	}, nil
}

//	TxWitness Serialization	end
