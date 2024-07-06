package pqringctx

import (
	"bytes"
	"fmt"
)

//	LgrTxoMLP	begin

// LgrTxoMLPIdSerializeSize returns the serialize size of LgrTxoMLP.id.
// Note that this must keep the same as pqringct.LgrTxoIdSerializeSize.
// added on 2023.12.14
// reviewed on 2023.12.14
// moved from mlptransaction.go 2024.07.01
// reviewed by Alice, 2024.07.01
func (pp *PublicParameter) LgrTxoMLPIdSerializeSize() int {
	return HashOutputBytesLen
}

// LgrTxoMLPSerializeSize returns the serialize size of LgrTxoMLP.
// Note that, for the case of lgrTxo.txo being a TxoRctPre, this must keep the same as pqringct.LgrTxoSerializeSize.
// added on 2023.12.14
// reviewed on 2023.12.14
// moved from mlptransaction.go 2024.07.01
// reviewed by Alice, 2024.07.01
func (pp *PublicParameter) lgrTxoMLPSerializeSize(lgrTxo *LgrTxoMLP) (int, error) {

	if !pp.LgrTxoMLPSanityCheck(lgrTxo) {
		return 0, fmt.Errorf("LgrTxoMLPSerializeSize: the input LgrTxoMLP is not well-form")
	}

	txoSerialize, err := pp.TxoMLPSerializeSize(lgrTxo.txo)
	if err != nil {
		return 0, err
	}

	return txoSerialize + pp.LgrTxoMLPIdSerializeSize(), nil
}

// SerializeLgrTxoMLP serializes the input LgrTxoMLP to []byte.
// Note that for the case of txoRCTPre, this must keep the same as pqringct.SerializeLgrTxo.
// added on 2023.12.14
// reviewed on 2023.12.14
// moved from mlptransaction.go 2024.07.01
// reviewed by Alice, 2024.07.01
func (pp *PublicParameter) SerializeLgrTxoMLP(lgrTxo *LgrTxoMLP) ([]byte, error) {

	if !pp.LgrTxoMLPSanityCheck(lgrTxo) {
		return nil, fmt.Errorf("SerializeLgrTxoMLP: the input LgrTxoMLP is not well-form")
	}

	length, err := pp.lgrTxoMLPSerializeSize(lgrTxo)
	if err != nil {
		return nil, err
	}
	w := bytes.NewBuffer(make([]byte, 0, length))

	//	txo: fixed length
	//  It is fixed length in pqringct, but not anymore in pqringctx.
	//	To keep back-compatible with pqringct, here we still use w.Write, as in pqringct.
	serializedTxo, err := pp.SerializeTxoMLP(lgrTxo.txo)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(serializedTxo)
	if err != nil {
		return nil, err
	}

	//	id: fixed-length
	_, err = w.Write(lgrTxo.id)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// DeserializeLgrTxoMLP deserialize the input []byte to a LgrTxoMLP.
// Note that for the case of txoRCTPre, this must keep the same as pqringct.DeserializeLgrTxo.
// added on 2023.12.14
// reviewed on 2023.12.14
// reviewed on 2023.12.20
// moved from mlptransaction.go 2024.07.01
// reviewed by Alice, 2024.07.01
func (pp *PublicParameter) DeserializeLgrTxoMLP(serializedLgrTxo []byte) (*LgrTxoMLP, error) {
	if len(serializedLgrTxo) == 0 {
		return nil, fmt.Errorf("DeserializeLgrTxoMLP: the input serializedLgrTxo is empty")
	}

	r := bytes.NewReader(serializedLgrTxo)

	// To be compatible with pqringct, we have to use this way to determine the bytes for the serializedTxo.
	// Note that this is based on the fact that pp.LgrTxoMLPIdSerializeSize() is a fixed length.
	serializedTxoLen := len(serializedLgrTxo) - pp.LgrTxoMLPIdSerializeSize()

	if serializedTxoLen <= 0 {
		return nil, fmt.Errorf("DeserializeLgrTxoMLP: the input serializedLgrTxo has an incorrect length")
	}

	serializedTxo := make([]byte, serializedTxoLen)
	_, err := r.Read(serializedTxo)
	if err != nil {
		return nil, err
	}
	txo, err := pp.DeserializeTxoMLP(serializedTxo)
	if err != nil {
		return nil, err
	}

	id := make([]byte, pp.LgrTxoMLPIdSerializeSize())
	_, err = r.Read(id)
	if err != nil {
		return nil, err
	}

	return &LgrTxoMLP{
		txo: txo,
		id:  id,
	}, nil
}

//	LgrTxoMLP	end

//	LgrTxo SerialNumber	begin

// LedgerTxoSerialNumberGen generates serialNumber for the input LgrTxoMLP, using the input coinSerialNumberSecretKey.
// NOTE: the input coinSerialNumberSecretKey could be nil, for example, when the input LgrTxoMLP is on a CoinAddressTypePublicKeyHashForSingle.
// NOTE: this must keep the same as pqringct.ledgerTXOSerialNumberGen, and consistent with the codes in TransferTxMLPGen.
// moved from mlptxo.go
// moved from mlptransaction.go 2024.07.01
// reviewed by Alice, 2024.07.01
func (pp *PublicParameter) LedgerTxoSerialNumberGen(lgrTxo *LgrTxoMLP, coinSerialNumberSecretKey []byte) ([]byte, error) {

	if !pp.LgrTxoMLPSanityCheck(lgrTxo) {
		return nil, fmt.Errorf("LedgerTxoSerialNumberGen: the input LgrTxoMLP is not well-form")
	}

	m_r, err := pp.expandKIDRMLP(lgrTxo)
	if err != nil {
		return nil, err
	}

	coinAddressType := lgrTxo.txo.CoinAddressType()

	var ma_p *PolyANTT
	if len(coinSerialNumberSecretKey) != 0 {
		if coinAddressType != CoinAddressTypePublicKeyForRingPre && coinAddressType != CoinAddressTypePublicKeyForRing {
			return nil, fmt.Errorf("LedgerTxoSerialNumberGen: the input coinSerialNumberSecretKey is not nil/empty, while the input lgrTxo's CoinAddressType (%d) is not CoinAddressTypePublicKeyForRingPre or CoinAddressTypePublicKeyForRing", coinAddressType)
		}

		askSn, err := pp.coinSerialNumberSecretKeyForPKRingParse(coinSerialNumberSecretKey)
		if err != nil {
			return nil, err
		}

		ma_p = pp.PolyANTTAdd(askSn.ma, m_r)

	} else {

		if coinAddressType != CoinAddressTypePublicKeyHashForSingle {
			return nil, fmt.Errorf("LedgerTxoSerialNumberGen: the input coinSerialNumberSecretKey is nil/empty, while the input lgrTxo's CoinAddressType (%d) is not CoinAddressTypePublicKeyHashForSingle", coinAddressType)
		}

		ma_p = m_r
	}

	sn, err := pp.ledgerTxoSerialNumberComputeMLP(ma_p)
	if err != nil {
		return nil, err
	}
	return sn, nil
}

// ledgerTxoSerialNumberSerializeSizeMLP returns serial size of null-serial-number.
// Note that this must keep the same as pqringct.ledgerTxoSerialNumberSerializeSize.
// reviewed on 2023.12.07.
// reviewed on 2023.12.14
// moved from mlptransaction.go 2024.07.01
// reviewed by Alice, 2024.07.01
func (pp *PublicParameter) ledgerTxoSerialNumberSerializeSizeMLP() int {
	return HashOutputBytesLen
}

// ledgerTxoSerialNumberComputeMLP computes the serial number from the input m'_a.
// Note that m'_a is the actual unique coin-serial-number. To have better efficiency, we store H(m'_a) as the coin-serial-number.
// That's why we refer to it as a "compute" algorithm, rather than "Generate".
// Note that this must keep the same as pqringct.ledgerTxoSerialNumberCompute.
// reviewed on 2023.12.14
// moved from mlptransaction.go 2024.07.01
// reviewed by Alice, 2024.07.01
func (pp *PublicParameter) ledgerTxoSerialNumberComputeMLP(ma_p *PolyANTT) ([]byte, error) {

	if !pp.PolyANTTSanityCheck(ma_p) {
		return nil, fmt.Errorf("ledgerTxoSerialNumberComputeMLP: the input ma_p is not well-form")
	}

	length := pp.PolyANTTSerializeSize()
	w := bytes.NewBuffer(make([]byte, 0, length))

	err := pp.writePolyANTT(w, ma_p)
	if err != nil {
		return nil, err
	}

	sn, err := Hash(w.Bytes())
	if err != nil {
		return nil, err
	}

	return sn, nil

	//tmp := make([]byte, pp.paramDA*8)
	//for k := 0; k < pp.paramDA; k++ {
	//	tmp = append(tmp, byte(a.coeffs[k]>>0))
	//	tmp = append(tmp, byte(a.coeffs[k]>>8))
	//	tmp = append(tmp, byte(a.coeffs[k]>>16))
	//	tmp = append(tmp, byte(a.coeffs[k]>>24))
	//	tmp = append(tmp, byte(a.coeffs[k]>>32))
	//	tmp = append(tmp, byte(a.coeffs[k]>>40))
	//	tmp = append(tmp, byte(a.coeffs[k]>>48))
	//	tmp = append(tmp, byte(a.coeffs[k]>>56))
	//}
	//res, err := Hash(tmp)
	//if err != nil {
	//	log.Fatalln("Error call Hash() in ledgerTxoSerialNumberCompute")
	//}
	//return res
}

// expandKIDRMLP expands the input LgrTxoMLP to a PolyANTT, named m_r, which will be used as a unique randomness for a LgrTxoMLP,
// since the caller will guarantee each LgrTxoMLP has a unique LgrTxoMLP.id.
// Note that for the case of the input lgrtxo.txo being a TxoRCTPre, this must keep the same as pqringct.expandKIDR.
// added on 2023.12.14
// reviewed on 2023.12.14
// reviewed by Alice, 2024.07.01
func (pp *PublicParameter) expandKIDRMLP(lgrtxo *LgrTxoMLP) (*PolyANTT, error) {

	if !pp.LgrTxoMLPSanityCheck(lgrtxo) {
		return nil, fmt.Errorf("expandKIDRMLP: the input LgrTxoMLP is not well-form")
	}

	serializedLgrTxo, err := pp.SerializeLgrTxoMLP(lgrtxo)
	if err != nil {
		return nil, err
	}
	seed, err := Hash(serializedLgrTxo)
	if err != nil {
		return nil, err
	}

	coeffs, err := pp.randomDaIntegersInQa(seed)
	if err != nil {
		return nil, err
	}
	return &PolyANTT{coeffs}, nil

	//bitNum := 38
	//bound := pp.paramQA
	//xof := sha3.NewShake128()
	//xof.Reset()
	//length := pp.paramDA
	//coeffs := make([]int64, 0, length)
	//xof.Write(seed)
	//for len(coeffs) < length {
	//	expectedNum := length - len(coeffs)
	//	buf := make([]byte, (int64(bitNum*expectedNum)*(1<<bitNum)/bound+7)/8)
	//	xof.Read(buf)
	//	tmp := fillWithBoundOld(buf, expectedNum, bitNum, bound)
	//	coeffs = append(coeffs, tmp...)
	//}
	//for i := 0; i < length; i++ {
	//	coeffs[i] = reduceInt64(coeffs[i], pp.paramQA)
	//}
	//return &PolyANTT{coeffs: coeffs}, nil
}

//	LgrTxo SerialNumber	end

//	Sanity-Check functions	begin

// LgrTxoMLPSanityCheck checks whether the input lgrTxoMLP *LgrTxoMLP is well-from:
// (1) lgrTxoMLP is not nil
// (2) lgrTxoMLP.id is not nil/empty
// (3) lgrTxoMLP.txo is well-form
// added and reviewed by Alice, 2024.07.01
// moved from mlptransaction.go, 2024.07.06
// todo: review by 2024.07
func (pp *PublicParameter) LgrTxoMLPSanityCheck(lgrTxoMLP *LgrTxoMLP) bool {
	if lgrTxoMLP == nil {
		return false
	}

	if len(lgrTxoMLP.id) == 0 {
		return false
	}

	if !pp.TxoMLPSanityCheck(lgrTxoMLP.txo) {
		return false
	}

	return true
}

//	Sanity-Check functions	end
