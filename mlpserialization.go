package pqringctx

import (
	"errors"
	"github.com/cryptosuite/pqringctx/pqringctxkem"
)

func (pp *PublicParameter) GetTxoMLPSerializeSizeApprox(coinAddressType CoinAddressType) (int, error) {
	switch coinAddressType {
	case CoinAddressTypePublicKeyForRingPre:
		return pp.TxoPKRCTSerializeSize(coinAddressType), nil
	case CoinAddressTypePublicKeyForRing:
		return pp.TxoPKRCTSerializeSize(coinAddressType), nil
	case CoinAddressTypePublicKeyHashForSingle:
		return pp.TxoPKHSDNSerializeSizeApprox(), nil
	default:
		return 0, errors.New("TxoMLPSerializeSize: unsupported coinAddressType")
	}
}

func (pp *PublicParameter) TxoPKRCTSerializeSize(coinAddressType CoinAddressType) int {
	coinTypeLen := 1
	if coinAddressType == CoinAddressTypePublicKeyForRingPre {
		coinTypeLen = 0
	}
	return coinTypeLen +
		pp.AddressPublicKeyForRingSerializeSize() +
		pp.ValueCommitmentSerializeSize() +
		pp.TxoValueBytesLen() +
		VarIntSerializeSize(uint64(pqringctxkem.GetKemCiphertextBytesLen(pp.paramKem))) + pqringctxkem.GetKemCiphertextBytesLen(pp.paramKem)
	//	note that PQRingCTX use the same KEM as PQRingCT.
}

func (pp *PublicParameter) TxoPKHSDNSerializeSizeApprox() int {
	return 1 + // coinAddressType
		HashOutputBytesLen + // hash of AddressPublicKeyForSingle
		8 // uint64, as the value is in [0, 2^51-1], we use the max bytes (say, 8) as the Approx size.
}

func (pp *PublicParameter) GetNullSerialNumber() []byte {
	snSize := pp.ledgerTxoSerialNumberSerializeSize()
	nullSn := make([]byte, snSize)
	for i := 0; i < snSize; i++ {
		nullSn[i] = 0
	}
	return nullSn
}
