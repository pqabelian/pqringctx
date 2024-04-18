package pqringctx

import (
	"reflect"
	"testing"
)

func TestPublicParameter_ExtractValueAndRandFromTxoMLP(t *testing.T) {
	ppLocal := Initialize(nil)

	t.Run("Pre", func(t *testing.T) {
		value := uint64(512)

		coinAddressPre, _, _, err := AddressKeyGen(pp, RandomBytes(pp.paramKeyGenSeedBytesLen))
		if err != nil {
			panic(err)
		}

		randSeed := RandomBytes(pp.paramKeyGenSeedBytesLen)

		valuePublicKeyPre, valueSecretKeyPre, err := ValueKeyGen(pp, randSeed)
		if err != nil {
			panic(err)
		}

		txo, cmtr, err := ppLocal.txoRCTPreGen(coinAddressPre, valuePublicKeyPre, value)
		if err != nil {
			t.Errorf("txo gen fail")
			return
		}
		gotValue, gotCmtr, err := ppLocal.ExtractValueAndRandFromTxoMLP(txo, valuePublicKeyPre, valueSecretKeyPre)
		if err != nil {
			t.Errorf("txo gen fail")
			return
		}

		if gotValue != value {
			t.Errorf("ExtractValueAndRandFromTxoMLP() gotValue = %v, want %v", gotValue, value)
			return
		}
		if !reflect.DeepEqual(cmtr, gotCmtr) {
			t.Errorf("ExtractValueAndRandFromTxoMLP() gotCmtr = %v, want %v", gotCmtr, cmtr)
			return
		}
	})

	t.Run("RCT", func(t *testing.T) {
		value := uint64(512)

		coinSpendKeyRandSeed := RandomBytes(pp.paramKeyGenSeedBytesLen)
		coinSerialNumberKeyRandSeed := RandomBytes(pp.paramKeyGenSeedBytesLen)

		coinDetectorKey := RandomBytes(pp.GetParamMACKeyBytesLen())
		publicRand := RandomBytes(pp.GetParamKeyGenPublicRandBytesLen())

		var err error
		coinAddress, _, _, err := pp.CoinAddressKeyForPKRingGen(coinSpendKeyRandSeed, coinSerialNumberKeyRandSeed, coinDetectorKey, publicRand)
		if err != nil {
			panic(err)
		}

		randSeed := RandomBytes(pp.paramKeyGenSeedBytesLen)

		coinValuePublicKey, coinValueSecretKey, err := pp.CoinValueKeyGen(randSeed)
		if err != nil {
			panic(err)
		}

		txo, cmtr, err := ppLocal.txoRCTGen(coinAddress, coinValuePublicKey, value)
		if err != nil {
			t.Errorf("txo gen fail")
			return
		}
		gotValue, gotCmtr, err := ppLocal.ExtractValueAndRandFromTxoMLP(txo, coinValuePublicKey, coinValueSecretKey)
		if err != nil {
			t.Errorf("txo gen fail")
			return
		}

		if gotValue != value {
			t.Errorf("ExtractValueAndRandFromTxoMLP() gotValue = %v, want %v", gotValue, value)
			return
		}
		if !reflect.DeepEqual(cmtr, gotCmtr) {
			t.Errorf("ExtractValueAndRandFromTxoMLP() gotCmtr = %v, want %v", gotCmtr, cmtr)
			return
		}
	})

	t.Run("Single", func(t *testing.T) {
		value := uint64(512)

		coinSpendKeyRandSeed := RandomBytes(pp.paramKeyGenSeedBytesLen)

		coinDetectorKey := RandomBytes(pp.GetParamMACKeyBytesLen())
		publicRand := RandomBytes(pp.GetParamKeyGenPublicRandBytesLen())

		coinAddress, _, err := pp.CoinAddressKeyForPKHSingleGen(coinSpendKeyRandSeed, coinDetectorKey, publicRand)
		if err != nil {
			panic(err)
		}

		txo, err := ppLocal.txoSDNGen(coinAddress, value)
		if err != nil {
			t.Errorf("txo gen fail")
			return
		}
		gotValue, _, err := ppLocal.ExtractValueAndRandFromTxoMLP(txo, nil, nil)
		if err != nil {
			t.Errorf("txo gen fail")
			return
		}

		if gotValue != value {
			t.Errorf("ExtractValueAndRandFromTxoMLP() gotValue = %v, want %v", gotValue, value)
			return
		}

	})
}
