package pqringctx

import (
	"reflect"
	"testing"
)

func TestPublicParameter_CoinAddressKeyForPKRingGen_CoinAddressKeyForPKRingVerify(t *testing.T) {
	pp := Initialize(nil)

	for i := 0; i < 100; i++ {
		coinSpendKeyRandSeed := RandomBytes(pp.paramKeyGenSeedBytesLen)
		coinSerialNumberKeyRandSeed := RandomBytes(pp.paramKeyGenSeedBytesLen)

		coinDetectorKey := RandomBytes(pp.GetParamMACKeyBytesLen())
		publicRand := RandomBytes(pp.GetParamKeyGenPublicRandBytesLen())

		coinAddress, coinSpendSecretKey, coinSerialNumberSecretKey, err := pp.CoinAddressKeyForPKRingGen(coinSpendKeyRandSeed, coinSerialNumberKeyRandSeed, coinDetectorKey, publicRand)
		if err != nil {
			t.Fatal(err)
		}

		for j := 0; j < 10; j++ {
			verify, err := pp.CoinAddressKeyForPKRingVerify(coinAddress, coinSpendSecretKey, coinSerialNumberSecretKey, coinDetectorKey)
			if err != nil {
				t.Fatal(err)
			}
			if !verify {
				t.Errorf("Verify Fail")
			}
		}
	}
}

func TestPublicParameter_CoinAddressKeyForPKHSingleGen_CoinAddressKeyForPKHSingleVerify(t *testing.T) {
	pp := Initialize(nil)

	for i := 0; i < 100; i++ {
		coinSpendKeyRandSeed := RandomBytes(pp.paramKeyGenSeedBytesLen)

		coinDetectorKey := RandomBytes(pp.GetParamMACKeyBytesLen())
		publicRand := RandomBytes(pp.GetParamKeyGenPublicRandBytesLen())

		coinAddress, coinSpendSecretKey, err := pp.CoinAddressKeyForPKHSingleGen(coinSpendKeyRandSeed, coinDetectorKey, publicRand)
		if err != nil {
			t.Fatal(err)
		}
		for j := 0; j < 10; j++ {
			verify, err := pp.CoinAddressKeyForPKHSingleVerify(coinAddress, coinSpendSecretKey, coinDetectorKey)
			if err != nil {
				t.Fatal(err)
			}
			if !verify {
				t.Errorf("Verify Fail")
			}
		}
	}
}

func TestPublicParameter_CoinValueKeyGen_CoinValueKeyVerify(t *testing.T) {
	pp := Initialize(nil)

	for i := 0; i < 100; i++ {
		randSeed := RandomBytes(pp.paramKeyGenSeedBytesLen)

		coinValuePublicKey, coinValueSecretKey, err := pp.CoinValueKeyGen(randSeed)
		if err != nil {
			t.Fatal(err)
		}
		for j := 0; j < 10; j++ {
			copiedCoinValueSecretKey := make([]byte, len(coinValueSecretKey))
			copy(copiedCoinValueSecretKey, coinValueSecretKey)
			verify, hints := pp.CoinValueKeyVerify(coinValuePublicKey, copiedCoinValueSecretKey)
			if len(hints) != 0 {
				t.Logf("%d-th Verification", i)
				t.Fatal(hints)
			}
			if !verify {
				t.Logf("%d-th Verification", i)
				t.Errorf("Verify Fail")
			}
		}
	}
}
func TestPublicParameter_MLPKey_Sizes(t *testing.T) {
	pp := Initialize(nil)

	coinAddressTypes := []CoinAddressType{
		CoinAddressTypePublicKeyForRingPre,
		CoinAddressTypePublicKeyForRing,
		CoinAddressTypePublicKeyHashForSingle,
	}

	for i := 0; i < len(coinAddressTypes); i++ {
		reflectType := reflect.ValueOf(coinAddressTypes[i]).Type()
		t.Logf(" -- CoinAddress Type: %s -- ", reflectType.Name())

		size, err := pp.GetCoinAddressSize(coinAddressTypes[i])
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("CoinAddress Size: %d byte", size)

		size, err = pp.GetCoinSpendSecretKeySize(coinAddressTypes[i])
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("CoinSpendSecretKey Size: %d byte", size)

		size, err = pp.GetCoinSerialNumberSecretKeySize(coinAddressTypes[i])
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("CoinSerialNumberSecretKey Size: %d byte", size)

		t.Logf(" -------------------------- ")
	}

	t.Logf(" -------------------------- ")
	t.Logf("CoinValuePublicKey Size: %d byte", pp.GetCoinValuePublicKeySize())
	t.Logf("CoinValueSecretKey Size: %d byte", pp.GetCoinValueSecretKeySize())
	t.Logf(" -------------------------- ")
}
