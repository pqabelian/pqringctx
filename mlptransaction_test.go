package pqringctx

import (
	"fmt"
	"github.com/cryptosuite/pqringct"
	"math/rand"
	"testing"
)

var pp = Initialize(nil)
var ppOld = pqringct.Initialize(nil)

var coinAddressMapping map[CoinAddressType][][]byte
var coinSpendSecretKeyMapping map[CoinAddressType][][]byte
var coinSerialNumberSecretKeyMap map[CoinAddressType][][]byte
var coinValuePublicKeyMap map[CoinAddressType][][]byte
var coinValueSecretKeyMap map[CoinAddressType][][]byte
var coinDetectorKeyMap map[CoinAddressType][][]byte

var numPre = 10
var seedPres = make([][]byte, 0, numPre)
var detectorKeyPres = make([][]byte, numPre)
var coinAddressPres = make([][]byte, 0, numPre)
var coinSpendSecretKeyPres = make([][]byte, 0, numPre)
var coinSerialNumberSecretKeyPres = make([][]byte, 0, numPre)
var valueKeyPreSeeds = make([][]byte, 0, numPre)
var valuePublicKeyPres = make([][]byte, 0, numPre)
var valueSecretKeyPres = make([][]byte, 0, numPre)

var numRand = 10
var coinSpendKeyRandSeeds = make([][]byte, 0, numRand)
var coinSerialNumberKeyRandSeeds = make([][]byte, 0, numRand)
var detectorKeys = make([][]byte, 0, numRand)
var coinAddresss = make([][]byte, 0, numRand)
var coinSpendSecretKeys = make([][]byte, 0, numRand)
var coinSerialNumberSecretKeys = make([][]byte, 0, numRand)
var valueKeySeeds = make([][]byte, 0, numRand)
var valuePublicKeys = make([][]byte, 0, numRand)
var valueSecretKeys = make([][]byte, 0, numRand)

var numSingle = 10
var coinSpendKeyRandSeedForSingles = make([][]byte, 0, numSingle)
var detectorKeyForSingles = make([][]byte, 0, numSingle)
var coinAddressForSingles = make([][]byte, 0, numSingle)
var coinSpendSecretKeyForSingles = make([][]byte, 0, numSingle)
var coinSerialNumberSecretKeySingles = make([][]byte, numSingle)
var valuePublicKeyForSingles = make([][]byte, numSingle)
var valueSecretKeyForSingles = make([][]byte, numSingle)

func InitialAddress() {
	coinAddressKeyForPKRingPreGen := func() (seed []byte,
		coinAddress []byte, coinSpendSecretKey []byte, coinSerialNumberSecretKey []byte) {
		seed = RandomBytes(pp.paramKeyGenSeedBytesLen)

		serializedAPk, serializedASksp, serializedASksn, err := pqringct.AddressKeyGen(ppOld, seed)
		if err != nil {
			panic(err)
		}

		return seed, serializedAPk, serializedASksp, serializedASksn
	}
	coinValueKeyPreGen := func() (randSeed []byte, coinValuePublicKey []byte, coinValueSecretKey []byte) {
		randSeed = RandomBytes(pp.paramKeyGenSeedBytesLen)

		var err error
		coinValuePublicKey, coinValueSecretKey, err = pqringct.ValueKeyGen(ppOld, randSeed)
		if err != nil {
			panic(err)
		}
		return randSeed, coinValuePublicKey, coinValueSecretKey
	}

	coinAddressKeyForPKRingGen := func() (coinSpendKeyRandSeed []byte, coinSerialNumberKeyRandSeed []byte, coinDetectorKey []byte,
		coinAddress []byte, coinSpendSecretKey []byte, coinSerialNumberSecretKey []byte) {

		coinSpendKeyRandSeed = RandomBytes(pp.paramKeyGenSeedBytesLen)
		coinSerialNumberKeyRandSeed = RandomBytes(pp.paramKeyGenSeedBytesLen)

		coinDetectorKey = RandomBytes(pp.GetParamMACKeyBytesLen())
		publicRand := RandomBytes(pp.GetParamKeyGenPublicRandBytesLen())

		var err error
		coinAddress, coinSpendSecretKey, coinSerialNumberSecretKey, err = pp.CoinAddressKeyForPKRingGen(coinSpendKeyRandSeed, coinSerialNumberKeyRandSeed, coinDetectorKey, publicRand)
		if err != nil {
			panic(err)
		}
		return coinSpendKeyRandSeed, coinSerialNumberKeyRandSeed, coinDetectorKey, coinAddress, coinSpendSecretKey, coinSerialNumberSecretKey
	}
	coinAddressKeyForPKHSingleGen := func() (coinSpendKeyRandSeed []byte, coinDetectorKey []byte,
		coinAddress []byte, coinSpendSecretKey []byte) {

		coinSpendKeyRandSeed = RandomBytes(pp.paramKeyGenSeedBytesLen)

		coinDetectorKey = RandomBytes(pp.GetParamMACKeyBytesLen())
		publicRand := RandomBytes(pp.GetParamKeyGenPublicRandBytesLen())

		var err error
		coinAddress, coinSpendSecretKey, err = pp.CoinAddressKeyForPKHSingleGen(coinSpendKeyRandSeed, coinDetectorKey, publicRand)
		if err != nil {
			panic(err)
		}
		return coinSpendKeyRandSeed, coinDetectorKey, coinAddress, coinSpendSecretKey
	}
	coinValueKeyGen := func() (randSeed []byte, coinValuePublicKey []byte, coinValueSecretKey []byte) {
		randSeed = RandomBytes(pp.paramKeyGenSeedBytesLen)

		var err error
		coinValuePublicKey, coinValueSecretKey, err = pp.CoinValueKeyGen(randSeed)
		if err != nil {
			panic(err)
		}
		return randSeed, coinValuePublicKey, coinValueSecretKey
	}

	for i := 0; i < numPre; i++ {
		seedPre, coinAddressPre, coinAddressSpendKeyPre, coinSerialNumberSKPre := coinAddressKeyForPKRingPreGen()
		seedPres = append(seedPres, seedPre)
		coinAddressPres = append(coinAddressPres, coinAddressPre)
		coinSpendSecretKeyPres = append(coinSpendSecretKeyPres, coinAddressSpendKeyPre)
		coinSerialNumberSecretKeyPres = append(coinSerialNumberSecretKeyPres, coinSerialNumberSKPre)

		valueKeyPreSeed, valuePublicKeyPre, valueSecretKeyPre := coinValueKeyPreGen()
		valueKeyPreSeeds = append(valueKeyPreSeeds, valueKeyPreSeed)
		valuePublicKeyPres = append(valuePublicKeyPres, valuePublicKeyPre)
		valueSecretKeyPres = append(valueSecretKeyPres, valueSecretKeyPre)
	}

	for i := 0; i < numRand; i++ {
		coinSpendKeyRandSeed, coinSerialNumberKeyRandSeed, detectorKey, coinAddress, coinSpendSecretKey, coinSerialNumberSecretKey := coinAddressKeyForPKRingGen()
		coinSpendKeyRandSeeds = append(coinSpendKeyRandSeeds, coinSpendKeyRandSeed)
		coinSerialNumberKeyRandSeeds = append(coinSerialNumberKeyRandSeeds, coinSerialNumberKeyRandSeed)
		detectorKeys = append(detectorKeys, detectorKey)
		coinAddresss = append(coinAddresss, coinAddress)
		coinSpendSecretKeys = append(coinSpendSecretKeys, coinSpendSecretKey)
		coinSerialNumberSecretKeys = append(coinSerialNumberSecretKeys, coinSerialNumberSecretKey)

		valueKeySeed, valuePublicKey, valueSecretKey := coinValueKeyGen()
		valueKeySeeds = append(valueKeySeeds, valueKeySeed)
		valuePublicKeys = append(valuePublicKeys, valuePublicKey)
		valueSecretKeys = append(valueSecretKeys, valueSecretKey)
	}

	for i := 0; i < numSingle; i++ {
		coinSpendKeyRandSeedForSingle, detectorKeyForSingle, coinAddressForSingle, coinSpendSecretKeyForSingle := coinAddressKeyForPKHSingleGen()
		coinSpendKeyRandSeedForSingles = append(coinSpendKeyRandSeedForSingles, coinSpendKeyRandSeedForSingle)
		detectorKeyForSingles = append(detectorKeyForSingles, detectorKeyForSingle)
		coinAddressForSingles = append(coinAddressForSingles, coinAddressForSingle)
		coinSpendSecretKeyForSingles = append(coinSpendSecretKeyForSingles, coinSpendSecretKeyForSingle)
	}

	coinAddressMapping = map[CoinAddressType][][]byte{
		CoinAddressTypePublicKeyForRingPre:    coinAddressPres,
		CoinAddressTypePublicKeyForRing:       coinAddresss,
		CoinAddressTypePublicKeyHashForSingle: coinAddressForSingles,
	}
	coinSpendSecretKeyMapping = map[CoinAddressType][][]byte{
		CoinAddressTypePublicKeyForRingPre:    coinSpendSecretKeyPres,
		CoinAddressTypePublicKeyForRing:       coinSpendSecretKeys,
		CoinAddressTypePublicKeyHashForSingle: coinSpendSecretKeyForSingles,
	}
	coinSerialNumberSecretKeyMap = map[CoinAddressType][][]byte{
		CoinAddressTypePublicKeyForRingPre:    coinSerialNumberSecretKeyPres,
		CoinAddressTypePublicKeyForRing:       coinSerialNumberSecretKeys,
		CoinAddressTypePublicKeyHashForSingle: coinSerialNumberSecretKeySingles,
	}
	coinDetectorKeyMap = map[CoinAddressType][][]byte{
		CoinAddressTypePublicKeyForRingPre:    detectorKeyPres,
		CoinAddressTypePublicKeyForRing:       detectorKeys,
		CoinAddressTypePublicKeyHashForSingle: detectorKeyForSingles,
	}
	coinValuePublicKeyMap = map[CoinAddressType][][]byte{
		CoinAddressTypePublicKeyForRingPre:    valuePublicKeyPres,
		CoinAddressTypePublicKeyForRing:       valuePublicKeys,
		CoinAddressTypePublicKeyHashForSingle: valuePublicKeyForSingles,
	}
	coinValueSecretKeyMap = map[CoinAddressType][][]byte{
		CoinAddressTypePublicKeyForRingPre:    valueSecretKeyPres,
		CoinAddressTypePublicKeyForRing:       valueSecretKeys,
		CoinAddressTypePublicKeyHashForSingle: valueSecretKeyForSingles,
	}
}

func TestPublicParameter_CoinbaseTxMLPGen_CoinbaseTxMLPVerify_Pure_Ring(t *testing.T) {
	InitialAddress()
	type cbtxGenArgs struct {
		vin              uint64
		txOutputDescMLPs []*TxOutputDescMLP
		txMemo           []byte
	}

	tests := []struct {
		name       string
		args       cbtxGenArgs
		wantErr    bool
		want       bool
		wantVerify bool
	}{
		{
			name: "[PASS]Pure PKRing -- Pure Old",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              2,
					},
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              254,
					},
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              256,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    false,
			want:       true,
			wantVerify: true,
		},
		{
			name: "[FAIL]Pure PKRing -- Pure Old -- value-gt",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              3,
					},
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              254,
					},
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              256,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    true,
			want:       false,
			wantVerify: false,
		},
		{
			name: "[FAIL]Pure PKRing -- Pure Old -- value-lt",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              1,
					},
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              254,
					},
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              256,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    true,
			want:       false,
			wantVerify: false,
		},

		{
			name: "[PASS]Pure PKRing -- Hybrid - 1",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              2,
					},
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              254,
					},
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              256,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    false,
			want:       true,
			wantVerify: true,
		},
		{
			name: "[FAIL]Pure PKRing -- Hybrid - 1 -- value-gt",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              3,
					},
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              254,
					},
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              256,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    true,
			want:       false,
			wantVerify: false,
		},
		{
			name: "[FAIL]Pure PKRing -- Hybrid - 1 -- value-lt",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              1,
					},
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              254,
					},
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              256,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    true,
			want:       false,
			wantVerify: false,
		},

		{
			name: "[PASS]Pure PKRing -- Hybrid - 2",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              2,
					},
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              254,
					},
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              256,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    false,
			want:       true,
			wantVerify: true,
		},
		{
			name: "[FAIL]Pure PKRing -- Hybrid - 2 -- value-gt",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              3,
					},
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              254,
					},
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              256,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    true,
			want:       false,
			wantVerify: false,
		},
		{
			name: "[FAIL]Pure PKRing -- Hybrid - 2 -- value-lt",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              1,
					},
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              254,
					},
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              256,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    true,
			want:       false,
			wantVerify: false,
		},

		{
			name: "[PASS]Pure PKRing -- Pure New",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              2,
					},
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              254,
					},
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              256,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    false,
			want:       true,
			wantVerify: true,
		},
		{
			name: "[FAIL]Pure PKRing -- Pure New -- value-gt",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              3,
					},
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              254,
					},
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              256,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    true,
			want:       false,
			wantVerify: false,
		},
		{
			name: "[FAIL]Pure PKRing -- Pure New -- value-lt",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              1,
					},
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              254,
					},
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              256,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    true,
			want:       false,
			wantVerify: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cbTx, err := pp.CoinbaseTxMLPGen(tt.args.vin, tt.args.txOutputDescMLPs, tt.args.txMemo)
			if (err != nil) != tt.wantErr {
				t.Errorf("CoinbaseTxMLPGen() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if (cbTx != nil) != tt.want {
				t.Errorf("CoinbaseTxMLPGen() error = %v, want %v", err, tt.wantErr)
				return
			}
			err = pp.CoinbaseTxMLPVerify(cbTx)
			if (err == nil) != tt.wantVerify {
				t.Errorf("CoinbaseTxMLPVerify() error = %v, wantVerifyErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestPublicParameter_CoinbaseTxMLPGen_CoinbaseTxMLPVerify_Hybrid(t *testing.T) {
	InitialAddress()
	type cbtxGenArgs struct {
		vin              uint64
		txOutputDescMLPs []*TxOutputDescMLP
		txMemo           []byte
	}

	tests := []struct {
		name       string
		args       cbtxGenArgs
		wantErr    bool
		want       bool
		wantVerify bool
	}{
		{
			name: "[PASS]Hybrid - 1",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              254,
					},
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              256,
					},
					{
						coinAddress: coinAddressForSingles[rand.Intn(numSingle)],
						value:       2,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    false,
			want:       true,
			wantVerify: true,
		},
		{
			name: "[FAIL]Hybrid - 1 -- value-gt-1",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              255,
					},
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              256,
					},
					{
						coinAddress: coinAddressForSingles[rand.Intn(numSingle)],
						value:       2,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    true,
			want:       false,
			wantVerify: false,
		},
		{
			name: "[FAIL]Hybrid - 1 -- value-gt-2",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              254,
					},
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              257,
					},
					{
						coinAddress: coinAddressForSingles[rand.Intn(numSingle)],
						value:       2,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    true,
			want:       false,
			wantVerify: false,
		},
		{
			name: "[FAIL]Hybrid - 1 -- value-gt-3",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              254,
					},
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              256,
					},
					{
						coinAddress: coinAddressForSingles[rand.Intn(numSingle)],
						value:       3,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    true,
			want:       false,
			wantVerify: false,
		},
		{
			name: "[FAIL]Hybrid - 1 -- value-lt-1",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              253,
					},
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              256,
					},
					{
						coinAddress: coinAddressForSingles[rand.Intn(numSingle)],
						value:       2,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    true,
			want:       false,
			wantVerify: false,
		},
		{
			name: "[FAIL]Hybrid - 1 -- value-lt-2",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              254,
					},
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              255,
					},
					{
						coinAddress: coinAddressForSingles[rand.Intn(numSingle)],
						value:       2,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    true,
			want:       false,
			wantVerify: false,
		},
		{
			name: "[FAIL]Hybrid - 1 -- value-lt-3",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              254,
					},
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              256,
					},
					{
						coinAddress: coinAddressForSingles[rand.Intn(numSingle)],
						value:       3,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    true,
			want:       false,
			wantVerify: false,
		},

		{
			name: "[PASS]Hybrid - 2",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              254,
					},
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              256,
					},
					{
						coinAddress: coinAddressForSingles[rand.Intn(numSingle)],
						value:       2,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    false,
			want:       true,
			wantVerify: true,
		},
		{
			name: "[FAIL]Hybrid - 2 -- value-gt-1",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              255,
					},
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              256,
					},
					{
						coinAddress: coinAddressForSingles[rand.Intn(numSingle)],
						value:       2,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    true,
			want:       false,
			wantVerify: false,
		},
		{
			name: "[FAIL]Hybrid - 2 -- value-gt-2",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              254,
					},
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              257,
					},
					{
						coinAddress: coinAddressForSingles[rand.Intn(numSingle)],
						value:       2,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    true,
			want:       false,
			wantVerify: false,
		},
		{
			name: "[FAIL]Hybrid - 2 -- value-gt-3",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              254,
					},
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              256,
					},
					{
						coinAddress: coinAddressForSingles[rand.Intn(numSingle)],
						value:       3,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    true,
			want:       false,
			wantVerify: false,
		},
		{
			name: "[FAIL]Hybrid - 2 -- value-lt-1",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              253,
					},
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              256,
					},
					{
						coinAddress: coinAddressForSingles[rand.Intn(numSingle)],
						value:       2,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    true,
			want:       false,
			wantVerify: false,
		},
		{
			name: "[FAIL]Hybrid - 2 -- value-lt-2",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              254,
					},
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              255,
					},
					{
						coinAddress: coinAddressForSingles[rand.Intn(numSingle)],
						value:       2,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    true,
			want:       false,
			wantVerify: false,
		},
		{
			name: "[FAIL]Hybrid - 2 -- value-lt-3",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddressPres[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeyPres[rand.Intn(numPre)],
						value:              254,
					},
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              256,
					},
					{
						coinAddress: coinAddressForSingles[rand.Intn(numSingle)],
						value:       3,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    true,
			want:       false,
			wantVerify: false,
		},

		{
			name: "[PASS]Hybrid - 3",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              254,
					},
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              256,
					},
					{
						coinAddress: coinAddressForSingles[rand.Intn(numSingle)],
						value:       2,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    false,
			want:       true,
			wantVerify: true,
		},
		{
			name: "[FAIL]Hybrid - 3 -- value-gt-1",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              255,
					},
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              256,
					},
					{
						coinAddress: coinAddressForSingles[rand.Intn(numSingle)],
						value:       2,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    true,
			want:       false,
			wantVerify: false,
		},
		{
			name: "[FAIL]Hybrid - 3 -- value-gt-2",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              254,
					},
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              257,
					},
					{
						coinAddress: coinAddressForSingles[rand.Intn(numSingle)],
						value:       2,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    true,
			want:       false,
			wantVerify: false,
		},
		{
			name: "[FAIL]Hybrid - 3 -- value-gt-3",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              254,
					},
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              256,
					},
					{
						coinAddress: coinAddressForSingles[rand.Intn(numSingle)],
						value:       3,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    true,
			want:       false,
			wantVerify: false,
		},
		{
			name: "[FAIL]Hybrid - 3 -- value-lt-1",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              253,
					},
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              256,
					},
					{
						coinAddress: coinAddressForSingles[rand.Intn(numSingle)],
						value:       2,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    true,
			want:       false,
			wantVerify: false,
		},
		{
			name: "[FAIL]Hybrid - 3 -- value-lt-2",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              254,
					},
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              255,
					},
					{
						coinAddress: coinAddressForSingles[rand.Intn(numSingle)],
						value:       2,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    true,
			want:       false,
			wantVerify: false,
		},
		{
			name: "[FAIL]Hybrid - 3 -- value-lt-3",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              254,
					},
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numRand)],
						value:              256,
					},
					{
						coinAddress: coinAddressForSingles[rand.Intn(numSingle)],
						value:       3,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    true,
			want:       false,
			wantVerify: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cbTx, err := pp.CoinbaseTxMLPGen(tt.args.vin, tt.args.txOutputDescMLPs, tt.args.txMemo)
			if (err != nil) != tt.wantErr {
				t.Errorf("CoinbaseTxMLPGen() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if (cbTx != nil) != tt.want {
				t.Errorf("CoinbaseTxMLPGen() error = %v, want %v", err, tt.wantErr)
				return
			}
			err = pp.CoinbaseTxMLPVerify(cbTx)
			if (err == nil) != tt.wantVerify {
				t.Errorf("CoinbaseTxMLPVerify() error = %v, wantVerifyErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestPublicParameter_CoinbaseTxMLPGen_CoinbaseTxMLPVerify_Pure_Single(t *testing.T) {
	InitialAddress()
	type cbtxGenArgs struct {
		vin              uint64
		txOutputDescMLPs []*TxOutputDescMLP
		txMemo           []byte
	}

	tests := []struct {
		name       string
		args       cbtxGenArgs
		wantErr    bool
		want       bool
		wantVerify bool
	}{
		{
			name: "[PASS]Pure Single",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress: coinAddressForSingles[rand.Intn(numSingle)],
						value:       256,
					},
					{
						coinAddress: coinAddressForSingles[rand.Intn(numSingle)],
						value:       2,
					},
					{
						coinAddress: coinAddressForSingles[rand.Intn(numSingle)],
						value:       254,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    false,
			want:       true,
			wantVerify: true,
		},
		{
			name: "[FAIL]Pure Single--value-gt",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress: coinAddressForSingles[rand.Intn(numSingle)],
						value:       257,
					},
					{
						coinAddress: coinAddressForSingles[rand.Intn(numSingle)],
						value:       2,
					},
					{
						coinAddress: coinAddressForSingles[rand.Intn(numSingle)],
						value:       254,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    true,
			want:       false,
			wantVerify: false,
		},
		{
			name: "[FAIL]Pure Single--value-lt",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress: coinAddressForSingles[rand.Intn(numSingle)],
						value:       255,
					},
					{
						coinAddress: coinAddressForSingles[rand.Intn(numSingle)],
						value:       2,
					},
					{
						coinAddress: coinAddressForSingles[rand.Intn(numSingle)],
						value:       254,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    true,
			want:       false,
			wantVerify: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cbTx, err := pp.CoinbaseTxMLPGen(tt.args.vin, tt.args.txOutputDescMLPs, tt.args.txMemo)
			if (err != nil) != tt.wantErr {
				t.Errorf("CoinbaseTxMLPGen() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if (cbTx != nil) != tt.want {
				t.Errorf("CoinbaseTxMLPGen() error = %v, want %v", err, tt.wantErr)
				return
			}
			err = pp.CoinbaseTxMLPVerify(cbTx)
			if (err == nil) != tt.wantVerify {
				t.Errorf("CoinbaseTxMLPVerify() error = %v, wantVerifyErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestPublicParameter_CoinbaseTxMLPGen_CoinbaseTxMLPVerify_Other(t *testing.T) {
	InitialAddress()
	type cbtxGenArgs struct {
		vin              uint64
		txOutputDescMLPs []*TxOutputDescMLP
		txMemo           []byte
	}

	tests := []struct {
		name       string
		args       cbtxGenArgs
		wantErr    bool
		want       bool
		wantVerify bool
	}{
		{
			name: "[FAIL]Pure PKRing--nil struct-1",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        nil,
						coinValuePublicKey: valuePublicKeys[rand.Intn(numPre)],
						value:              2,
					},
					{
						coinAddress:        coinAddresss[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numPre)],
						value:              254,
					},
					{
						coinAddress:        coinAddresss[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numPre)],
						value:              256,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    true,
			want:       false,
			wantVerify: false,
		},
		{
			name: "[FAIL]Pure PKRing--nil struct-2",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddresss[rand.Intn(numPre)],
						coinValuePublicKey: nil,
						value:              2,
					},
					{
						coinAddress:        coinAddresss[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numPre)],
						value:              254,
					},
					{
						coinAddress:        coinAddresss[rand.Intn(numPre)],
						coinValuePublicKey: valuePublicKeys[rand.Intn(numPre)],
						value:              256,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    true,
			want:       false,
			wantVerify: false,
		},

		{
			name: "[FAIL]Hybrid--non-successive",
			args: cbtxGenArgs{
				vin: 512,
				txOutputDescMLPs: []*TxOutputDescMLP{
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: coinAddresss[rand.Intn(numRand)],
						value:              256,
					},
					{
						coinAddress: coinAddressForSingles[rand.Intn(numSingle)],
						value:       2,
					},
					{
						coinAddress:        coinAddresss[rand.Intn(numRand)],
						coinValuePublicKey: coinAddresss[rand.Intn(numRand)],
						value:              254,
					},
				},
				txMemo: RandomBytes(10),
			},
			wantErr:    true,
			want:       false,
			wantVerify: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cbTx, err := pp.CoinbaseTxMLPGen(tt.args.vin, tt.args.txOutputDescMLPs, tt.args.txMemo)
			if (err != nil) != tt.wantErr {
				t.Errorf("CoinbaseTxMLPGen() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if (cbTx != nil) != tt.want {
				t.Errorf("CoinbaseTxMLPGen() error = %v, want %v", err, tt.wantErr)
				return
			}
			err = pp.CoinbaseTxMLPVerify(cbTx)
			if (err == nil) != tt.wantVerify {
				t.Errorf("CoinbaseTxMLPVerify() error = %v, wantVerifyErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func InitialTxo(addressType CoinAddressType, addrIdxs []int, vin uint64, values []uint64) []TxoMLP {
	if len(values) != len(addrIdxs) {
		panic("wrong request")
	}
	for i := 0; i < len(values); i++ {
		vin -= values[i]
	}
	if vin != 0 {
		panic("wrong request")
	}
	txOutputDescMLPs := make([]*TxOutputDescMLP, 0, len(values))
	for i := 0; i < len(values); i++ {
		index := addrIdxs[i]
		value := values[i]
		vin += value
		switch addressType {
		case CoinAddressTypePublicKeyForRingPre:
			txOutputDescMLPs = append(txOutputDescMLPs, &TxOutputDescMLP{
				coinAddress:        coinAddressPres[index],
				coinValuePublicKey: valuePublicKeyPres[index],
				value:              value,
			})
		case CoinAddressTypePublicKeyForRing:
			txOutputDescMLPs = append(txOutputDescMLPs, &TxOutputDescMLP{
				coinAddress:        coinAddresss[index],
				coinValuePublicKey: valuePublicKeys[index],
				value:              value,
			})
		case CoinAddressTypePublicKeyHashForSingle:
			txOutputDescMLPs = append(txOutputDescMLPs, &TxOutputDescMLP{
				coinAddress: coinAddressForSingles[index],
				value:       value,
			})
		}
	}
	cbTx, err := pp.CoinbaseTxMLPGen(vin, txOutputDescMLPs, RandomBytes(10))
	if err != nil {
		panic(err)
	}

	err = pp.CoinbaseTxMLPVerify(cbTx)
	if err != nil {
		panic(err)
	}
	return cbTx.txos
}

func GenerateInputDescMLPs(ringSize int, coinAddressType CoinAddressType, vin uint64) (txInputDescMLPs []*TxInputDescMLP) {
	inputValues := make([]uint64, ringSize)
	addrIndexes := make([]int, ringSize)
	remainVin := vin
	for i := 0; i < ringSize; i++ {
		addrIndexes[i] = rand.Intn(numPre)
		if i == ringSize-1 {
			inputValues[ringSize-1] = remainVin
		} else {
			inputValues[i] = uint64(rand.Intn(int(remainVin)))
		}
		remainVin -= inputValues[i]
	}

	txos := InitialTxo(coinAddressType, addrIndexes, vin, inputValues)

	txInputDescMLPs = make([]*TxInputDescMLP, 0, ringSize)
	lgrTxoList := make([]*LgrTxoMLP, 0, ringSize)
	for i := 0; i < ringSize; i++ {
		lgrTxoList = append(lgrTxoList, &LgrTxoMLP{
			txo: txos[i],
			id:  RandomBytes(HashOutputBytesLen),
		})
	}

	inputCoinSpendSecretKeys := coinSpendSecretKeyMapping[coinAddressType]
	inputCoinSerialNumberSecretKeys := coinSerialNumberSecretKeyMap[coinAddressType]
	inputCoinValuePublicKeys := coinValuePublicKeyMap[coinAddressType]
	inputCoinValueSecretKeys := coinValueSecretKeyMap[coinAddressType]
	inputCoinDetectorKeys := coinDetectorKeyMap[coinAddressType]

	for i := 0; i < ringSize; i++ {
		txInputDescMLPs = append(txInputDescMLPs, &TxInputDescMLP{
			lgrTxoList:                lgrTxoList,
			sidx:                      uint8(i),
			coinSpendSecretKey:        inputCoinSpendSecretKeys[addrIndexes[i]],
			coinSerialNumberSecretKey: inputCoinSerialNumberSecretKeys[addrIndexes[i]],
			coinValuePublicKey:        inputCoinValuePublicKeys[addrIndexes[i]],
			coinValueSecretKey:        inputCoinValueSecretKeys[addrIndexes[i]],
			coinDetectorKey:           inputCoinDetectorKeys[addrIndexes[i]],
			value:                     inputValues[i],
		})
	}

	return
}

func TestPublicParameter_TransferTxMLPGen_TransferTxMLPVerify(t *testing.T) {
	InitialAddress()

	//vin := uint64(512)
	vin := uint64(1)<<pp.paramN - 1
	for _, inputCoinAddressType := range []CoinAddressType{ /*CoinAddressTypePublicKeyForRingPre,*/ CoinAddressTypePublicKeyForRing, CoinAddressTypePublicKeyHashForSingle} {
		for _, outputCoinAddressType := range []CoinAddressType{CoinAddressTypePublicKeyForRingPre, CoinAddressTypePublicKeyForRing, CoinAddressTypePublicKeyHashForSingle} {
			ringSizeMax := 6
			if inputCoinAddressType == CoinAddressTypePublicKeyHashForSingle {
				ringSizeMax = 1
			}
			for ringSize := 1; ringSize < ringSizeMax; ringSize++ {
				txInputRingDescMLPs := GenerateInputDescMLPs(ringSize, inputCoinAddressType, vin)
				var txInputDescMLPs []*TxInputDescMLP
				inputSize := 1

				totalInputValue := uint64(0)
				inputValues := make([]uint64, inputSize)
				choosed := map[int]struct{}{}
				for inputIdx := 0; inputIdx < inputSize; inputIdx++ {
					txInputDescMLPs = make([]*TxInputDescMLP, inputSize)
					currentChoose := rand.Intn(ringSize)
					_, ok := choosed[currentChoose]
					for ok {
						currentChoose = rand.Intn(ringSize)
						_, ok = choosed[currentChoose]
					}
					txInputDescMLPs[inputIdx] = txInputRingDescMLPs[currentChoose]

					totalInputValue += txInputRingDescMLPs[currentChoose].value
					inputValues[inputIdx] = txInputRingDescMLPs[currentChoose].value
				}
				fee := uint64(rand.Intn(int(totalInputValue)))

				outputCoinAddressMap := coinAddressMapping[outputCoinAddressType]
				outputCoinValuePublicKeyMap := coinValuePublicKeyMap[outputCoinAddressType]

				for outputSize := 1; outputSize < 6; outputSize++ {
					remainVin := totalInputValue - fee
					nOutPres := make([]int, outputSize)
					outputValues := make([]uint64, outputSize)
					for i := 0; i < outputSize; i++ {
						nOutPres[i] = rand.Intn(numPre)
						if i == outputSize-1 {
							outputValues[outputSize-1] = remainVin
						} else {
							outputValues[i] = uint64(rand.Intn(int(remainVin)))
						}

						remainVin -= outputValues[i]
					}

					addressTypeNameMapping := map[CoinAddressType]string{
						CoinAddressTypePublicKeyForRingPre:    "RingPre",
						CoinAddressTypePublicKeyForRing:       "RingRand",
						CoinAddressTypePublicKeyHashForSingle: "Single",
					}
					testCaseName := fmt.Sprintf("%s(%d, RingSize %d) -> %s(%d)", addressTypeNameMapping[inputCoinAddressType], inputSize, ringSize, addressTypeNameMapping[outputCoinAddressType], outputSize)
					t.Run(testCaseName, func(t *testing.T) {
						t.Logf("TestCase:%s", testCaseName)
						t.Logf("inputValues = %v", inputValues)
						t.Logf("outputValues = %v", outputValues)
						t.Logf("fee = %v", fee)
						txOutputDescMLPs := make([]*TxOutputDescMLP, 0, outputSize)
						for i := 0; i < outputSize; i++ {
							txOutputDescMLPs = append(txOutputDescMLPs, &TxOutputDescMLP{
								coinAddress:        outputCoinAddressMap[nOutPres[i]],
								coinValuePublicKey: outputCoinValuePublicKeyMap[nOutPres[i]],
								value:              outputValues[i],
							})
						}

						trTx, err := pp.TransferTxMLPGen(
							txInputDescMLPs,
							txOutputDescMLPs,
							fee,
							RandomBytes(10))
						if (err != nil) != false {
							t.Errorf("TransferTxMLPGen() error = %v, wantErr %v", err, false)
							return
						}
						if (trTx != nil) != true {
							t.Errorf("TransferTxMLPGen() error = %v, want %v", err, true)
							return
						}
						err = pp.TransferTxMLPVerify(trTx)
						if (err == nil) != true {
							t.Errorf("TransferTxMLPVerify() error = %v, wantVerifyErr %v", err, true)
							return
						}
					})
				}
			}
		}
	}
}
