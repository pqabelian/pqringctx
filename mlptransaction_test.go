package pqringctx

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"
)

var pp = Initialize(nil)

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

var numSingle = 120
var coinSpendKeyRandSeedForSingles = make([][]byte, 0, numSingle)
var detectorKeyForSingles = make([][]byte, 0, numSingle)
var coinAddressForSingles = make([][]byte, 0, numSingle)
var coinSpendSecretKeyForSingles = make([][]byte, 0, numSingle)
var coinSerialNumberSecretKeySingles = make([][]byte, numSingle)
var valuePublicKeyForSingles = make([][]byte, numSingle)
var valueSecretKeyForSingles = make([][]byte, numSingle)

var addressTypeNameMapping = map[CoinAddressType]string{
	CoinAddressTypePublicKeyForRingPre:    "RingPre",
	CoinAddressTypePublicKeyForRing:       "RingRand",
	CoinAddressTypePublicKeyHashForSingle: "Single",
}
var txWitnessCbTxCaseMapping = map[TxWitnessCbTxCase]string{
	TxWitnessCbTxCaseC0: "TxWitnessCbTxCaseC0",
	TxWitnessCbTxCaseC1: "TxWitnessCbTxCaseC1",
	TxWitnessCbTxCaseCn: "TxWitnessCbTxCaseCn",
}
var txWitnessTrTxCaseMapping = map[TxWitnessTrTxCase]string{
	TxWitnessTrTxCaseI0C0:      "TxWitnessTrTxCaseI0C0",
	TxWitnessTrTxCaseI0C1:      "TxWitnessTrTxCaseI0C1",
	TxWitnessTrTxCaseI0Cn:      "TxWitnessTrTxCaseI0Cn",
	TxWitnessTrTxCaseI1C0:      "TxWitnessTrTxCaseI1C0",
	TxWitnessTrTxCaseI1C1Exact: "TxWitnessTrTxCaseI1C1Exact",
	TxWitnessTrTxCaseI1C1CAdd:  "TxWitnessTrTxCaseI1C1CAdd",
	TxWitnessTrTxCaseI1C1IAdd:  "TxWitnessTrTxCaseI1C1IAdd",
	TxWitnessTrTxCaseI1CnExact: "TxWitnessTrTxCaseI1CnExact",
	TxWitnessTrTxCaseI1CnCAdd:  "TxWitnessTrTxCaseI1CnCAdd",
	TxWitnessTrTxCaseI1CnIAdd:  "TxWitnessTrTxCaseI1CnIAdd",
	TxWitnessTrTxCaseImC0:      "TxWitnessTrTxCaseImC0",
	TxWitnessTrTxCaseImC1Exact: "TxWitnessTrTxCaseImC1Exact",
	TxWitnessTrTxCaseImC1CAdd:  "TxWitnessTrTxCaseImC1CAdd",
	TxWitnessTrTxCaseImC1IAdd:  "TxWitnessTrTxCaseImC1IAdd",
	TxWitnessTrTxCaseImCnExact: "TxWitnessTrTxCaseImCnExact",
	TxWitnessTrTxCaseImCnCAdd:  "TxWitnessTrTxCaseImCnCAdd",
	TxWitnessTrTxCaseImCnIAdd:  "TxWitnessTrTxCaseImCnIAdd",
}

func InitialAddress() {
	coinAddressKeyForPKRingPreGen := func() (seed []byte,
		coinAddress []byte, coinSpendSecretKey []byte, coinSerialNumberSecretKey []byte) {
		seed = RandomBytes(pp.paramKeyGenSeedBytesLen)

		serializedAPk, serializedASksp, serializedASksn, err := AddressKeyGen(pp, seed)
		if err != nil {
			panic(err)
		}

		return seed, serializedAPk, serializedASksp, serializedASksn
	}
	coinValueKeyPreGen := func() (randSeed []byte, coinValuePublicKey []byte, coinValueSecretKey []byte) {
		randSeed = RandomBytes(pp.paramKeyGenSeedBytesLen)

		var err error
		coinValuePublicKey, coinValueSecretKey, err = ValueKeyGen(pp, randSeed)
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

// TxInputDescMLPRingRequest is used to generate a ring with GenerateInputDescMLPsRing
type TxInputDescMLPRingRequest struct {
	CoinAddressType CoinAddressType
	RingSize        int
	InputValues     []uint64
	TotalValue      uint64
}

const appLayerRingSize = 7

// GenerateInputDescMLPsRing generate txos form to ring and transfer each to a TxInputDescMLP
func GenerateInputDescMLPsRing(req *TxInputDescMLPRingRequest) (txInputDescMLPs []*TxInputDescMLP) {
	if len(req.InputValues) == 0 {
		inputValues := make([]uint64, req.RingSize)
		remainVin := req.TotalValue
		for i := 0; i < req.RingSize; i++ {
			if i == req.RingSize-1 {
				inputValues[req.RingSize-1] = remainVin
			} else {
				inputValues[i] = uint64(rand.Intn(int(remainVin)))
			}
			remainVin -= inputValues[i]
		}
	} else if len(req.InputValues) != req.RingSize {
		panic("wrong request")
	}
	ringSize := req.RingSize
	inputValues := req.InputValues
	coinAddressType := req.CoinAddressType
	if coinAddressType == CoinAddressTypePublicKeyForRingPre || coinAddressType == CoinAddressTypePublicKeyForRing {
		if ringSize > int(appLayerRingSize) {
			panic("invalid ring size")
		}
	} else if coinAddressType == CoinAddressTypePublicKeyHashForSingle {
		if ringSize != 1 {
			panic("invalid ring size")
		}
	} else {
		panic("invalid coin address type")
	}

	var txos []TxoMLP
	addrIndexes := make([]int, ringSize)
	vin := uint64(0)
	for i := 0; i < ringSize; i++ {
		addrIndexes[i] = rand.Intn(numPre)
		vin += inputValues[i]

		txos = append(txos, InitialTxo(coinAddressType, []int{addrIndexes[i]}, inputValues[i], []uint64{inputValues[i]})...) // one TXO one time
	}

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

// GenerateInputDescMLPsRing select specified number TxInputDescMLP from result of GenerateInputDescMLPsRing
func SelectTxInputDescMLPFromInputDescMLPsRing(txInputRingDescMLPs []*TxInputDescMLP, count int) ([]*TxInputDescMLP, uint64, []uint64) {
	n := len(txInputRingDescMLPs)
	randRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	randRand.Shuffle(n, func(i, j int) {
		txInputRingDescMLPs[i], txInputRingDescMLPs[j] = txInputRingDescMLPs[j], txInputRingDescMLPs[i]
	})

	totalInputValue := uint64(0)
	inputValues := make([]uint64, count)

	res := make([]*TxInputDescMLP, 0, count)
	for i := 0; i < n && i < count; i++ {
		res = append(res, txInputRingDescMLPs[i])
		totalInputValue += txInputRingDescMLPs[i].value
		inputValues[i] = txInputRingDescMLPs[i].value
	}

	return res, totalInputValue, inputValues
}

type InputRequest struct {
	inputRingPreNum            int
	inputRingPreRingSizes      []int
	inputRingPreRingSelectNums []int
	inputRingPreValues         [][]uint64
	inputRingPreTotalValue     []uint64

	inputRingRandNum        int
	inputRingRandRingSizes  []int
	inputRingRandSelectNums []int
	inputRingRandValues     [][]uint64
	inputRingRandTotalValue []uint64

	inputSingleNum    int
	inputSingleValues []uint64
}

func GenerateInputWithTypeSize(inputRingPreSize, inputRingRandSize, inputSingleSize int) (res []*TxInputDescMLP, totalInputValueForRing uint64, totalInputValueForSingle uint64, inputValues []uint64) {
	total := rand.Intn((1<<pp.paramN)-1-inputSingleSize) + inputSingleSize
	totalInputRingValue := uint64(rand.Intn(total - inputSingleSize))
	totalInputSingleValue := uint64(total) - totalInputRingValue
	req := &InputRequest{}

	remain := totalInputRingValue

	req.inputRingPreNum = inputRingPreSize
	req.inputRingPreRingSizes = make([]int, req.inputRingPreNum)
	req.inputRingPreRingSelectNums = make([]int, req.inputRingPreNum)
	req.inputRingPreValues = make([][]uint64, req.inputRingPreNum)
	req.inputRingPreTotalValue = make([]uint64, req.inputRingPreNum)
	for i := 0; i < inputRingPreSize; i++ {
		req.inputRingPreRingSizes[i] = rand.Intn(appLayerRingSize-1) + 1
		req.inputRingPreRingSelectNums[i] = 1
		req.inputRingPreValues[i] = make([]uint64, req.inputRingPreRingSizes[i])
		for j := 0; j < req.inputRingPreRingSizes[i]; j++ {
			req.inputRingPreValues[i][j] = uint64(rand.Intn(int(remain)))
			remain -= req.inputRingPreValues[i][j]
			req.inputRingPreTotalValue[i] += req.inputRingPreValues[i][j]
		}
	}

	req.inputRingRandNum = inputRingRandSize
	req.inputRingRandRingSizes = make([]int, req.inputRingRandNum)
	req.inputRingRandSelectNums = make([]int, req.inputRingRandNum)
	req.inputRingRandValues = make([][]uint64, req.inputRingRandNum)
	req.inputRingRandTotalValue = make([]uint64, req.inputRingRandNum)
	for i := 0; i < inputRingRandSize; i++ {
		req.inputRingRandRingSizes[i] = rand.Intn(appLayerRingSize-1) + 1
		req.inputRingRandSelectNums[i] = 1
		req.inputRingRandValues[i] = make([]uint64, req.inputRingRandRingSizes[i])
		for j := 0; j < req.inputRingRandRingSizes[i]; j++ {
			req.inputRingRandValues[i][j] = uint64(rand.Intn(int(remain)))
			remain -= req.inputRingRandValues[i][j]
			req.inputRingRandTotalValue[i] += req.inputRingRandValues[i][j]
		}
	}

	remain = totalInputSingleValue
	req.inputSingleNum = inputSingleSize
	req.inputSingleValues = make([]uint64, req.inputSingleNum)
	for i := 0; i < inputSingleSize; i++ {
		req.inputSingleValues[i] = 1
		remain -= req.inputSingleValues[i]
	}
	if remain < 0 {
		panic("invalid input single num")
	}
	//req.inputSingleNum = inputSingleSize
	//req.inputSingleValues = make([]uint64, req.inputSingleNum)
	for i := 0; i < inputSingleSize; i++ {
		if remain != 0 {
			req.inputSingleValues[i] += uint64(rand.Intn(int(remain)))
			remain -= req.inputSingleValues[i]
		}
	}

	return GenerateInput(req)
}
func GenerateInput(req *InputRequest) (res []*TxInputDescMLP, totalInputValueForRing uint64, totalInputValueForSingle uint64, inputValues []uint64) {
	res = make([]*TxInputDescMLP, 0, req.inputRingPreNum+req.inputRingRandNum+req.inputSingleNum)
	totalInputValueForRing = 0
	totalInputValueForSingle = 0
	inputValues = make([]uint64, 0, req.inputRingPreNum+req.inputRingRandNum+req.inputSingleNum)
	if req.inputRingPreNum != 0 {
		for i := 0; i < req.inputRingPreNum; i++ {
			inputRingPreRingSize := req.inputRingPreRingSizes[i]
			inputRingPreValues := req.inputRingPreValues[i]
			inputRingPreTotalValue := req.inputRingPreTotalValue[i]
			txInputDescMLPs := GenerateInputDescMLPsRing(&TxInputDescMLPRingRequest{
				CoinAddressType: CoinAddressTypePublicKeyForRingPre,
				RingSize:        inputRingPreRingSize,
				InputValues:     inputRingPreValues,
				TotalValue:      inputRingPreTotalValue,
			})

			selectNum := req.inputRingPreRingSelectNums[i]
			txInputDescMLPRingPre, totalInputValuePre, inputValuesPre := SelectTxInputDescMLPFromInputDescMLPsRing(txInputDescMLPs, selectNum)
			res = append(res, txInputDescMLPRingPre...)
			totalInputValueForRing += totalInputValuePre
			inputValues = append(inputValues, inputValuesPre...)
		}
	}

	if req.inputRingRandNum != 0 {
		for i := 0; i < req.inputRingRandNum; i++ {
			inputRingRandRingSize := req.inputRingRandRingSizes[i]
			inputRingRandValues := req.inputRingRandValues[i]
			inputRingRandTotalValue := req.inputRingRandTotalValue[i]
			txInputDescMLPs := GenerateInputDescMLPsRing(&TxInputDescMLPRingRequest{
				CoinAddressType: CoinAddressTypePublicKeyForRing,
				RingSize:        inputRingRandRingSize,
				InputValues:     inputRingRandValues,
				TotalValue:      inputRingRandTotalValue,
			})

			selectNum := req.inputRingRandSelectNums[i]
			txInputDescMLPRingRand, totalInputValueRand, inputValuesRand := SelectTxInputDescMLPFromInputDescMLPsRing(txInputDescMLPs, selectNum)
			res = append(res, txInputDescMLPRingRand...)
			totalInputValueForRing += totalInputValueRand
			inputValues = append(inputValues, inputValuesRand...)
		}
	}

	if req.inputSingleNum != 0 {
		for i := 0; i < req.inputSingleNum; i++ {
			inputSingleValues := req.inputSingleValues[i]
			txInputDescMLPs := GenerateInputDescMLPsRing(&TxInputDescMLPRingRequest{
				CoinAddressType: CoinAddressTypePublicKeyHashForSingle,
				RingSize:        1,
				InputValues:     []uint64{inputSingleValues},
				TotalValue:      inputSingleValues,
			})
			txInputDescMLPSingle, totalInputValueRand, inputValuesRand := SelectTxInputDescMLPFromInputDescMLPsRing(txInputDescMLPs, 1)
			res = append(res, txInputDescMLPSingle...)
			totalInputValueForSingle += totalInputValueRand
			inputValues = append(inputValues, inputValuesRand...)
		}
	}

	return res, totalInputValueForRing, totalInputValueForSingle, inputValues
}
func generateNWithBound(count int, bound int) []int {
	res := make([]int, 0, bound)
	for i := 0; i < count; i++ {
		res = append(res, rand.Intn(bound))
	}
	return res
}
func SplitNum(total uint64, num int) []uint64 {
	remain := total - uint64(num)
	if remain < 0 {
		return nil
	}
	outputValues := make([]uint64, num)
	for i := 0; i < num; i++ {
		if remain <= 0 {
			return nil
		}
		if i == num-1 {
			outputValues[num-1] = remain
		} else {
			outputValues[i] = uint64(rand.Intn(int(remain)))
		}

		remain -= outputValues[i]
	}
	for i := 0; i < num; i++ {
		outputValues[i] += 1
	}
	return outputValues
}
func GenerateOutputWithValues(outputRingPreValues []uint64, outputRingRandValues []uint64, outputSingleValues []uint64) (txOutputDescMLPS []*TxOutputDescMLP) {
	if len(outputRingPreValues) != 0 {
		nOutPres := generateNWithBound(len(outputRingPreValues), numPre)
		outputCoinAddressMap := coinAddressMapping[CoinAddressTypePublicKeyForRingPre]
		outputCoinValuePublicKeyMap := coinValuePublicKeyMap[CoinAddressTypePublicKeyForRingPre]
		for i := 0; i < len(outputRingPreValues); i++ {
			txOutputDescMLPS = append(txOutputDescMLPS, &TxOutputDescMLP{
				coinAddress:        outputCoinAddressMap[nOutPres[i]],
				coinValuePublicKey: outputCoinValuePublicKeyMap[nOutPres[i]],
				value:              outputRingPreValues[i],
			})
		}
	}

	if len(outputRingRandValues) != 0 {
		nOutRands := generateNWithBound(len(outputRingRandValues), numRand)
		outputCoinAddressMap := coinAddressMapping[CoinAddressTypePublicKeyForRing]
		outputCoinValuePublicKeyMap := coinValuePublicKeyMap[CoinAddressTypePublicKeyForRing]
		for i := 0; i < len(outputRingRandValues); i++ {
			txOutputDescMLPS = append(txOutputDescMLPS, &TxOutputDescMLP{
				coinAddress:        outputCoinAddressMap[nOutRands[i]],
				coinValuePublicKey: outputCoinValuePublicKeyMap[nOutRands[i]],
				value:              outputRingRandValues[i],
			})

		}
	}

	if len(outputSingleValues) != 0 {
		nOutSingle := generateNWithBound(len(outputSingleValues), numSingle)
		outputCoinAddressMap := coinAddressMapping[CoinAddressTypePublicKeyHashForSingle]
		outputCoinValuePublicKeyMap := coinValuePublicKeyMap[CoinAddressTypePublicKeyHashForSingle]
		for i := 0; i < len(outputSingleValues); i++ {
			txOutputDescMLPS = append(txOutputDescMLPS, &TxOutputDescMLP{
				coinAddress:        outputCoinAddressMap[nOutSingle[i]],
				coinValuePublicKey: outputCoinValuePublicKeyMap[nOutSingle[i]],
				value:              outputSingleValues[i],
			})
		}
	}

	return txOutputDescMLPS

}
func GenerateOutput(totalRingValue uint64, totalSingleValue uint64, outputRingPreNum int, outputRingNum int, outputSingleNum int) (txOutputDescMLPS []*TxOutputDescMLP, outputValues []uint64) {
	outputValues = SplitNum(totalRingValue, outputRingPreNum+outputRingNum)
	outputValues = append(outputValues, SplitNum(totalSingleValue, outputSingleNum)...)
	txOutputDescMLPS = GenerateOutputWithValues(outputValues[:outputRingPreNum], outputValues[outputRingPreNum:outputRingPreNum+outputRingNum], outputValues[outputRingPreNum+outputRingNum:])
	return txOutputDescMLPS, outputValues
}

func TestPublicParameter_TransferTxMLPGen_TransferTxMLPVerify(t *testing.T) {
	InitialAddress()
	// for all witness type
	inputRingPreSize := 0
	inputRingRandSize := 5
	inputSingleSize := 100

	outputRingPreSize := 1
	outputRingRandSize := 1
	outputSingleSize := 1

	testCaseName := fmt.Sprintf("Input[%d][%d][%d] -> Output[%d][%d][%d]", inputRingPreSize, inputRingRandSize, inputSingleSize, outputRingPreSize, outputRingRandSize, outputSingleSize)
	t.Run(testCaseName, func(t *testing.T) {
		txInputDescMLPs, totalInputValueForRing, totalInputValueForSingle, inputValues := GenerateInputWithTypeSize(inputRingPreSize, inputRingRandSize, inputSingleSize)
		fee := uint64(rand.Intn(int(totalInputValueForRing + totalInputValueForSingle)))
		totalOutputValue := totalInputValueForRing + totalInputValueForSingle - fee

		outputValueForRing := uint64(rand.Intn(int(totalOutputValue) - outputSingleSize))
		outputValueForSingle := totalOutputValue - (outputValueForRing)

		txOutputDescMLPs, outputValues := GenerateOutput(outputValueForRing, outputValueForSingle, outputRingPreSize, outputRingRandSize, outputSingleSize)

		t.Logf("TestCase:%s", testCaseName)
		t.Logf("InputValues = %v", inputValues)
		t.Logf("outputValues = %v", outputValues)
		t.Logf("fee = %v", fee)

		trTx, err := pp.TransferTxMLPGen(
			txInputDescMLPs,
			txOutputDescMLPs,
			fee,
			RandomBytes(10))
		if err != nil {
			t.Errorf("TransferTxMLPGen() error = %v, wantErr %v", err, false)
			return
		}
		if trTx == nil {
			t.Errorf("TransferTxMLPGen() error = %v, want %v", err, true)
			return
		}

		t.Logf("Transfer Witness Case:%s", txWitnessTrTxCaseMapping[trTx.txWitness.TxCase()])

		err = pp.TransferTxMLPVerify(trTx)
		if err != nil {
			t.Errorf("TransferTxMLPVerify() error = %v, wantVerifyErr %v", err, true)
			return
		}
	})
}

func TestPublicParameter_TransferTxMLPGen_TransferTxMLPVerify_For_All_Witness_Type_Case(t *testing.T) {
	InitialAddress()

	tests := []struct {
		name              string
		inputRingPreSize  int
		inputRingRandSize int
		inputSingleSize   int

		outputRingPreSize  int
		outputRingRandSize int
		outputSingleSize   int

		expectedWitnessCase TxWitnessTrTxCase
	}{
		{
			name: "I0C0",
			// ensure  inputRingPreSize +  inputRingRandSize = 0
			inputRingPreSize:  0,
			inputRingRandSize: 0,
			inputSingleSize:   100,

			// ensure  outputRingPreSize +  outputRingRandSize = 0
			outputRingPreSize:   0,
			outputRingRandSize:  0,
			outputSingleSize:    100,
			expectedWitnessCase: TxWitnessTrTxCaseI0C0,
		},
		{
			name: "I0C1",
			// ensure  inputRingPreSize +  inputRingRandSize = 0
			inputRingPreSize:  0,
			inputRingRandSize: 0,
			inputSingleSize:   2,

			// ensure  outputRingPreSize +  outputRingRandSize = 1
			outputRingPreSize:   0,
			outputRingRandSize:  1,
			outputSingleSize:    10,
			expectedWitnessCase: TxWitnessTrTxCaseI0C1,
		},
		{
			name: "I0Cn",
			// ensure  inputRingPreSize +  inputRingRandSize = 0
			inputRingPreSize:  0,
			inputRingRandSize: 0,
			inputSingleSize:   2,
			// ensure  outputRingPreSize +  outputRingRandSize >= 2
			outputRingPreSize:   1,
			outputRingRandSize:  1,
			outputSingleSize:    10,
			expectedWitnessCase: TxWitnessTrTxCaseI0Cn,
		},
		{
			name: "I1C0",
			// ensure  inputRingPreSize +  inputRingRandSize = 1
			inputRingPreSize:  1,
			inputRingRandSize: 0,
			inputSingleSize:   2,
			// ensure  outputRingPreSize +  outputRingRandSize = 0
			outputRingPreSize:   0,
			outputRingRandSize:  0,
			outputSingleSize:    10,
			expectedWitnessCase: TxWitnessTrTxCaseI1C0,
		},
		{
			name: "I1C10",
			// ensure  inputRingPreSize +  inputRingRandSize = 1
			inputRingPreSize:  1,
			inputRingRandSize: 0,
			inputSingleSize:   2,

			// ensure  outputRingPreSize +  outputRingRandSize = 1
			outputRingPreSize:   1,
			outputRingRandSize:  0,
			outputSingleSize:    10,
			expectedWitnessCase: TxWitnessTrTxCaseI1C1Exact,
		},

		{
			name: "I1C1+",
			// ensure  inputRingPreSize +  inputRingRandSize = 1
			inputRingPreSize:  1,
			inputRingRandSize: 0,
			inputSingleSize:   2,
			// ensure  outputRingPreSize +  outputRingRandSize = 1
			outputRingPreSize:   1,
			outputRingRandSize:  0,
			outputSingleSize:    10,
			expectedWitnessCase: TxWitnessTrTxCaseI1C1CAdd,
		},
		{
			name: "I1C1-",
			// ensure  inputRingPreSize +  inputRingRandSize = 1
			inputRingPreSize:  1,
			inputRingRandSize: 0,
			inputSingleSize:   2,
			// ensure  outputRingPreSize +  outputRingRandSize = 1
			outputRingPreSize:   1,
			outputRingRandSize:  0,
			outputSingleSize:    10,
			expectedWitnessCase: TxWitnessTrTxCaseI1C1IAdd,
		},
		{
			name: "I1Cn0",
			// ensure  inputRingPreSize +  inputRingRandSize = 1
			inputRingPreSize:  1,
			inputRingRandSize: 0,
			inputSingleSize:   2,
			// ensure  outputRingPreSize +  outputRingRandSize >= 2
			outputRingPreSize:   1,
			outputRingRandSize:  1,
			outputSingleSize:    10,
			expectedWitnessCase: TxWitnessTrTxCaseI1CnExact,
		},
		{
			name: "I1Cn+",
			// ensure  inputRingPreSize +  inputRingRandSize = 1
			inputRingPreSize:  1,
			inputRingRandSize: 0,
			inputSingleSize:   2,
			// ensure  outputRingPreSize +  outputRingRandSize >=2
			outputRingPreSize:   1,
			outputRingRandSize:  1,
			outputSingleSize:    10,
			expectedWitnessCase: TxWitnessTrTxCaseI1CnCAdd,
		},
		{
			name: "I1Cn-",
			// ensure  inputRingPreSize +  inputRingRandSize = 1
			inputRingPreSize:  1,
			inputRingRandSize: 0,
			inputSingleSize:   2,
			// ensure  outputRingPreSize +  outputRingRandSize >=2
			outputRingPreSize:   1,
			outputRingRandSize:  1,
			outputSingleSize:    10,
			expectedWitnessCase: TxWitnessTrTxCaseI1CnIAdd,
		},
		{
			name: "ImC0",
			// ensure  inputRingPreSize +  inputRingRandSize >= 2
			inputRingPreSize:  1,
			inputRingRandSize: 1,
			inputSingleSize:   2,
			// ensure  outputRingPreSize +  outputRingRandSize == 0
			outputRingPreSize:   0,
			outputRingRandSize:  0,
			outputSingleSize:    10,
			expectedWitnessCase: TxWitnessTrTxCaseImC0,
		},
		{
			name: "ImC10",
			// ensure  inputRingPreSize +  inputRingRandSize >= 2
			inputRingPreSize:  1,
			inputRingRandSize: 1,
			inputSingleSize:   2,
			// ensure  outputRingPreSize +  outputRingRandSize == 1
			outputRingPreSize:   1,
			outputRingRandSize:  0,
			outputSingleSize:    10,
			expectedWitnessCase: TxWitnessTrTxCaseImC1Exact,
		},
		{
			name: "ImC1+",
			// ensure  inputRingPreSize +  inputRingRandSize >= 2
			inputRingPreSize:  1,
			inputRingRandSize: 1,
			inputSingleSize:   2,
			// ensure  outputRingPreSize +  outputRingRandSize == 1
			outputRingPreSize:   1,
			outputRingRandSize:  0,
			outputSingleSize:    10,
			expectedWitnessCase: TxWitnessTrTxCaseImC1CAdd,
		},
		{
			name: "ImC1-",
			// ensure  inputRingPreSize +  inputRingRandSize >= 2
			inputRingPreSize:  1,
			inputRingRandSize: 1,
			inputSingleSize:   2,
			// ensure  outputRingPreSize +  outputRingRandSize == 1
			outputRingPreSize:   1,
			outputRingRandSize:  0,
			outputSingleSize:    10,
			expectedWitnessCase: TxWitnessTrTxCaseImC1IAdd,
		},
		{
			name: "ImCn0",
			// ensure  inputRingPreSize +  inputRingRandSize >= 2
			inputRingPreSize:  1,
			inputRingRandSize: 1,
			inputSingleSize:   2,
			// ensure  outputRingPreSize +  outputRingRandSize >= 2
			outputRingPreSize:   1,
			outputRingRandSize:  1,
			outputSingleSize:    10,
			expectedWitnessCase: TxWitnessTrTxCaseImCnExact,
		},
		{
			name: "ImCn+",
			// ensure  inputRingPreSize +  inputRingRandSize >= 2
			inputRingPreSize:  1,
			inputRingRandSize: 1,
			inputSingleSize:   2,
			// ensure  outputRingPreSize +  outputRingRandSize >= 2
			outputRingPreSize:   1,
			outputRingRandSize:  1,
			outputSingleSize:    10,
			expectedWitnessCase: TxWitnessTrTxCaseImCnCAdd,
		},
		{
			name: "ImCn-",
			// ensure  inputRingPreSize +  inputRingRandSize >= 2
			inputRingPreSize:  1,
			inputRingRandSize: 1,
			inputSingleSize:   2,
			// ensure  outputRingPreSize +  outputRingRandSize >= 2
			outputRingPreSize:   1,
			outputRingRandSize:  1,
			outputSingleSize:    10,
			expectedWitnessCase: TxWitnessTrTxCaseImCnIAdd,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("TestCase:%s", fmt.Sprintf("Input[%d][%d][%d] -> Output[%d][%d][%d]", tt.inputRingPreSize, tt.inputRingRandSize, tt.inputSingleSize, tt.outputRingPreSize, tt.outputRingRandSize, tt.outputSingleSize))
			txInputDescMLPs, totalInputValueForRing, totalInputValueForSingle, inputValues := GenerateInputWithTypeSize(tt.inputRingPreSize, tt.inputRingRandSize, tt.inputSingleSize)
			t.Logf("InputValues = %v, totalInputValueForRing = %v, totalInputValueForSingle = %v", inputValues, totalInputValueForRing, totalInputValueForSingle)

			var fee uint64
			var totalOutputValueForSingle uint64
			if strings.HasSuffix(txWitnessTrTxCaseMapping[tt.expectedWitnessCase], "Exact") {
				// tt.outputRingPreSize + tt.outputRingRandSize >= 1

				// fee +  totalOutputValueForSingle  ==  totalInputValueForSingle
				fee = uint64(rand.Intn(int(totalInputValueForSingle)))
				totalOutputValueForSingle = totalInputValueForSingle - fee
			} else if strings.HasSuffix(txWitnessTrTxCaseMapping[tt.expectedWitnessCase], "IAdd") {
				// tt.outputRingPreSize + tt.outputRingRandSize >= 1

				// fee +  totalOutputValueForSingle  <  totalInputValueForSingle
				feeAndTotalOutputValueForSingle := uint64(rand.Intn(int(totalInputValueForSingle) - tt.outputSingleSize))
				fee = uint64(rand.Intn(int(feeAndTotalOutputValueForSingle)))
				totalOutputValueForSingle = feeAndTotalOutputValueForSingle - fee // ensure totalOutputValueForSingle > tt.outputSingleSize
			} else if strings.HasSuffix(txWitnessTrTxCaseMapping[tt.expectedWitnessCase], "CAdd") {
				// tt.outputRingPreSize + tt.outputRingRandSize >= 1

				// fee +  totalOutputValueForSingle  >  totalInputValueForSingle
				feeAndTotalOutputValueForSingle := uint64(rand.Intn(int(totalInputValueForRing))) + totalInputValueForSingle
				fee = uint64(rand.Intn(int(feeAndTotalOutputValueForSingle)))
				totalOutputValueForSingle = feeAndTotalOutputValueForSingle - fee
			} else {
				fee = uint64(rand.Intn(int(totalInputValueForRing+totalInputValueForSingle) - tt.outputSingleSize))
				totalOutputValueForSingle = uint64(rand.Intn(int(totalInputValueForRing+totalInputValueForSingle-fee))) + uint64(tt.outputSingleSize)
				if tt.outputRingPreSize+tt.outputRingRandSize == 0 {
					totalOutputValueForSingle = totalInputValueForRing + totalInputValueForSingle - fee
				}
			}
			totalOutputValueForRing := totalInputValueForRing + totalInputValueForSingle - fee - totalOutputValueForSingle
			txOutputDescMLPs, outputValues := GenerateOutput(totalOutputValueForRing, totalOutputValueForSingle, tt.outputRingPreSize, tt.outputRingRandSize, tt.outputSingleSize)
			t.Logf("outputValues = %v, totalOutputValueForRing = %v, totalInputValueForRing = %v", outputValues, totalOutputValueForRing, totalInputValueForRing)
			t.Logf("fee = %v", fee)

			trTx, err := pp.TransferTxMLPGen(
				txInputDescMLPs,
				txOutputDescMLPs,
				fee,
				RandomBytes(10))
			if err != nil {
				t.Errorf("TransferTxMLPGen() error = %v, wantErr %v", err, false)
				return
			}
			if trTx == nil {
				t.Errorf("TransferTxMLPGen() error = %v, want %v", err, true)
				return
			}

			t.Logf("Transfer Witness Case:%s", txWitnessTrTxCaseMapping[trTx.txWitness.TxCase()])
			if trTx.txWitness.TxCase() != tt.expectedWitnessCase {
				t.Errorf("expect witness case %s, but got %s", txWitnessTrTxCaseMapping[tt.expectedWitnessCase], txWitnessTrTxCaseMapping[trTx.txWitness.TxCase()])
			}

			err = pp.TransferTxMLPVerify(trTx)
			if err != nil {
				t.Errorf("TransferTxMLPVerify() error = %v, wantVerifyErr %v", err, true)
				return
			}
		})
	}
}
