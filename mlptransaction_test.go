package pqringctx

import (
	"github.com/cryptosuite/pqringct"
	"math/rand"
	"testing"
)

var pp = Initialize(nil)
var ppOld = pqringct.Initialize(nil)

var numPre = 100
var seedPres = make([][]byte, 0, numPre)
var coinAddressPres = make([][]byte, 0, numPre)
var coinAddressSpendKeyPres = make([][]byte, 0, numPre)
var coinSerialNumberSKPres = make([][]byte, 0, numPre)
var valueKeyPreSeeds = make([][]byte, 0, numPre)
var valuePublicKeyPres = make([][]byte, 0, numPre)
var valueSecretKeyPres = make([][]byte, 0, numPre)

var numRand = 100
var coinSpendKeyRandSeeds = make([][]byte, 0, numRand)
var coinSerialNumberKeyRandSeeds = make([][]byte, 0, numRand)
var detectorKeys = make([][]byte, 0, numRand)
var coinAddresss = make([][]byte, 0, numRand)
var coinSpendSecretKeys = make([][]byte, 0, numRand)
var coinSerialNumberSecretKeys = make([][]byte, 0, numRand)
var valueKeySeeds = make([][]byte, 0, numRand)
var valuePublicKeys = make([][]byte, 0, numRand)
var valueSecretKeys = make([][]byte, 0, numRand)

var numSingle = 100
var coinSpendKeyRandSeedForSingles = make([][]byte, 0, numSingle)
var detectorKeyForSingles = make([][]byte, 0, numSingle)
var coinAddressForSingles = make([][]byte, 0, numSingle)
var coinSpendSecretKeyForSingles = make([][]byte, 0, numSingle)

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
		coinAddressSpendKeyPres = append(coinAddressSpendKeyPres, coinAddressSpendKeyPre)
		coinSerialNumberSKPres = append(coinSerialNumberSKPres, coinSerialNumberSKPre)

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
