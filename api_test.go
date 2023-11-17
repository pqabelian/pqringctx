package pqringct

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

func ledgerTxoIdGen(ringHash []byte, index uint8) []byte {
	w := bytes.NewBuffer(make([]byte, 0, HashOutputBytesLen+1))
	var err error
	// ringHash
	_, err = w.Write(ringHash)
	if err != nil {
		return nil
	}
	// index
	err = w.WriteByte(index >> 0)
	if err != nil {
		return nil
	}
	rst, err := Hash(w.Bytes())
	if err != nil {
		return nil
	}
	return rst
}

func TestPublicParameter_TransferTxGen_TransferTxVerify(t *testing.T) {
	pp := Initialize(nil)

	peerNum := 2
	seeds := make([][]byte, peerNum)
	apks := make([]*AddressPublicKey, peerNum)
	asks := make([]*AddressSecretKey, peerNum)
	serializedVPks := make([][]byte, peerNum)
	serializedVSks := make([][]byte, peerNum)
	serializedVSksCopy := make([][][]byte, peerNum)
	serializedAPks := make([][]byte, peerNum)
	serializedASksps := make([][]byte, peerNum)
	serializedASksns := make([][]byte, peerNum)
	for i := 0; i < peerNum; i++ {
		seeds[i] = RandomBytes(pp.paramKeyGenSeedBytesLen)
		apks[i], asks[i], _ = pp.addressKeyGen(seeds[i])
		serializedVPks[i], serializedVSks[i], _ = pp.valueKeyGen(seeds[i])
		copyNum := 3
		serializedVSksCopy[i] = make([][]byte, copyNum)
		for j := 0; j < copyNum; j++ {
			serializedVSksCopy[i][j] = make([]byte, len(serializedVSks[i]))
			copy(serializedVSksCopy[i][j], serializedVSks[i])
		}
		serializedAPks[i], _ = pp.SerializeAddressPublicKey(apks[i])
		serializedASksps[i], _ = pp.SerializeAddressSecretKeySp(asks[i].AddressSecretKeySp)
		serializedASksns[i], _ = pp.SerializeAddressSecretKeySn(asks[i].AddressSecretKeySn)
	}
	cbTxNum, outputNum := 3, 2
	cbTxs := make([]*CoinbaseTx, cbTxNum)
	txOutputDescs := make([]*TxOutputDesc, outputNum)
	for i := 0; i < outputNum; i++ {
		txOutputDescs[i] = &TxOutputDesc{
			serializedAPk: serializedAPks[i],
			serializedVPk: serializedVPks[i],
			value:         256,
		}
	}
	var err error
	// generate coinbase transaction with txOutputDescs
	for i := 0; i < cbTxNum; i++ {
		cbTxs[i], err = pp.coinbaseTxGen(512, txOutputDescs, nil)
		if err != nil {
			t.Errorf(err.Error())
		}
		var cbTx1Serialized []byte
		cbTx1Serialized, err = pp.SerializeCoinbaseTx(cbTxs[i], true)
		if err != nil {
			t.Errorf(err.Error())
		}
		var cbTx1Deser *CoinbaseTx
		cbTx1Deser, err = pp.DeserializeCoinbaseTx(cbTx1Serialized, true)
		if err != nil {
			t.Errorf(err.Error())
		}
		var valid bool
		valid, err = pp.coinbaseTxVerify(cbTx1Deser)
		if err != nil {
			t.Errorf(err.Error())
		}
		if valid {
			fmt.Println("CbTx1 (J=2) serialze and deserialize Pass")
		}
	}

	type args struct {
		inputDescs  []*TxInputDesc
		outputDescs []*TxOutputDesc
		fee         uint64
		txMemo      []byte
	}

	ehash := make([]byte, HashOutputBytesLen)
	tests := []struct {
		name    string
		args    args
		wantErr bool
		want    bool
	}{
		{
			name: "1->2",
			args: args{
				inputDescs: []*TxInputDesc{
					{
						lgrTxoList: []*LgrTxo{
							{
								txo: cbTxs[0].OutputTxos[0],
								id:  ledgerTxoIdGen(ehash, 0),
							},
							{
								txo: cbTxs[0].OutputTxos[1],
								id:  ledgerTxoIdGen(ehash, 1),
							},
							{
								txo: cbTxs[2].OutputTxos[0],
								id:  ledgerTxoIdGen(ehash, 2),
							},
						},
						sidx:            0,
						serializedASksp: serializedASksps[0],
						serializedASksn: serializedASksns[0],
						serializedVPk:   serializedVPks[0],
						serializedVSk:   serializedVSksCopy[0][0],
						value:           256,
					},
				},
				outputDescs: []*TxOutputDesc{
					{
						serializedAPk: serializedAPks[0],
						serializedVPk: serializedVPks[0],
						value:         200,
					},
					{
						serializedAPk: serializedAPks[1],
						serializedVPk: serializedVPks[1],
						value:         46,
					},
				},
				fee:    10,
				txMemo: []byte{},
			},
			wantErr: false,
			want:    true,
		},
		{
			name: "2->2",
			args: args{
				inputDescs: []*TxInputDesc{
					{
						lgrTxoList: []*LgrTxo{
							{
								txo: cbTxs[0].OutputTxos[0],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTxs[0].OutputTxos[1],
								id:  make([]byte, HashOutputBytesLen),
							},
						},
						sidx:            0,
						serializedASksp: serializedASksps[0],
						serializedASksn: serializedASksns[0],
						serializedVPk:   serializedVPks[0],
						serializedVSk:   serializedVSksCopy[0][1],
						value:           256,
					},
					{
						lgrTxoList: []*LgrTxo{
							{
								txo: cbTxs[1].OutputTxos[0],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTxs[1].OutputTxos[1],
								id:  make([]byte, HashOutputBytesLen),
							},
						},
						sidx:            0,
						serializedASksp: serializedASksps[0],
						serializedASksn: serializedASksns[0],
						serializedVPk:   serializedVPks[0],
						serializedVSk:   serializedVSksCopy[0][2],
						value:           256,
					},
				},
				outputDescs: []*TxOutputDesc{
					{
						serializedAPk: serializedAPks[0],
						serializedVPk: serializedVPks[0],
						value:         500,
					},
					{
						serializedAPk: serializedAPks[1],
						serializedVPk: serializedVPks[1],
						value:         2,
					},
				},
				fee:    10,
				txMemo: []byte{},
			},
			wantErr: false,
			want:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotTrTx, err := pp.transferTxGen(tt.args.inputDescs, tt.args.outputDescs, tt.args.fee, tt.args.txMemo)
			if (err != nil) != tt.wantErr {
				t.Errorf("transferTxGen() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			gotTrTxSerialized, err := pp.SerializeTransferTx(gotTrTx, true)
			if err != nil {
				t.Errorf(err.Error())
			}
			gotTrTxDeser, err := pp.DeserializeTransferTx(gotTrTxSerialized, true)
			if err != nil {
				t.Errorf(err.Error())
			}

			ringSizes := make([]int, len(gotTrTx.Inputs))
			for i := 0; i < len(gotTrTx.Inputs); i++ {
				ringSizes[i] = 2
			}
			fmt.Println("TrTxWitnessSizeApprox:", pp.TrTxWitnessSerializeSizeApprox(ringSizes, len(gotTrTx.OutputTxos)))
			fmt.Println("TrTxWitnessSizeExact:", pp.TrTxWitnessSerializeSize(gotTrTx.TxWitness))

			got, err := pp.transferTxVerify(gotTrTxDeser)
			if (err != nil) != tt.wantErr {
				t.Errorf("transferTxGen() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("transferTxVerify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValueKeyGen_ValueKeyVerify(t *testing.T) {
	pp := Initialize(nil)
	type args struct {
		pp   *PublicParameter
		seed []byte
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "1",
			args: args{
				pp:   pp,
				seed: RandomBytes(pp.paramKeyGenSeedBytesLen),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fmt.Println("seed = ", hex.EncodeToString(tt.args.seed))
			serializedPK, serializedSK, err := ValueKeyGen(tt.args.pp, tt.args.seed)
			if err != nil {
				t.Errorf("ValueKeyGen() error = %v", err)
				return
			}

			valid, hints := ValueKeyVerify(tt.args.pp, serializedPK, serializedSK)
			if !valid {
				t.Errorf("ValueKeyGen is unmatched with ValueKeyVerify() error = %s", hints)
				return
			}

		})
	}
}
