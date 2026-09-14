package pqringctx

import (
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

func TestPublicParameter_Deserialize(t *testing.T) {
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

			for i := 0; i < len(trTx.txos); i++ {
				serializeTxoMLP, err := pp.SerializeTxoMLP(trTx.txos[i])
				if err != nil {
					t.Fatalf("SerializeTxoMLP() error = %v, wantErr %v", err, false)
				}

				// nothing to read
				_, err = pp.DeserializeTxoMLP(serializeTxoMLP[:0])
				if err == nil {
					t.Fatalf("expected non-nil when nothing to read")
				}

				// truncated
				_, err = pp.DeserializeTxoMLP(serializeTxoMLP[:len(serializeTxoMLP)-1])
				if err == nil {
					t.Fatalf("expected non-nil when nothing to read")
				}

				// complete
				deserializedTxoMLP, err := pp.DeserializeTxoMLP(serializeTxoMLP)
				if err != nil {
					t.Fatalf(err.Error())
				}
				if !reflect.DeepEqual(deserializedTxoMLP, trTx.txos[i]) {
					t.Fatalf("deserialized witness is unmatched with deserialized TxooMLP")
				}
			}
			serializeTxWitnessTrTx, err := pp.SerializeTxWitnessTrTx(trTx.txWitness)
			if err != nil {
				t.Fatalf("SerializeTrTxWitness() error = %v, wantErr %v", err, false)
			}

			// nothing to read
			_, err = pp.DeserializeTxWitnessTrTx(serializeTxWitnessTrTx[:0])
			if err == nil {
				t.Fatalf("expected non-nil when nothing to read")
			}

			// truncated
			_, err = pp.DeserializeTxWitnessTrTx(serializeTxWitnessTrTx[:len(serializeTxWitnessTrTx)-1])
			if err == nil {
				t.Fatalf("expected non-nil when nothing to read")
			}

			// complete
			deserializedTxWitnessTrTx, err := pp.DeserializeTxWitnessTrTx(serializeTxWitnessTrTx)
			if err != nil {
				t.Fatalf(err.Error())
			}
			if !reflect.DeepEqual(deserializedTxWitnessTrTx, trTx.txWitness) {
				t.Fatalf("deserialized witness is unmatched with deserialized witness")
			}

			err = pp.TransferTxMLPVerify(trTx)
			if err != nil {
				t.Errorf("TransferTxMLPVerify() error = %v, wantVerifyErr %v", err, true)
				return
			}
		})
	}
}
