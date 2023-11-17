package pqringct

import (
	"log"
	"testing"
)

func Test_randomDcIntegersInQc(t *testing.T) {
	pp := Initialize(nil)
	type args struct {
		seed   []byte
		length int
	}
	tests := []struct {
		name string
		args args
		want []int32
	}{
		{
			"Test1",
			args{
				seed:   []byte("This is the seed for testing"),
				length: pp.paramDC,
			},
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pp.randomDcIntegersInQc(tt.args.seed)
			if err != nil {
				log.Fatal(err)
			}
			//if !reflect.DeepEqual(got, tt.want) {
			//	t.Errorf("randomDcIntegersInQc() = %v, want %v", got, tt.want)
			//}
			for i := 0; i < len(got); i++ {
				if got[i] < -(pp.paramQC-1)>>1 || got[i] > (pp.paramQC-1)>>1 {
					t.Errorf("randomDcIntegersInQc() sample a value %v", got[i])
				}
			}
		})
	}
}

func Test_randomDaIntegersInQa(t *testing.T) {
	pp := Initialize(nil)
	type args struct {
		seed   []byte
		length int
	}
	tests := []struct {
		name string
		args args
		want []int32
	}{
		{
			"Test1",
			args{
				seed:   []byte("This is the seed for testing"),
				length: pp.paramDA,
			},
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pp.randomDaIntegersInQa(tt.args.seed)
			if err != nil {
				log.Fatal(err)
			}
			//if !reflect.DeepEqual(got, tt.want) {
			//	t.Errorf("randomDcIntegersInQc() = %v, want %v", got, tt.want)
			//}
			for i := 0; i < len(got); i++ {
				tmp := (pp.paramQA - 1) >> 1
				if got[i] < -tmp || got[i] > tmp {
					t.Errorf("randomDaIntegersInQa() sample a value %v", got[i])
				}
			}
		})
	}
}
