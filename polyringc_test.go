package pqringct

import (
	"fmt"
	"log"
	"testing"
)

//func TestReduce(t *testing.T) {
//	var a big.Int
//	var q int64
//	q = 17
//	a.SetInt64(-9)
//	fmt.Println(reduceBigInt(&a, q))
//}

func TestPublicParameterv2_NTTPolyC_NTTInvPolyC(t *testing.T) {
	pp := Initialize(nil)
	c := pp.NewPolyC()
	for i := 0; i < pp.paramDC; i++ {
		c.coeffs[i] = int64(i + 1)
	}
	cinv := pp.NTTPolyC(c)
	fmt.Println(cinv.coeffs)
	got := pp.NTTInvPolyC(cinv)
	fmt.Println(got.coeffs)

}

func TestPublicParameter_NTTPolyC(t *testing.T) {
	pp := Initialize(nil)

	//bigQa := new(big.Int).SetInt64(pp.paramQA)
	//for i := 1; i < pp.paramZetaAOrder; i++ {
	//	a := new(big.Int).SetInt64(pp.paramZetasA[i])
	//	b := new(big.Int).SetInt64(pp.paramZetasA[pp.paramZetaAOrder-i])
	//	a.Mul(a, b)
	//	a.Mod(a, bigQa)
	//	fmt.Println(a.Int64())
	//}

	seed := RandomBytes(pp.paramKeyGenSeedBytesLen)
	tmpC, err := pp.randomDcIntegersInQc(seed)
	if err != nil {
		log.Fatal(err)
	}
	//tmpA := make([]int64, pp.paramDA)
	//for i := 0; i < pp.paramDA; i++ {
	//	tmpA[i] = int64(1000 + i)
	//}
	//for i := 0; i < pp.paramDA; i++ {
	//	if i&1 == 1 {
	//		tmpA[i] = -tmpA[i]
	//	}
	//}
	//tmpA[0] = (pp.paramQA-1)/2 - 1
	nttc := pp.NTTPolyC(&PolyC{coeffs: tmpC})
	got := pp.NTTInvPolyC(nttc)
	for i := 0; i < pp.paramDC; i++ {
		if got.coeffs[i] != tmpC[i] {
			fmt.Println("i=", i, " got[i]=", got.coeffs[i], " origin[i]=", tmpC[i])
		}
	}
}
