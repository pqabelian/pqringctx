package pqringct

import (
	"errors"
	"github.com/cryptosuite/pqringct/pqringctkem"
	"log"
	"math/big"
)

func NewPublicParameter(
	paramDA int, paramQA int64, paramThetaA int, paramKA int, paramLambdaA int, paramGammaA int, paramEtaA int64, paramBetaA int16,
	paramI int, paramJ int, paramN int,
	paramDC int, paramQC int64, paramK int, paramKC int, paramLambdaC int, paramEtaC int64, paramBetaC int16,
	paramEtaF int64, paramKeyGenSeedBytesLen int,
	paramDCInv int64, paramKInv int64,
	paramZetaA int64, paramZetaAOrder int,
	paramZetaC int64, paramZetaCOrder int, paramSigmaPermutations [][]int, paramParameterSeedString []byte, paramKem *pqringctkem.ParamKem) (*PublicParameter, error) {

	res := &PublicParameter{
		paramDA:                 paramDA,
		paramQA:                 paramQA,
		paramThetaA:             paramThetaA,
		paramKA:                 paramKA,
		paramLambdaA:            paramLambdaA,
		paramLA:                 paramKA + paramLambdaA + 1,
		paramGammaA:             paramGammaA,
		paramEtaA:               paramEtaA,
		paramBetaA:              paramBetaA,
		paramI:                  paramI,
		paramJ:                  paramJ,
		paramN:                  paramN,
		paramDC:                 paramDC,
		paramQC:                 paramQC,
		paramK:                  paramK,
		paramKC:                 paramKC,
		paramLambdaC:            paramLambdaC,
		paramLC:                 paramKC + paramI + paramJ + 7 + paramLambdaC,
		paramEtaC:               paramEtaC,
		paramBetaC:              paramBetaC,
		paramEtaF:               paramEtaF,
		paramKeyGenSeedBytesLen: paramKeyGenSeedBytesLen,
		//		paramQCm:      	paramQC >> 1,
		paramDCInv:               paramDCInv,
		paramKInv:                paramKInv,
		paramZetaA:               paramZetaA,
		paramZetaAOrder:          paramZetaAOrder,
		paramZetaC:               paramZetaC,
		paramZetaCOrder:          paramZetaCOrder,
		paramSigmaPermutations:   paramSigmaPermutations,
		paramParameterSeedString: paramParameterSeedString,
		paramKem:                 paramKem,
	}
	if res.paramParameterSeedString == nil || len(res.paramParameterSeedString) == 0 {
		res.paramParameterSeedString = []byte("Welcome to Post Quantum World!")
	}
	// initialize the NTTCFactors
	slotNumC := res.paramZetaCOrder / 2 // factored to irreducible factors, fully splitting
	segNumC := 1
	nttFactorsC := make([]int, 1)
	nttFactorsC[0] = slotNumC / 2

	for {
		segNumC = segNumC << 1
		if segNumC == slotNumC {
			break
		}
		tmpFactors := make([]int, 2*len(nttFactorsC))
		for i := 0; i < len(nttFactorsC); i++ {
			tmpFactors[2*i] = (nttFactorsC[i] + slotNumC) / 2
			tmpFactors[2*i+1] = nttFactorsC[i] / 2
		}
		nttFactorsC = tmpFactors
	}
	res.paramNTTCFactors = nttFactorsC

	// initialize the NTTAFactors
	slotNumA := res.paramZetaAOrder / 2 // factored to irreducible factors
	segNumA := 1
	nttFactorsA := make([]int, 1)
	nttFactorsA[0] = slotNumA / 2

	for {
		segNumA = segNumA << 1
		if segNumA == slotNumA {
			break
		}
		tmpFactors := make([]int, 2*len(nttFactorsA))
		for i := 0; i < len(nttFactorsA); i++ {
			tmpFactors[2*i] = (nttFactorsA[i] + slotNumA) / 2
			tmpFactors[2*i+1] = nttFactorsA[i] / 2
		}
		nttFactorsA = tmpFactors
	}
	res.paramNTTAFactors = nttFactorsA

	//  parameters for Number Theory Transform
	curr := new(big.Int)

	res.paramZetasC = make([]int64, res.paramZetaCOrder)
	//for i := 0; i < res.paramZetaCOrder; i++ {
	//	res.paramZetasC[i] = powerAndModP(res.paramZetaC, int64(i), res.paramQC)
	//}
	bigQC := new(big.Int).SetInt64(res.paramQC)
	zetaC := new(big.Int).SetInt64(res.paramZetaC)
	res.paramZetasC[0] = 1
	curr.SetInt64(1)
	for i := 1; i < res.paramZetaCOrder; i++ {
		curr.Mul(curr, zetaC)
		curr.Mod(curr, bigQC)
		res.paramZetasC[i] = reduceInt64(curr.Int64(), res.paramQC)
	}

	res.paramZetasA = make([]int64, res.paramZetaAOrder)
	//for i := 0; i < res.paramZetaAOrder; i++ {
	//	res.paramZetasA[i] = powerAndModP(res.paramZetaA, int64(i), res.paramQA)
	//}
	bigQA := new(big.Int).SetInt64(res.paramQA)
	zetaA := new(big.Int).SetInt64(res.paramZetaA)
	res.paramZetasA[0] = 1
	curr.SetInt64(1)
	for i := 1; i < res.paramZetaAOrder; i++ {
		curr.Mul(curr, zetaA)
		curr.Mod(curr, bigQA)
		res.paramZetasA[i] = reduceInt64(curr.Int64(), res.paramQA)
	}

	seed, err := Hash(res.paramParameterSeedString)
	if err != nil {
		return nil, err
	}

	// generate the public matrix paramMatrixA from seed
	//seedMatrixA := make([]byte, 32)
	//sha3.ShakeSum256(seedMatrixA, append([]byte{'M', 'A'}, seed...))
	seedMatrixA := append([]byte{'M', 'A'}, seed...)
	res.paramMatrixA, err = res.expandPubMatrixA(seedMatrixA)
	if err != nil {
		return nil, err
	}

	// generate the public matrix paramVectorA from seed
	//seedVectorA := make([]byte, 32)
	//sha3.ShakeSum256(seedVectorA, append([]byte{'M', 'a'}, seed...))
	seedVectorA := append([]byte{'V', 'a'}, seed...)
	res.paramVectorA, err = res.expandPubVectorA(seedVectorA)
	if err != nil {
		return nil, err
	}

	// generate the public matrix paramMatrixB from seed
	//seedMatrixB := make([]byte, 32)
	//sha3.ShakeSum256(seedMatrixB, append([]byte{'M', 'B'}, seed...))
	seedMatrixB := append([]byte{'M', 'B'}, seed...)
	res.paramMatrixB, err = res.expandPubMatrixB(seedMatrixB)
	if err != nil {
		return nil, err
	}

	// generate the public matrix paramMatrixH from seed
	//seedMatrixH := make([]byte, 32)
	//sha3.ShakeSum256(seedMatrixH, append([]byte{'M', 'H'}, seed...))
	seedMatrixH := append([]byte{'M', 'H'}, seed...)
	res.paramMatrixH, err = res.expandPubMatrixH(seedMatrixH)
	if err != nil {
		return nil, err
	}

	muCoeff := make([]int64, paramDC)
	for i := 0; i < res.paramN; i++ {
		muCoeff[i] = 1
	}
	for i := res.paramN; i < res.paramDC; i++ {
		muCoeff[i] = 0
	}
	res.paramMu = &PolyCNTT{muCoeff}

	return res, nil
}

type PublicParameter struct {
	// Paramter for Address
	paramDA int
	paramQA int64
	// For challenge
	paramThetaA int

	paramKA      int
	paramLambdaA int
	// paramLA = paramKA + paramLambdaA + 1
	paramLA int

	// For randomness
	paramGammaA int
	// For masking
	paramEtaA int64
	// For bounding
	paramBetaA int16

	// Parameter for Commit
	// paramI defines the maximum number of consumed coins of a transfer transaction
	// As we need to loop for paramI and paramJ, we define them with 'int' type.
	paramI int
	// paramJ defines the maximum number of generated coins of a transaction
	// As we need to loop for paramI and paramJ, we define them with 'int' type.
	paramJ int
	// paramN defines the value of V by V=2^N - 1
	// paramN <= paramDC
	// As we need to loop for paramN, we define them with 'int' type.
	paramN int
	// paramDC: the degree of the polynomial ring, say R =Z[X] / (X^d + 1)
	// d should be a power of two, not too small (otherwise is insecure) and not too large (otherwise inefficient)
	// here we define it as 'int', since we need to loop from 0 to d-1 for some matrix, and int is fine for the possible
	// values, such as d=128, 256, 512, and even 1024, on any platform/OS, since int maybe int32 or int64.
	// require: d >= 128
	paramDC int
	// paramQC is the module to define R_q[X] = Z_q[X] / (X^d +1)
	// q = 1 mod 2d will guarantee that R_q[X] is a fully-splitting ring, say that X^d+1 = (X-\zeta)(X-\zetz^3)...(X-\zeta^{2d-1}),
	// where \zeta is a primitive 2d-th root of unity in Z_q^*.
	// For efficiency, q is expected to small. Considering the security, q (approx.)= 2^32 is fine.
	// For uint32, q lies in [0, 2^32-1], and Z_q = [-(q-1)/2, (q-1)/1], int32 will be fine to denote the values in Z_q.
	// q_m = (q-1)/2, as this value will be often used in computation, we define it as a parameter, rather than compute it each time.
	paramQC int64
	// paramK is a power of two such that k|d and q^{-k} is negligible.
	// As we will also loop for k, we define it with 'int' type.
	paramK int
	// paramKInv = k^{-1} mod q

	// As we need to loop for paramKC, we define it with 'int' type
	paramKC      int
	paramLambdaC int
	// paramLC = paramKC + paramI + paramJ + 7 + paramLambdaC
	paramLC int

	// As paramEtaC is used to specify the infNorm of polys in Ring, thus we define it with type 'int32' (as q)
	paramEtaC int64

	// As paramBetaC is used to specify the infNorm of polys in Ring
	paramBetaC int16

	// As paramEtaF may be (q_c-1)/16, we define it with 'int64' type
	paramEtaF int64

	// paramKeyGenSeedBytesLen specifies the seed length for KeyGen
	paramKeyGenSeedBytesLen int

	// Some Helpful parameter
	/*	// paramQCm = (q_c -1)/2, as this value will be often used in computation, we define it as a parameter, rather than compute it each time.
		paramQCm int64*/
	//paramDCInv = d_c^{-1} mod q_c
	paramDCInv int64
	//paramKInv = k^{-1} mod q_c
	paramKInv int64

	// For splitting
	// paramZetaA is a primitive paramZetaAOrder-th root of unity in Z_{q_a}^*.
	paramZetaA       int64
	paramZetasA      []int64
	paramZetaAOrder  int
	paramNTTAFactors []int

	// paramZetaC is a primitive paramZetaCOrder(=2d_c)-th root of unity in Z_{q_c}^*.
	// As zeta_c \in Z_q, we define it with 'int64' type.
	paramZetaC       int64
	paramZetasC      []int64
	paramZetaCOrder  int
	paramNTTCFactors []int

	// paramSigmaPermutations is determined by (d_c,k) and the selection of sigma
	// paramSigmaPermutations [t] with t=0~(k-1) works for sigma^t
	paramSigmaPermutations [][]int

	// As paramParameterSeedString is used to generate the public matrix, such as paramMatrixA, paramVectorA, paramMatrixB, paramMatrixH
	paramParameterSeedString []byte

	// paramMatrixA is expand from paramParameterSeedString, with size k_a rows, each row with size l_a
	paramMatrixA []*PolyANTTVec

	// paramVectorA is expand from paramParameterSeedString, with size l_a
	paramVectorA *PolyANTTVec

	//paramMatrixB is expand from paramParameterSeedString, with size k_c rows, each row with size l_c
	paramMatrixB []*PolyCNTTVec

	// paramMatrixH is expand from paramParameterSeedString, with size (paramI + paramJ + 7) rows, each row with size l_c
	paramMatrixH []*PolyCNTTVec

	// paramMu defines the const mu, which is determined by the value of N and d
	// paramMu will be used as a constant PolyCNTT, where coeff[0]~coeff[N-1] is 1, and the remainder coeffs are 0.
	paramMu *PolyCNTT

	// paramKem defines the key encapsulate mechanism
	paramKem *pqringctkem.ParamKem
}

func (pp *PublicParameter) ParamSeedBytesLen() int {
	return pp.paramKeyGenSeedBytesLen
}

func (pp *PublicParameter) expandPubMatrixA(seed []byte) ([]*PolyANTTVec, error) {
	if len(seed) == 0 {
		return nil, errors.New("expandPubMatrixA: the seed is empty")
	}
	seedUsed := append([]byte("MatrixA"), seed...)

	res := make([]*PolyANTTVec, pp.paramKA)

	unit := pp.NewZeroPolyA()
	unit.coeffs[0] = 1
	unitNTT := pp.NTTPolyA(unit)

	// generate the right sub-matrix A'
	matrixAp, err := pp.generatePolyANTTMatrix(seedUsed, pp.paramKA, 1+pp.paramLambdaA)
	if err != nil {
		return nil, err
	}

	for i := 0; i < pp.paramKA; i++ {
		res[i] = pp.NewZeroPolyANTTVec(pp.paramLA)

		//for t := 0; t < pp.paramDA; t++ {
		//	// repeatedly use unitNTT, set the coeffs rather than the pointer
		//	res[i].polyANTTs[i].coeffs[t] = unitNTT.coeffs[t]
		//}
		copy(res[i].polyANTTs[i].coeffs, unitNTT.coeffs)

		for j := 0; j < 1+pp.paramLambdaA; j++ {
			res[i].polyANTTs[pp.paramKA+j] = matrixAp[i].polyANTTs[j]
		}

	}

	return res, nil
}

func (pp *PublicParameter) expandPubVectorA(seed []byte) (*PolyANTTVec, error) {
	if len(seed) == 0 {
		return nil, errors.New("expandPubVectorA: the seed is empty")
	}
	seedUsed := append([]byte("VectorA"), seed...)

	unit := pp.NewZeroPolyA()
	unit.coeffs[0] = 1
	unitNTT := pp.NTTPolyA(unit)

	// generate the right vector a'
	vectorAp, err := pp.generatePolyANTTMatrix(seedUsed, 1, pp.paramLambdaA)
	if err != nil {
		return nil, err
	}

	// [0 ... 0(k_a) , 1, vectorAp (lambda_a)]
	res := pp.NewZeroPolyANTTVec(pp.paramLA) // L_a = K_a+1+lambda_a

	res.polyANTTs[pp.paramKA] = unitNTT

	for j := 0; j < pp.paramLambdaA; j++ {
		res.polyANTTs[pp.paramKA+1+j] = vectorAp[0].polyANTTs[j]
	}
	return res, nil
}

func (pp *PublicParameter) expandPubMatrixB(seed []byte) (matrixB []*PolyCNTTVec, err error) {
	if len(seed) == 0 {
		return nil, errors.New("expandPubMatrixB: the seed is empty")
	}
	seedUsed := append([]byte("MatrixB"), seed...)

	res := make([]*PolyCNTTVec, pp.paramKC)

	unit := pp.NewZeroPolyC()
	unit.coeffs[0] = 1
	unitNTT := pp.NTTPolyC(unit)

	// generate the right sub-matrix B'
	matrixBp, err := pp.generatePolyCNTTMatrix(seedUsed, pp.paramKC, pp.paramI+pp.paramJ+7+pp.paramLambdaC)
	if err != nil {
		return nil, err
	}

	for i := 0; i < pp.paramKC; i++ {
		res[i] = pp.NewZeroPolyCNTTVec(pp.paramLC)

		//for t := 0; t < pp.paramDC; t++ {
		//	res[i].polyCNTTs[i].coeffs[t] = unitNTT.coeffs[t]
		//}
		copy(res[i].polyCNTTs[i].coeffs, unitNTT.coeffs)

		for j := 0; j < pp.paramI+pp.paramJ+7+pp.paramLambdaC; j++ {
			res[i].polyCNTTs[pp.paramKC+j] = matrixBp[i].polyCNTTs[j]
		}

	}

	return res, nil
}

func (pp *PublicParameter) expandPubMatrixH(seed []byte) (matrixH []*PolyCNTTVec, err error) {
	if len(seed) == 0 {
		return nil, errors.New("expandPubMatrixH: the seed is empty")
	}
	seedUsed := append([]byte("MatrixH"), seed...)

	res := make([]*PolyCNTTVec, pp.paramI+pp.paramJ+7)

	unitPoly := pp.NewZeroPolyC()
	unitPoly.coeffs[0] = 1
	unitNTT := pp.NTTPolyC(unitPoly)

	// generate the right sub-matrix H'
	matrixHp, err := pp.generatePolyCNTTMatrix(seedUsed, pp.paramI+pp.paramJ+7, pp.paramLambdaC)
	if err != nil {
		return nil, err
	}

	for i := 0; i < pp.paramI+pp.paramJ+7; i++ {
		res[i] = pp.NewZeroPolyCNTTVec(pp.paramLC) // L_c=K_c+I+J+7+lambda_c

		//for t := 0; t < pp.paramDC; t++ {
		//	res[i].polyCNTTs[pp.paramKC+i].coeffs[t] = unitNTT.coeffs[t]
		//}
		copy(res[i].polyCNTTs[pp.paramKC+i].coeffs, unitNTT.coeffs)

		for j := 0; j < pp.paramLambdaC; j++ {
			res[i].polyCNTTs[pp.paramKC+pp.paramI+pp.paramJ+7+j] = matrixHp[i].polyCNTTs[j]
		}
	}

	return res, nil
}

// Initialize is the init function, it must be called explicitly when using this package
func Initialize(paramterSeedString []byte) *PublicParameter {
	var err error
	var defaultPP *PublicParameter
	defaultPP, err = NewPublicParameter(
		256,
		8522826353, // 2^32+2^31+2^30+2^29+2^28+2^27+2^26+2^9+2^6+2^5+2^4+1
		60,
		8,
		7,
		2,
		1<<19-1, //524287
		120,
		5,
		5,
		51,
		128,
		9007199254746113,
		4,
		10,
		10,
		16777215,
		128,
		1<<23-1, //	eta_f should be smaller than q_c/16, 2^49-1 is fine, but for size optimization, we use 2^{23}-1
		64,      // 64 bytes = 512 bits
		-70368744177704,
		-2251799813686528,
		-2943398012,
		16,
		-3961374278055081,
		256,
		//paramSigmaPermutations is sigma=65 when Dc=128, Qc = 1 mod 256
		[][]int{
			{
				0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
				16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
				32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
				48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
				64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
				80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95,
				96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
				112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127,
			},
			{
				32, 97, 34, 99, 36, 101, 38, 103, 40, 105, 42, 107, 44, 109, 46, 111,
				48, 113, 50, 115, 52, 117, 54, 119, 56, 121, 58, 123, 60, 125, 62, 127,
				64, 1, 66, 3, 68, 5, 70, 7, 72, 9, 74, 11, 76, 13, 78, 15,
				80, 17, 82, 19, 84, 21, 86, 23, 88, 25, 90, 27, 92, 29, 94, 31,
				96, 33, 98, 35, 100, 37, 102, 39, 104, 41, 106, 43, 108, 45, 110, 47,
				112, 49, 114, 51, 116, 53, 118, 55, 120, 57, 122, 59, 124, 61, 126, 63,
				0, 65, 2, 67, 4, 69, 6, 71, 8, 73, 10, 75, 12, 77, 14, 79,
				16, 81, 18, 83, 20, 85, 22, 87, 24, 89, 26, 91, 28, 93, 30, 95,
			},
			{
				64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
				80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95,
				96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
				112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127,
				0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
				16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
				32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
				48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
			},
			{
				96, 33, 98, 35, 100, 37, 102, 39, 104, 41, 106, 43, 108, 45, 110, 47,
				112, 49, 114, 51, 116, 53, 118, 55, 120, 57, 122, 59, 124, 61, 126, 63,
				0, 65, 2, 67, 4, 69, 6, 71, 8, 73, 10, 75, 12, 77, 14, 79,
				16, 81, 18, 83, 20, 85, 22, 87, 24, 89, 26, 91, 28, 93, 30, 95,
				32, 97, 34, 99, 36, 101, 38, 103, 40, 105, 42, 107, 44, 109, 46, 111,
				48, 113, 50, 115, 52, 117, 54, 119, 56, 121, 58, 123, 60, 125, 62, 127,
				64, 1, 66, 3, 68, 5, 70, 7, 72, 9, 74, 11, 76, 13, 78, 15,
				80, 17, 82, 19, 84, 21, 86, 23, 88, 25, 90, 27, 92, 29, 94, 31,
			},
		},
		paramterSeedString,
		//[]byte("Welcome to Post Quantum World!")
		&pqringctkem.ParamKem{
			Version: pqringctkem.KEM_OQS_KYBER,
			//Kyber:   kyber.Kyber768,
			Kyber:    nil,
			OQSKyber: "Kyber768",
		},
	)
	if err != nil {
		log.Fatalln(err)
	}
	return defaultPP
}
