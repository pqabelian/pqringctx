package pqringctx

import (
	"errors"
	"github.com/pqabelian/pqringctx/pqringctxkem"
	"log"
	"math/big"
)

func NewPublicParameter(
	paramDA int, paramQA int64, paramThetaA int, paramKA int, paramLambdaA int, paramGammaA int, paramEtaA int64, paramBetaA int16,
	paramI uint8, paramJ uint8,
	paramISingle uint8, paramISingleDistinct uint8, paramJSingle uint8,
	paramRingSizeMax uint8,
	paramN int,
	paramDC int, paramQC int64, paramK int, paramKC int, paramLambdaC int, paramEtaC int64, paramBetaC int16,
	paramEtaF int64,
	paramKeyGenSeedBytesLen int,
	paramKeyGenPublicRandBytesLen int,
	paramDCInv int64, paramKInv int64,
	paramZetaA int64, paramZetaAOrder int,
	paramZetaC int64, paramZetaCOrder int, paramSigmaPermutations [][]int, paramParameterSeedString []byte, paramKem *pqringctxkem.ParamKem) (*PublicParameter, error) {

	// TODO add constrain for parameter, such as paramN can not exceed 63
	res := &PublicParameter{
		paramDA:                       paramDA,
		paramQA:                       paramQA,
		paramThetaA:                   paramThetaA,
		paramKA:                       paramKA,
		paramLambdaA:                  paramLambdaA,
		paramLA:                       paramKA + paramLambdaA + 1,
		paramGammaA:                   paramGammaA,
		paramEtaA:                     paramEtaA,
		paramBetaA:                    paramBetaA,
		paramI:                        paramI,
		paramJ:                        paramJ,
		paramISingle:                  paramISingle,
		paramISingleDistinct:          paramISingleDistinct,
		paramJSingle:                  paramJSingle,
		paramRingSizeMax:              paramRingSizeMax,
		paramN:                        paramN,
		paramDC:                       paramDC,
		paramQC:                       paramQC,
		paramK:                        paramK,
		paramKC:                       paramKC,
		paramLambdaC:                  paramLambdaC,
		paramLC:                       paramKC + int(paramI) + int(paramJ) + 7 + paramLambdaC,
		paramEtaC:                     paramEtaC,
		paramBetaC:                    paramBetaC,
		paramEtaF:                     paramEtaF,
		paramKeyGenSeedBytesLen:       paramKeyGenSeedBytesLen,
		paramKeyGenPublicRandBytesLen: paramKeyGenPublicRandBytesLen,
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
	// Parameter for Address
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
	// paramI defines the maximum number of consumed RingCT-privacy coins of a transfer transaction
	// To explicitly limit the paramI and paramJ as a number denoted by 1 byte, we define them with uint8.
	// Note that there is still an implicit setting, say, paramI + paramJ + 4 should be still a number in the scope of uint8.
	// Note this is at the system design level, it is fine to have such an implicit setting.
	// Previously being "paramI int"
	paramI uint8

	// paramJ defines the maximum number of generated RingCT-privacy coins of a transaction.
	// To explicitly limit the paramI and paramJ as a number denoted by 1 byte, we define them with uint8.
	// Note that there is still an implicit setting, say, paramI + paramJ + 4 should be still a number in the scope of uint8.
	// Note this is at the system design level, it is fine to have such an implicit setting.
	// Previously being "paramJ int"
	paramJ uint8

	// paramISingle defines the maximum number of consumed Pseudonym-privacy coins of a transfer transaction
	// To explicitly limit the paramISingle, paramISingleDistinct, and paramJSingle as a number denoted by 1 byte, we define them with uint8.
	// Note that there is still an implicit setting, say, paramI + paramISingle should be still a number in the scope of uint8.
	paramISingle uint8

	// paramISingleDistinct defines the maximum number of the distinct coin-addresses of the consumed Pseudonym-privacy coins of a transfer transaction
	// To explicitly limit the paramISingle, paramISingleDistinct, and paramJSingle as a number denoted by 1 byte, we define them with uint8.
	paramISingleDistinct uint8

	// paramJSingle defines the maximum number of generated Pseudonym-privacy coins of a transaction
	// To explicitly limit the paramISingle, paramISingleDistinct, and paramJSingle as a number denoted by 1 byte, we define them with uint8.
	// Note that there is still an implicit setting, say, paramJ + paramJSingle should be still a number in the scope of uint8.
	paramJSingle uint8

	// paramRingSizeMax defines the maximum allowed ring size. it should be not too big, in particular,
	// we assume it to be smaller than 255, and use uint8 to restrict it.
	paramRingSizeMax uint8

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
	// q_m = (q-1)/2, as this value will often be used in computation, we define it as a parameter, rather than compute it each time.
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

	paramKeyGenPublicRandBytesLen int

	// Some Helpful parameter
	/*	// paramQCm = (q_c -1)/2, as this value will often be used in computation, we define it as a parameter, rather than compute it each time.
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

	// paramMatrixA expands from paramParameterSeedString, with size k_a(paramKA) rows, each row with size l_a(paramLA)
	//
	//*                 paramKA			paramKA+(1+paramLAMBDA)
	// *                    |			 |
	// *                    v			v
	// * [ unit    0  ...   0   x ... x ]
	// * [   0   unit ...   0   x ... x ]
	// * ...
	// * [   0     0  ... unit  x ... x ]
	paramMatrixA []*PolyANTTVec

	// paramVectorA expands from paramParameterSeedString, with size l_a (paramLA)
	//
	// *            paramKA 	paramKA+1	paramKA+(1+paramLAMBDA)
	// *              |  		|			|
	// *              v  		v			v
	// * [ 0 0  ... 0 			unit  x ... x ]
	paramVectorA *PolyANTTVec

	//paramMatrixB expands from paramParameterSeedString, with size k_c(paramKC) rows, each row with size l_c(paramLC)
	//
	// *                 paramKC
	// *                    |
	// *                    v
	// * [ unit    0  ...   0   y ... y ]
	// * [   0   unit ...   0   y ... y ]
	// * ...
	// * [   0     0  ... unit  y ... y ]
	paramMatrixB []*PolyCNTTVec

	// paramMatrixH expands from paramParameterSeedString, with size (paramI + paramJ + 7) rows, each row with size l_c(paramLC)
	//
	// *                      paramKC + paramI + paramJ + 7 + paramLambdaC
	// *               paramKC + paramI + paramJ + 7 |
	// *              paramKC             |          |
	// *                |                 |          |
	// *                v                 v          v
	// * [   0  0  ...  0 unit   0  ...   0    y ... y ]
	// * [   0  0  ...  0   0  unit ...   0    y ... y ]
	// * ...
	// * [   0  0  ...  0   0    0  ... unit   y ... y ]
	paramMatrixH []*PolyCNTTVec

	// paramMu defines the const mu, which is determined by the value of N and d
	// paramMu will be used as a constant PolyCNTT, where coeff[0]~coeff[N-1] is 1, and the remainder coeffs are 0.
	// *            paramN    paramDC
	// *              |         |
	// *              v         v
	// * [ 1  1  ...  1 0 0 ... 0]
	//	}
	//	for i := res.paramN; i < res.paramDC; i++ {
	//		muCoeff[i] = 0
	//	}
	paramMu *PolyCNTT

	// paramKem defines the key encapsulate mechanism
	paramKem *pqringctxkem.ParamKem
}

// expandPubMatrixA expand matrix from specified seed
// the matrix would be PublicParameter.paramKA * PublicParameter.paramLA
// the origin matrix would look like the following:
// unit = [1,0,...,0] in S_{q_a}^{d_a}
// 0 is zero element in  S_{q_a}^{d_a}
// x is random element in S_{q_a}^{d_a}
// *          PublicParameter.paramKA
// *                    |
// *                    v
// * [ unit    0  ...   0   x ... x ]
// * [   0   unit ...   0   x ... x ]
// * ...
// * [   0     0  ... unit  x ... x ]
// For ease of use, the returned representation will be the NTT representation instead of the original representation
// reviewed by Alice, 2024.06.18
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

// expandPubVectorA expand vector from specified seed
// the length of vector would be  PublicParameter.paramLA
// the origin vector would look like the following:
// unit = [1,0,...,0] in S_{q_a}^{d_a}
// 0 is zero element in  S_{q_a}^{d_a}
// x is random element in S_{q_a}^{d_a}
// *         PublicParameter.paramKA+1
// *                |
// *                v
// * [ 0 0  ... 0 unit  x ... x ]
// For ease of use, the returned representation will be the NTT representation instead of the original representation
// reviewed by Alice, 2024.06.18
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

// expandPubMatrixB expand matrix from specified seed
// the matrix would be PublicParameter.paramKC * PublicParameter.paramLC
// the origin matrix would look like the following:
// unit = [1,0,...,0] in S_{q_c}^{d_c}
// 0 is zero element in  S_{q_c}^{d_c}
// y is random element in S_{q_c}^{d_c}
// *          PublicParameter.paramKC
// *                    |
// *                    v
// * [ unit    0  ...   0   y ... y ]
// * [   0   unit ...   0   y ... y ]
// * ...
// * [   0     0  ... unit  y ... y ]
// For ease of use, the returned representation will be the NTT representation instead of the original representation
// reviewed by Alice, 2024.06.18
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
	matrixBp, err := pp.generatePolyCNTTMatrix(seedUsed, pp.paramKC, int(pp.paramI)+int(pp.paramJ)+7+pp.paramLambdaC)
	if err != nil {
		return nil, err
	}

	for i := 0; i < pp.paramKC; i++ {
		res[i] = pp.NewZeroPolyCNTTVec(pp.paramLC)

		//for t := 0; t < pp.paramDC; t++ {
		//	res[i].polyCNTTs[i].coeffs[t] = unitNTT.coeffs[t]
		//}
		copy(res[i].polyCNTTs[i].coeffs, unitNTT.coeffs)

		for j := 0; j < int(pp.paramI)+int(pp.paramJ)+7+pp.paramLambdaC; j++ {
			res[i].polyCNTTs[pp.paramKC+j] = matrixBp[i].polyCNTTs[j]
		}

	}

	return res, nil
}

// expandPubMatrixH expand matrix from specified seed
// the matrix would be (PublicParameter.paramI + PublicParameter.paramJ + 7) * PublicParameter.paramLC
// the origin matrix would look like the following:
// unit = [1,0,...,0] in S_{q_c}^{d_c}
// 0 is zero element in  S_{q_c}^{d_c}
// y is random element in S_{q_c}^{d_c}
// *    PublicParameter.paramKC + PublicParameter.paramI + PublicParameter.paramJ + 7
// *    PublicParameter.paramKC       |
// *                |                 |
// *                v                 v
// * [   0  0  ...  0 unit   0  ...   0    y ... y ]		h
// * [   0  0  ...  0   0  unit ...   0    y ... y ]		h_1
// * ...
// * [   0  0  ...  0   0    0  ... unit   y ... y ]		h_{Imax+Jmax+6}
// For ease of use, the returned representation will be the NTT representation instead of the original representation
// reviewed by Alice, 2024.06.18
func (pp *PublicParameter) expandPubMatrixH(seed []byte) (matrixH []*PolyCNTTVec, err error) {
	if len(seed) == 0 {
		return nil, errors.New("expandPubMatrixH: the seed is empty")
	}
	seedUsed := append([]byte("MatrixH"), seed...)

	res := make([]*PolyCNTTVec, int(pp.paramI)+int(pp.paramJ)+7)

	unitPoly := pp.NewZeroPolyC()
	unitPoly.coeffs[0] = 1
	unitNTT := pp.NTTPolyC(unitPoly)

	// generate the right sub-matrix H'
	matrixHp, err := pp.generatePolyCNTTMatrix(seedUsed, int(pp.paramI)+int(pp.paramJ)+7, pp.paramLambdaC)
	if err != nil {
		return nil, err
	}

	for i := 0; i < int(pp.paramI)+int(pp.paramJ)+7; i++ {
		res[i] = pp.NewZeroPolyCNTTVec(pp.paramLC) // L_c=K_c+I+J+7+lambda_c

		//for t := 0; t < pp.paramDC; t++ {
		//	res[i].polyCNTTs[pp.paramKC+i].coeffs[t] = unitNTT.coeffs[t]
		//}
		copy(res[i].polyCNTTs[pp.paramKC+i].coeffs, unitNTT.coeffs)

		for j := 0; j < pp.paramLambdaC; j++ {
			res[i].polyCNTTs[pp.paramKC+int(pp.paramI)+int(pp.paramJ)+7+j] = matrixHp[i].polyCNTTs[j]
		}
	}

	return res, nil
}

// Initialize is the init function, it must be called explicitly when using this package
// reviewed by Alice, 2024.06.18
func Initialize(parameterSeedString []byte) *PublicParameter {
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
		100, // todo(MLP): todo
		50,  // todo(MLP): todo
		100, // todo(MLP): todo
		128, // todo(MLP): todo
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
		parameterSeedString,
		//[]byte("Welcome to Post Quantum World!")
		&pqringctxkem.ParamKem{
			Version: pqringctxkem.KEM_OQS_KYBER,
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

// GetParamSeedBytesLen
// reviewed by Alice, 2024.06.18
func (pp *PublicParameter) GetParamSeedBytesLen() int {
	return pp.paramKeyGenSeedBytesLen
}

// GetParamKeyGenPublicRandBytesLen returns ParamKeyGenPublicRandBytesLen
// reviewed on 2023.12.30
// reviewed by Alice, 2024.06.24
func (pp *PublicParameter) GetParamKeyGenPublicRandBytesLen() int {
	return pp.paramKeyGenPublicRandBytesLen
}

// GetParamMACKeyBytesLen returns ParamMACKeyBytesLen.
// reviewed on 2023.12.30
// reviewed by Alice, 2024.06.24
func (pp *PublicParameter) GetParamMACKeyBytesLen() int {
	return MACKeyBytesLen
}

// GetParamMACOutputBytesLen
// reviewed by Alice, 2024.06.18
func (pp *PublicParameter) GetParamMACOutputBytesLen() int {
	return MACOutputBytesLen
}

// GetTxInputMaxNumForRing returns the allowed maximum number of Inputs for Ring.
// reviewed on 2024.01.01, by Alice
// reviewed by Alice, 2024.06.18
func (pp *PublicParameter) GetTxInputMaxNumForRing() uint8 {
	return pp.paramI
}

// GetTxInputMaxNumForSingle returns the allowed maximum number of Inputs for Single.
// reviewed on 2024.01.01, by Alice
// reviewed by Alice, 2024.06.18
func (pp *PublicParameter) GetTxInputMaxNumForSingle() uint8 {
	return pp.paramISingle
}

// GetTxInputMaxNumForSingleDistinct returns the allowed maximum number of Inputs for Single with different coinAddresses.
// reviewed on 2024.01.01, by Alice
// reviewed by Alice, 2024.06.18
func (pp *PublicParameter) GetTxInputMaxNumForSingleDistinct() uint8 {
	return pp.paramISingleDistinct
}

// GetTxOutputMaxNumForRing returns the allowed maximum number of Outputs for Ring.
// reviewed on 2024.01.01, by Alice
// reviewed by Alice, 2024.06.18
func (pp *PublicParameter) GetTxOutputMaxNumForRing() uint8 {
	return pp.paramJ
}

// GetTxOutputMaxNumForSingle returns the allowed maximum number of Outputs for Single.
// reviewed on 2024.01.01, by Alice
// reviewed by Alice, 2024.06.18
func (pp *PublicParameter) GetTxOutputMaxNumForSingle() uint8 {
	return pp.paramJSingle
}
