package pqringctx

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

// ElrSignatureMLP defines the data structure for ELRSSignature.
// refactored and reviewed by Alice, 2024.07.02
// todo: review by 2024.07
type ElrSignatureMLP struct {
	ringSize uint8    // to be self-contained, give the explicit size
	seeds    [][]byte //	length ringSize, each (seed[]) for a ring member.
	//	z_as, as the responses, need to have the infinite norm in a scope, say [-(eta_a - beta_a), (eta_a - beta_a)].
	//	z_cs, z_cps, as the responses, need to have the infinite norm in a scope, say [-(eta_c - beta_c), (eta_c - beta_c)].
	//	That is why we use PolyAVec (resp. PolyCVec), rather than PolyANTTVec (resp. PolyCNTTVec).
	z_as  []*PolyAVec   // length ringSize, each for a ring member. Each element lies in (S_{eta_a - beta_a})^{L_a}.
	z_cs  [][]*PolyCVec // length ringSize, each length paramK. Each element lies (S_{eta_c - beta_c})^{L_c}.
	z_cps [][]*PolyCVec // length ringSize, each length paramK. Each element lies (S_{eta_c - beta_c})^{L_c}.
}

// SimpleSignatureMLP defines the data structure for SimpleSignature.
// reviewed by Alice, 2024.06.30
type SimpleSignatureMLP struct {
	seed_ch []byte
	//	z, as the responses, need to have the infinite normal ina scope, say [-(eta_a - beta_a), (eta_a - beta_a)].
	//	That is why we use PolyAVec, rather than PolyANTTVec.
	z *PolyAVec // lies in (S_{eta_a - beta_a})^{L_a}.

}

// elr Signature	begin

// elrSignatureMLPSign generates ElrSignatureMLP.
// Note that this is the same as pqringct.elrsSign.
// reviewed on 2023.12.15
// reviewed by Alice, 2024.07.01
func (pp *PublicParameter) elrSignatureMLPSign(
	lgrTxoList []*LgrTxoMLP, ma_p *PolyANTT, cmt_p *ValueCommitment, extTrTxCon []byte,
	sindex uint8, sa *PolyANTTVec, rc *PolyCNTTVec, rc_p *PolyCNTTVec) (*ElrSignatureMLP, error) {

	var err error

	// sanity-checks	begin
	if !pp.LgrTxoRingSanityCheck(lgrTxoList) {
		return nil, fmt.Errorf("elrsMLPSign: the input lgrTxoList is not well-form")
	}
	ringLen := uint8(len(lgrTxoList)) // well-form lgrTxoList has a valid length in scope uint8

	if !pp.PolyANTTSanityCheck(ma_p) {
		return nil, fmt.Errorf("elrsMLPSign: The input ma_p is not well-form")
	}

	if !pp.ValueCommitmentSanityCheck(cmt_p) {
		return nil, fmt.Errorf("elrsMLPSign: The input cmt_p is not well-form")
	}

	if len(extTrTxCon) == 0 {
		return nil, fmt.Errorf("elrsMLPSign: The input extTrTxCon is not well-form")
	}

	if sindex >= ringLen {
		return nil, fmt.Errorf("elrsMLPSign: The input signer index is not in the scope")
	}

	//	sa is the NTT form of a well-form AddressSecretKeySp
	askSp, err := pp.newAddressSecretKeySpFromPolyANTTVec(sa)
	if err != nil {
		return nil, err
	}

	//	rc is the NTT form of a well-form randomness for value-commitment
	if !pp.ValueCommitmentRandomnessNTTSanityCheck(rc) {
		return nil, fmt.Errorf("elrsMLPSign: The input rc is not well-form")
	}

	//	rc_p is the NTT form of a well-form randomness for value-commitment
	if !pp.ValueCommitmentRandomnessNTTSanityCheck(rc_p) {
		return nil, fmt.Errorf("elrsMLPSign: The input rc_p is not well-form")
	}

	// Note that the committed message m is not used in the sign signature so that it is not included in the input parameter.
	// As a result, here the sanity-check does not check whether (lgrTxoList[sindex].txo.cmt, rc, m) (cmt_p, rc_p, m) form valid openings.

	//	For address part, we can check whether the input sa and computed ma forms a valid secret key for the coin to spend.
	m_r, err := pp.expandKIDRMLP(lgrTxoList[sindex])
	if err != nil {
		return nil, err
	}

	m_a := pp.PolyANTTSub(ma_p, m_r)
	askSn, err := pp.newAddressSecretKeySnFromPolyANTT(m_a)
	if err != nil {
		return nil, err
	}

	ask := &AddressSecretKeyForRing{
		AddressSecretKeySp: askSp,
		AddressSecretKeySn: askSn,
	}

	// lgrTxoList[sindex].txo.addressPublicKeyForRing.t
	// lgrTxoList[sindex].txo.addressPublicKeyForRing.e
	var t_jbar *PolyANTTVec
	var e_jbar *PolyANTT
	switch txoToSpend := lgrTxoList[sindex].txo.(type) {
	case *TxoRCTPre:
		t_jbar = txoToSpend.addressPublicKeyForRing.t
		e_jbar = txoToSpend.addressPublicKeyForRing.e
	case *TxoRCT:
		t_jbar = txoToSpend.addressPublicKeyForRing.t
		e_jbar = txoToSpend.addressPublicKeyForRing.e
	default:
		return nil, fmt.Errorf("elrsMLPSign: lgrTxoList[%d].txo is not TxoRCTPre or TxoRCT", sindex)
	}
	apk := &AddressPublicKeyForRing{
		t: t_jbar,
		e: e_jbar,
	}

	validAddressKey, hints := pp.addressKeyForRingVerify(apk, ask)
	if !validAddressKey {
		return nil, fmt.Errorf("elrsMLPSign: lgrTxoList[%d].txo's address and the input (sa, ma) does not match: %v", sindex, hints)
	}
	// sanity-checks	end

	seeds := make([][]byte, ringLen)
	z_as_ntt := make([]*PolyANTTVec, ringLen)
	z_as := make([]*PolyAVec, ringLen)

	w_as := make([]*PolyANTTVec, ringLen)
	delta_as := make([]*PolyANTT, ringLen)

	z_cs_ntt := make([][]*PolyCNTTVec, ringLen)
	z_cps_ntt := make([][]*PolyCNTTVec, ringLen)
	z_cs := make([][]*PolyCVec, ringLen)
	z_cps := make([][]*PolyCVec, ringLen)

	w_cs := make([][]*PolyCNTTVec, ringLen)
	w_cps := make([][]*PolyCNTTVec, ringLen)
	delta_cs := make([][]*PolyCNTT, ringLen)

	for j := uint8(0); j < ringLen; j++ {
		if j == sindex {
			continue
		}
		seeds[j] = RandomBytes(HashOutputBytesLen) // we use Hash to generate seed for challenge

		tmpA, err := pp.expandChallengeA(seeds[j])
		if err != nil {
			return nil, err
		}
		da := pp.NTTPolyA(tmpA)

		tmpC, err := pp.expandChallengeC(seeds[j])
		if err != nil {
			return nil, err
		}
		dc := pp.NTTPolyC(tmpC)

		// sample randomness for z_a_j
		z_as[j], err = pp.sampleResponseA()
		if err != nil {
			return nil, err
		}
		z_as_ntt[j] = pp.NTTPolyAVec(z_as[j])

		// lgrTxoList[j].txo.addressPublicKeyForRing.t
		// lgrTxoList[j].txo.addressPublicKeyForRing.e
		var t_j *PolyANTTVec
		var e_j *PolyANTT
		var b_j *PolyCNTTVec
		var c_j *PolyCNTT
		switch txoInst := lgrTxoList[j].txo.(type) {
		case *TxoRCTPre:
			t_j = txoInst.addressPublicKeyForRing.t
			e_j = txoInst.addressPublicKeyForRing.e
			b_j = txoInst.valueCommitment.b
			c_j = txoInst.valueCommitment.c
		case *TxoRCT:
			t_j = txoInst.addressPublicKeyForRing.t
			e_j = txoInst.addressPublicKeyForRing.e
			b_j = txoInst.valueCommitment.b
			c_j = txoInst.valueCommitment.c
		case *TxoSDN:
			return nil, fmt.Errorf("elrsMLPSign: lgrTxoList[%d].txo is a TxoSDN", j)
		default:
			return nil, fmt.Errorf("elrsMLPSign: lgrTxoList[%d].txo is not TxoRCTPre, TxoRCT, or TxoSDN", j)
		}
		// w_a_j = A*z_a_j - d_a_j*t_j
		w_as[j] = pp.PolyANTTVecSub(
			pp.PolyANTTMatrixMulVector(pp.paramMatrixA, z_as_ntt[j], pp.paramKA, pp.paramLA),
			pp.PolyANTTVecScaleMul(da, t_j, pp.paramKA),
			pp.paramKA,
		)
		// delta_a_j = <a,z_a_j> - d_a_j * (e_j + expandKIDR(txo[j]) - m_a_p)
		lgrTxoH, err := pp.expandKIDRMLP(lgrTxoList[j])
		if err != nil {
			return nil, err
		}
		delta_as[j] = pp.PolyANTTSub(
			pp.PolyANTTVecInnerProduct(pp.paramVectorA, z_as_ntt[j], pp.paramLA),
			pp.PolyANTTMul(
				da,
				pp.PolyANTTSub(
					pp.PolyANTTAdd(
						e_j,
						lgrTxoH,
					),
					ma_p,
				),
			),
		)

		z_cs_ntt[j] = make([]*PolyCNTTVec, pp.paramK)
		z_cps_ntt[j] = make([]*PolyCNTTVec, pp.paramK)
		z_cs[j] = make([]*PolyCVec, pp.paramK)
		z_cps[j] = make([]*PolyCVec, pp.paramK)

		w_cs[j] = make([]*PolyCNTTVec, pp.paramK)
		w_cps[j] = make([]*PolyCNTTVec, pp.paramK)

		delta_cs[j] = make([]*PolyCNTT, pp.paramK)
		for tao := 0; tao < pp.paramK; tao++ {
			z_cs[j][tao], err = pp.sampleResponseC()
			if err != nil {
				return nil, err
			}
			z_cps[j][tao], err = pp.sampleResponseC()
			if err != nil {
				return nil, err
			}

			z_cs_ntt[j][tao] = pp.NTTPolyCVec(z_cs[j][tao])
			z_cps_ntt[j][tao] = pp.NTTPolyCVec(z_cps[j][tao])
			sigmataodc := pp.sigmaPowerPolyCNTT(dc, tao)
			w_cs[j][tao] = pp.PolyCNTTVecSub(
				pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, z_cs_ntt[j][tao], pp.paramKC, pp.paramLC),
				pp.PolyCNTTVecScaleMul(
					sigmataodc,
					b_j,
					pp.paramKC,
				),
				pp.paramKC,
			)
			w_cps[j][tao] = pp.PolyCNTTVecSub(
				pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, z_cps_ntt[j][tao], pp.paramKC, pp.paramLC),
				pp.PolyCNTTVecScaleMul(
					sigmataodc,
					cmt_p.b,
					pp.paramKC,
				),
				pp.paramKC,
			)
			delta_cs[j][tao] = pp.PolyCNTTSub(
				pp.PolyCNTTVecInnerProduct(
					pp.paramMatrixH[0],
					pp.PolyCNTTVecSub(z_cs_ntt[j][tao], z_cps_ntt[j][tao], pp.paramLC),
					pp.paramLC,
				),
				pp.PolyCNTTMul(
					sigmataodc,
					pp.PolyCNTTSub(c_j, cmt_p.c),
				),
			)
		}
	}

	z_cs_ntt[sindex] = make([]*PolyCNTTVec, pp.paramK)
	z_cps_ntt[sindex] = make([]*PolyCNTTVec, pp.paramK)
	z_cs[sindex] = make([]*PolyCVec, pp.paramK)
	z_cps[sindex] = make([]*PolyCVec, pp.paramK)

	w_cs[sindex] = make([]*PolyCNTTVec, pp.paramK)
	w_cps[sindex] = make([]*PolyCNTTVec, pp.paramK)
	delta_cs[sindex] = make([]*PolyCNTT, pp.paramK)

elrSignatureMLPSignRestart:
	// randomness y_a_j_bar
	tmpYa, err := pp.sampleMaskingVecA()
	if err != nil {
		return nil, err
	}
	y_a := pp.NTTPolyAVec(tmpYa)
	w_as[sindex] = pp.PolyANTTMatrixMulVector(pp.paramMatrixA, y_a, pp.paramKA, pp.paramLA)
	delta_as[sindex] = pp.PolyANTTVecInnerProduct(pp.paramVectorA, y_a, pp.paramLA)

	y_cs := make([]*PolyCNTTVec, pp.paramK)
	y_cps := make([]*PolyCNTTVec, pp.paramK)

	for tao := 0; tao < pp.paramK; tao++ {
		tmpYc, err := pp.sampleMaskingVecC()
		if err != nil {
			return nil, err
		}
		tmpYcp, err := pp.sampleMaskingVecC()
		if err != nil {
			return nil, err
		}

		y_cs[tao] = pp.NTTPolyCVec(tmpYc)
		y_cps[tao] = pp.NTTPolyCVec(tmpYcp)
		w_cs[sindex][tao] = pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, y_cs[tao], pp.paramKC, pp.paramLC)
		w_cps[sindex][tao] = pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, y_cps[tao], pp.paramKC, pp.paramLC)
		delta_cs[sindex][tao] = pp.PolyCNTTVecInnerProduct(
			pp.paramMatrixH[0],
			pp.PolyCNTTVecSub(y_cs[tao], y_cps[tao], pp.paramLC),
			pp.paramLC,
		)
	}

	preMsg, err := pp.collectBytesForElrSignatureMLPChallenge(lgrTxoList, ma_p, cmt_p, extTrTxCon, w_as, delta_as, w_cs, w_cps, delta_cs)
	if err != nil {
		return nil, err
	}
	seed_ch, err := Hash(preMsg)
	if err != nil {
		return nil, err
	}
	/*	seeds[sindex] = make([]byte, len(seed_ch))
		for i := 0; i < len(seed_ch); i++ {
			seeds[sindex][i] = seed_ch[i]
		}*/
	seeds[sindex] = seed_ch
	seedByteLen := len(seed_ch)
	for j := uint8(0); j < ringLen; j++ {
		if j == sindex {
			continue
		}
		for i := 0; i < seedByteLen; i++ {
			seeds[sindex][i] ^= seeds[j][i]
		}
	}

	tmpA, err := pp.expandChallengeA(seeds[sindex])
	if err != nil {
		return nil, err
	}
	tmpC, err := pp.expandChallengeC(seeds[sindex])
	if err != nil {
		return nil, err
	}
	dA := pp.NTTPolyA(tmpA)
	dC := pp.NTTPolyC(tmpC)

	z_as_ntt[sindex] = pp.PolyANTTVecAdd(y_a, pp.PolyANTTVecScaleMul(dA, sa, pp.paramLA), pp.paramLA)
	z_as[sindex] = pp.NTTInvPolyAVec(z_as_ntt[sindex])

	for tao := 0; tao < pp.paramK; tao++ {
		sigmaTaoDc := pp.sigmaPowerPolyCNTT(dC, tao)
		z_cs_ntt[sindex][tao] = pp.PolyCNTTVecAdd(
			y_cs[tao],
			pp.PolyCNTTVecScaleMul(sigmaTaoDc, rc, pp.paramLC),
			pp.paramLC,
		)
		z_cps_ntt[sindex][tao] = pp.PolyCNTTVecAdd(
			y_cps[tao],
			pp.PolyCNTTVecScaleMul(sigmaTaoDc, rc_p, pp.paramLC),
			pp.paramLC,
		)

		z_cs[sindex][tao] = pp.NTTInvPolyCVec(z_cs_ntt[sindex][tao])
		z_cps[sindex][tao] = pp.NTTInvPolyCVec(z_cps_ntt[sindex][tao])
	}

	// This line code is put here, rather than earlier before the computation of (z_cs, z_cps), is to defend against time-based side-channel.
	if z_as[sindex].infNorm() > pp.paramEtaA-int64(pp.paramBetaA) {
		goto elrSignatureMLPSignRestart
	}

	boundC := pp.paramEtaC - int64(pp.paramBetaC)
	for tao := 0; tao < pp.paramK; tao++ {
		if (z_cs[sindex][tao].infNorm() > boundC) || (z_cps[sindex][tao].infNorm() > boundC) {
			goto elrSignatureMLPSignRestart
		}
		//if z_cps[sindex][tao].infNorm() > boundC {
		//	goto ELRSSignRestart
		//}
	}

	return &ElrSignatureMLP{
		ringSize: ringLen,
		seeds:    seeds,
		z_as:     z_as,
		z_cs:     z_cs,
		z_cps:    z_cps,
	}, nil
}

// collectBytesForElrSignatureMLPChallenge collect preMsg in elrSignatureMLPSign, for the Fiat-Shamir transform.
// Note that this is almost the same as pqringct.collectBytesForElrsChallenge.
// todo_DONE: the paper is not accurate, use the following params
// refactored and reviewed by Alice, 2024.07.01
// todo: concat the system parameters
func (pp *PublicParameter) collectBytesForElrSignatureMLPChallenge(
	lgrTxoList []*LgrTxoMLP, ma_p *PolyANTT, cmt_p *ValueCommitment,
	extTrTxCon []byte,
	w_as []*PolyANTTVec, delta_as []*PolyANTT,
	w_cs [][]*PolyCNTTVec, w_cps [][]*PolyCNTTVec, delta_cs [][]*PolyCNTT) ([]byte, error) {

	length := len(pp.paramParameterSeedString) // crs
	// lgxTxoList []*LgrTxoMLP
	for j := 0; j < len(lgrTxoList); j++ {
		lgrTxoLen, err := pp.lgrTxoMLPSerializeSize(lgrTxoList[j])
		if err != nil {
			return nil, err
		}
		length = length + lgrTxoLen
	}

	length = length + //	crs + lgxTxoList []*LgrTxoMLP
		pp.paramDA*8 + //	ma_p *PolyANTT
		(pp.paramKC+1)*pp.paramDC*8 + //	cmt_p *ValueCommitment
		len(extTrTxCon) + //	extTrTxCon []byte
		len(lgrTxoList)*(pp.paramKA+1)*pp.paramDA*8 + //	w_as []*PolyANTTVec, delta_as []*PolyANTT,
		len(lgrTxoList)*pp.paramK*(pp.paramKC*2+1)*pp.paramDC*8 //	w_cs [][]*PolyCNTTVec, w_cps [][]*PolyCNTTVec, delta_cs [][]*PolyCNTT

	rst := make([]byte, 0, length)

	appendPolyANTTToBytes := func(a *PolyANTT) {
		for k := 0; k < pp.paramDA; k++ {
			rst = append(rst, byte(a.coeffs[k]>>0))
			rst = append(rst, byte(a.coeffs[k]>>8))
			rst = append(rst, byte(a.coeffs[k]>>16))
			rst = append(rst, byte(a.coeffs[k]>>24))
			rst = append(rst, byte(a.coeffs[k]>>32))
			rst = append(rst, byte(a.coeffs[k]>>40))
			rst = append(rst, byte(a.coeffs[k]>>48))
			rst = append(rst, byte(a.coeffs[k]>>56))

		}
	}

	appendPolyCNTTToBytes := func(a *PolyCNTT) {
		for k := 0; k < pp.paramDC; k++ {
			rst = append(rst, byte(a.coeffs[k]>>0))
			rst = append(rst, byte(a.coeffs[k]>>8))
			rst = append(rst, byte(a.coeffs[k]>>16))
			rst = append(rst, byte(a.coeffs[k]>>24))
			rst = append(rst, byte(a.coeffs[k]>>32))
			rst = append(rst, byte(a.coeffs[k]>>40))
			rst = append(rst, byte(a.coeffs[k]>>48))
			rst = append(rst, byte(a.coeffs[k]>>56))
		}
	}

	//	crs
	rst = append(rst, pp.paramParameterSeedString...)

	// lgrTxoList
	for i := 0; i < len(lgrTxoList); i++ {
		serializeLgrTxo, err := pp.SerializeLgrTxoMLP(lgrTxoList[i])
		if err != nil {
			//log.Fatalln("error for pp.SerializeLgrTxo()")
			return nil, err
		}
		rst = append(rst, serializeLgrTxo...)
		//_, err = w.Write(serializeLgrTxo)
		//if err != nil {
		//	//log.Fatalln("error for w.Write()")
		//	return nil, err
		//}
	}

	// ma_p *PolyANTT
	appendPolyANTTToBytes(ma_p)

	// cmt_p *ValueCommitment
	for i := 0; i < len(cmt_p.b.polyCNTTs); i++ {
		appendPolyCNTTToBytes(cmt_p.b.polyCNTTs[i])
	}
	appendPolyCNTTToBytes(cmt_p.c)

	// msg
	rst = append(rst, extTrTxCon...)

	// w_as []*PolyANTTVec
	for i := 0; i < len(w_as); i++ {
		for j := 0; j < len(w_as[i].polyANTTs); j++ {
			appendPolyANTTToBytes(w_as[i].polyANTTs[j])
		}
	}
	// delta_as []*PolyANTT
	for i := 0; i < len(delta_as); i++ {
		appendPolyANTTToBytes(delta_as[i])
	}

	// w_cs [][]*PolyCNTTVec
	for i := 0; i < len(w_cs); i++ {
		for j := 0; j < len(w_cs[i]); j++ {
			for k := 0; k < len(w_cs[i][j].polyCNTTs); k++ {
				appendPolyCNTTToBytes(w_cs[i][j].polyCNTTs[k])
			}
		}
	}
	// w_cps [][]*PolyCNTTVec
	for i := 0; i < len(w_cps); i++ {
		for j := 0; j < len(w_cps[i]); j++ {
			for k := 0; k < len(w_cps[i][j].polyCNTTs); k++ {
				appendPolyCNTTToBytes(w_cps[i][j].polyCNTTs[k])
			}
		}
	}
	// delta_cs [][]*PolyCNTT
	for i := 0; i < len(delta_cs); i++ {
		for j := 0; j < len(delta_cs[i]); j++ {
			appendPolyCNTTToBytes(delta_cs[i][j])
		}
	}

	return rst, nil
}

// elrSignatureMLPVerify() verify the validity of a given (message, signature) pair.
// reviewed by Alice, 2024.07.02
func (pp *PublicParameter) elrSignatureMLPVerify(lgrTxoList []*LgrTxoMLP, ma_p *PolyANTT, cmt_p *ValueCommitment, extTrTxCon []byte, sig *ElrSignatureMLP) error {

	if !pp.LgrTxoRingSanityCheck(lgrTxoList) {
		return fmt.Errorf("elrSignatureMLPVerify: the input lgrTxoList []*LgrTxoMLP is not well-form")
	}
	ringLen := uint8(len(lgrTxoList)) // well-form LgrTxoRing has a valid length in scope uint8

	if !pp.PolyANTTSanityCheck(ma_p) {
		return fmt.Errorf("elrSignatureMLPVerify: the input ma_p *PolyANTT is not well-form")
	}

	if !pp.ValueCommitmentSanityCheck(cmt_p) {
		return fmt.Errorf("elrSignatureMLPVerify: the input cmt_p *ValueCommitment is not well-form")
	}

	if len(extTrTxCon) == 0 {
		return fmt.Errorf("elrSignatureMLPVerify: the input extTrTxCon []byte is not well-form")
	}

	if !pp.ElrSignatureMLPSanityCheck(sig) {
		return fmt.Errorf("elrSignatureMLPVerify: the input sig *ElrSignatureMLP is not well-form")
	}

	if ringLen != sig.ringSize {
		return fmt.Errorf("elrSignatureMLPVerify: the length/ringsSize of the input (lgrTxoList []*LgrTxoMLP, sig *ElrSignatureMLP) does not match")
	}

	w_as := make([]*PolyANTTVec, ringLen)
	delta_as := make([]*PolyANTT, ringLen)

	w_cs := make([][]*PolyCNTTVec, ringLen)
	w_cps := make([][]*PolyCNTTVec, ringLen)
	delta_cs := make([][]*PolyCNTT, ringLen)
	for j := uint8(0); j < ringLen; j++ {
		tmpDA, err := pp.expandChallengeA(sig.seeds[j])
		if err != nil {
			return err
		}
		da := pp.NTTPolyA(tmpDA)

		tmpDC, err := pp.expandChallengeC(sig.seeds[j])
		if err != nil {
			return err
		}
		dc := pp.NTTPolyC(tmpDC)

		// lgrTxoList[j].txo.addressPublicKeyForRing.t
		// lgrTxoList[j].txo.addressPublicKeyForRing.e
		var t_j *PolyANTTVec
		var e_j *PolyANTT
		var b_j *PolyCNTTVec
		var c_j *PolyCNTT
		switch txoInst := lgrTxoList[j].txo.(type) {
		case *TxoRCTPre:
			t_j = txoInst.addressPublicKeyForRing.t
			e_j = txoInst.addressPublicKeyForRing.e
			b_j = txoInst.valueCommitment.b
			c_j = txoInst.valueCommitment.c
		case *TxoRCT:
			t_j = txoInst.addressPublicKeyForRing.t
			e_j = txoInst.addressPublicKeyForRing.e
			b_j = txoInst.valueCommitment.b
			c_j = txoInst.valueCommitment.c
		case *TxoSDN:
			return fmt.Errorf("elrSignatureMLPVerify: lgrTxoList[%d].txo is a TxoSDN", j)
		default:
			return fmt.Errorf("elrSignatureMLPVerify: lgrTxoList[%d].txo is not TxoRCTPre, TxoRCT, or TxoSDN", j)
		}

		z_a_ntt := pp.NTTPolyAVec(sig.z_as[j])
		// w_a_j = A*z_a_j - d_a_j*t_j
		w_as[j] = pp.PolyANTTVecSub(
			pp.PolyANTTMatrixMulVector(pp.paramMatrixA, z_a_ntt, pp.paramKA, pp.paramLA),
			pp.PolyANTTVecScaleMul(da, t_j, pp.paramKA),
			pp.paramKA,
		)
		// theta_a_j = <a,z_a_j> - d_a_j * (e_j + expandKIDR(txo[j]) - m_a_p)
		lgrTxoH, err := pp.expandKIDRMLP(lgrTxoList[j])
		if err != nil {
			return err
		}
		delta_as[j] = pp.PolyANTTSub(
			pp.PolyANTTVecInnerProduct(pp.paramVectorA, z_a_ntt, pp.paramLA),
			pp.PolyANTTMul(
				da,
				pp.PolyANTTSub(
					pp.PolyANTTAdd(
						e_j,
						lgrTxoH,
					),
					ma_p,
				),
			),
		)

		w_cs[j] = make([]*PolyCNTTVec, pp.paramK)
		w_cps[j] = make([]*PolyCNTTVec, pp.paramK)
		delta_cs[j] = make([]*PolyCNTT, pp.paramK)
		for tao := 0; tao < pp.paramK; tao++ {
			z_c_ntt := pp.NTTPolyCVec(sig.z_cs[j][tao])
			z_cp_ntt := pp.NTTPolyCVec(sig.z_cps[j][tao])
			sigmataodc := pp.sigmaPowerPolyCNTT(dc, tao)

			w_cs[j][tao] = pp.PolyCNTTVecSub(
				pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, z_c_ntt, pp.paramKC, pp.paramLC),
				pp.PolyCNTTVecScaleMul(
					sigmataodc,
					b_j,
					pp.paramKC,
				),
				pp.paramKC,
			)
			w_cps[j][tao] = pp.PolyCNTTVecSub(
				pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, z_cp_ntt, pp.paramKC, pp.paramLC),
				pp.PolyCNTTVecScaleMul(
					sigmataodc,
					cmt_p.b,
					pp.paramKC,
				),
				pp.paramKC,
			)
			delta_cs[j][tao] = pp.PolyCNTTSub(
				pp.PolyCNTTVecInnerProduct(
					pp.paramMatrixH[0],
					pp.PolyCNTTVecSub(z_c_ntt, z_cp_ntt, pp.paramLC),
					pp.paramLC,
				),
				pp.PolyCNTTMul(
					sigmataodc,
					pp.PolyCNTTSub(c_j, cmt_p.c),
				),
			)
		}
	}

	preMsg, err := pp.collectBytesForElrSignatureMLPChallenge(lgrTxoList, ma_p, cmt_p, extTrTxCon, w_as, delta_as, w_cs, w_cps, delta_cs)
	if err != nil {
		return err
	}
	seed_ch, err := Hash(preMsg)
	if err != nil {
		return err
	}

	seedByteLen := len(seed_ch)
	for j := uint8(0); j < ringLen; j++ {
		for i := 0; i < len(seed_ch); i++ {
			seed_ch[i] ^= sig.seeds[j][i]
		}
	}
	for i := 0; i < seedByteLen; i++ {
		if seed_ch[i] != 0 {
			return fmt.Errorf("elrSignatureMLPVerify: the computed final seed_ch's %d position is not as expected", i)
		}
	}

	return nil
}

// elrSignatureMLPSerializeSize returns the serialize size for a ElrSignatureMLP with the input ringSize.
// reviewed on 2023.12.19
// reviewed by Alice, 2024.07.02
func (pp *PublicParameter) elrSignatureMLPSerializeSize(ringSize uint8) int {
	length := 1 + //	for the ringSize
		int(ringSize)*HashOutputBytesLen + //	seeds [][]byte
		int(ringSize)*pp.PolyAVecSerializeSizeEtaByVecLen(pp.paramLA) + //	z_as  []*PolyAVec
		int(ringSize)*pp.paramK*pp.PolyCVecSerializeSizeEtaByVecLen(pp.paramLC)*2 //	z_cs  [][]*PolyCVec, z_cps [][]*PolyCVec
	return length
}

// serializeElrSignatureMLP serializes the input ElrSignatureMLP into []byte.
// reviewed on 2023.12.19
// reviewed by Alice, 2024.07.02
func (pp *PublicParameter) serializeElrSignatureMLP(sig *ElrSignatureMLP) ([]byte, error) {

	if !pp.ElrSignatureMLPSanityCheck(sig) {
		return nil, fmt.Errorf("serializeElrSignatureMLP: the input sig *ElrSignatureMLP is not well-form")
	}

	ringSize := sig.ringSize

	length := pp.elrSignatureMLPSerializeSize(ringSize)
	w := bytes.NewBuffer(make([]byte, 0, length))

	//	ringSize
	err := w.WriteByte(ringSize)

	// seeds [][]byte
	for i := uint8(0); i < ringSize; i++ {
		_, err = w.Write(sig.seeds[i])
		if err != nil {
			return nil, err
		}
	}

	// z_as  []*PolyAVec eta
	for i := uint8(0); i < ringSize; i++ {
		err = pp.writePolyAVecEta(w, sig.z_as[i])
		if err != nil {
			return nil, err
		}
	}

	// z_cs  [][]*PolyCVec eta
	for i := uint8(0); i < ringSize; i++ {
		for t := 0; t < pp.paramK; t++ {
			err = pp.writePolyCVecEta(w, sig.z_cs[i][t])
			if err != nil {
				return nil, err
			}
		}
	}

	// z_cps [][]*PolyCVec eta
	for i := uint8(0); i < ringSize; i++ {
		for t := 0; t < pp.paramK; t++ {
			err = pp.writePolyCVecEta(w, sig.z_cps[i][t])
			if err != nil {
				return nil, err
			}
		}
	}

	return w.Bytes(), nil
}

// deserializeElrSignatureMLP deserialize the input []byte to an ElrSignatureMLP.
// reviewed on 2023.12.19
// reviewed by Alice, 2024.07.02
func (pp *PublicParameter) deserializeElrSignatureMLP(serializedSig []byte) (*ElrSignatureMLP, error) {
	if len(serializedSig) == 0 {
		return nil, fmt.Errorf("deserializeElrSignatureMLP: the input serializedSig is nil/empty")
	}

	r := bytes.NewReader(serializedSig)

	ringSize, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	seeds := make([][]byte, ringSize)      //	seeds [][]byte
	z_as := make([]*PolyAVec, ringSize)    //	z_as  []*PolyAVec
	z_cs := make([][]*PolyCVec, ringSize)  //	z_cs  [][]*PolyCVec
	z_cps := make([][]*PolyCVec, ringSize) //	z_cps [][]*PolyCVec

	//	seeds [][]byte
	for i := uint8(0); i < ringSize; i++ {
		seeds[i] = make([]byte, HashOutputBytesLen)
		_, err = r.Read(seeds[i])
		if err != nil {
			return nil, err
		}
	}

	//	z_as  []*PolyAVec
	for i := uint8(0); i < ringSize; i++ {
		z_as[i], err = pp.readPolyAVecEta(r)
		if err != nil {
			return nil, err
		}
	}

	//	z_cs  [][]*PolyCVec
	for i := uint8(0); i < ringSize; i++ {
		z_cs[i] = make([]*PolyCVec, pp.paramK)
		for t := 0; t < pp.paramK; t++ {
			z_cs[i][t], err = pp.readPolyCVecEta(r)
		}
		if err != nil {
			return nil, err
		}
	}

	//	z_cps [][]*PolyCVec
	for i := uint8(0); i < ringSize; i++ {
		z_cps[i] = make([]*PolyCVec, pp.paramK)
		for t := 0; t < pp.paramK; t++ {
			z_cps[i][t], err = pp.readPolyCVecEta(r)
		}
		if err != nil {
			return nil, err
		}
	}

	return &ElrSignatureMLP{
		ringSize: ringSize,
		seeds:    seeds,
		z_as:     z_as,
		z_cs:     z_cs,
		z_cps:    z_cps,
	}, nil
}

//	elr Signature	end

// Simple Signature	begin

// simpleSignatureSign generates a simple signature for the input (t, extTrTxCon).
// The input t and s should satisfy t = A s.
// In this algorithm we do not check the sanity of (t) and (s),
// and will leave the sanity-check work (e.g., t != nil ) to the corresponding simpleSignatureVerify algorithm.
// reviewed on 2023.12.18
// refactored and reviewed by Alice, 2024.07.02
// todo: multi-round review
func (pp *PublicParameter) simpleSignatureSign(t *PolyANTTVec, extTrTxCon []byte,
	s *PolyANTTVec) (*SimpleSignatureMLP, error) {

	//	Sanity-checks 	begin
	if len(extTrTxCon) == 0 {
		return nil, fmt.Errorf("simpleSignatureSign: the input extTrTxCon is nil/empty")
	}

	askSp, err := pp.newAddressSecretKeySpFromPolyANTTVec(s)
	if err != nil {
		return nil, err
	}

	ask := &AddressSecretKeyForSingle{
		askSp,
	}

	apk := &AddressPublicKeyForSingle{
		t: t,
	}

	validAddressKey, hints := pp.addressKeyForSingleVerify(apk, ask)
	if !validAddressKey {
		return nil, fmt.Errorf("simpleSignatureSign: the input (t,s) does not match: %v", hints)
	}
	//	Sanity-checks 	end

simpleSignatureSignRestart:
	// randomness y
	tmpY, err := pp.sampleMaskingVecA()
	if err != nil {
		return nil, err
	}
	y := pp.NTTPolyAVec(tmpY)

	// w = A y
	w := pp.PolyANTTMatrixMulVector(pp.paramMatrixA, y, pp.paramKA, pp.paramLA)

	preMsg, err := pp.collectBytesForSimpleSignatureChallenge(t, extTrTxCon, w)
	if err != nil {
		return nil, err
	}
	seed_ch, err := Hash(preMsg)
	if err != nil {
		return nil, err
	}

	ch_poly, err := pp.expandChallengeA(seed_ch)
	if err != nil {
		return nil, err
	}
	ch := pp.NTTPolyA(ch_poly)

	//	z = y + d s
	z_ntt := pp.PolyANTTVecAdd(y, pp.PolyANTTVecScaleMul(ch, s, pp.paramLA), pp.paramLA)
	z := pp.NTTInvPolyAVec(z_ntt)

	if z.infNorm() > pp.paramEtaA-int64(pp.paramBetaA) {
		goto simpleSignatureSignRestart
	}

	return &SimpleSignatureMLP{
		seed_ch: seed_ch,
		z:       z,
	}, nil
}

// simpleSignatureVerify verifies SimpleSignatureMLP.
// reviewed on 2023.12.18
// refactored on 2024.01.07, using err == nil or not to denote valid or invalid
// todo: multi-round review
// refactored and reviewed by Alice, 2024.07.02
func (pp *PublicParameter) simpleSignatureVerify(t *PolyANTTVec, extTrTxCon []byte, sig *SimpleSignatureMLP) error {

	//	sanity-checks	begin
	if len(extTrTxCon) == 0 {
		return fmt.Errorf("simpleSignatureVerify: the input extTrTxCon is nil/empty")
	}

	apk := &AddressPublicKeyForSingle{
		t: t,
	}
	if !pp.AddressPublicKeyForSingleSanityCheck(apk) {
		return fmt.Errorf("simpleSignatureVerify: the input t *PolyANTTVec is not well-form")
	}

	if !pp.SimpleSignatureSanityCheck(sig) {
		return fmt.Errorf("simpleSignatureVerify: the input sig *SimpleSignatureMLP is not well-form")
	}
	//	sanity-checks	end

	ch_poly, err := pp.expandChallengeA(sig.seed_ch)
	if err != nil {
		return err
	}
	ch := pp.NTTPolyA(ch_poly)

	z_ntt := pp.NTTPolyAVec(sig.z)

	w := pp.PolyANTTVecSub(
		pp.PolyANTTMatrixMulVector(pp.paramMatrixA, z_ntt, pp.paramKA, pp.paramLA),
		pp.PolyANTTVecScaleMul(ch, t, pp.paramKA),
		pp.paramKA)

	preMsg, err := pp.collectBytesForSimpleSignatureChallenge(t, extTrTxCon, w)
	if err != nil {
		return err
	}

	seed_ch, err := Hash(preMsg)
	if err != nil {
		return err
	}

	if bytes.Compare(seed_ch, sig.seed_ch) != 0 {
		return fmt.Errorf("simpleSignatureVerify: the computed seed_ch is different from sig.seed_ch")
	}

	return nil
}

// simpleSignatureSerializeSize returns the serialize size for SimpleSignatureMLP.
// reviewed by Alice, 2024.07.02
func (pp *PublicParameter) simpleSignatureSerializeSize() int {
	length := HashOutputBytesLen + //	seed_ch []byte
		pp.PolyAVecSerializeSizeEtaByVecLen(pp.paramLA) //	z       *PolyAVec
	return length
}

// serializeSimpleSignature serializes the input SimpleSignatureMLP into []byte.
// reviewed by Alice, 2024.07.02
func (pp *PublicParameter) serializeSimpleSignature(sig *SimpleSignatureMLP) ([]byte, error) {

	if !pp.SimpleSignatureSanityCheck(sig) {
		return nil, fmt.Errorf("serializeSimpleSignature: the input sig *SimpleSignatureMLP is not well-form")
	}

	length := pp.simpleSignatureSerializeSize()
	w := bytes.NewBuffer(make([]byte, 0, length))

	// seed_ch []byte
	_, err := w.Write(sig.seed_ch)
	if err != nil {
		return nil, err
	}

	// z       *PolyAVec
	err = pp.writePolyAVecEta(w, sig.z)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// deserializeElrSignatureMLP deserialize the input []byte to an ElrSignatureMLP.
// reviewed by Alice, 2024.07.02
func (pp *PublicParameter) deserializeSimpleSignature(serializedSig []byte) (*SimpleSignatureMLP, error) {
	if len(serializedSig) == 0 {
		return nil, fmt.Errorf("deserializeSimpleSignature: the input serializedSig is nil/empty")
	}

	r := bytes.NewReader(serializedSig)

	//	seed_ch []byte
	seed_ch := make([]byte, HashOutputBytesLen)
	_, err := r.Read(seed_ch)
	if err != nil {
		return nil, err
	}

	//	z       *PolyAVec
	z, err := pp.readPolyAVecEta(r)
	if err != nil {
		return nil, err
	}

	return &SimpleSignatureMLP{
		seed_ch: seed_ch,
		z:       z,
	}, nil
}

// collectBytesForSimpleSignatureChallenge collect preMsg for simpleSignatureSign, for the Fiat-Shamir transform.
// todo: concat the system public parameter
// reviewed on 2023.12.18
// refactored and reviewed by Alice, 2024.07.02
func (pp *PublicParameter) collectBytesForSimpleSignatureChallenge(t *PolyANTTVec, extTrTxCon []byte,
	w *PolyANTTVec) ([]byte, error) {

	length := len(pp.paramParameterSeedString) + // crs
		pp.paramKA*pp.paramDA*8 + //	t *PolyANTTVec
		len(extTrTxCon) + //	extTrTxCon []byte
		pp.paramKA*pp.paramDA*8 //	w *PolyANTTVec

	rst := make([]byte, 0, length)

	appendPolyANTTToBytes := func(a *PolyANTT) {
		for k := 0; k < pp.paramDA; k++ {
			rst = append(rst, byte(a.coeffs[k]>>0))
			rst = append(rst, byte(a.coeffs[k]>>8))
			rst = append(rst, byte(a.coeffs[k]>>16))
			rst = append(rst, byte(a.coeffs[k]>>24))
			rst = append(rst, byte(a.coeffs[k]>>32))
			rst = append(rst, byte(a.coeffs[k]>>40))
			rst = append(rst, byte(a.coeffs[k]>>48))
			rst = append(rst, byte(a.coeffs[k]>>56))
		}
	}

	//	crs
	rst = append(rst, pp.paramParameterSeedString...)

	//	t *PolyANTTVec
	for i := 0; i < len(t.polyANTTs); i++ {
		appendPolyANTTToBytes(t.polyANTTs[i])
	}

	//	extTrTxCon []byte
	rst = append(rst, extTrTxCon...)

	// w *PolyANTTVec
	for i := 0; i < len(w.polyANTTs); i++ {
		appendPolyANTTToBytes(w.polyANTTs[i])
	}

	return rst, nil
}

//	Simple Signature	end

//	helper functions	begin

// newAddressSecretKeySpFromPolyANTTVec makes an AddressSecretKeySp from the input sNTT *PolyANTTVec.
// added by Alice, 2024.07.01
// todo: review by 2024.07
func (pp *PublicParameter) newAddressSecretKeySpFromPolyANTTVec(sNTT *PolyANTTVec) (*AddressSecretKeySp, error) {

	if sNTT == nil {
		return nil, fmt.Errorf("newAddressSecretKeySpFromPolyANTTVec: The input sNTT *PolyANTTVec is nil/empty")
	}

	if len(sNTT.polyANTTs) != pp.paramLA {
		return nil, fmt.Errorf("newAddressSecretKeySpFromPolyANTTVec: The input sNTT *PolyANTTVec has in incorrect size (%d)", len(sNTT.polyANTTs))
	}

	sPolyAs := make([]*PolyA, pp.paramLA)
	for i := 0; i < pp.paramLA; i++ {
		if !pp.PolyANTTSanityCheck(sNTT.polyANTTs[i]) {
			return nil, fmt.Errorf("newAddressSecretKeySpFromPolyANTTVec: The input sNTT.polyANTTs[%d] is not well-from", i)
		}
		// Note that the above sanity-check is necessary, since bad-form PolyANTT may cause panic in NTTInv.

		sPolyAs[i] = pp.NTTInvPolyA(sNTT.polyANTTs[i])
		if sPolyAs[i].infNorm() > 2 {
			// Note that pp.paramGammaA = 2
			return nil, fmt.Errorf("newAddressSecretKeySpFromPolyANTTVec: The input sNTT.polyANTTs[%d]'s poly's normal is not in the allowed scope", i)
		}
	}

	askSp := &AddressSecretKeySp{
		s: &PolyAVec{polyAs: sPolyAs},
	}

	return askSp, nil
}

// newAddressSecretKeySnFromPolyANTT makes an AddressSecretKeySn from the input sNTT maNTT *PolyANTT.
// added by Alice, 2024.07.01
// todo: review by 2024.07
func (pp *PublicParameter) newAddressSecretKeySnFromPolyANTT(maNTT *PolyANTT) (*AddressSecretKeySn, error) {

	if !pp.PolyANTTSanityCheck(maNTT) {
		return nil, fmt.Errorf("newAddressSecretKeySnFromPolyANTT: The input maNTT *PolyANTT is not well-form")

	}

	askSn := &AddressSecretKeySn{
		ma: maNTT,
	}

	return askSn, nil
}

//	helper functions	end

// Sanity-checks	begin

// LgrTxoRingSanityCheck checks whether the input lgrTxoList []LgrTxoMLP is well-from.
// (1) lgrTxoList is not nil/empty;
// (2) There is not repeated lgrTxoId in one ring;
// (3) Each Txo is well-form, and coinAddressType is either CoinAddressTypePublicKeyForRingPre or CoinAddressTypePublicKeyForRing.
// added by Alice, 2024.07.02
// todo: review by 2024.07
func (pp *PublicParameter) LgrTxoRingSanityCheck(lgrTxoList []*LgrTxoMLP) bool {

	ringLen := len(lgrTxoList)
	if ringLen <= 0 || ringLen > int(pp.paramRingSizeMax) {
		return false
	}

	lgrTxoIdsMap := make(map[string]int) // There should not be repeated lgrTxoId in one ring.
	for i := 0; i < ringLen; i++ {
		lgrTxo := lgrTxoList[i]
		if !pp.LgrTxoMLPSanityCheck(lgrTxo) {
			return false
		}

		idString := hex.EncodeToString(lgrTxo.id)
		if _, exists := lgrTxoIdsMap[idString]; exists {
			return false
		}
		lgrTxoIdsMap[idString] = i

		if lgrTxo.txo.CoinAddressType() != CoinAddressTypePublicKeyForRingPre &&
			lgrTxo.txo.CoinAddressType() != CoinAddressTypePublicKeyForRing {
			return false
		}
	}

	return true
}

// ElrSignatureMLPSanityCheck checks whether the input elrSignatureMLP *ElrSignatureMLP is well-form:
// (1) elrSignatureMLP is not nil;
// (2) elrSignatureMLP.ringSize is valid;
// (3) elrSignatureMLP.seeds is well-form, say has ringSize seeds, and each has valid length;
// (4) elrSignatureMLP.z_as is well-form, including the normal;
// (5) elrSignatureMLP.z_cs is well-form, including the normal;
// (6) elrSignatureMLP.z_cps is well-form, including the normal.
// added by Alice, 2024.07.02
// todo: review by 2024.07
func (pp *PublicParameter) ElrSignatureMLPSanityCheck(elrSignatureMLP *ElrSignatureMLP) bool {

	if elrSignatureMLP == nil {
		return false
	}

	if elrSignatureMLP.ringSize <= 0 || elrSignatureMLP.ringSize > pp.paramRingSizeMax {
		return false
	}

	if len(elrSignatureMLP.seeds) != int(elrSignatureMLP.ringSize) {
		return false
	}
	for j := uint8(0); j < elrSignatureMLP.ringSize; j++ {
		if len(elrSignatureMLP.seeds[j]) != HashOutputBytesLen {
			return false
		}
	}

	zBoundA := pp.paramEtaA - int64(pp.paramBetaA)
	if len(elrSignatureMLP.z_as) != int(elrSignatureMLP.ringSize) {
		return false
	}
	for j := uint8(0); j < elrSignatureMLP.ringSize; j++ {
		if elrSignatureMLP.z_as[j] == nil {
			return false
		}
		if len(elrSignatureMLP.z_as[j].polyAs) != pp.paramLA {
			return false
		}
		for i := 0; i < pp.paramLA; i++ {
			if !pp.PolyASanityCheck(elrSignatureMLP.z_as[j].polyAs[i]) {
				return false
			}

			if elrSignatureMLP.z_as[j].polyAs[i].infNorm() > zBoundA {
				return false
			}
		}
	}

	zBoundC := pp.paramEtaC - int64(pp.paramBetaC)
	if len(elrSignatureMLP.z_cs) != int(elrSignatureMLP.ringSize) {
		return false
	}
	for j := uint8(0); j < elrSignatureMLP.ringSize; j++ {
		if len(elrSignatureMLP.z_cs[j]) != pp.paramK {
			return false
		}

		for tau := 0; tau < pp.paramK; tau++ {
			if elrSignatureMLP.z_cs[j][tau] == nil {
				return false
			}

			if len(elrSignatureMLP.z_cs[j][tau].polyCs) != pp.paramLC {
				return false
			}

			for i := 0; i < pp.paramLC; i++ {
				if !pp.PolyCSanityCheck(elrSignatureMLP.z_cs[j][tau].polyCs[i]) {
					return false
				}

				if elrSignatureMLP.z_cs[j][tau].polyCs[i].infNorm() > zBoundC {
					return false
				}
			}
		}
	}

	if len(elrSignatureMLP.z_cps) != int(elrSignatureMLP.ringSize) {
		return false
	}
	for j := uint8(0); j < elrSignatureMLP.ringSize; j++ {
		if len(elrSignatureMLP.z_cps[j]) != pp.paramK {
			return false
		}

		for tau := 0; tau < pp.paramK; tau++ {
			if elrSignatureMLP.z_cps[j][tau] == nil {
				return false
			}

			if len(elrSignatureMLP.z_cps[j][tau].polyCs) != pp.paramLC {
				return false
			}

			for i := 0; i < pp.paramLC; i++ {
				if !pp.PolyCSanityCheck(elrSignatureMLP.z_cps[j][tau].polyCs[i]) {
					return false
				}

				if elrSignatureMLP.z_cps[j][tau].polyCs[i].infNorm() > zBoundC {
					return false
				}
			}
		}
	}

	return true
}

func (pp *PublicParameter) SimpleSignatureSanityCheck(simpleSignatureMLP *SimpleSignatureMLP) bool {

	if simpleSignatureMLP == nil {
		return false
	}

	if len(simpleSignatureMLP.seed_ch) != HashOutputBytesLen {
		return false
	}

	if simpleSignatureMLP.z == nil {
		return false
	}

	zBoundA := pp.paramEtaA - int64(pp.paramBetaA)
	if len(simpleSignatureMLP.z.polyAs) != pp.paramLA {
		return false
	}
	for i := 0; i < pp.paramLA; i++ {
		if !pp.PolyASanityCheck(simpleSignatureMLP.z.polyAs[i]) {
			return false
		}

		if simpleSignatureMLP.z.polyAs[i].infNorm() > zBoundA {
			return false
		}
	}

	return true
}

//	Sanity-checks	end
