package pqringct

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/cryptosuite/pqringct/pqringctkem"
	"log"
	"reflect"
	"testing"
)

func Test_writePolyANTT_readPolyANTT(t *testing.T) {
	testBound := true
	//testBound := true

	var polyANTT *PolyANTT
	manualCheck := true

	pp := Initialize(nil)

	for t := 0; t < 1000; t++ {
		coeffs, err := pp.randomDaIntegersInQa(nil)
		if err != nil {
			log.Fatal(err)
		}
		polyANTT = &PolyANTT{coeffs}

		if testBound {
			polyANTT.coeffs[0] = (pp.paramQA - 1) >> 1
			polyANTT.coeffs[1] = -polyANTT.coeffs[0]
			polyANTT.coeffs[2] = 1
			polyANTT.coeffs[3] = -1
			polyANTT.coeffs[4] = 2
			polyANTT.coeffs[5] = -2
		}

		size := pp.PolyANTTSerializeSize()
		w := bytes.NewBuffer(make([]byte, 0, size))
		err = pp.writePolyANTT(w, polyANTT)
		if err != nil {
			log.Fatal(err)
		}

		serialized := w.Bytes()
		if len(serialized) != size {
			log.Fatal(errors.New("size is worng"))
		}
		//fmt.Println("serilaizeSize of a PolyANTT:", size)

		r := bytes.NewReader(serialized)
		rePolyANTT, err := pp.readPolyANTT(r)
		if err != nil {
			log.Fatal(err)
		}

		for i := 0; i < pp.paramDA; i++ {
			if polyANTT.coeffs[i] != rePolyANTT.coeffs[i] {
				log.Fatal("i=", i, " origin[i]=", polyANTT.coeffs[i], " read[i]=", rePolyANTT.coeffs[i])
			}

		}
	}

	if manualCheck {
		fmt.Println("SerializeSize of a PolyANTT:", pp.PolyANTTSerializeSize())

		for i := 0; i < pp.paramDA; i++ {
			fmt.Println(polyANTT.coeffs[i])
		}
	}
}

func Test_writePolyANTTVec_readPolyANTTVec(t *testing.T) {
	pp := Initialize(nil)

	polyANTTs := make([]*PolyANTT, pp.paramKA)
	for i := 0; i < pp.paramKA; i++ {
		coeffs, err := pp.randomDaIntegersInQa(nil)
		if err != nil {
			log.Fatal(err)
		}
		polyANTTs[i] = &PolyANTT{coeffs}
	}

	polyANTTVec := &PolyANTTVec{polyANTTs: polyANTTs}

	length := pp.PolyANTTVecSerializeSize(polyANTTVec)

	w := bytes.NewBuffer(make([]byte, 0, length))
	err := pp.writePolyANTTVec(w, polyANTTVec)
	if err != nil {
		log.Fatal(err)
	}

	serialized := w.Bytes()

	if len(serialized) != length {
		log.Fatal("size is wrong")
	}

	r := bytes.NewReader(serialized)
	recovered, err := pp.readPolyANTTVec(r)
	if err != nil {
		log.Fatal(err)
	}
	for i := 0; i < pp.paramKA; i++ {
		for j := 0; j < pp.paramDA; j++ {
			if polyANTTVec.polyANTTs[i].coeffs[j] != recovered.polyANTTs[i].coeffs[j] {
				log.Fatal("i=", i, "j=", j, " origin[i]=", polyANTTVec.polyANTTs[i].coeffs[j], " read[i]=", recovered.polyANTTs[i].coeffs[j])
			}
		}

	}

	//	test nil
	w = bytes.NewBuffer(make([]byte, 0, pp.PolyANTTVecSerializeSize(nil)))
	err = pp.writePolyANTTVec(w, nil)
	if err != nil {
		log.Fatal(err)
	}
	ss := w.Bytes()
	ssLen := len(ss)
	fmt.Println("serialize empty, length:", ssLen)

	r = bytes.NewReader(ss)
	recovered, err = pp.readPolyANTTVec(r)
	if err != nil {
		log.Fatal(err)
	}

	if recovered != nil {
		log.Fatal("serialize empty FAIL")
	}
}

func Test_writePolyAEta_readPolyAEta(t *testing.T) {
	pp := Initialize(nil)

	testBound := true
	//testBound := true

	var polyA *PolyA
	manualCheck := true

	var err error
	for t := 0; t < 10000; t++ {
		polyA, err = pp.randomPolyAinEtaA()
		if err != nil {
			log.Fatal(err)
		}

		if testBound {
			polyA.coeffs[0] = pp.paramEtaA
			polyA.coeffs[1] = -polyA.coeffs[0]
			polyA.coeffs[2] = 1
			polyA.coeffs[3] = -1
			polyA.coeffs[4] = 2
			polyA.coeffs[5] = -2
		}

		size := pp.PolyASerializeSizeEta()
		w := bytes.NewBuffer(make([]byte, 0, size))
		err := pp.writePolyAEta(w, polyA)
		if err != nil {
			log.Fatal(err)
		}

		serialized := w.Bytes()
		if len(serialized) != size {
			log.Fatal(errors.New("size is worng"))
		}

		r := bytes.NewReader(serialized)
		rePolyA, err := pp.readPolyAEta(r)
		if err != nil {
			log.Fatal(err)
		}

		for i := 0; i < pp.paramDA; i++ {
			if polyA.coeffs[i] != rePolyA.coeffs[i] {
				log.Fatal("i=", i, " origin[i]=", polyA.coeffs[i], " read[i]=", rePolyA.coeffs[i])
			}
		}
	}

	if manualCheck {
		fmt.Println("SerializeSize of a PolyAEta:", pp.PolyASerializeSizeEta())

		for i := 0; i < pp.paramDA; i++ {
			fmt.Println(polyA.coeffs[i])
		}
	}
}

func Test_writePolyANTTVecEta_readPolyANTTVecEta(t *testing.T) {
	pp := Initialize(nil)

	var err error

	polyAs := make([]*PolyA, pp.paramKA)
	for i := 0; i < pp.paramKA; i++ {
		polyAs[i], err = pp.randomPolyAinEtaA()
	}

	polyAVec := &PolyAVec{polyAs: polyAs}

	length := pp.PolyAVecSerializeSizeEta(polyAVec)

	fmt.Println("serializeSize:", length)

	w := bytes.NewBuffer(make([]byte, 0, length))
	err = pp.writePolyAVecEta(w, polyAVec)
	if err != nil {
		log.Fatal(err)
	}
	serialized := w.Bytes()

	if len(serialized) != length {
		log.Fatal("size is wrong")
	}

	r := bytes.NewReader(serialized)
	recovered, err := pp.readPolyAVecEta(r)
	if err != nil {
		log.Fatal(err)
	}
	for i := 0; i < pp.paramKA; i++ {
		for j := 0; j < pp.paramDA; j++ {
			if polyAVec.polyAs[i].coeffs[j] != recovered.polyAs[i].coeffs[j] {
				log.Fatal("i=", i, "j=", j, " origin[i]=", polyAVec.polyAs[i].coeffs[j], " read[i]=", recovered.polyAs[i].coeffs[j])
			}
		}
	}

	//	test nil
	w = bytes.NewBuffer(make([]byte, 0, pp.PolyAVecSerializeSizeEta(nil)))
	err = pp.writePolyAVecEta(w, nil)
	if err != nil {
		log.Fatal(err)
	}
	ss := w.Bytes()
	ssLen := len(ss)
	fmt.Println("serialize empty, length:", ssLen)

	r = bytes.NewReader(ss)
	recovered, err = pp.readPolyAVecEta(r)
	if err != nil {
		log.Fatal(err)
	}

	if recovered != nil {
		log.Fatal("serialize empty FAIL")
	}
}

func Test_writePolyAGamma_readPolyAGamma(t *testing.T) {
	pp := Initialize(nil)

	testBound := true
	//testBound := true

	var polyA *PolyA
	manualCheck := true

	var err error
	for t := 0; t < 10000; t++ {
		polyA, err = pp.randomPolyAinGammaA2(nil)
		if err != nil {
			log.Fatal(err)
		}

		if testBound {
			polyA.coeffs[0] = int64(pp.paramGammaA)
			polyA.coeffs[1] = -polyA.coeffs[0]
			polyA.coeffs[2] = 1
			polyA.coeffs[3] = -1
			polyA.coeffs[4] = 2
			polyA.coeffs[5] = -2
		}

		size := pp.PolyASerializeSizeGamma()
		w := bytes.NewBuffer(make([]byte, 0, size))
		err := pp.writePolyAGamma(w, polyA)
		if err != nil {
			log.Fatal(err)
		}

		serialized := w.Bytes()
		if len(serialized) != size {
			log.Fatal(errors.New("size is worng"))
		}

		r := bytes.NewReader(serialized)
		rePolyA, err := pp.readPolyAGamma(r)
		if err != nil {
			log.Fatal(err)
		}

		for i := 0; i < pp.paramDA; i++ {
			if polyA.coeffs[i] != rePolyA.coeffs[i] {
				log.Fatal("i=", i, " origin[i]=", polyA.coeffs[i], " read[i]=", rePolyA.coeffs[i])
			}
		}
	}

	if manualCheck {
		fmt.Println("SerializeSize of a PolyAGamma:", pp.PolyASerializeSizeGamma())

		for i := 0; i < pp.paramDA; i++ {
			fmt.Println(polyA.coeffs[i])
		}
	}
}

func Test_writePolyCNTT_readPolyCNTT(t *testing.T) {
	testBound := true
	//testBound := true

	var polyCNTT *PolyCNTT
	manualCheck := true

	pp := Initialize(nil)

	for t := 0; t < 1000; t++ {
		coeffs, err := pp.randomDcIntegersInQc(nil)
		if err != nil {
			log.Fatal(err)
		}
		polyCNTT = &PolyCNTT{coeffs}

		if testBound {
			polyCNTT.coeffs[0] = (pp.paramQC - 1) >> 1
			polyCNTT.coeffs[1] = -polyCNTT.coeffs[0]
			polyCNTT.coeffs[2] = 1
			polyCNTT.coeffs[3] = -1
			polyCNTT.coeffs[4] = 2
			polyCNTT.coeffs[5] = -2
			polyCNTT.coeffs[6] = 0
		}

		size := pp.PolyCNTTSerializeSize()
		w := bytes.NewBuffer(make([]byte, 0, size))
		err = pp.writePolyCNTT(w, polyCNTT)
		if err != nil {
			log.Fatal(err)
		}

		serialized := w.Bytes()
		if len(serialized) != size {
			log.Fatal(errors.New("size is worng"))
		}
		//fmt.Println("serilaizeSize of a PolyANTT:", size)

		r := bytes.NewReader(serialized)
		rePolyCNTT, err := pp.readPolyCNTT(r)
		if err != nil {
			log.Fatal(err)
		}

		for i := 0; i < pp.paramDC; i++ {
			if polyCNTT.coeffs[i] != rePolyCNTT.coeffs[i] {
				log.Fatal("i=", i, " origin[i]=", polyCNTT.coeffs[i], " read[i]=", rePolyCNTT.coeffs[i])
			}

		}
	}

	if manualCheck {
		fmt.Println("SerializeSize of a PolyCNTT:", pp.PolyCNTTSerializeSize())

		for i := 0; i < pp.paramDC; i++ {
			fmt.Println(polyCNTT.coeffs[i])
		}
	}
}

func Test_writePolyCNTTVec_readPolyCNTTVec(t *testing.T) {
	pp := Initialize(nil)

	polyCNTTs := make([]*PolyCNTT, pp.paramKC)
	for i := 0; i < pp.paramKC; i++ {
		coeffs, err := pp.randomDcIntegersInQc(nil)
		if err != nil {
			log.Fatal(err)
		}
		polyCNTTs[i] = &PolyCNTT{coeffs}
	}

	polyCNTTVec := &PolyCNTTVec{polyCNTTs: polyCNTTs}

	length := pp.PolyCNTTVecSerializeSize(polyCNTTVec)

	w := bytes.NewBuffer(make([]byte, 0, length))
	err := pp.writePolyCNTTVec(w, polyCNTTVec)
	if err != nil {
		log.Fatal(err)
	}

	serialized := w.Bytes()

	if len(serialized) != length {
		log.Fatal("size is wrong")
	}

	r := bytes.NewReader(serialized)
	recovered, err := pp.readPolyCNTTVec(r)
	if err != nil {
		log.Fatal(err)
	}
	for i := 0; i < pp.paramKC; i++ {
		for j := 0; j < pp.paramDC; j++ {
			if polyCNTTVec.polyCNTTs[i].coeffs[j] != recovered.polyCNTTs[i].coeffs[j] {
				log.Fatal("i=", i, "j=", j, " origin[i]=", polyCNTTVec.polyCNTTs[i].coeffs[j], " read[i]=", recovered.polyCNTTs[i].coeffs[j])
			}
		}

	}

	//	test nil
	w = bytes.NewBuffer(make([]byte, 0, pp.PolyCNTTVecSerializeSize(nil)))
	err = pp.writePolyCNTTVec(w, nil)
	if err != nil {
		log.Fatal(err)
	}
	ss := w.Bytes()
	ssLen := len(ss)
	fmt.Println("serialize empty, length:", ssLen)

	r = bytes.NewReader(ss)
	recovered, err = pp.readPolyCNTTVec(r)
	if err != nil {
		log.Fatal(err)
	}

	if recovered != nil {
		log.Fatal("serialize empty FAIL")
	}

}

func Test_writePolyCEta_readPolyCEta(t *testing.T) {
	testBound := true
	//testBound := true

	var polyCEta *PolyC
	manualCheck := true

	pp := Initialize(nil)

	var err error
	for t := 0; t < 1000; t++ {
		polyCEta, err = pp.randomPolyCinEtaC()
		if err != nil {
			log.Fatal(err)
		}

		if testBound {
			polyCEta.coeffs[0] = pp.paramEtaC
			polyCEta.coeffs[1] = -polyCEta.coeffs[0]
			polyCEta.coeffs[2] = 1
			polyCEta.coeffs[3] = -1
			polyCEta.coeffs[4] = 2
			polyCEta.coeffs[5] = -2
			polyCEta.coeffs[6] = 0
		}

		size := pp.PolyCSerializeSizeEta()
		w := bytes.NewBuffer(make([]byte, 0, size))
		err = pp.writePolyCEta(w, polyCEta)
		if err != nil {
			log.Fatal(err)
		}

		serialized := w.Bytes()
		if len(serialized) != size {
			log.Fatal(errors.New("size is worng"))
		}
		//fmt.Println("serilaizeSize of a PolyANTT:", size)

		r := bytes.NewReader(serialized)
		rePolyCEta, err := pp.readPolyCEta(r)
		if err != nil {
			log.Fatal(err)
		}

		for i := 0; i < pp.paramDC; i++ {
			if polyCEta.coeffs[i] != rePolyCEta.coeffs[i] {
				log.Fatal("i=", i, " origin[i]=", polyCEta.coeffs[i], " read[i]=", rePolyCEta.coeffs[i])
			}

		}
	}

	if manualCheck {
		fmt.Println("SerializeSize of a PolyCEta:", pp.PolyCSerializeSizeEta())

		for i := 0; i < pp.paramDC; i++ {
			fmt.Println(polyCEta.coeffs[i])
		}
	}
}

func Test_writePolyCVecEta_readPolyCVecEta(t *testing.T) {
	pp := Initialize(nil)

	var err error
	polyCs := make([]*PolyC, pp.paramKC)
	for i := 0; i < pp.paramKC; i++ {
		polyCs[i], err = pp.randomPolyCinEtaC()
		if err != nil {
			log.Fatal(err)
		}
	}

	polyCVecEta := &PolyCVec{polyCs: polyCs}

	length := pp.PolyCVecSerializeSizeEta(polyCVecEta)

	w := bytes.NewBuffer(make([]byte, 0, length))
	err = pp.writePolyCVecEta(w, polyCVecEta)
	if err != nil {
		log.Fatal(err)
	}

	serialized := w.Bytes()

	if len(serialized) != length {
		log.Fatal("size is wrong")
	}

	r := bytes.NewReader(serialized)
	recovered, err := pp.readPolyCVecEta(r)
	if err != nil {
		log.Fatal(err)
	}
	for i := 0; i < pp.paramKC; i++ {
		for j := 0; j < pp.paramDC; j++ {
			if polyCVecEta.polyCs[i].coeffs[j] != recovered.polyCs[i].coeffs[j] {
				log.Fatal("i=", i, "j=", j, " origin[i]=", polyCVecEta.polyCs[i].coeffs[j], " read[i]=", recovered.polyCs[i].coeffs[j])
			}
		}

	}

	//	test nil
	w = bytes.NewBuffer(make([]byte, 0, pp.PolyCVecSerializeSizeEta(nil)))
	err = pp.writePolyCVecEta(w, nil)
	if err != nil {
		log.Fatal(err)
	}
	ss := w.Bytes()
	ssLen := len(ss)
	fmt.Println("serialize empty, length:", ssLen)

	r = bytes.NewReader(ss)
	recovered, err = pp.readPolyCVecEta(r)
	if err != nil {
		log.Fatal(err)
	}

	if recovered != nil {
		log.Fatal("serialize empty FAIL")
	}
}

func TestAddressPubicKeySerialize(t *testing.T) {
	pp := Initialize(nil)

	testAbnormal := false

	// normal
	apkt := pp.NewPolyANTTVec(pp.paramKA)
	for i := 0; i < pp.paramKA; i++ {
		coeffs, err := pp.randomDaIntegersInQa(nil)
		if err != nil {
			log.Fatal(err)
		}
		apkt.polyANTTs[i] = &PolyANTT{coeffs}
	}

	coeffs, err := pp.randomDaIntegersInQa(nil)
	if err != nil {
		log.Fatal(err)
	}
	apke := &PolyANTT{coeffs}

	apk := &AddressPublicKey{t: apkt, e: apke}

	size := pp.AddressPublicKeySerializeSize()

	serialized, err := pp.SerializeAddressPublicKey(apk)
	if err != nil {
		log.Fatal(err)
	}

	if len(serialized) != size {
		log.Fatal("the size does not match")
	}

	recoverd, err := pp.DeserializeAddressPublicKey(serialized)

	length := len(recoverd.t.polyANTTs)
	if length != pp.paramKA {
		log.Fatal("the length of t is does not match the design")
	}
	for i := 0; i < len(recoverd.t.polyANTTs); i++ {
		for j := 0; j < pp.paramDA; j++ {
			if apk.t.polyANTTs[i].coeffs[j] != recoverd.t.polyANTTs[i].coeffs[j] {
				log.Fatal("i=", i, "j=", j, " origin[i,j]=", apk.t.polyANTTs[i].coeffs[j], " read[i]=", recoverd.t.polyANTTs[i].coeffs[j])
			}
		}
	}

	// abnormal
	if testAbnormal {
		apkt = pp.NewPolyANTTVec(pp.paramKA + 1)
		for i := 0; i < pp.paramKA+1; i++ {
			coeffs, err := pp.randomDaIntegersInQa(nil)
			if err != nil {
				log.Fatal(err)
			}
			apkt.polyANTTs[i] = &PolyANTT{coeffs}
		}
		coeffs, err := pp.randomDaIntegersInQa(nil)
		if err != nil {
			log.Fatal(err)
		}
		apke = &PolyANTT{coeffs}

		apk = &AddressPublicKey{t: apkt, e: apke}

		size = pp.AddressPublicKeySerializeSize()

		_, err = pp.SerializeAddressPublicKey(apk)
		if err != nil {
			log.Fatal(err)
		}
	}

}

func TestSerializeAddressSecretKeySp(t *testing.T) {
	pp := Initialize(nil)

	testAbnormal := false

	var err error
	s := pp.NewPolyAVec(pp.paramLA)
	for i := 0; i < pp.paramLA; i++ {
		s.polyAs[i], err = pp.randomPolyAinGammaA2(nil)
		if err != nil {
			log.Fatal(err)
		}
	}

	asksp := &AddressSecretKeySp{
		s: s,
	}

	serializedAskSp, err := pp.SerializeAddressSecretKeySp(asksp)
	if err != nil {
		log.Fatal(err)
	}
	if len(serializedAskSp) != pp.AddressSecretKeySpSerializeSize() {
		log.Fatal("the size does not match design")
	}

	recovered, err := pp.DeserializeAddressSecretKeySp(serializedAskSp)
	if err != nil {
		log.Fatal(err)
	}

	if len(recovered.s.polyAs) != pp.paramLA {
		log.Fatal("the length does not match design")
	}

	for i := 0; i < len(recovered.s.polyAs); i++ {
		for j := 0; j < pp.paramDA; j++ {
			if asksp.s.polyAs[i].coeffs[j] != recovered.s.polyAs[i].coeffs[j] {
				log.Fatal("i=", i, "j=", j, " origin[i,j]=", asksp.s.polyAs[i].coeffs[j], " read[i]=", recovered.s.polyAs[i].coeffs[j])
			}
		}
	}

	// abnormal
	if testAbnormal {
		ask := &AddressSecretKeySp{}

		_, err = pp.SerializeAddressSecretKeySp(ask)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func TestSerializeAddressSecretKeySn(t *testing.T) {
	pp := Initialize(nil)
	coeffs, err := pp.randomDaIntegersInQa(nil)
	if err != nil {
		log.Fatal(err)
	}
	m_a := &PolyANTT{
		coeffs,
	}

	asksn := &AddressSecretKeySn{m_a}

	serilaized, err := pp.SerializeAddressSecretKeySn(asksn)
	if err != nil {
		log.Fatal(err)
	}

	if len(serilaized) != pp.AddressSecretKeySnSerializeSize() {
		log.Fatal("the size does not match design")
	}
	recovered, err := pp.DeserializeAddressSecretKeySn(serilaized)
	if err != nil {
		log.Fatal(err)
	}

	if len(recovered.ma.coeffs) != pp.paramDA {
		log.Fatal("the length does not match design")
	}

	for i := 0; i < len(recovered.ma.coeffs); i++ {
		if asksn.ma.coeffs[i] != recovered.ma.coeffs[i] {
			log.Fatal("i=", i, " origin[i]=", asksn.ma.coeffs[i], " read[i]=", recovered.ma.coeffs[i])
		}
	}
}

func TestSerializeValueCommitment(t *testing.T) {
	pp := Initialize(nil)

	b := pp.NewPolyCNTTVec(pp.paramKC)
	for i := 0; i < len(b.polyCNTTs); i++ {
		coeffs, err := pp.randomDcIntegersInQc(nil)
		if err != nil {
			log.Fatal(err)
		}
		b.polyCNTTs[i] = &PolyCNTT{coeffs}
	}
	coeffs, err := pp.randomDcIntegersInQc(nil)
	if err != nil {
		log.Fatal(err)
	}
	c := &PolyCNTT{coeffs}

	vcmt := &ValueCommitment{b, c}

	serialized, err := pp.SerializeValueCommitment(vcmt)
	if err != nil {
		log.Fatal(err)
	}

	if len(serialized) != pp.ValueCommitmentSerializeSize() {
		log.Fatal("wrong size")
	}

	fmt.Println("serialized Length:", len(serialized))

	recovered, err := pp.DeserializeValueCommitment(serialized)
	if err != nil {
		log.Fatal(err)
	}

	for i := 0; i < pp.paramKC; i++ {
		for j := 0; j < pp.paramDC; j++ {
			if vcmt.b.polyCNTTs[i].coeffs[j] != recovered.b.polyCNTTs[i].coeffs[j] {
				log.Fatal("i=", i, "j=", j, " origin[i,j]=", vcmt.b.polyCNTTs[i].coeffs[j], " recovered[i,j]=", recovered.b.polyCNTTs[i].coeffs[j])
			}
		}
	}

}

func TestEncodeTxoValueToBytes(t *testing.T) {
	pp := Initialize(nil)

	testAbnormal := false

	value := uint64(1<<51 - 1)
	serialzed, err := pp.encodeTxoValueToBytes(value)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("encode:", serialzed)

	valueRead, err := pp.decodeTxoValueFromBytes(serialzed)

	fmt.Println("original:", value)
	fmt.Println("recovered:", valueRead)

	if valueRead != value {
		log.Fatal("valeu:", value, "FAIL")
	}

	value = uint64(1<<51 - 2)
	serialzed, err = pp.encodeTxoValueToBytes(value)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("encode:", serialzed)

	valueRead, err = pp.decodeTxoValueFromBytes(serialzed)

	fmt.Println("original:", value)
	fmt.Println("recovered:", valueRead)

	if valueRead != value {
		log.Fatal("valeu:", value, "FAIL")
	}

	value = uint64(0)
	serialzed, err = pp.encodeTxoValueToBytes(value)
	if err != nil {
		log.Fatal(err)
	}
	valueRead, err = pp.decodeTxoValueFromBytes(serialzed)
	fmt.Println("encode:", serialzed)
	fmt.Println("original:", value)
	fmt.Println("recovered:", valueRead)

	if valueRead != value {
		log.Fatal("valeu:", value, "FAIL")
	}

	value = uint64(1)
	serialzed, err = pp.encodeTxoValueToBytes(value)
	if err != nil {
		log.Fatal(err)
	}
	valueRead, err = pp.decodeTxoValueFromBytes(serialzed)
	fmt.Println("encode:", serialzed)
	fmt.Println("original:", value)
	fmt.Println("recovered:", valueRead)

	if valueRead != value {
		log.Fatal("valeu:", value, "FAIL")
	}

	//valuep := int64(-1)
	//rst := make([]byte, 7)
	//for i := 0; i < 7; i++ {
	//	rst[0] = byte(valuep >> 0)
	//	rst[1] = byte(valuep >> 8)
	//	rst[2] = byte(valuep >> 16)
	//	rst[3] = byte(valuep >> 24)
	//	rst[4] = byte(valuep >> 32)
	//	rst[5] = byte(valuep >> 40)
	//	rst[6] = byte(valuep >> 48)
	//	//rst[6] = byte(valuep>>48) | 0xF8
	//}
	//
	//fmt.Println("encode:", rst)
	//valueRead, err = pp.decodeTxoValueFromBytes(rst)
	//fmt.Println("testp:", valuep)
	//fmt.Println(valueRead)

	if testAbnormal {
		value = 1<<51 + 1
		rst := make([]byte, 7)
		for i := 0; i < 7; i++ {
			rst[0] = byte(value >> 0)
			rst[1] = byte(value >> 8)
			rst[2] = byte(value >> 16)
			rst[3] = byte(value >> 24)
			rst[4] = byte(value >> 32)
			rst[5] = byte(value >> 40)
			rst[6] = byte(value >> 48)
		}

		valueRead, err = pp.decodeTxoValueFromBytes(serialzed)
		fmt.Println("encode:", serialzed)
		fmt.Println(value)
		fmt.Println(valueRead)

		if valueRead != value {
			log.Fatal("valeu:", value, "FAIL")
		}
	}
}

func TestSerializeTxo(t *testing.T) {

	pp := Initialize(nil)

	apk, _, err := pp.addressKeyGen(nil)
	if err != nil {
		log.Fatal(err)
	}

	vpk, _, err := pp.valueKeyGen(nil)
	if err != nil {
		log.Fatal(err)
	}

	value := uint64(1<<51 - 1)

	txo, r, err := pp.txoGen(apk, vpk, value)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("length of r:", len(r.polyCNTTs))

	serialzed, err := pp.SerializeTxo(txo)
	if err != nil {
		log.Fatal(err)
	}

	if len(serialzed) != pp.TxoSerializeSize() {
		log.Fatal("wrong size")
	}

	fmt.Println("txo size:", len(serialzed))

	recovered, err := pp.DeserializeTxo(serialzed)

	if len(recovered.AddressPublicKey.t.polyANTTs) != pp.paramKA {
		log.Fatal("wrong lenth of AddressPublicKey.t")
	}
	if len(txo.AddressPublicKey.t.polyANTTs) != pp.paramKA {
		log.Fatal("wrong lenth of AddressPublicKey.t")
	}

	for i := 0; i < pp.paramKA; i++ {
		for j := 0; j < pp.paramDA; j++ {
			if txo.AddressPublicKey.t.polyANTTs[i].coeffs[j] != recovered.AddressPublicKey.t.polyANTTs[i].coeffs[j] {
				log.Fatal("t.polyANTTs[i].coeffs[j] are not equal", i, j)
			}
		}
	}
	for j := 0; j < pp.paramDA; j++ {
		if txo.AddressPublicKey.e.coeffs[j] != recovered.AddressPublicKey.e.coeffs[j] {
			log.Fatal("e.coeffs[j] are not equal", j)
		}
	}

	for i := 0; i < pp.paramKC; i++ {
		for j := 0; j < pp.paramDC; j++ {
			if txo.ValueCommitment.b.polyCNTTs[i].coeffs[j] != recovered.ValueCommitment.b.polyCNTTs[i].coeffs[j] {
				log.Fatal("txo.ValueCommitment.b.polyCNTTs[i].coeffs[j] are not equal", i, j)
			}
		}
	}
	for j := 0; j < pp.paramDC; j++ {
		if txo.ValueCommitment.c.coeffs[j] != recovered.ValueCommitment.c.coeffs[j] {
			log.Fatal("ValueCommitment.c.coeffs[j] are not equal", j)
		}
	}

	if bytes.Compare(txo.Vct, recovered.Vct) != 0 {
		log.Fatal("wrong Vct")
	}

	if bytes.Compare(txo.CtKemSerialized, recovered.CtKemSerialized) != 0 {
		log.Fatal("wrong CtKemSerialized")
	}

}

func TestSerializeLgrTxo(t *testing.T) {
	pp := Initialize(nil)

	apk, _, err := pp.addressKeyGen(nil)
	if err != nil {
		log.Fatal(err)
	}

	vpk, _, err := pp.valueKeyGen(nil)
	if err != nil {
		log.Fatal(err)
	}

	value := uint64(1<<51 - 1)
	txo, _, err := pp.txoGen(apk, vpk, value)

	if err != nil {
		log.Fatal(err)
	}
	id := make([]byte, pp.LgrTxoIdSerializeSize())
	for i := 0; i < len(id); i++ {
		id[i] = byte(i)
	}

	fmt.Println("LgrTxoId BytesLen:", len(id))
	lgxTxo := &LgrTxo{
		txo: txo,
		id:  id,
	}

	serialzied, err := pp.SerializeLgrTxo(lgxTxo)
	if err != nil {
		log.Fatal(err)
	}

	if len(serialzied) != pp.LgrTxoSerializeSize() {
		log.Fatal("Wrong Size")
	}

	fmt.Println("LgrTxo Size:", len(serialzied))

	recovered, err := pp.DeserializeLgrTxo(serialzied)
	if err != nil {
		log.Fatal(err)
	}
	serialzedOriTxo, err := pp.SerializeTxo(txo)
	if err != nil {
		log.Fatal(err)
	}
	serialzedRecTxo, err := pp.SerializeTxo(recovered.txo)
	if err != nil {
		log.Fatal(err)
	}

	if bytes.Compare(serialzedOriTxo, serialzedRecTxo) != 0 {
		log.Fatal("Wrong Serialized Txo")
	}
	if bytes.Compare(id, recovered.id) != 0 {
		log.Fatal("Wrong Serialized Id")
	}
}

func TestSerializeRpulpProof(t *testing.T) {
	pp := Initialize(nil)
	n := 10
	var seed []byte
	// c_waves []*PolyCNTT
	c_waves := make([]*PolyCNTT, n)
	for i := 0; i < n; i++ {
		seed = RandomBytes(RandSeedBytesLen)
		tmp, err := pp.randomDcIntegersInQc(seed)
		if err != nil {
			log.Fatal(err)
		}
		c_waves[i] = &PolyCNTT{coeffs: tmp}
	}

	//	c_hat_g *PolyCNTT
	var c_hat_g *PolyCNTT
	seed = RandomBytes(RandSeedBytesLen)
	tmp, err := pp.randomDcIntegersInQc(seed)
	if err != nil {
		log.Fatal(err)
	}
	//tmp := pp.randomDcIntegersInQc(seed)
	c_hat_g = &PolyCNTT{coeffs: tmp}

	//	psi     *PolyCNTT
	var psi *PolyCNTT
	seed = RandomBytes(RandSeedBytesLen)
	tmp, err = pp.randomDcIntegersInQc(seed)
	if err != nil {
		log.Fatal(err)
	}
	psi = &PolyCNTT{coeffs: tmp}

	//	phi     *PolyCNTT
	var phi *PolyCNTT
	seed = RandomBytes(RandSeedBytesLen)
	tmp, err = pp.randomDcIntegersInQc(seed)
	if err != nil {
		log.Fatal(err)
	}
	phi = &PolyCNTT{coeffs: tmp}

	//	chseed  []byte
	chseed := RandomBytes(HashOutputBytesLen)

	paramK := 5   // should be paramK
	paramLc := 40 // should be k_c + 10 + 7 + lambda_c
	//	cmt_zs [][]*PolyCVec
	cmt_zs := make([][]*PolyCVec, paramK)
	for i := 0; i < paramK; i++ {
		cmt_zs[i] = make([]*PolyCVec, n)
		for j := 0; j < n; j++ {
			cmt_zs[i][j] = pp.NewPolyCVec(paramLc)
			for k := 0; k < paramLc; k++ {
				seed = RandomBytes(HashOutputBytesLen)
				tmp, err := pp.randomPolyCForResponseC()
				if err != nil {
					log.Fatal(err)
				}
				cmt_zs[i][j].polyCs[k] = tmp
			}
		}
	}

	//	zs     []*PolyCVec
	zs := make([]*PolyCVec, paramK)
	for i := 0; i < paramK; i++ {
		zs[i] = pp.NewPolyCVec(paramLc)
		for j := 0; j < paramLc; j++ {
			seed = RandomBytes(RandSeedBytesLen)
			tmp, err := pp.randomPolyCForResponseC()
			if err != nil {
				log.Fatal(err)
			}
			zs[i].polyCs[j] = tmp
		}
	}

	rpulpProof := &rpulpProof{
		c_waves: c_waves,
		c_hat_g: c_hat_g,
		psi:     psi,
		phi:     phi,
		chseed:  chseed,
		cmt_zs:  cmt_zs,
		zs:      zs,
	}

	serializedRpulpProof, err := pp.SerializeRpulpProof(rpulpProof)
	if err != nil {
		log.Fatalln(err)
	}

	if len(serializedRpulpProof) != pp.RpulpProofSerializeSize(rpulpProof) {
		log.Fatalln("wrong size")
	}
	got, err := pp.DeserializeRpulpProof(serializedRpulpProof)
	if err != nil {
		log.Fatalln(err)
	}
	equal := reflect.DeepEqual(got, rpulpProof)
	if !equal {
		t.Fatal("error for serialize and deserialize RpulpProof")
	}
}

func TestSerializeCbTxWitnessJ1(t *testing.T) {
	pp := Initialize(nil)

	var cbTxJ1 = &CbTxWitnessJ1{}
	cbTxJ1.chseed = make([]byte, HashOutputBytesLen)
	for i := 0; i < HashOutputBytesLen; i++ {
		cbTxJ1.chseed[i] = byte(i)
	}

	var err error
	cbTxJ1.zs = make([]*PolyCVec, pp.paramK)
	for i := 0; i < pp.paramK; i++ {
		cbTxJ1.zs[i] = pp.NewPolyCVec(pp.paramLC)
		for j := 0; j < pp.paramLC; j++ {
			cbTxJ1.zs[i].polyCs[j], err = pp.randomPolyCForResponseC()
			if err != nil {
				log.Fatal(err)
			}
		}
	}

	serialized, err := pp.SerializeCbTxWitnessJ1(cbTxJ1)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("approximate size:", pp.CbTxWitnessJ1SerializeSizeApprox())

	fmt.Println("expected size:", pp.CbTxWitnessJ1SerializeSize(cbTxJ1))

	fmt.Println("actual size:", len(serialized))

	recovered, err := pp.DeserializeCbTxWitnessJ1(serialized)
	if err != nil {
		log.Fatal(err)
	}

	if !reflect.DeepEqual(cbTxJ1, recovered) {
		log.Fatal("Fail")
	}
}

func TestWriteCarryVectorRProof(t *testing.T) {
	pp := Initialize(nil)

	u_p, err := pp.randomDcIntegersInQcEtaF()
	if err != nil {
		log.Fatal(err)
	}
	u_p[0] = pp.paramEtaF
	u_p[1] = -u_p[0]
	u_p[2] = 1
	u_p[3] = -1
	u_p[4] = 0

	w := bytes.NewBuffer(make([]byte, 0, pp.paramDC))
	err = pp.writeCarryVectorRProof(w, u_p)
	if err != nil {
		log.Fatal(err)
	}

	serilazed := w.Bytes()

	fmt.Println("size:", len(serilazed))

	r := bytes.NewReader(serilazed)
	recovered, err := pp.readCarryVectorRProof(r)
	if err != nil {
		log.Fatal(err)
	}
	for i := 0; i < pp.paramDC; i++ {
		if recovered[i] != u_p[i] {
			log.Fatal("i:", i, "read:", recovered[i], "original:", u_p[i])
		}
	}
}

func TestSerializeCoinbaseTx(t *testing.T) {
	pp := Initialize(nil)
	seed1 := RandomBytes(pp.paramKeyGenSeedBytesLen)
	apk1, _, _ := pp.addressKeyGen(seed1)
	serializedVPk1, _, _ := pp.valueKeyGen(seed1)
	serializedAPk1, _ := pp.SerializeAddressPublicKey(apk1)

	seed2 := RandomBytes(pp.paramKeyGenSeedBytesLen)
	apk2, _, _ := pp.addressKeyGen(seed2)
	serializedVPk2, _, _ := pp.valueKeyGen(seed2)
	serializedAPk2, _ := pp.SerializeAddressPublicKey(apk2)

	seed3 := RandomBytes(pp.paramKeyGenSeedBytesLen)
	apk3, _, _ := pp.addressKeyGen(seed3)
	serializedVPk3, _, _ := pp.valueKeyGen(seed3)
	serializedAPk3, _ := pp.SerializeAddressPublicKey(apk3)

	seed4 := RandomBytes(pp.paramKeyGenSeedBytesLen)
	apk4, _, _ := pp.addressKeyGen(seed4)
	serializedVPk4, _, _ := pp.valueKeyGen(seed4)
	serializedAPk4, _ := pp.SerializeAddressPublicKey(apk4)

	seed5 := RandomBytes(pp.paramKeyGenSeedBytesLen)
	apk5, _, _ := pp.addressKeyGen(seed5)
	serializedVPk5, _, _ := pp.valueKeyGen(seed5)
	serializedAPk5, _ := pp.SerializeAddressPublicKey(apk5)

	type cbtxGenArgs struct {
		vin           uint64
		txOutputDescs []*TxOutputDesc
		txMemo        []byte
	}
	tests := []struct {
		name    string
		args    cbtxGenArgs
		wantErr bool
		want    bool
	}{
		{
			"test one",
			cbtxGenArgs{
				vin: 512,
				txOutputDescs: []*TxOutputDesc{
					{
						serializedAPk: serializedAPk1,
						serializedVPk: serializedVPk1,
						value:         512,
					},
				},
				txMemo: []byte{'1'},
			},
			false,
			true,
		},
		{
			"test two",
			cbtxGenArgs{
				vin: 512,
				txOutputDescs: []*TxOutputDesc{
					{
						serializedAPk: serializedAPk1,
						serializedVPk: serializedVPk1,
						value:         500,
					},
					{
						serializedAPk: serializedAPk2,
						serializedVPk: serializedVPk2,
						value:         12,
					},
				},
				txMemo: []byte{'2'},
			},
			false,
			true,
		},
		{
			"test five",
			cbtxGenArgs{
				vin: 1<<51 - 1,
				txOutputDescs: []*TxOutputDesc{
					{
						serializedAPk: serializedAPk1,
						serializedVPk: serializedVPk1,
						value:         1,
					},
					{
						serializedAPk: serializedAPk2,
						serializedVPk: serializedVPk2,
						value:         2,
					},
					{
						serializedAPk: serializedAPk3,
						serializedVPk: serializedVPk3,
						value:         3,
					},
					{
						serializedAPk: serializedAPk4,
						serializedVPk: serializedVPk4,
						value:         4,
					},
					{
						serializedAPk: serializedAPk5,
						serializedVPk: serializedVPk5,
						value:         1<<51 - 1 - 1 - 2 - 3 - 4,
					},
				},
				txMemo: []byte{'5'},
			},
			false,
			true,
		},
	}
	var cbTx *CoinbaseTx
	var err error
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cbTx, err = pp.coinbaseTxGen(tt.args.vin, tt.args.txOutputDescs, tt.args.txMemo)
			if (err != nil) != tt.wantErr {
				t.Errorf("coinbaseTxGen() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			serializedWithoutWitness, err := pp.SerializeCoinbaseTx(cbTx, false)
			serializedWithWitness, err := pp.SerializeCoinbaseTx(cbTx, true)
			ouputNum := len(cbTx.OutputTxos)
			fmt.Println("outputNum:", ouputNum)
			if ouputNum == 1 {
				fmt.Println("expected witness size:", pp.CbTxWitnessJ1SerializeSize(cbTx.TxWitnessJ1))

				serializedWitness, err := pp.SerializeCbTxWitnessJ1(cbTx.TxWitnessJ1)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Println("exact witness size:", len(serializedWitness))
				fmt.Println("approx witness size:", pp.CbTxWitnessJ1SerializeSizeApprox())

				exactSizeInTx := len(serializedWithWitness) - len(serializedWithoutWitness)
				fmt.Println("exact witness size in Tx:", exactSizeInTx)

				serTxo, err := pp.SerializeTxo(cbTx.OutputTxos[0])
				if err != nil {
					log.Fatal(err)
				}
				fmt.Println("exact txo size:", len(serTxo))
				fmt.Println("expected txo size:", pp.TxoSerializeSize())

			} else {
				fmt.Println("expected witness size:", pp.CbTxWitnessJ2SerializeSize(cbTx.TxWitnessJ2))
				serializedWitness, err := pp.SerializeCbTxWitnessJ2(cbTx.TxWitnessJ2)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Println("exact witness size:", len(serializedWitness))
				fmt.Println("approx witness size:", pp.CbTxWitnessJ2SerializeSizeApprox(ouputNum))

				exactSizeInTx := len(serializedWithWitness) - len(serializedWithoutWitness)
				fmt.Println("exact witness size in Tx:", exactSizeInTx)

				fmt.Println("expected rpf size:", pp.RpulpProofSerializeSize(cbTx.TxWitnessJ2.rpulpproof))
				serializedRpf, err := pp.SerializeRpulpProof(cbTx.TxWitnessJ2.rpulpproof)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Println("exact rpf size:", len(serializedRpf))
			}

			cbTxRe, err := pp.DeserializeCoinbaseTx(serializedWithWitness, true)
			if err != nil {
				log.Fatal(err)
			}

			got, err := pp.coinbaseTxVerify(cbTxRe)
			if (err != nil) != tt.wantErr {
				t.Errorf("coinbaseTxGen() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("coinbaseTxVerify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSerializeTransferTx(t *testing.T) {
	pp := Initialize(nil)

	seed1 := RandomBytes(pp.paramKeyGenSeedBytesLen)
	apk1, ask1, _ := pp.addressKeyGen(seed1)
	serializedASkSp1, _ := pp.SerializeAddressSecretKeySp(ask1.AddressSecretKeySp)
	serializedASkSn1, _ := pp.SerializeAddressSecretKeySn(ask1.AddressSecretKeySn)
	serializedVPk1, serializedVSk1, _ := pp.valueKeyGen(seed1)
	serializedAPk1, _ := pp.SerializeAddressPublicKey(apk1)

	if false {
		fmt.Println(len(serializedASkSp1))
		fmt.Println(len(serializedASkSn1))
		fmt.Println(len(serializedVSk1))
	}

	seed2 := RandomBytes(pp.paramKeyGenSeedBytesLen)
	apk2, ask2, _ := pp.addressKeyGen(seed2)
	serializedASkSp2, _ := pp.SerializeAddressSecretKeySp(ask2.AddressSecretKeySp)
	serializedASkSn2, _ := pp.SerializeAddressSecretKeySn(ask2.AddressSecretKeySn)
	serializedVPk2, serializedVSk2, _ := pp.valueKeyGen(seed2)
	serializedAPk2, _ := pp.SerializeAddressPublicKey(apk2)

	if false {
		fmt.Println(len(serializedASkSp2))
		fmt.Println(len(serializedASkSn2))
		fmt.Println(len(serializedVSk2))
	}

	seed3 := RandomBytes(pp.paramKeyGenSeedBytesLen)
	apk3, ask3, _ := pp.addressKeyGen(seed3)
	serializedASkSp3, _ := pp.SerializeAddressSecretKeySp(ask3.AddressSecretKeySp)
	serializedASkSn3, _ := pp.SerializeAddressSecretKeySn(ask3.AddressSecretKeySn)

	serializedVPk3, serializedVSk3, _ := pp.valueKeyGen(seed3)
	serializedAPk3, _ := pp.SerializeAddressPublicKey(apk3)

	if false {
		fmt.Println(len(serializedASkSp3))
		fmt.Println(len(serializedASkSn3))
		fmt.Println(len(serializedVSk3))
	}

	seed4 := RandomBytes(pp.paramKeyGenSeedBytesLen)
	apk4, ask4, _ := pp.addressKeyGen(seed4)
	serializedASkSp4, _ := pp.SerializeAddressSecretKeySp(ask4.AddressSecretKeySp)
	serializedASkSn4, _ := pp.SerializeAddressSecretKeySn(ask4.AddressSecretKeySn)
	serializedVPk4, serializedVSk4, _ := pp.valueKeyGen(seed4)
	serializedAPk4, _ := pp.SerializeAddressPublicKey(apk4)

	if false {
		fmt.Println(len(serializedASkSp4))
		fmt.Println(len(serializedASkSn4))
		fmt.Println(len(serializedVSk4))
	}

	seed5 := RandomBytes(pp.paramKeyGenSeedBytesLen)
	apk5, ask5, _ := pp.addressKeyGen(seed5)
	serializedASkSp5, _ := pp.SerializeAddressSecretKeySp(ask5.AddressSecretKeySp)
	serializedASkSn5, _ := pp.SerializeAddressSecretKeySn(ask5.AddressSecretKeySn)
	serializedVPk5, serializedVSk5, _ := pp.valueKeyGen(seed5)
	serializedAPk5, _ := pp.SerializeAddressPublicKey(apk5)

	if false {
		fmt.Println(len(serializedASkSp5))
		fmt.Println(len(serializedASkSn5))
		fmt.Println(len(serializedVSk5))
	}

	seed6 := RandomBytes(pp.paramKeyGenSeedBytesLen)
	apk6, ask6, _ := pp.addressKeyGen(seed6)
	serializedASkSp6, _ := pp.SerializeAddressSecretKeySp(ask6.AddressSecretKeySp)
	serializedASkSn6, _ := pp.SerializeAddressSecretKeySn(ask6.AddressSecretKeySn)
	serializedVPk6, serializedVSk6, _ := pp.valueKeyGen(seed6)
	serializedAPk6, _ := pp.SerializeAddressPublicKey(apk6)

	if false {
		fmt.Println(len(serializedASkSp6))
		fmt.Println(len(serializedASkSn6))
		fmt.Println(len(serializedVSk6))
		fmt.Println(len(serializedVPk6))
		fmt.Println(len(serializedAPk6))
	}

	seed7 := RandomBytes(pp.paramKeyGenSeedBytesLen)
	apk7, ask7, _ := pp.addressKeyGen(seed7)
	serializedASkSp7, _ := pp.SerializeAddressSecretKeySp(ask7.AddressSecretKeySp)
	serializedASkSn7, _ := pp.SerializeAddressSecretKeySn(ask7.AddressSecretKeySn)
	serializedVPk7, serializedVSk7, _ := pp.valueKeyGen(seed7)
	serializedAPk7, _ := pp.SerializeAddressPublicKey(apk7)

	if false {
		fmt.Println(len(serializedASkSp7))
		fmt.Println(len(serializedASkSn7))
		fmt.Println(len(serializedVSk7))
		fmt.Println(len(serializedVPk7))
		fmt.Println(len(serializedAPk7))
	}

	var cbTx0, cbTx1 *CoinbaseTx

	type cbtxGenArgs struct {
		vin           uint64
		txOutputDescs []*TxOutputDesc
		txMemo        []byte
	}
	testsCb := []struct {
		name    string
		args    cbtxGenArgs
		wantErr bool
		want    bool
	}{
		{
			"test output 5",
			cbtxGenArgs{
				vin: 2500,
				txOutputDescs: []*TxOutputDesc{
					{
						serializedAPk: serializedAPk1,
						serializedVPk: serializedVPk1,
						value:         600,
					},
					{
						serializedAPk: serializedAPk2,
						serializedVPk: serializedVPk2,
						value:         700,
					},
					{
						serializedAPk: serializedAPk3,
						serializedVPk: serializedVPk3,
						value:         300,
					},
					{
						serializedAPk: serializedAPk4,
						serializedVPk: serializedVPk4,
						value:         400,
					},
					{
						serializedAPk: serializedAPk5,
						serializedVPk: serializedVPk5,
						value:         500,
					},
				},
				txMemo: []byte{'c', 'b', 't', 'x'},
			},
			false,
			true,
		},

		{
			"test output 2",
			cbtxGenArgs{
				vin: 1300,
				txOutputDescs: []*TxOutputDesc{
					{
						serializedAPk: serializedAPk1,
						serializedVPk: serializedVPk1,
						value:         600,
					},
					{
						serializedAPk: serializedAPk2,
						serializedVPk: serializedVPk2,
						value:         700,
					},
				},
				txMemo: []byte{'c', 'b', 't', 'x'},
			},
			false,
			true,
		},
	}

	var err error
	//	for _, tt := range testsCb {
	tt := testsCb[0]
	t.Run(tt.name, func(t *testing.T) {
		cbTx0, err = pp.coinbaseTxGen(tt.args.vin, tt.args.txOutputDescs, tt.args.txMemo)
		if (err != nil) != tt.wantErr {
			t.Errorf("coinbaseTxGen() error = %v, wantErr %v", err, tt.wantErr)
			return
		}
		//serializedWithWitness0, err := pp.SerializeCoinbaseTx(cbTx0, true)
		//
		//cbTxRe0, err := pp.DeserializeCoinbaseTx(serializedWithWitness0, true)
		//if err != nil {
		//	log.Fatal(err)
		//}
		//
		//if !reflect.DeepEqual(cbTx0, cbTxRe0) {
		//	log.Fatal("deserialized does not equal to the original")
		//}
		//
		//got0, err := pp.coinbaseTxVerify(cbTxRe0)
		//if (err != nil) != tt.wantErr {
		//	t.Errorf("coinbaseTxGen() error = %v, wantErr %v", err, tt.wantErr)
		//	return
		//}
		//if got0 != tt.want {
		//	t.Errorf("coinbaseTxVerify() = %v, want %v", got0, tt.want)
		//}
	})
	//	}

	tt = testsCb[1]
	t.Run(tt.name, func(t *testing.T) {
		cbTx1, err = pp.coinbaseTxGen(tt.args.vin, tt.args.txOutputDescs, tt.args.txMemo)
		if (err != nil) != tt.wantErr {
			t.Errorf("coinbaseTxGen() error = %v, wantErr %v", err, tt.wantErr)
			return
		}
		//		serializedWithWitness1, err := pp.SerializeCoinbaseTx(cbTx1, true)

		//cbTxRe1, err := pp.DeserializeCoinbaseTx(serializedWithWitness1, true)
		//if err != nil {
		//	log.Fatal(err)
		//}

		//if !reflect.DeepEqual(cbTx1, cbTxRe1) {
		//	log.Fatal("deserialized does not equal to the original")
		//}

		//got1, err := pp.coinbaseTxVerify(cbTxRe1)
		//if (err != nil) != tt.wantErr {
		//	t.Errorf("coinbaseTxGen() error = %v, wantErr %v", err, tt.wantErr)
		//	return
		//}
		//if got1 != tt.want {
		//	t.Errorf("coinbaseTxVerify() = %v, want %v", got1, tt.want)
		//}
	})

	type TrTxArgs struct {
		inputDescs  []*TxInputDesc
		outputDescs []*TxOutputDesc
		fee         uint64
		txMemo      []byte
	}

	testTrTxs := []struct {
		name    string
		args    TrTxArgs
		wantErr bool
		want    bool
	}{
		// TODO: Add test cases.
		//{
		//	name: "test 1-2",
		//	args: TrTxArgs{
		//		inputDescs: []*TxInputDesc{
		//			{
		//				lgrTxoList: []*LgrTxo{
		//					{
		//						txo: cbTx0.OutputTxos[1],
		//						id:  make([]byte, HashOutputBytesLen),
		//					},
		//					{
		//						txo: cbTx0.OutputTxos[0],
		//						id:  make([]byte, HashOutputBytesLen),
		//					},
		//				},
		//				sidx:            0,
		//				serializedASksp: serializedASkSp2,
		//				serializedASksn: serializedASkSn2,
		//				serializedVPk:   serializedVPk2,
		//				serializedVSk:   serializedVSk2,
		//				value:           700,
		//			},
		//		},
		//		outputDescs: []*TxOutputDesc{
		//			{
		//				serializedAPk: serializedAPk1,
		//				serializedVPk: serializedVPk1,
		//				value:         150,
		//			},
		//			{
		//				serializedAPk: serializedAPk2,
		//				serializedVPk: serializedVPk2,
		//				value:         250,
		//			},
		//		},
		//		fee:    300,
		//		txMemo: []byte{},
		//	},
		//	wantErr: false,
		//	want:    true,
		//},
		//{
		//	name: "test 2-2",
		//	args: TrTxArgs{
		//		inputDescs: []*TxInputDesc{
		//			{
		//				lgrTxoList: []*LgrTxo{
		//					{
		//						txo: cbTx1.OutputTxos[0],
		//						id:  make([]byte, HashOutputBytesLen),
		//					},
		//					{
		//						txo: cbTx1.OutputTxos[1],
		//						id:  make([]byte, HashOutputBytesLen),
		//					},
		//				},
		//				sidx:            0,
		//				serializedASksp: serializedASkSp1,
		//				serializedASksn: serializedASkSn1,
		//				serializedVPk:   serializedVPk1,
		//				serializedVSk:   serializedVSk1,
		//				value:           600,
		//			},
		//			{
		//				lgrTxoList: []*LgrTxo{
		//					{
		//						txo: cbTx1.OutputTxos[0],
		//						id:  make([]byte, HashOutputBytesLen),
		//					},
		//					{
		//						txo: cbTx1.OutputTxos[1],
		//						id:  make([]byte, HashOutputBytesLen),
		//					},
		//				},
		//				sidx:            1,
		//				serializedASksp: serializedASkSp2,
		//				serializedASksn: serializedASkSn2,
		//				serializedVPk:   serializedVPk2,
		//				serializedVSk:   serializedVSk2,
		//				value:           700,
		//			},
		//		},
		//		outputDescs: []*TxOutputDesc{
		//			{
		//				serializedAPk: serializedAPk1,
		//				serializedVPk: serializedVPk1,
		//				value:         1000,
		//			},
		//			{
		//				serializedAPk: serializedAPk2,
		//				serializedVPk: serializedVPk2,
		//				value:         200,
		//			},
		//		},
		//		fee:    100,
		//		txMemo: []byte{},
		//	},
		//	wantErr: false,
		//	want:    true,
		//},
		//{
		//	name: "test 1(7)-2",
		//	args: TrTxArgs{
		//		inputDescs: []*TxInputDesc{
		//			{
		//				lgrTxoList: []*LgrTxo{
		//					{
		//						txo: cbTx0.OutputTxos[0],
		//						id:  make([]byte, HashOutputBytesLen),
		//					},
		//					{
		//						txo: cbTx0.OutputTxos[1],
		//						id:  make([]byte, HashOutputBytesLen),
		//					},
		//					{
		//						txo: cbTx0.OutputTxos[2],
		//						id:  make([]byte, HashOutputBytesLen),
		//					},
		//					{
		//						txo: cbTx0.OutputTxos[3],
		//						id:  make([]byte, HashOutputBytesLen),
		//					},
		//					{
		//						txo: cbTx0.OutputTxos[4],
		//						id:  make([]byte, HashOutputBytesLen),
		//					},
		//					{
		//						txo: cbTx1.OutputTxos[0],
		//						id:  make([]byte, HashOutputBytesLen),
		//					},
		//					{
		//						txo: cbTx1.OutputTxos[1],
		//						id:  make([]byte, HashOutputBytesLen),
		//					},
		//				},
		//				sidx:            0,
		//				serializedASksp: serializedASkSp1,
		//				serializedASksn: serializedASkSn1,
		//				serializedVPk:   serializedVPk1,
		//				serializedVSk:   serializedVSk1,
		//				value:           600,
		//			},
		//		},
		//		outputDescs: []*TxOutputDesc{
		//			{
		//				serializedAPk: serializedAPk1,
		//				serializedVPk: serializedVPk1,
		//				value:         200,
		//			},
		//			{
		//				serializedAPk: serializedAPk2,
		//				serializedVPk: serializedVPk2,
		//				value:         250,
		//			},
		//		},
		//		fee:    150,
		//		txMemo: []byte{},
		//	},
		//	wantErr: false,
		//	want:    true,
		//},
		{
			name: "test 5(7)-5",
			args: TrTxArgs{
				inputDescs: []*TxInputDesc{
					{
						lgrTxoList: []*LgrTxo{
							{
								txo: cbTx0.OutputTxos[0],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTx0.OutputTxos[1],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTx0.OutputTxos[2],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTx0.OutputTxos[3],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTx0.OutputTxos[4],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTx1.OutputTxos[0],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTx1.OutputTxos[1],
								id:  make([]byte, HashOutputBytesLen),
							},
						},
						sidx:            0,
						serializedASksp: serializedASkSp1,
						serializedASksn: serializedASkSn1,
						serializedVPk:   serializedVPk1,
						serializedVSk:   serializedVSk1,
						value:           600,
					},
					{
						lgrTxoList: []*LgrTxo{
							{
								txo: cbTx0.OutputTxos[0],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTx0.OutputTxos[1],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTx0.OutputTxos[2],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTx0.OutputTxos[3],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTx0.OutputTxos[4],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTx1.OutputTxos[0],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTx1.OutputTxos[1],
								id:  make([]byte, HashOutputBytesLen),
							},
						},
						sidx:            1,
						serializedASksp: serializedASkSp2,
						serializedASksn: serializedASkSn2,
						serializedVPk:   serializedVPk2,
						serializedVSk:   serializedVSk2,
						value:           700,
					},
					{
						lgrTxoList: []*LgrTxo{
							{
								txo: cbTx0.OutputTxos[0],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTx0.OutputTxos[1],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTx0.OutputTxos[2],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTx0.OutputTxos[3],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTx0.OutputTxos[4],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTx1.OutputTxos[0],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTx1.OutputTxos[1],
								id:  make([]byte, HashOutputBytesLen),
							},
						},
						sidx:            2,
						serializedASksp: serializedASkSp3,
						serializedASksn: serializedASkSn3,
						serializedVPk:   serializedVPk3,
						serializedVSk:   serializedVSk3,
						value:           300,
					},
					{
						lgrTxoList: []*LgrTxo{
							{
								txo: cbTx0.OutputTxos[0],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTx0.OutputTxos[1],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTx0.OutputTxos[2],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTx0.OutputTxos[3],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTx0.OutputTxos[4],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTx1.OutputTxos[0],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTx1.OutputTxos[1],
								id:  make([]byte, HashOutputBytesLen),
							},
						},
						sidx:            3,
						serializedASksp: serializedASkSp4,
						serializedASksn: serializedASkSn4,
						serializedVPk:   serializedVPk4,
						serializedVSk:   serializedVSk4,
						value:           400,
					},
					{
						lgrTxoList: []*LgrTxo{
							{
								txo: cbTx0.OutputTxos[0],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTx0.OutputTxos[1],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTx0.OutputTxos[2],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTx0.OutputTxos[3],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTx0.OutputTxos[4],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTx1.OutputTxos[0],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTx1.OutputTxos[1],
								id:  make([]byte, HashOutputBytesLen),
							},
						},
						sidx:            4,
						serializedASksp: serializedASkSp5,
						serializedASksn: serializedASkSn5,
						serializedVPk:   serializedVPk5,
						serializedVSk:   serializedVSk5,
						value:           500,
					},
				},
				outputDescs: []*TxOutputDesc{
					{
						serializedAPk: serializedAPk1,
						serializedVPk: serializedVPk1,
						value:         300,
					},
					{
						serializedAPk: serializedAPk2,
						serializedVPk: serializedVPk2,
						value:         400,
					},
					{
						serializedAPk: serializedAPk3,
						serializedVPk: serializedVPk3,
						value:         500,
					},
					{
						serializedAPk: serializedAPk4,
						serializedVPk: serializedVPk4,
						value:         600,
					},
					{
						serializedAPk: serializedAPk5,
						serializedVPk: serializedVPk5,
						value:         650,
					},
				},
				fee:    50,
				txMemo: []byte{},
			},
			wantErr: false,
			want:    true,
		},
	}
	for _, tt := range testTrTxs {
		t.Run(tt.name, func(t *testing.T) {
			trTx, err := pp.transferTxGen(tt.args.inputDescs, tt.args.outputDescs, tt.args.fee, tt.args.txMemo)
			if (err != nil) != tt.wantErr {
				t.Errorf("transferTxGen() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			serializedtrTx, err := pp.SerializeTransferTx(trTx, true)
			if err != nil {
				t.Errorf(err.Error())
			}

			fmt.Println(len(serializedtrTx))

			trTxDeser, err := pp.DeserializeTransferTx(serializedtrTx, true)
			if err != nil {
				t.Errorf(err.Error())
			}

			//if !reflect.DeepEqual(trTxDeser, trTx) {
			//	log.Fatal("deserialzed does not equal the original")
			//}

			ringSizes := make([]int, len(trTxDeser.Inputs))
			for i := 0; i < len(trTxDeser.Inputs); i++ {
				ringSizes[i] = len(trTxDeser.Inputs[i].TxoList)
			}
			fmt.Println("TrTxWitnessSizeApprox:", pp.TrTxWitnessSerializeSizeApprox(ringSizes, len(trTxDeser.OutputTxos)))
			fmt.Println("TrTxWitnessSizeExact:", pp.TrTxWitnessSerializeSize(trTxDeser.TxWitness))
			serWitness, err := pp.SerializeTrTxWitness(trTxDeser.TxWitness)
			fmt.Println("TrTxWitnessSizeActual:", len(serWitness))

			fmt.Println("RpulpProofSizeExpected:", pp.RpulpProofSerializeSize(trTxDeser.TxWitness.rpulpproof))
			serRpf, err := pp.SerializeRpulpProof(trTxDeser.TxWitness.rpulpproof)
			fmt.Println("RpulpProofSizeActual:", len(serRpf))

			serElsSig, err := pp.SerializeElrsSignature(trTxDeser.TxWitness.elrsSigs[0])
			fmt.Println("ElrsSig Approx Size:", pp.ElrsSignatureSerializeSizeApprox(7))
			fmt.Println("ElrsSig Expected Size:", pp.ElrsSignatureSerializeSize(trTxDeser.TxWitness.elrsSigs[0]))
			fmt.Println("ElrsSig Actual Size:", len(serElsSig))

			got, err := pp.transferTxVerify(trTxDeser)
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

// new test case end
//
//func TestSerializeTxoValue(t *testing.T) {
//	pp := DefaultPP
//
//	value := uint64(123456789)
//	fmt.Println(value, "pvalue")
//
//	seed := make([]byte, 7)
//	for i := 0; i < 7; i++ {
//		seed[i] = byte(i)
//	}
//
//	sk, err := pp.expandValuePadRandomness(seed)
//
//	vbytes, err := pp.encodeTxoValueToBytes(value)
//	if err != nil {
//		log.Fatalln(err)
//	}
//
//	rst := make([]byte, pp.TxoValueBytesLen())
//	for i := 0; i < pp.TxoValueBytesLen(); i++ {
//		rst[i] = vbytes[i] ^ sk[i]
//	}
//	cipherValue, err := pp.decodeTxoValueFromBytes(rst)
//	if err != nil {
//		log.Fatalln(err)
//	}
//	fmt.Println(cipherValue, "cvalue")
//
//	skr, err := pp.expandValuePadRandomness(seed)
//
//	recover := make([]byte, pp.TxoValueBytesLen())
//	for i := 0; i < pp.TxoValueBytesLen(); i++ {
//		recover[i] = rst[i] ^ skr[i]
//	}
//	recoverValue, err := pp.decodeTxoValueFromBytes(recover)
//	if err != nil {
//		log.Fatalln(err)
//	}
//	fmt.Println(recoverValue, "revalue")
//
//}
//
//func TestPublicParameter_writePolyANTT_readPolyANTT(t *testing.T) {
//	pp := DefaultPP
//	seed := make([]byte, pp.paramKeyGenSeedBytesLen)
//	tmp := pp.randomDaIntegersInQa(seed)
//	a := &PolyANTT{coeffs: tmp}
//	w := bytes.NewBuffer(make([]byte, 0, pp.paramDA*8))
//	err := pp.writePolyANTT(w, a)
//	if err != nil {
//		log.Fatalln(err)
//	}
//	serializedA := w.Bytes()
//	r := bytes.NewReader(serializedA)
//	got, err := pp.readPolyANTT(r)
//	if err != nil {
//		log.Fatalln(err)
//	}
//	for i := 0; i < pp.paramDA; i++ {
//		if got.coeffs[i] != a.coeffs[i] {
//			t.Fatal("i=", i, " got[i]=", got.coeffs[i], " origin[i]=", a.coeffs[i])
//		}
//	}
//}
//func TestPublicParameter_writePolyCNTT_readPolyCNTT(t *testing.T) {
//	pp := DefaultPP
//	seed := make([]byte, pp.paramKeyGenSeedBytesLen)
//	tmp := pp.randomDcIntegersInQc(seed)
//	a := &PolyCNTT{coeffs: tmp}
//	w := bytes.NewBuffer(make([]byte, 0, pp.paramDC*8))
//	err := pp.writePolyCNTT(w, a)
//	if err != nil {
//		log.Fatalln(err)
//	}
//	//for i := 0; i < pp.paramDC; i++ {
//	//	fmt.Println(a.coeffs[i])
//	//}
//	//fmt.Println("wait")
//	serializedA := w.Bytes()
//	r := bytes.NewReader(serializedA)
//	got, err := pp.readPolyCNTT(r)
//	if err != nil {
//		log.Fatalln(err)
//	}
//	//for i := 0; i < pp.paramDC; i++ {
//	//	fmt.Println(got.coeffs[i])
//	//}
//	for i := 0; i < pp.paramDC; i++ {
//		if got.coeffs[i] != a.coeffs[i] {
//			t.Fatal("i=", i, " got[i]=", got.coeffs[i], " origin[i]=", a.coeffs[i])
//		}
//	}
//}
//
//func TestPublicParameter_writePolyANTTVec_readPolyANTTVec(t *testing.T) {
//	pp := DefaultPP
//	as := pp.NewPolyANTTVec(pp.paramLA)
//	for i := 0; i < pp.paramLA; i++ {
//		seed := RandomBytes(pp.paramKeyGenSeedBytesLen)
//		tmp := pp.randomDaIntegersInQa(seed)
//		as.polyANTTs[i] = &PolyANTT{coeffs: tmp}
//	}
//	w := bytes.NewBuffer(make([]byte, 0, pp.PolyANTTVecSerializeSize(as)))
//	err := pp.writePolyANTTVec(w, as)
//	if err != nil {
//		log.Fatalln(err)
//	}
//	serializedA := w.Bytes()
//	r := bytes.NewReader(serializedA)
//	got, err := pp.readPolyANTTVec(r)
//	if err != nil {
//		log.Fatalln(err)
//	}
//	for i := 0; i < pp.paramLA; i++ {
//		for j := 0; j < pp.paramDA; j++ {
//			if got.polyANTTs[i].coeffs[j] != as.polyANTTs[i].coeffs[j] {
//				t.Fatal("j=", j, " got[i][j]=", got.polyANTTs[i].coeffs[j], " origin[i][j]=", as.polyANTTs[i].coeffs[j])
//			}
//		}
//	}
//}
//func TestPublicParameter_writePolyCNTTVec_readPolyCNTTVec(t *testing.T) {
//	pp := DefaultPP
//	as := pp.NewPolyCNTTVec(pp.paramLC)
//	for i := 0; i < pp.paramLC; i++ {
//		seed := RandomBytes(pp.paramKeyGenSeedBytesLen)
//		tmp := pp.randomDcIntegersInQc(seed)
//		as.polyCNTTs[i] = &PolyCNTT{coeffs: tmp}
//	}
//	w := bytes.NewBuffer(make([]byte, 0, pp.PolyCNTTVecSerializeSize(as)))
//	err := pp.writePolyCNTTVec(w, as)
//	if err != nil {
//		log.Fatalln(err)
//	}
//	serializedC := w.Bytes()
//	r := bytes.NewReader(serializedC)
//	got, err := pp.readPolyCNTTVec(r)
//	if err != nil {
//		log.Fatalln(err)
//	}
//	for i := 0; i < pp.paramLC; i++ {
//		for j := 0; j < pp.paramDC; j++ {
//			if got.polyCNTTs[i].coeffs[j] != as.polyCNTTs[i].coeffs[j] {
//				t.Fatal("j=", j, " got[i][j]=", got.polyCNTTs[i].coeffs[j], " origin[i][j]=", as.polyCNTTs[i].coeffs[j])
//			}
//		}
//	}
//}
//
//func TestPublicParameter_writePolyAVecEta_readPolyAVecEta(t *testing.T) {
//	pp := DefaultPP
//	var err error
//	as := pp.NewPolyAVec(pp.paramLA)
//	for i := 0; i < pp.paramLA; i++ {
//		//	seed := RandomBytes(pp.paramKeyGenSeedBytesLen)
//		as.polyAs[i], err = pp.randomPolyAinEtaA()
//		if err != nil {
//			log.Fatalln(err)
//		}
//	}
//
//	w := bytes.NewBuffer(make([]byte, 0, pp.PolyAVecSerializeSizeEta(as)))
//	err = pp.writePolyAVecEta(w, as)
//	if err != nil {
//		log.Fatalln(err)
//	}
//
//	serializedA := w.Bytes()
//	r := bytes.NewReader(serializedA)
//	got, err := pp.readPolyAVecEta(r)
//	if err != nil {
//		log.Fatalln(err)
//	}
//	for i := 0; i < pp.paramLA; i++ {
//		for j := 0; j < pp.paramDA; j++ {
//			if got.polyAs[i].coeffs[j] != as.polyAs[i].coeffs[j] {
//				t.Fatal("j=", j, " got[i][j]=", got.polyAs[i].coeffs[j], " origin[i][j]=", as.polyAs[i].coeffs[j])
//			}
//		}
//	}
//}
//
//func TestPublicParameter_writePolyAGamma_readPolyAGamma(t *testing.T) {
//	pp := DefaultPP
//	seed := RandomBytes(pp.paramKeyGenSeedBytesLen)
//	as, err := pp.randomPolyAinGammaA2(seed)
//	if err != nil {
//		log.Fatalln(err)
//	}
//
//	w := bytes.NewBuffer(make([]byte, 0, pp.PolyASerializeSizeGamma()))
//	err = pp.writePolyAGamma(w, as)
//	if err != nil {
//		log.Fatalln(err)
//	}
//
//	serializedA := w.Bytes()
//	r := bytes.NewReader(serializedA)
//	got, err := pp.readPolyAGamma(r)
//	if err != nil {
//		log.Fatalln(err)
//	}
//	for j := 0; j < pp.paramDA; j++ {
//		if got.coeffs[j] != as.coeffs[j] {
//			t.Fatal("j=", j, " got[i][j]=", got.coeffs[j], " origin[i][j]=", as.coeffs[j])
//		}
//	}
//}

//func TestPublicParameter_writePolyAVecGamma_readPolyAVecGamma(t *testing.T) {
//	pp :=  Initialize(nil)
//	as := pp.NewPolyAVec(pp.paramLA)
//	for i := 0; i < pp.paramLA; i++ {
//		seed := RandomBytes(pp.paramKeyGenSeedBytesLen)
//		tmp, err := randomPolyAinGammaA2(seed, pp.paramDA)
//		if err != nil {
//			log.Fatalln(err)
//		}
//		as.polyAs[i] = &PolyA{coeffs: tmp}
//	}
//
//	w := bytes.NewBuffer(make([]byte, 0, pp.PolyAVecSerializeSizeGamma(as)))
//	err := pp.writePolyAVecGamma(w, as)
//	if err != nil {
//		log.Fatalln(err)
//	}
//
//	serializedA := w.Bytes()
//	r := bytes.NewReader(serializedA)
//	got, err := pp.readPolyAVecGamma(r)
//	if err != nil {
//		log.Fatalln(err)
//	}
//	for i := 0; i < pp.paramLA; i++ {
//		for j := 0; j < pp.paramDA; j++ {
//			if got.polyAs[i].coeffs[j] != as.polyAs[i].coeffs[j] {
//				t.Fatal("j=", j, " got[i][j]=", got.polyAs[i].coeffs[j], " origin[i][j]=", as.polyAs[i].coeffs[j])
//			}
//		}
//	}
//}

func TestPublicParameter_writePolyCVecEta_readPolyCVecEta(t *testing.T) {
	pp := Initialize(nil)
	var err error
	as := pp.NewPolyCVec(pp.paramLC)
	for i := 0; i < pp.paramLC; i++ {
		//seed := RandomBytes(pp.paramKeyGenSeedBytesLen)
		as.polyCs[i], err = pp.randomPolyCinEtaC()
		if err != nil {
			log.Fatalln(err)
		}
	}

	w := bytes.NewBuffer(make([]byte, 0, pp.PolyCVecSerializeSizeEta(as)))
	err = pp.writePolyCVecEta(w, as)
	if err != nil {
		log.Fatalln(err)
	}

	serializedC := w.Bytes()
	r := bytes.NewReader(serializedC)
	got, err := pp.readPolyCVecEta(r)
	if err != nil {
		log.Fatalln(err)
	}
	for i := 0; i < pp.paramLC; i++ {
		for j := 0; j < pp.paramDC; j++ {
			if got.polyCs[i].coeffs[j] != as.polyCs[i].coeffs[j] {
				t.Fatal("i=", i, "j=", j, " got[i][j]=", got.polyCs[i].coeffs[j], " origin[i][j]=", as.polyCs[i].coeffs[j])
			}
		}
	}
}

func TestPublicParameter_SerializeAddressSecretSpAndSnKey_DeserializeAddressSecretSpAndSnKey(t *testing.T) {
	pp := Initialize(nil)
	ts := pp.NewPolyAVec(pp.paramLA)
	for i := 0; i < pp.paramLA; i++ {
		seed := RandomBytes(pp.paramKeyGenSeedBytesLen)
		tmp, err := pp.randomPolyAinGammaA2(seed)
		if err != nil {
			log.Fatalln(err)
		}
		ts.polyAs[i] = tmp
	}
	var e *PolyANTT
	seed := RandomBytes(pp.paramKeyGenSeedBytesLen)
	tmp, err := pp.randomDaIntegersInQa(seed)
	if err != nil {
		log.Fatal(err)
	}
	e = &PolyANTT{coeffs: tmp}

	asksp := &AddressSecretKeySp{ts}
	asksn := &AddressSecretKeySn{e}

	serializedAskSp, err := pp.SerializeAddressSecretKeySp(asksp)
	if err != nil {
		log.Fatalln(err)
	}
	got, err := pp.DeserializeAddressSecretKeySp(serializedAskSp)
	if err != nil {
		log.Fatalln(err)
	}
	for i := 0; i < len(got.s.polyAs); i++ {
		for j := 0; j < len(got.s.polyAs[i].coeffs); j++ {
			if got.s.polyAs[i].coeffs[j] != asksp.s.polyAs[i].coeffs[j] {
				t.Fatal("j=", j, " got[i][j]=", got.s.polyAs[i].coeffs[j], " origin[i][j]=", asksp.s.polyAs[i].coeffs[j])
			}
		}
	}

	serializedAskSn, err := pp.SerializeAddressSecretKeySn(asksn)
	if err != nil {
		log.Fatalln(err)
	}
	gotsn, err := pp.DeserializeAddressSecretKeySn(serializedAskSn)
	if err != nil {
		log.Fatalln(err)
	}
	for i := 0; i < len(gotsn.ma.coeffs); i++ {
		if gotsn.ma.coeffs[i] != asksn.ma.coeffs[i] {
			t.Fatal("i=", i, " gotsn[i]=", gotsn.ma.coeffs[i], " origin[i]=", asksn.ma.coeffs[i])
		}
	}
}

func TestPublicParameter_SerializeValueCommitment_DeserializeValueCommitment(t *testing.T) {
	pp := Initialize(nil)
	b := pp.NewPolyCNTTVec(pp.paramKC)
	for i := 0; i < pp.paramKC; i++ {
		seed := RandomBytes(pp.paramKeyGenSeedBytesLen)
		tmp, err := pp.randomDcIntegersInQc(seed)
		if err != nil {
			log.Fatal(err)
		}
		b.polyCNTTs[i] = &PolyCNTT{coeffs: tmp}
	}
	var c *PolyCNTT
	seed := RandomBytes(pp.paramKeyGenSeedBytesLen)
	tmp, err := pp.randomDcIntegersInQc(seed)
	if err != nil {
		log.Fatal(err)
	}
	c = &PolyCNTT{coeffs: tmp}

	vcmt := &ValueCommitment{
		b: b,
		c: c,
	}

	serializedVCmt, err := pp.SerializeValueCommitment(vcmt)
	if err != nil {
		log.Fatalln(err)
	}
	got, err := pp.DeserializeValueCommitment(serializedVCmt)
	if err != nil {
		log.Fatalln(err)
	}
	for i := 0; i < len(got.b.polyCNTTs); i++ {
		for j := 0; j < len(got.b.polyCNTTs[i].coeffs); j++ {
			if got.b.polyCNTTs[i].coeffs[j] != vcmt.b.polyCNTTs[i].coeffs[j] {
				t.Fatal("j=", j, " got[i][j]=", got.b.polyCNTTs[i].coeffs[j], " origin[i][j]=", vcmt.b.polyCNTTs[i].coeffs[j])
			}
		}
	}
	fmt.Println("------------------------------")
	for i := 0; i < len(got.c.coeffs); i++ {
		if got.c.coeffs[i] != vcmt.c.coeffs[i] {
			t.Fatal("i=", i, " got[i]=", got.c.coeffs[i], " origin[i]=", vcmt.c.coeffs[i])
		}
	}
}

func TestPublicParameter_SerializeAddressPublicKey(t *testing.T) {
	pp := Initialize(nil)
	ts := pp.NewPolyANTTVec(pp.paramKA)
	for i := 0; i < pp.paramKA; i++ {
		seed := RandomBytes(pp.paramKeyGenSeedBytesLen)
		tmp, err := pp.randomDaIntegersInQa(seed)
		if err != nil {
			log.Fatal(err)
		}
		ts.polyANTTs[i] = &PolyANTT{coeffs: tmp}
	}
	var e *PolyANTT
	seed := RandomBytes(pp.paramKeyGenSeedBytesLen)
	tmp, err := pp.randomDaIntegersInQa(seed)
	if err != nil {
		log.Fatal(err)
	}
	e = &PolyANTT{coeffs: tmp}

	apk := &AddressPublicKey{
		t: ts,
		e: e,
	}

	serializedApk, err := pp.SerializeAddressPublicKey(apk)
	if err != nil {
		log.Fatalln(err)
	}
	got, err := pp.DeserializeAddressPublicKey(serializedApk)
	if err != nil {
		log.Fatalln(err)
	}
	for i := 0; i < len(got.t.polyANTTs); i++ {
		for j := 0; j < len(got.t.polyANTTs[i].coeffs); j++ {
			if got.t.polyANTTs[i].coeffs[j] != apk.t.polyANTTs[i].coeffs[j] {
				t.Fatal("j=", j, " got[i][j]=", got.t.polyANTTs[i].coeffs[j], " origin[i][j]=", apk.t.polyANTTs[i].coeffs[j])
			}
		}
	}
	for i := 0; i < len(got.e.coeffs); i++ {
		if got.e.coeffs[i] != apk.e.coeffs[i] {
			t.Fatal("i=", i, " got[i]=", got.e.coeffs[i], " origin[i]=", apk.e.coeffs[i])
		}
	}
}

func TestPublicParameter_SerializeTxo_DeserializeTxo(t *testing.T) {
	var seed []byte
	pp := Initialize(nil)
	ts := pp.NewPolyANTTVec(pp.paramKA)
	for i := 0; i < pp.paramKA; i++ {
		seed = RandomBytes(pp.paramKeyGenSeedBytesLen)
		tmp, err := pp.randomDaIntegersInQa(seed)
		if err != nil {
			log.Fatal(err)
		}
		ts.polyANTTs[i] = &PolyANTT{coeffs: tmp}
	}
	var e *PolyANTT
	seed = RandomBytes(pp.paramKeyGenSeedBytesLen)
	tmp, err := pp.randomDaIntegersInQa(nil)
	if err != nil {
		log.Fatal(err)
	}
	e = &PolyANTT{coeffs: tmp}

	apk := &AddressPublicKey{
		t: ts,
		e: e,
	}

	b := pp.NewPolyCNTTVec(pp.paramKC)
	for i := 0; i < pp.paramKC; i++ {
		seed = RandomBytes(pp.paramKeyGenSeedBytesLen)
		tmp, err := pp.randomDcIntegersInQc(seed)
		if err != nil {
			log.Fatal(err)
		}
		b.polyCNTTs[i] = &PolyCNTT{coeffs: tmp}
	}
	var c *PolyCNTT
	seed = RandomBytes(pp.paramKeyGenSeedBytesLen)
	tmp, err = pp.randomDcIntegersInQc(seed)
	if err != nil {
		log.Fatal(err)
	}
	c = &PolyCNTT{coeffs: tmp}

	vcmt := &ValueCommitment{
		b: b,
		c: c,
	}

	value := uint64(123)
	vct, err := pp.encodeTxoValueToBytes(value)
	if err != nil {
		log.Fatalln(err)
	}

	Ckem := RandomBytes(pqringctkem.GetKemCiphertextBytesLen(pp.paramKem))

	txo := &Txo{
		AddressPublicKey: apk,
		ValueCommitment:  vcmt,
		Vct:              vct,
		CtKemSerialized:  Ckem,
	}

	serializedTxo, err := pp.SerializeTxo(txo)
	if err != nil {
		log.Fatalln(err)
	}
	got, err := pp.DeserializeTxo(serializedTxo)
	if err != nil {
		log.Fatalln(err)
	}
	equal := reflect.DeepEqual(got, txo)
	if !equal {
		t.Fatal("error for serialize and deserialize txo")
	}

}

func TestPublicParameter_SerializeLgrTxo_DeserializeLgrTxo(t *testing.T) {
	var seed []byte
	pp := Initialize(nil)
	ts := pp.NewPolyANTTVec(pp.paramKA)
	for i := 0; i < pp.paramKA; i++ {
		seed = RandomBytes(pp.paramKeyGenSeedBytesLen)
		tmp, err := pp.randomDaIntegersInQa(seed)
		if err != nil {
			log.Fatal(err)
		}
		ts.polyANTTs[i] = &PolyANTT{coeffs: tmp}
	}
	var e *PolyANTT
	seed = RandomBytes(pp.paramKeyGenSeedBytesLen)
	tmp, err := pp.randomDaIntegersInQa(nil)
	if err != nil {
		log.Fatal(err)
	}
	e = &PolyANTT{coeffs: tmp}

	apk := &AddressPublicKey{
		t: ts,
		e: e,
	}

	b := pp.NewPolyCNTTVec(pp.paramKC)
	for i := 0; i < pp.paramKC; i++ {
		seed = RandomBytes(pp.paramKeyGenSeedBytesLen)
		tmp, err := pp.randomDcIntegersInQc(seed)
		if err != nil {
			log.Fatal(err)
		}
		b.polyCNTTs[i] = &PolyCNTT{coeffs: tmp}
	}
	var c *PolyCNTT
	seed = RandomBytes(pp.paramKeyGenSeedBytesLen)
	tmp, err = pp.randomDcIntegersInQc(seed)
	if err != nil {
		log.Fatal(err)
	}
	c = &PolyCNTT{coeffs: tmp}

	vcmt := &ValueCommitment{
		b: b,
		c: c,
	}

	length := pp.TxoValueBytesLen()
	vct := RandomBytes(length)

	Ckem := RandomBytes(pqringctkem.GetKemCiphertextBytesLen(pp.paramKem))

	txo := &Txo{
		AddressPublicKey: apk,
		ValueCommitment:  vcmt,
		Vct:              vct,
		CtKemSerialized:  Ckem,
	}

	id := RandomBytes(HashOutputBytesLen)
	lgrTxo := &LgrTxo{
		txo: txo,
		id:  id,
	}
	serializedLgrTxo, err := pp.SerializeLgrTxo(lgrTxo)
	if err != nil {
		log.Fatalln(err)
	}
	got, err := pp.DeserializeLgrTxo(serializedLgrTxo)
	if err != nil {
		log.Fatalln(err)
	}
	equal := reflect.DeepEqual(got, lgrTxo)
	if !equal {
		t.Fatal("error for serialize and deserialize lgrTxo")
	}
}

func TestPublicParameter_SerializeRpulpProof_DeserializeRpulpProof(t *testing.T) {
	pp := Initialize(nil)
	J := 2
	var seed []byte
	// c_waves []*PolyCNTT
	c_waves := make([]*PolyCNTT, J)
	for i := 0; i < J; i++ {
		seed = RandomBytes(pp.paramKeyGenSeedBytesLen)
		tmp, err := pp.randomDcIntegersInQc(seed)
		if err != nil {
			log.Fatal(err)
		}
		c_waves[i] = &PolyCNTT{coeffs: tmp}
	}

	//	c_hat_g *PolyCNTT
	var c_hat_g *PolyCNTT
	seed = RandomBytes(pp.paramKeyGenSeedBytesLen)
	tmp, err := pp.randomDcIntegersInQc(seed)
	if err != nil {
		log.Fatal(err)
	}
	c_hat_g = &PolyCNTT{coeffs: tmp}

	//	psi     *PolyCNTT
	var psi *PolyCNTT
	seed = RandomBytes(pp.paramKeyGenSeedBytesLen)
	tmp, err = pp.randomDcIntegersInQc(seed)
	if err != nil {
		log.Fatal(err)
	}
	psi = &PolyCNTT{coeffs: tmp}

	//	phi     *PolyCNTT
	var phi *PolyCNTT
	seed = RandomBytes(pp.paramKeyGenSeedBytesLen)
	tmp, err = pp.randomDcIntegersInQc(seed)
	if err != nil {
		log.Fatal(err)
	}
	phi = &PolyCNTT{coeffs: tmp}

	//	chseed  []byte
	chseed := RandomBytes(pp.paramKeyGenSeedBytesLen)

	//	cmt_zs [][]*PolyCVec
	cmt_zs := make([][]*PolyCVec, pp.paramK)
	for i := 0; i < pp.paramK; i++ {
		cmt_zs[i] = make([]*PolyCVec, J)
		for j := 0; j < J; j++ {
			cmt_zs[i][j] = pp.NewPolyCVec(pp.paramLC)
			for k := 0; k < pp.paramLC; k++ {
				seed = RandomBytes(pp.paramKeyGenSeedBytesLen)
				tmp, err := pp.randomPolyCForResponseC()
				if err != nil {
					log.Fatal(err)
				}
				cmt_zs[i][j].polyCs[k] = tmp
			}
		}
	}

	//	zs     []*PolyCVec
	zs := make([]*PolyCVec, pp.paramK)
	for i := 0; i < pp.paramK; i++ {
		zs[i] = pp.NewPolyCVec(pp.paramLC)
		for j := 0; j < J; j++ {
			seed = RandomBytes(pp.paramKeyGenSeedBytesLen)
			tmp, err := pp.randomPolyCForResponseC()
			if err != nil {
				log.Fatal(err)
			}
			zs[i].polyCs[j] = tmp
		}
	}

	rpulpProof := &rpulpProof{
		c_waves: c_waves,
		c_hat_g: c_hat_g,
		psi:     psi,
		phi:     phi,
		chseed:  chseed,
		cmt_zs:  cmt_zs,
		zs:      zs,
	}

	serializedRpulpProof, err := pp.SerializeRpulpProof(rpulpProof)
	if err != nil {
		log.Fatalln(err)
	}
	got, err := pp.DeserializeRpulpProof(serializedRpulpProof)
	if err != nil {
		log.Fatalln(err)
	}
	equal := reflect.DeepEqual(got, rpulpProof)
	if !equal {
		t.Fatal("error for serialize and deserialize lgrTxo")
	}
}
