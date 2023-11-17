package pqringct

import (
	"fmt"
	"log"
	"math"
	"testing"
)

func TestGeneratePolyANTTMatrix(t *testing.T) {
	pp := Initialize(nil)

	slotNum := 100
	start := -(pp.paramQA - 1) / 2
	end := (pp.paramQA-1)/2 + 1
	step := (end - start) / int64(slotNum)
	count := make([]int, slotNum)
	for i := 0; i < slotNum; i++ {
		count[i] = 0
	}

	for i := 0; i < 10; i++ {
		crsByte := RandomBytes(RandSeedBytesLen)
		matrixA, err := pp.generatePolyANTTMatrix(crsByte, pp.paramKA, 1+pp.paramLambdaA)
		if err != nil {
			log.Fatal(err)
		}
		for j := 0; j < pp.paramKA; j++ {
			for k := 0; k < 1+pp.paramLambdaA; k++ {
				for h := 0; h < pp.paramDA; h++ {
					coeff := matrixA[j].polyANTTs[k].coeffs[h]
					if coeff < start {
						log.Fatal("Left out")
					} else if coeff >= end {
						log.Fatal("Right out")
					}
					for slot := 0; slot < slotNum; slot++ {
						left := start + int64(slot)*step
						right := start + (int64(slot)+1)*step
						if slot == slotNum-1 {
							right = end
						}
						if coeff >= left && coeff < right {
							count[slot] = count[slot] + 1
							break
						}
					}
				}
			}
		}
	}

	total := 0
	for i := 0; i < slotNum; i++ {
		total += count[i]
	}

	standRatio := 1.0 / float64(slotNum)
	errTolerate := standRatio * 0.1
	for i := 0; i < slotNum; i++ {
		ratio := float64(count[i]) / float64(total)

		if math.Abs(ratio-standRatio) > errTolerate {
			fmt.Println("i:", i, "count:", count[i], "percent:", ratio)
		}
		//fmt.Println("i:", i, "count:", count[i], "percent:", ratio)
	}

}

func TestGeneratePolyCNTTMatrix(t *testing.T) {
	pp := Initialize(nil)

	slotNum := 100
	start := -(pp.paramQC - 1) / 2
	end := (pp.paramQC-1)/2 + 1
	step := (end - start) / int64(slotNum)
	count := make([]int, slotNum)
	for i := 0; i < slotNum; i++ {
		count[i] = 0
	}

	for i := 0; i < 10; i++ {
		crsByte := RandomBytes(RandSeedBytesLen)
		matrixA, err := pp.generatePolyCNTTMatrix(crsByte, pp.paramKC, 1+pp.paramLambdaC)
		if err != nil {
			log.Fatal(err)
		}
		for j := 0; j < pp.paramKC; j++ {
			for k := 0; k < 1+pp.paramLambdaC; k++ {
				for h := 0; h < pp.paramDC; h++ {
					coeff := matrixA[j].polyCNTTs[k].coeffs[h]
					if coeff < start {
						log.Fatal("Left out")
					} else if coeff >= end {
						log.Fatal("Right out")
					}
					for slot := 0; slot < slotNum; slot++ {
						left := start + int64(slot)*step
						right := start + (int64(slot)+1)*step
						if slot == slotNum-1 {
							right = end
						}
						if coeff >= left && coeff < right {
							count[slot] = count[slot] + 1
							break
						}
					}
				}
			}
		}
	}

	total := 0
	for i := 0; i < slotNum; i++ {
		total += count[i]
	}

	standRatio := 1.0 / float64(slotNum)
	errTolerate := standRatio * 0.1
	for i := 0; i < slotNum; i++ {
		ratio := float64(count[i]) / float64(total)

		if math.Abs(ratio-standRatio) > errTolerate {
			fmt.Println("i:", i, "count:", count[i], "percent:", ratio)
		}
		//fmt.Println("i:", i, "count:", count[i], "percent:", ratio)
	}

}

// todo: matrix elements
func TestPublicParameters_MatrixA(t *testing.T) {
	//seedStr := RandomBytes(RandSeedBytesLen)
	pp := Initialize(nil)

	type empty struct {
		a int8
	}

	coeffmap := make(map[int64]*string)

	slotNum := 30
	standRadio := 1.0 / float64(slotNum)

	count := make([]int, slotNum)

	end := (pp.paramQA - 1) / 2
	start := -end
	step := (end - start) / int64(slotNum)
	for i := 0; i < pp.paramKA; i++ {
		for j := pp.paramKA; j < pp.paramLA; j++ {
			for k := 0; k < pp.paramDA; k++ {
				coeff := pp.paramMatrixA[i].polyANTTs[j].coeffs[k]

				if coeffmap[coeff] != nil {
					fmt.Println("repeated:", coeffmap[coeff])
				}

				str := "" + "MatrixA" + fmt.Sprint(i) + "," + fmt.Sprint(j) + "," + fmt.Sprint(k)
				coeffmap[coeff] = &str

				if coeff < start || coeff > end {
					log.Fatal("out bound")
				}
				for st := 0; st < slotNum; st++ {
					left := start + int64(st)*step
					right := start + (int64(st)+1)*step
					if st == slotNum-1 {
						right = end + 1
					}
					if coeff >= left && coeff < right {
						count[st] = count[st] + 1
					}
				}

			}

		}
	}

	fmt.Println("MatrixA:")
	total := 0
	for i := 0; i < slotNum; i++ {
		total += count[i]
	}
	fmt.Println("total:", total)
	fmt.Println("maps len:", len(coeffmap))

	for i := 0; i < slotNum; i++ {
		ratio := float64(count[i]) / float64(total)
		if math.Abs(ratio-standRadio) > 0.1*standRadio {
			fmt.Println("i:", i, "count:", count[i], "ratio:", ratio)
		}
	}

	//	Vector

	count = make([]int, slotNum)

	end = (pp.paramQA - 1) / 2
	start = -end
	step = (end - start) / int64(slotNum)
	for j := pp.paramKA + 1; j < pp.paramLA; j++ {
		for k := 0; k < pp.paramDA; k++ {
			coeff := pp.paramVectorA.polyANTTs[j].coeffs[k]

			if coeffmap[coeff] != nil {
				fmt.Println("repeated:", coeffmap[coeff])
			}
			str := "" + "VectorA" + "," + fmt.Sprint(j) + "," + fmt.Sprint(k)
			coeffmap[coeff] = &str

			if coeff < start || coeff > end {
				log.Fatal("out bound")
			}
			for st := 0; st < slotNum; st++ {
				left := start + int64(st)*step
				right := start + (int64(st)+1)*step
				if st == slotNum-1 {
					right = end + 1
				}
				if coeff >= left && coeff < right {
					count[st] = count[st] + 1
				}
			}

		}

	}

	fmt.Println("VectorA:")
	total = 0
	for i := 0; i < slotNum; i++ {
		total += count[i]
	}
	fmt.Println("total:", total)
	fmt.Println("maps len:", len(coeffmap))

	for i := 0; i < slotNum; i++ {
		ratio := float64(count[i]) / float64(total)
		if math.Abs(ratio-standRadio) > 0.1*standRadio {
			fmt.Println("i:", i, "count:", count[i], "ratio:", ratio)
		}
	}

	//	matrixB

	count = make([]int, slotNum)

	end = (pp.paramQC - 1) / 2
	start = -end
	step = (end - start) / int64(slotNum)
	for i := 0; i < pp.paramKC; i++ {
		for j := pp.paramKC; j < pp.paramLC; j++ {
			for k := 0; k < pp.paramDC; k++ {
				coeff := pp.paramMatrixB[i].polyCNTTs[j].coeffs[k]

				if coeffmap[coeff] != nil {
					fmt.Println("repeated:", coeffmap[coeff])
				}
				str := "" + "MatrixB" + fmt.Sprint(i) + "," + fmt.Sprint(j) + "," + fmt.Sprint(k)
				coeffmap[coeff] = &str

				if coeff < start || coeff > end {
					log.Fatal("out bound")
				}
				for st := 0; st < slotNum; st++ {
					left := start + int64(st)*step
					right := start + (int64(st)+1)*step
					if st == slotNum-1 {
						right = end + 1
					}
					if coeff >= left && coeff < right {
						count[st] = count[st] + 1
					}
				}

			}

		}
	}

	fmt.Println("VectorB:")
	total = 0
	for i := 0; i < slotNum; i++ {
		total += count[i]
	}
	fmt.Println("total:", total)
	fmt.Println("maps len:", len(coeffmap))

	for i := 0; i < slotNum; i++ {
		ratio := float64(count[i]) / float64(total)
		if math.Abs(ratio-standRadio) > 0.1*standRadio {
			fmt.Println("i:", i, "count:", count[i], "ratio:", ratio)
		}
	}

	//	matrixH

	count = make([]int, slotNum)

	end = (pp.paramQC - 1) / 2
	start = -end
	step = (end - start) / int64(slotNum)
	for i := 0; i < pp.paramI+pp.paramJ+7; i++ {
		for j := pp.paramKC + pp.paramI + pp.paramJ + 7; j < pp.paramLC; j++ {
			for k := 0; k < pp.paramDC; k++ {
				coeff := pp.paramMatrixH[i].polyCNTTs[j].coeffs[k]

				if coeffmap[coeff] != nil {
					fmt.Println("repeated:", coeffmap[coeff])
				}
				str := "" + "MatrixH" + fmt.Sprint(i) + "," + fmt.Sprint(j) + "," + fmt.Sprint(k)
				coeffmap[coeff] = &str

				if coeff < start || coeff > end {
					log.Fatal("out bound")
				}
				for st := 0; st < slotNum; st++ {
					left := start + int64(st)*step
					right := start + (int64(st)+1)*step
					if st == slotNum-1 {
						right = end + 1
					}
					if coeff >= left && coeff < right {
						count[st] = count[st] + 1
					}
				}

			}

		}
	}

	fmt.Println("VectorH:")
	total = 0
	for i := 0; i < slotNum; i++ {
		total += count[i]
	}
	fmt.Println("total:", total)
	fmt.Println("maps len:", len(coeffmap))

	for i := 0; i < slotNum; i++ {
		ratio := float64(count[i]) / float64(total)
		if math.Abs(ratio-standRadio) > 0.1*standRadio {
			fmt.Println("i:", i, "count:", count[i], "ratio:", ratio)
		}
	}
}
