package solution

import (
	"bufio"
	"fmt"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
	"log"
	"os"
	"strconv"
	"strings"
)

func Conv3x4(params hefloat.Parameters, eval hefloat.Evaluator, ecd hefloat.Encoder, in *rlwe.Ciphertext, weightsDir string, numSlots int) *rlwe.Ciphertext {
	rotations := make([]*rlwe.Ciphertext, 9)
	var err error

	rotations[0] = in
	rotations[1], err = eval.RotateNew(in, 1)
	if err != nil {
		panic(err)
	}
	rotations[2], err = eval.RotateNew(in, 2)
	if err != nil {
		panic(err)
	}
	rotations[3], err = eval.RotateNew(in, 32)
	if err != nil {
		panic(err)
	}
	rotations[4], err = eval.RotateNew(in, 33)
	if err != nil {
		panic(err)
	}
	rotations[5], err = eval.RotateNew(in, 34)
	if err != nil {
		panic(err)
	}
	rotations[6], err = eval.RotateNew(in, 64)
	if err != nil {
		panic(err)
	}
	rotations[7], err = eval.RotateNew(in, 65)
	if err != nil {
		panic(err)
	}
	rotations[8], err = eval.RotateNew(in, 66)
	if err != nil {
		panic(err)
	}

	var finalSum *rlwe.Ciphertext

	for c := 0; c < 4; c++ {
		var kRows []*rlwe.Ciphertext
		for k := 0; k < 9; k++ {
			weights, err := readValuesFromFile(fmt.Sprintf("%s/conv1-ch%d-k%d.bin", weightsDir, c, k))
			if err != nil {
				panic(err)
			}
			encoded := encode(params, ecd, weights, in.Level())

			mult, err := eval.MulRelinNew(rotations[k], encoded)
			if err := eval.Rescale(mult, mult); err != nil {
				panic(err)
			}
			kRows = append(kRows, mult)
		}

		sum := kRows[0]
		for _, row := range kRows[1:] {
			sum, err = eval.AddNew(sum, row)
			if err != nil {
				panic(err)
			}
		}

		res := sum.CopyNew()

		// Perform shift and add operations
		sumShift, err := eval.RotateNew(sum, 1024)
		if err != nil {
			panic(err)
		}
		res, err = eval.AddNew(res, sumShift)
		if err != nil {
			panic(err)
		}
		sumShift, err = eval.RotateNew(sumShift, 1024)
		if err != nil {
			panic(err)
		}
		res, err = eval.AddNew(res, sumShift)
		if err != nil {
			panic(err)
		}

		// Add bias
		bias, err := readValuesFromFile(fmt.Sprintf("%s/conv1-ch%d-bias.bin", weightsDir, c))
		if err != nil {
			panic(err)
		}
		encodedBias := encode(params, ecd, bias, res.Level())
		res, err = eval.AddNew(res, encodedBias)
		if err != nil {
			panic(err)
		}

		// Apply mask
		mask, err := readValuesFromFile(fmt.Sprintf("%s/conv1-mask.bin", weightsDir))
		if err != nil {
			panic(err)
		}
		encodedMask := encode(params, ecd, mask, res.Level())
		if err = eval.MulRelin(res, encodedMask, res); err != nil {
			panic(err)
		}
		if err := eval.Rescale(res, res); err != nil {
			panic(err)
		}

		if c == 0 {
			finalSum = res.CopyNew()
			finalSum, err = eval.RotateNew(finalSum, 1024)
			if err != nil {
				panic(err)
			}
		} else {
			finalSum, err = eval.AddNew(finalSum, res)
			if err != nil {
				panic(err)
			}
			finalSum, err = eval.RotateNew(finalSum, 1024)
			if err != nil {
				panic(err)
			}
		}
	}

	return finalSum
}

func Conv3x16(params hefloat.Parameters, eval hefloat.Evaluator, ecd hefloat.Encoder, in *rlwe.Ciphertext, weightsDir string, numSlots int) *rlwe.Ciphertext {
	rotations := make([]*rlwe.Ciphertext, 9)
	var err error

	rotations[0] = in
	rotations[1], err = eval.RotateNew(in, 1)
	if err != nil {
		panic(err)
	}
	rotations[2], err = eval.RotateNew(in, 2)
	if err != nil {
		panic(err)
	}
	rotations[3], err = eval.RotateNew(in, 32)
	if err != nil {
		panic(err)
	}
	rotations[4], err = eval.RotateNew(in, 33)
	if err != nil {
		panic(err)
	}
	rotations[5], err = eval.RotateNew(in, 34)
	if err != nil {
		panic(err)
	}
	rotations[6], err = eval.RotateNew(in, 64)
	if err != nil {
		panic(err)
	}
	rotations[7], err = eval.RotateNew(in, 65)
	if err != nil {
		panic(err)
	}
	rotations[8], err = eval.RotateNew(in, 66)
	if err != nil {
		panic(err)
	}

	var finalSum *rlwe.Ciphertext

	for c := 0; c < 16; c++ {
		var kRows []*rlwe.Ciphertext
		for k := 0; k < 9; k++ {
			weights, err := readValuesFromFile(fmt.Sprintf("%s/conv1-ch%d-k%d.bin", weightsDir, c, k))
			if err != nil {
				panic(err)
			}
			encoded := encode(params, ecd, weights, in.Level())

			mult, err := eval.MulRelinNew(rotations[k], encoded)
			if err := eval.Rescale(mult, mult); err != nil {
				panic(err)
			}
			kRows = append(kRows, mult)
		}

		sum := kRows[0]
		for _, row := range kRows[1:] {
			sum, err = eval.AddNew(sum, row)
			if err != nil {
				panic(err)
			}
		}

		res := sum.CopyNew()

		// Perform shift and add operations
		sumShift, err := eval.RotateNew(sum, 1024)
		if err != nil {
			panic(err)
		}
		res, err = eval.AddNew(res, sumShift)
		if err != nil {
			panic(err)
		}
		sumShift, err = eval.RotateNew(sumShift, 1024)
		if err != nil {
			panic(err)
		}
		res, err = eval.AddNew(res, sumShift)
		if err != nil {
			panic(err)
		}

		// Add bias
		bias, err := readValuesFromFile(fmt.Sprintf("%s/conv1-ch%d-bias.bin", weightsDir, c))
		if err != nil {
			panic(err)
		}
		encodedBias := encode(params, ecd, bias, res.Level())
		res, err = eval.AddNew(res, encodedBias)
		if err != nil {
			panic(err)
		}

		// Apply mask
		mask, err := readValuesFromFile(fmt.Sprintf("%s/conv1-mask.bin", weightsDir))
		if err != nil {
			panic(err)
		}
		encodedMask := encode(params, ecd, mask, res.Level())
		if err = eval.MulRelin(res, encodedMask, res); err != nil {
			panic(err)
		}
		if err := eval.Rescale(res, res); err != nil {
			panic(err)
		}

		if c == 0 {
			finalSum = res.CopyNew()
			finalSum, err = eval.RotateNew(finalSum, 1024)
			if err != nil {
				panic(err)
			}
		} else {
			finalSum, err = eval.AddNew(finalSum, res)
			if err != nil {
				panic(err)
			}
			finalSum, err = eval.RotateNew(finalSum, 1024)
			if err != nil {
				panic(err)
			}
		}
	}

	return finalSum
}

func Fc4096x10(params hefloat.Parameters, eval hefloat.Evaluator, ecd hefloat.Encoder, in *rlwe.Ciphertext, weightsDir string) *rlwe.Ciphertext {
	var finalsum *rlwe.Ciphertext
	rolls := []int{2048, 1024, 512, 256, 128, 64, 32, 16, 8, 4, 2, 1}

	for i := 0; i < 10; i++ {
		weights, err := readValuesFromFile(fmt.Sprintf("%s/fc-c%d.bin", weightsDir, i))
		if err != nil {
			log.Fatalf("failed to read weights: %v", err)
		}
		encoded := encode(params, ecd, weights, in.Level())

		current, err := eval.MulRelinNew(in, encoded)
		if err != nil {
			panic(err)
		}

		for _, r := range rolls {
			rot, err := eval.RotateNew(current, r)
			if err != nil {
				log.Fatalf("failed to rotate: %v", err)
			}
			current, err = eval.AddNew(rot, current)
			if err != nil {
				panic(err)
			}
		}

		maskValues, err := readValuesFromFile(fmt.Sprintf("%s/fc-mask.bin", weightsDir))
		if err != nil {
			log.Fatalf("failed to read mask values: %v", err)
		}
		mask := encode(params, ecd, maskValues, current.Level())
		mulMasked, err := eval.MulRelinNew(current, mask)
		if err != nil {
			panic(err)
		}
		if err := eval.Rescale(mulMasked, mulMasked); err != nil {
			panic(err)
		}

		if i == 0 {
			finalsum = mulMasked
		} else {
			rot, err := eval.RotateNew(mulMasked, -i)
			if err != nil {
				log.Fatalf("failed to rotate: %v", err)
			}
			finalsum, err = eval.AddNew(finalsum, rot)
			if err != nil {
				panic(err)
			}
		}
	}

	biasValues, err := readValuesFromFile(fmt.Sprintf("%s/fc-bias.bin", weightsDir))
	if err != nil {
		log.Fatalf("failed to read bias values: %v", err)
	}
	bias := encode(params, ecd, biasValues, finalsum.Level())
	finalsum, err = eval.AddNew(finalsum, bias)
	if err != nil {
		panic(err)
	}

	return finalsum
}

func Fc16384x10(params hefloat.Parameters, eval hefloat.Evaluator, ecd hefloat.Encoder, in *rlwe.Ciphertext, weightsDir string) *rlwe.Ciphertext {
	var finalsum *rlwe.Ciphertext
	rolls := []int{8192, 4096, 2048, 1024, 512, 256, 128, 64, 32, 16}

	for i := 0; i < 16; i++ {
		weights, err := readValuesFromFile(fmt.Sprintf("%s/fc-c%d.bin", weightsDir, i))
		if err != nil {
			log.Fatalf("failed to read weights: %v", err)
		}
		encoded := encode(params, ecd, weights, in.Level())

		if i == 0 {
			finalsum, err = eval.MulRelinNew(in, encoded)
			if err := eval.Rescale(finalsum, finalsum); err != nil {
				panic(err)
			}
		} else {
			rotatedIn, err := eval.RotateNew(in, i)
			if err != nil {
				log.Fatalf("failed to rotate input: %v", err)
			}
			current, err := eval.MulRelinNew(rotatedIn, encoded)
			if err := eval.Rescale(rotatedIn, rotatedIn); err != nil {
				panic(err)
			}

			finalsum, err = eval.AddNew(finalsum, current)
			if err != nil {
				panic(err)
			}
		}
	}

	for _, r := range rolls {
		rotatedFinalsum, err := eval.RotateNew(finalsum, r)
		if err != nil {
			log.Fatalf("failed to rotate finalsum: %v", err)
		}
		finalsum, err = eval.AddNew(finalsum, rotatedFinalsum)
		if err != nil {
			panic(err)
		}
	}

	biasValues, err := readValuesFromFile(fmt.Sprintf("%s/fc-bias.bin", weightsDir))
	if err != nil {
		log.Fatalf("failed to read bias values: %v", err)
	}
	bias := encode(params, ecd, biasValues, finalsum.Level())
	finalsum, err = eval.AddNew(finalsum, bias)
	if err != nil {
		panic(err)
	}

	return finalsum
}

func SolveTestcase(params *hefloat.Parameters, evk *rlwe.MemEvaluationKeySet, in *rlwe.Ciphertext) (out *rlwe.Ciphertext, err error) {
	print(in.Slots())

	ecd := hefloat.NewEncoder(*params)
	eval := hefloat.NewEvaluator(*params, evk)
	if err = eval.MulRelin(in, 1/255.0, in); err != nil {
		panic(err)
	}
	if err := eval.Rescale(in, in); err != nil {
		panic(err)
	}

	convResult := Conv3x16(*params, *eval, *ecd, in, "weights", in.Slots())
	reluResult, err := eval.MulRelinNew(convResult, convResult)
	if err := eval.Rescale(reluResult, reluResult); err != nil {
		panic(err)
	}
	finalResult := Fc16384x10(*params, *eval, *ecd, reluResult, "weights")

	return finalResult, nil
}

func readValuesFromFile(filePath string) ([]float64, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var values []float64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ",")
		for _, part := range parts {
			value, err := strconv.ParseFloat(strings.TrimSpace(part), 64)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return values, nil
}

func encode(params hefloat.Parameters, encoder hefloat.Encoder, values []float64, level int) *rlwe.Plaintext {
	plaintext := hefloat.NewPlaintext(params, level)
	encoder.Encode(values, plaintext)
	return plaintext
}
