package main

import (
	"app/utils"
	"flag"
	"fmt"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
	"log"
)

func main() {
	ccFile := flag.String("cc", "", "")
	skFile := flag.String("sk", "", "")
	inputFile := flag.String("input", "", "")
	outputFile := flag.String("output", "", "")

	flag.Parse()

	params := new(hefloat.Parameters)
	if err := utils.Deserialize(params, *ccFile); err != nil {
		log.Fatalf(err.Error())
	}

	sk := new(rlwe.SecretKey)
	if err := utils.Deserialize(sk, *skFile); err != nil {
		log.Fatalf(err.Error())
	}

	in := new(rlwe.Ciphertext)
	if err := utils.Deserialize(in, *inputFile); err != nil {
		log.Fatalf(err.Error())
	}

	out := new(rlwe.Ciphertext)
	if err := utils.Deserialize(out, *outputFile); err != nil {
		log.Fatalf(err.Error())
	}

	dec := rlwe.NewDecryptor(*params, sk)
	ecd := hefloat.NewEncoder(*params)

	have := make([]float64, out.Slots())
	if err := ecd.Decode(dec.DecryptNew(out), have); err != nil {
		log.Fatalf("%T.Decode: %s", ecd, err.Error())
	}

	fmt.Println(have[:10])
}
