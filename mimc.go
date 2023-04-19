package main

import (
	"crypto/rand"
	"fmt"
	ghash "hash"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/emulated"
)

func mimc_native() {
	test_mimc(ecc.BLS12_381.ScalarField(), hash.MIMC_BLS12_381.New())
	test_mimc(ecc.BLS12_377.ScalarField(), hash.MIMC_BLS12_377.New())
}

func mimc_nna() {
	// we run MIMC on non native 377 fields over 381
	test_mimc_nna[BLS12377Fr](ecc.BLS12_381.ScalarField(), hash.MIMC_BLS12_377.New())
}

func test_mimc_nna[NNA emulated.FieldParams](circuitField *big.Int, h ghash.Hash) {
	var n NNA
	preimage, _ := rand.Int(rand.Reader, n.Modulus())
	_, _ = h.Write(preimage.Bytes())
	res := h.Sum(nil)

	preimageNNA := emulated.ValueOf[NNA](preimage)
	resNNA := emulated.ValueOf[NNA](res)

	circuit := MimCircuitNNA[NNA]{}
	witness := MimCircuitNNA[NNA]{
		Preimage: preimageNNA,
		Hash:     resNNA,
	}
	ccs, err := frontend.Compile(circuitField, r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("compiled")
	}
	fmt.Println("Number of variables = ", ccs.GetNbConstraints())
	witnessData, err := frontend.NewWitness(&witness, circuitField)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("secret witness parsed")
	}
	if err := ccs.IsSolved(witnessData); err != nil {
		panic("circuit is not solved")
	}
}

func test_mimc(circuitField *big.Int, h ghash.Hash) {

	preimage, err := rand.Int(rand.Reader, circuitField)
	if err != nil {
		panic(err)
	}
	_, _ = h.Write(preimage.Bytes())
	res := h.Sum(nil)

	circuit := MimCircuit{}
	witness := MimCircuit{
		PreImage: preimage,
		Hash:     res,
	}

	ccs, err := frontend.Compile(circuitField, r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("compiled")
	}
	fmt.Println("Number of variables = ", ccs.GetNbConstraints())
	witnessData, err := frontend.NewWitness(&witness, circuitField)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("secret witness parsed")
	}
	if err := ccs.IsSolved(witnessData); err != nil {
		panic("circuit is not solved")
	}
}

type MimCircuitNNA[T emulated.FieldParams] struct {
	Preimage emulated.Element[T]
	Hash     emulated.Element[T]
}

func (circuit *MimCircuitNNA[T]) Define(api frontend.API) error {
	f, err := emulated.NewField[T](api)
	if err != nil {
		return fmt.Errorf("new field: %w", err)
	}
	mimc, _ := mimc.NewMiMC(api)
	mimc.Write(circuit.Preimage)
	// This panics with
	// panic: parse circuit: emulated.Element[main.BLS12377Fr] to big.Int not supported
	res := mimc.Sum()
	api.AssertIsEqual(circuit.Hash, f.NewElement(res))
	// This should not work because res is on bls12-381 native element
	//api.AssertIsEqual(circuit.Hash, res)
	return nil
}

type MimCircuit struct {
	// struct tag on a variable is optional
	// default uses variable name and secret visibility.
	PreImage frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
}

func (circuit *MimCircuit) Define(api frontend.API) error {
	// hash function
	mimc, _ := mimc.NewMiMC(api)

	// specify constraints
	// mimc(preImage) == hash
	mimc.Write(circuit.PreImage)
	api.AssertIsEqual(circuit.Hash, mimc.Sum())

	return nil
}
