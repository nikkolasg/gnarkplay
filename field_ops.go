package main

import (
	"fmt"

	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
)

func field_ops_tests() {
	//testCircuit[BLS12377Fr](ecc.BLS12_381.ScalarField(), MUL, 100000)
	//testCircuit[BLS12377Fr](ecc.BLS12_381.ScalarField(), ADD)
	testCircuit[BLS12381Fr](ecc.BLS12_377.ScalarField(), ADD, 10000)
	//testCircuit[BLS12381Fr](ecc.BLS12_377.ScalarField(), MUL, 10000)

}

type OP = int

const (
	MUL OP = iota
	ADD
)

type ExampleFieldCircuit[T emulated.FieldParams] struct {
	o      OP
	nTimes int
	In1    emulated.Element[T]
	In2    emulated.Element[T]
	Res    emulated.Element[T]
}

func (c *ExampleFieldCircuit[T]) Define(api frontend.API) error {
	f, err := emulated.NewField[T](api)
	if err != nil {
		return fmt.Errorf("new field: %w", err)
	}
	for i := 0; i < c.nTimes; i++ {
		switch c.o {
		case ADD:
			res := f.Add(&c.In1, &c.In2)
			f.AssertIsEqual(res, &c.Res)
		case MUL:
			res := f.Mul(&c.In1, &c.In2)
			res = f.Reduce(res)
			f.AssertIsEqual(res, &c.Res)
		}
	}

	return nil
}

func testCircuit[NNA emulated.FieldParams](circuitField *big.Int, op OP, nTimes int) {
	op1 := 3
	op2 := 5
	var op3 uint
	switch op {
	case ADD:
		op3 = 8
	case MUL:
		op3 = 15
	}
	circuit := ExampleFieldCircuit[NNA]{o: op, nTimes: nTimes}
	witness := ExampleFieldCircuit[NNA]{
		o:      op,
		nTimes: nTimes,
		In1:    emulated.ValueOf[NNA](op1),
		In2:    emulated.ValueOf[NNA](op2),
		Res:    emulated.ValueOf[NNA](op3),
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

	publicWitnessData, err := witnessData.Public()
	if err != nil {
		panic(err)
	} else {
		fmt.Println("public witness parsed")
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("setup done")
	}
	//proof, err := groth16.Prove(ccs, pk, witnessData, backend.WithHints(emulated.GetHints()...))
	proof, err := groth16.Prove(ccs, pk, witnessData)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("proved")
	}
	err = groth16.Verify(proof, vk, publicWitnessData)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("verified")
	}
	//if err := ccs.IsSolved(witnessData); err != nil {
	//	panic("circuit is not solved")
	//}
	fmt.Println("All Good")
}
