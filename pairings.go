package main

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
)

type PairingComputationCircuit struct {
	// the witness vector is automatically allocated and initialised
	ElG1  sw_bls12381.G1Affine
	MElG1 sw_bls12381.G1Affine
	ElG2  sw_bls12381.G2Affine
}

func (c *PairingComputationCircuit) Define(api frontend.API) error {
	// we use cached instanse of pairing context. The pairing context itself
	// uses cached instance of range check context. We can call different
	// gadgets which all will use the same range check gadget instance.
	pairingCtx, err := sw_bls12381.NewPairing(api)
	if err != nil {
		return err
	}
	err = pairingCtx.PairingCheck([]*sw_bls12381.G1Affine{&c.ElG1, &c.MElG1},
		[]*sw_bls12381.G2Affine{&c.ElG2, &c.ElG2})
	if err != nil {
		return err
	}
	return nil
	// optimal range check table size computed, range check elements decomposed
	// into table entries and checked.
}

func test_pairings() {
	var P bls12381.G1Affine
	var Q bls12381.G2Affine
	var a, b fr.Element
	_, _, g1gen, g2gen := bls12381.Generators()
	a.SetRandom()
	b.SetRandom()

	P.ScalarMultiplication(&g1gen, a.BigInt(new(big.Int)))
	Q.ScalarMultiplication(&g2gen, b.BigInt(new(big.Int)))
	var mP = new(bls12381.G1Affine)
	mP = mP.Neg(&P)

	ok, err := bls12381.PairingCheck([]bls12381.G1Affine{P, *mP}, []bls12381.G2Affine{Q, Q})
	if err != nil {
		panic(err)
	}
	if !ok {
		panic("pairing is not OK")
	}

	assignment := PairingComputationCircuit{
		ElG1:  sw_bls12381.NewG1Affine(P),
		MElG1: sw_bls12381.NewG1Affine(*mP),
		ElG2:  sw_bls12381.NewG2Affine(Q),
	}

	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(),
		r1cs.NewBuilder, &PairingComputationCircuit{})
	if err != nil {
		panic(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}
	w, err := frontend.NewWitness(&assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		panic(err)
	}
	proof, err := groth16.Prove(ccs, pk, w)
	// prover computes the Groth16 proof and commitment proof of knowledge
	if err != nil {
		panic(err)
	}
	pw, err := w.Public()
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(proof, vk, pw)
	// verifier checks Groth16 proof and the commitment proof.
	if err != nil {
		panic(err)
	}
}

//type NNAScalarMul struct {
//	// the witness vector is automatically allocated and initialised
//	Base   sw_bls12381.G1Affine
//	Scalar sw_bls12381.Fr
//	Res    sw_bls12381.G1Affine
//}
//
//func (c *NNAScalarMul) Define(api frontend.API) error {
//}
//
//func test_NNAScalarMul() {
//	var P bls12381.G1Affine
//	var a fr.Element
//	_, _, g1gen, _ := bls12381.Generators()
//	a.SetRandom()
//
//	P.ScalarMultiplication(&g1gen, a.BigInt(new(big.Int)))
//
//	witness := NNAScalarMul{
//		Scalar: a,
//		Base:   sw_bls12381.NewG1Affine(g1gen),
//		Res:    sw_bls12381.NewG1Affine(P),
//	}
//
//	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(),
//		r1cs.NewBuilder, &NNAScalarMul{})
//	if err != nil {
//		panic(err)
//	}
//	pk, vk, err := groth16.Setup(ccs)
//	if err != nil {
//		panic(err)
//	}
//	w, err := frontend.NewWitness(&witness, ecc.BLS12_381.ScalarField())
//	if err != nil {
//		panic(err)
//	}
//	proof, err := groth16.Prove(ccs, pk, w)
//	// prover computes the Groth16 proof and commitment proof of knowledge
//	if err != nil {
//		panic(err)
//	}
//	pw, err := w.Public()
//	if err != nil {
//		panic(err)
//	}
//	err = groth16.Verify(proof, vk, pw)
//	// verifier checks Groth16 proof and the commitment proof.
//	if err != nil {
//		panic(err)
//	}
//
//}
