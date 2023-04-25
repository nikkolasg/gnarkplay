package main

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
)

type PairingComputationCircuit struct {
	// the witness vector is automatically allocated and initialised
	ElG1  sw_bn254.G1Affine
	MElG1 sw_bn254.G1Affine
	ElG2  sw_bn254.G2Affine
}

func (c *PairingComputationCircuit) Define(api frontend.API) error {
	// we use cached instanse of pairing context. The pairing context itself
	// uses cached instance of range check context. We can call different
	// gadgets which all will use the same range check gadget instance.
	pairingCtx, err := sw_bn254.NewPairing(api)
	if err != nil {
		return err
	}
	err = pairingCtx.PairingCheck([]*sw_bn254.G1Affine{&c.ElG1, &c.MElG1},
		[]*sw_bn254.G2Affine{&c.ElG2, &c.ElG2})
	if err != nil {
		return err
	}
	return nil
	// optimal range check table size computed, range check elements decomposed
	// into table entries and checked.
}

func test_pairings() {
	var P bn254.G1Affine
	var Q bn254.G2Affine
	var a, b fr.Element
	_, _, g1gen, g2gen := bn254.Generators()
	a.SetRandom()
	b.SetRandom()

	P.ScalarMultiplication(&g1gen, a.BigInt(new(big.Int)))
	Q.ScalarMultiplication(&g2gen, b.BigInt(new(big.Int)))
	var mP = new(bn254.G1Affine)
	mP = mP.Neg(&P)

	ok, err := bn254.PairingCheck([]bn254.G1Affine{P, *mP}, []bn254.G2Affine{Q, Q})
	if err != nil {
		panic(err)
	}
	if !ok {
		panic("pairing is not OK")
	}

	assignment := PairingComputationCircuit{
		ElG1:  sw_bn254.NewG1Affine(P),
		MElG1: sw_bn254.NewG1Affine(*mP),
		ElG2:  sw_bn254.NewG2Affine(Q),
		// automatically splits the extension field elements into limbs for
		// non-native field arithmetic.
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(),
		r1cs.NewBuilder, &PairingComputationCircuit{})
	if err != nil {
		panic(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}
	w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
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

func test_nnaEC() {

}
