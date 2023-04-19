package main

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
)

type BLS12377Fr struct{}

func (fp BLS12377Fr) NbLimbs() uint     { return 4 }
func (fp BLS12377Fr) BitsPerLimb() uint { return 64 }
func (fp BLS12377Fr) IsPrime() bool     { return true }
func (fp BLS12377Fr) Modulus() *big.Int { return ecc.BLS12_377.ScalarField() }

type BLS12381Fr struct{}

func (fp BLS12381Fr) NbLimbs() uint     { return 4 }
func (fp BLS12381Fr) BitsPerLimb() uint { return 64 }
func (fp BLS12381Fr) IsPrime() bool     { return true }
func (fp BLS12381Fr) Modulus() *big.Int { return ecc.BLS12_381.ScalarField() }
