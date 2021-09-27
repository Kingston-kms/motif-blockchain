package utils

import "math/big"

// ToMotif number of MOTIF to Wei
func ToMotif(ftm uint64) *big.Int {
	return new(big.Int).Mul(new(big.Int).SetUint64(ftm), big.NewInt(1e18))
}
