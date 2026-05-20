// Copyright 2024 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// EIP-7702 tx_setcode test suite. Verifies self-consistency of the Paxeer
// backport. Cross-implementation vectors (viem, ethers, foundry) should be
// added in a follow-up before the patch ships to mainnet.

package types

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// testAuthKey is a deterministic private key for signing test authorizations.
// 0x0001...0001 in 32 bytes — generates a stable address across runs.
func testAuthKey(t *testing.T) (sk []byte, addr common.Address) {
	t.Helper()
	sk = make([]byte, 32)
	sk[31] = 1
	priv, err := crypto.ToECDSA(sk)
	if err != nil {
		t.Fatalf("ToECDSA: %v", err)
	}
	addr = crypto.PubkeyToAddress(priv.PublicKey)
	return sk, addr
}

func signAuth(t *testing.T, sk []byte, a *Authorization) {
	t.Helper()
	priv, err := crypto.ToECDSA(sk)
	if err != nil {
		t.Fatalf("ToECDSA: %v", err)
	}
	hash := AuthorityHash(*a)
	sig, err := crypto.Sign(hash[:], priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	a.R = new(big.Int).SetBytes(sig[:32])
	a.S = new(big.Int).SetBytes(sig[32:64])
	a.V = new(big.Int).SetUint64(uint64(sig[64]))
}

func TestSetCodeTx_TxType(t *testing.T) {
	if SetCodeTxType != 0x04 {
		t.Fatalf("SetCodeTxType: want 0x04, got 0x%02x", SetCodeTxType)
	}
	tx := &SetCodeTx{}
	if tx.txType() != SetCodeTxType {
		t.Fatalf("txType(): want 0x04, got 0x%02x", tx.txType())
	}
}

func TestSetCodeTx_DelegationPrefix(t *testing.T) {
	want := []byte{0xef, 0x01, 0x00}
	if !bytes.Equal(DelegationPrefix, want) {
		t.Fatalf("DelegationPrefix: want %x, got %x", want, DelegationPrefix)
	}
}

func TestSetCodeTx_AuthMagic(t *testing.T) {
	if AuthMagic != 0x05 {
		t.Fatalf("AuthMagic: want 0x05, got 0x%02x", AuthMagic)
	}
}

func TestAuthorityHash_Deterministic(t *testing.T) {
	a := Authorization{
		ChainID: big.NewInt(125),
		Address: common.HexToAddress("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
		Nonce:   42,
	}
	h1 := AuthorityHash(a)
	h2 := AuthorityHash(a)
	if h1 != h2 {
		t.Fatalf("AuthorityHash is non-deterministic: %x vs %x", h1, h2)
	}
	if (h1 == common.Hash{}) {
		t.Fatalf("AuthorityHash returned the zero hash; should not happen")
	}
}

func TestAuthorityHash_DifferentInputsDifferentOutputs(t *testing.T) {
	base := Authorization{
		ChainID: big.NewInt(125),
		Address: common.HexToAddress("0x1111111111111111111111111111111111111111"),
		Nonce:   1,
	}
	mut := base
	mut.Nonce = 2
	if AuthorityHash(base) == AuthorityHash(mut) {
		t.Fatalf("AuthorityHash collided for different nonces")
	}
	mut2 := base
	mut2.ChainID = big.NewInt(999)
	if AuthorityHash(base) == AuthorityHash(mut2) {
		t.Fatalf("AuthorityHash collided for different chain IDs")
	}
	mut3 := base
	mut3.Address = common.HexToAddress("0x2222222222222222222222222222222222222222")
	if AuthorityHash(base) == AuthorityHash(mut3) {
		t.Fatalf("AuthorityHash collided for different target addresses")
	}
}

func TestRecoverAuthority_SignAndRecover(t *testing.T) {
	sk, want := testAuthKey(t)
	a := &Authorization{
		ChainID: big.NewInt(125),
		Address: common.HexToAddress("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
		Nonce:   7,
	}
	signAuth(t, sk, a)

	got, err := RecoverAuthority(*a)
	if err != nil {
		t.Fatalf("RecoverAuthority: %v", err)
	}
	if got != want {
		t.Fatalf("recovered address mismatch:\n  want %s\n  got  %s", want.Hex(), got.Hex())
	}
}

func TestRecoverAuthority_RejectsInvalidV(t *testing.T) {
	sk, _ := testAuthKey(t)
	a := &Authorization{
		ChainID: big.NewInt(125),
		Address: common.HexToAddress("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
		Nonce:   7,
	}
	signAuth(t, sk, a)
	// Tamper V: 27 is valid for legacy txs but illegal for 7702 authorization tuples.
	a.V = big.NewInt(27)
	if _, err := RecoverAuthority(*a); err == nil {
		t.Fatalf("RecoverAuthority accepted V=27; expected ErrInvalidAuthSig")
	}
	a.V = big.NewInt(2)
	if _, err := RecoverAuthority(*a); err == nil {
		t.Fatalf("RecoverAuthority accepted V=2; expected ErrInvalidAuthSig")
	}
}

func TestRecoverAuthority_RejectsNilFields(t *testing.T) {
	a := Authorization{
		ChainID: big.NewInt(125),
		Address: common.HexToAddress("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
		Nonce:   7,
	}
	if _, err := RecoverAuthority(a); err == nil {
		t.Fatalf("RecoverAuthority accepted nil V/R/S; expected ErrInvalidAuthSig")
	}
}

func TestDelegation_RecognizesMarker(t *testing.T) {
	target := common.HexToAddress("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	code := append(append([]byte{}, DelegationPrefix...), target.Bytes()...)
	got, ok := Delegation(code)
	if !ok {
		t.Fatalf("Delegation rejected a well-formed marker")
	}
	if got != target {
		t.Fatalf("Delegation target mismatch: want %s, got %s", target.Hex(), got.Hex())
	}
}

func TestDelegation_RejectsNonMarker(t *testing.T) {
	cases := map[string][]byte{
		"empty":            {},
		"too short":        {0xef, 0x01, 0x00, 0xaa},
		"wrong prefix":     append([]byte{0xee, 0x01, 0x00}, make([]byte, 20)...),
		"plain contract":   bytes.Repeat([]byte{0x60}, 23),
		"correct length wrong tail length": append([]byte{0xef, 0x01, 0x00}, make([]byte, 21)...),
	}
	for name, code := range cases {
		if _, ok := Delegation(code); ok {
			t.Fatalf("Delegation accepted invalid input %q (%x)", name, code)
		}
	}
}

func TestSetCodeTx_Copy_DeepCopiesAuthList(t *testing.T) {
	to := common.HexToAddress("0xabababababababababababababababababababab")
	orig := &SetCodeTx{
		ChainID:   big.NewInt(125),
		Nonce:     1,
		GasTipCap: big.NewInt(2),
		GasFeeCap: big.NewInt(3),
		Gas:       21000,
		To:        &to,
		Value:     big.NewInt(0),
		Data:      []byte{0xca, 0xfe},
		AuthList: []Authorization{{
			ChainID: big.NewInt(125),
			Address: common.HexToAddress("0x1111111111111111111111111111111111111111"),
			Nonce:   1,
			V:       big.NewInt(0),
			R:       big.NewInt(123),
			S:       big.NewInt(456),
		}},
		V: big.NewInt(0),
		R: big.NewInt(0),
		S: big.NewInt(0),
	}
	cpy := orig.copy().(*SetCodeTx)
	// Mutate cpy's auth list big.Int fields; orig must not see the change.
	cpy.AuthList[0].R.SetInt64(999)
	if orig.AuthList[0].R.Int64() != 123 {
		t.Fatalf("copy() shared the AuthList R *big.Int with the source; deep copy broken")
	}
	// Mutate cpy.Data; orig must not see it.
	cpy.Data[0] = 0xff
	if orig.Data[0] != 0xca {
		t.Fatalf("copy() shared the Data slice with the source; deep copy broken")
	}
}
