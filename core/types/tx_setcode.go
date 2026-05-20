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

// Package types — EIP-7702 (SetCodeTx) backport. See:
//   https://eips.ethereum.org/EIPS/eip-7702
// Paxeer backport spec: app/upgrades/v20agent/geth_7702_backport.md in the
// hyperpax-os-cronosRelease chain repo.

package types

import (
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// SetCodeTxType is the EIP-7702 transaction type.
const SetCodeTxType = 0x04

// DelegationPrefix is written into the authority's code slot to mark delegation.
// Layout: 0xef0100 || 20-byte target address (total 23 bytes).
var DelegationPrefix = []byte{0xef, 0x01, 0x00}

// Authorization is one entry of an EIP-7702 authorization list.
//
// RLP form: [chain_id, address, nonce, y_parity, r, s].
// y_parity is encoded via V *big.Int and MUST be 0 or 1; values 27/28 are
// rejected (those belong to legacy/EIP-155 transactions, not EIP-7702
// authorization tuples).
type Authorization struct {
	ChainID *big.Int       `json:"chainId"`
	Address common.Address `json:"address"` // delegation target
	Nonce   uint64         `json:"nonce"`
	V       *big.Int       `json:"v"`
	R       *big.Int       `json:"r"`
	S       *big.Int       `json:"s"`
}

// SetCodeTx is the EIP-7702 transaction.
//
// RLP form: 0x04 || rlp([chain_id, nonce, max_priority_fee, max_fee,
//
//	gas_limit, destination, value, data, access_list,
//	authorization_list, v, r, s]).
//
// Field order below MUST stay in lockstep with the wire format — the default
// RLP encoder serializes struct fields in declaration order.
type SetCodeTx struct {
	ChainID    *big.Int
	Nonce      uint64
	GasTipCap  *big.Int
	GasFeeCap  *big.Int
	Gas        uint64
	To         *common.Address `rlp:"nil"` // EIP-7702 forbids nil at the consensus layer; enforced in preCheck
	Value      *big.Int
	Data       []byte
	AccessList AccessList
	AuthList   []Authorization

	// Signature values
	V *big.Int `json:"v" gencodec:"required"`
	R *big.Int `json:"r" gencodec:"required"`
	S *big.Int `json:"s" gencodec:"required"`
}

// accessors for innerTx (TxData interface).
func (tx *SetCodeTx) txType() byte           { return SetCodeTxType }
func (tx *SetCodeTx) chainID() *big.Int      { return tx.ChainID }
func (tx *SetCodeTx) accessList() AccessList { return tx.AccessList }
func (tx *SetCodeTx) data() []byte           { return tx.Data }
func (tx *SetCodeTx) gas() uint64            { return tx.Gas }
func (tx *SetCodeTx) gasPrice() *big.Int     { return tx.GasFeeCap }
func (tx *SetCodeTx) gasTipCap() *big.Int    { return tx.GasTipCap }
func (tx *SetCodeTx) gasFeeCap() *big.Int    { return tx.GasFeeCap }
func (tx *SetCodeTx) value() *big.Int        { return tx.Value }
func (tx *SetCodeTx) nonce() uint64          { return tx.Nonce }
func (tx *SetCodeTx) to() *common.Address    { return tx.To }

func (tx *SetCodeTx) rawSignatureValues() (v, r, s *big.Int) {
	return tx.V, tx.R, tx.S
}

func (tx *SetCodeTx) setSignatureValues(chainID, v, r, s *big.Int) {
	tx.ChainID, tx.V, tx.R, tx.S = chainID, v, r, s
}

// copy creates a deep copy of the inner data and initializes all fields.
func (tx *SetCodeTx) copy() TxData {
	cpy := &SetCodeTx{
		Nonce:      tx.Nonce,
		To:         copyAddressPtr(tx.To),
		Data:       common.CopyBytes(tx.Data),
		Gas:        tx.Gas,
		AccessList: make(AccessList, len(tx.AccessList)),
		AuthList:   make([]Authorization, len(tx.AuthList)),
		Value:      new(big.Int),
		ChainID:    new(big.Int),
		GasTipCap:  new(big.Int),
		GasFeeCap:  new(big.Int),
		V:          new(big.Int),
		R:          new(big.Int),
		S:          new(big.Int),
	}
	copy(cpy.AccessList, tx.AccessList)
	// Deep-copy each Authorization: shallow struct copy is unsafe because the
	// *big.Int fields would otherwise alias the source.
	for i, a := range tx.AuthList {
		cpy.AuthList[i] = Authorization{
			Address: a.Address,
			Nonce:   a.Nonce,
			ChainID: new(big.Int),
			V:       new(big.Int),
			R:       new(big.Int),
			S:       new(big.Int),
		}
		if a.ChainID != nil {
			cpy.AuthList[i].ChainID.Set(a.ChainID)
		}
		if a.V != nil {
			cpy.AuthList[i].V.Set(a.V)
		}
		if a.R != nil {
			cpy.AuthList[i].R.Set(a.R)
		}
		if a.S != nil {
			cpy.AuthList[i].S.Set(a.S)
		}
	}
	if tx.Value != nil {
		cpy.Value.Set(tx.Value)
	}
	if tx.ChainID != nil {
		cpy.ChainID.Set(tx.ChainID)
	}
	if tx.GasTipCap != nil {
		cpy.GasTipCap.Set(tx.GasTipCap)
	}
	if tx.GasFeeCap != nil {
		cpy.GasFeeCap.Set(tx.GasFeeCap)
	}
	if tx.V != nil {
		cpy.V.Set(tx.V)
	}
	if tx.R != nil {
		cpy.R.Set(tx.R)
	}
	if tx.S != nil {
		cpy.S.Set(tx.S)
	}
	return cpy
}

// AuthMagic is the EIP-7702 domain-separation byte prepended before the
// RLP-encoded authorization tuple when computing the authority digest.
const AuthMagic byte = 0x05

// ErrInvalidAuthSig is returned by RecoverAuthority when the authorization
// tuple's signature fields are malformed (V not in {0,1}, R or S out of range,
// or ECDSA recovery itself fails).
var ErrInvalidAuthSig = errors.New("invalid authorization signature")

// AuthorityHash is the digest signed by an authority for a single Authorization.
//
//	keccak256(MAGIC || rlp([chain_id, address, nonce]))
//
// where MAGIC = 0x05. Uses prefixedRlpHash for consistency with the typed
// transaction sighash machinery in transaction_signing.go.
func AuthorityHash(a Authorization) common.Hash {
	return prefixedRlpHash(AuthMagic, []interface{}{a.ChainID, a.Address, a.Nonce})
}

// RecoverAuthority recovers the signer EOA of an authorization tuple.
//
// On any failure (malformed signature, ECDSA recovery error, uncompressed
// pubkey not yielding a valid point) it returns the zero address and a non-nil
// error. Callers MUST check the returned error before trusting the address.
//
// The y_parity (Authorization.V) is the raw recovery id 0 or 1 — NOT the
// legacy 27/28 form. Values outside {0, 1} are rejected.
func RecoverAuthority(a Authorization) (common.Address, error) {
	if a.V == nil || a.R == nil || a.S == nil {
		return common.Address{}, ErrInvalidAuthSig
	}
	if a.V.BitLen() > 8 {
		return common.Address{}, ErrInvalidAuthSig
	}
	vb := byte(a.V.Uint64())
	if vb != 0 && vb != 1 {
		return common.Address{}, ErrInvalidAuthSig
	}
	if !crypto.ValidateSignatureValues(vb, a.R, a.S, false) {
		return common.Address{}, ErrInvalidAuthSig
	}

	// Pack signature in geth's canonical 65-byte layout: [R || S || V].
	r := a.R.Bytes()
	s := a.S.Bytes()
	sig := make([]byte, crypto.SignatureLength)
	copy(sig[32-len(r):32], r)
	copy(sig[64-len(s):64], s)
	sig[64] = vb

	hash := AuthorityHash(a)
	pub, err := crypto.Ecrecover(hash[:], sig)
	if err != nil {
		return common.Address{}, err
	}
	if len(pub) == 0 || pub[0] != 4 {
		return common.Address{}, ErrInvalidAuthSig
	}
	var addr common.Address
	copy(addr[:], crypto.Keccak256(pub[1:])[12:])
	return addr, nil
}

// Delegation parses an authority's code slot. If the code matches the
// EIP-7702 delegation prefix (0xef0100 || 20-byte target) it returns the
// delegated target and true. Otherwise it returns the zero address and false.
func Delegation(code []byte) (common.Address, bool) {
	const markerLen = len("\xef\x01\x00") + common.AddressLength // 23
	if len(code) != markerLen {
		return common.Address{}, false
	}
	if code[0] != DelegationPrefix[0] || code[1] != DelegationPrefix[1] || code[2] != DelegationPrefix[2] {
		return common.Address{}, false
	}
	return common.BytesToAddress(code[3:]), true
}
