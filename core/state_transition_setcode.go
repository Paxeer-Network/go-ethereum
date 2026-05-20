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

// EIP-7702 (SetCodeTx) authorization application. Lives in its own file to
// minimize merge-conflict surface with upstream evmos updates to
// state_transition.go. See the Paxeer backport spec at
// app/upgrades/v20agent/geth_7702_backport.md in the hyperpax-os-cronosRelease
// chain repo.

package core

import (
	"bytes"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
)

// ApplyAuthorizations writes the EIP-7702 delegation marker (0xef0100 || target)
// into each authority's code slot. It is meant to be invoked BEFORE the call
// frame executes (i.e. between gas pre-pay and evm.Call), so that any code the
// transaction's `to` address invokes already sees the new delegation markers.
//
// Each authorization is processed in order. An authorization is **skipped**
// (gas still charged) on:
//   - signature recovery failure (malformed V/R/S, ECDSA failure)
//   - chain-id mismatch (must equal `chainID` OR be 0)
//   - authority nonce ≠ a.Nonce
//   - authority already has non-empty code that is NOT a delegation marker
//
// Skip semantics are mandatory per EIP-7702 §3: a malformed authorization
// charges gas but does not abort the surrounding transaction. Callers MUST NOT
// treat a low `applied` count as a transaction-level failure.
//
// Returns:
//   - gasUsed:  total gas to subtract from the tx's leftoverGas
//   - applied:  count of authorizations that successfully wrote a delegation
//     marker; suitable for event metadata, NOT for control flow
//
// The function is deterministic given the same statedb snapshot, chainID, and
// auths slice — no time, no rng, no goroutines.
func ApplyAuthorizations(
	statedb vm.StateDB,
	chainID *big.Int,
	auths []types.Authorization,
) (gasUsed uint64, applied int) {
	for _, a := range auths {
		// Always charge the base cost FIRST so that the gas total is the same
		// regardless of which validation branch the authorization fails on.
		// EIP-7702 explicitly requires uniform base-charge semantics to prevent
		// gas-sidechannels on the auth-list path.
		cost := params.PerAuthBaseCost

		// 1. Recover authority. Errors here charge base cost and skip.
		authority, err := types.RecoverAuthority(a)
		if err != nil || authority == (common.Address{}) {
			gasUsed += cost
			continue
		}

		// 2. Chain-id check. Per EIP-7702 the authorization is valid if its
		// chain_id matches the active chain OR is 0 (meaning "any chain").
		if a.ChainID != nil && a.ChainID.Sign() != 0 && a.ChainID.Cmp(chainID) != 0 {
			gasUsed += cost
			continue
		}

		// 3. Nonce check.
		if statedb.GetNonce(authority) != a.Nonce {
			gasUsed += cost
			continue
		}

		// 4. Existing-code check. The only acceptable non-empty code is a
		// pre-existing delegation marker (which we will overwrite). Any other
		// code (a real contract, EOF, etc.) blocks delegation.
		existingCode := statedb.GetCode(authority)
		if len(existingCode) > 0 && !bytes.HasPrefix(existingCode, types.DelegationPrefix) {
			gasUsed += cost
			continue
		}

		// 5. Surcharge if the authority is an empty account (balance = nonce =
		// code = 0). This pays for creating a new state object.
		if statedb.Empty(authority) {
			cost = params.PerEmptyAccountCost
		}
		gasUsed += cost

		// 6. Write delegation marker: 0xef0100 || target (23 bytes total).
		marker := make([]byte, 0, len(types.DelegationPrefix)+common.AddressLength)
		marker = append(marker, types.DelegationPrefix...)
		marker = append(marker, a.Address.Bytes()...)
		statedb.SetCode(authority, marker)

		// 7. Bump authority nonce. Per EIP-7702, the nonce is incremented
		// even though no transaction was sent from the authority. This is the
		// load-bearing replay-protection mechanism for authorization tuples.
		statedb.SetNonce(authority, a.Nonce+1)

		applied++
	}
	return gasUsed, applied
}
