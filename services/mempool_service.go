/*
 * Copyright (C) 2018 The ontology Authors
 * This file is part of The ontology library.
 *
 * The ontology is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The ontology is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with The ontology.  If not, see <http://www.gnu.org/licenses/>.
 */

package services

import (
	"context"

	"github.com/coinbase/rosetta-sdk-go/types"
	"github.com/ontio/ontology-rosetta/chain"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/payload"
	"github.com/ontio/ontology/http/base/actor"
)

// Mempool implements the /mempool endpoint.
func (s *service) Mempool(ctx context.Context, r *types.NetworkRequest) (*types.MempoolResponse, *types.Error) {
	if s.offline {
		return nil, errOfflineMode
	}
	txs := []*types.TransactionIdentifier{}
	for hash := range actor.GetTxsFromPool(false) {
		txs = append(txs, &types.TransactionIdentifier{
			Hash: hash.ToHexString(),
		})
	}
	return &types.MempoolResponse{
		TransactionIdentifiers: txs,
	}, nil
}

// MempoolTransaction implements the /mempool/transaction endpoint.
func (s *service) MempoolTransaction(ctx context.Context, r *types.MempoolTransactionRequest) (*types.MempoolTransactionResponse, *types.Error) {
	if s.offline {
		return nil, errOfflineMode
	}
	if r.TransactionIdentifier == nil {
		return nil, errInvalidTransactionHash
	}
	hash, err := common.Uint256FromHexString(r.TransactionIdentifier.Hash)
	if err != nil {
		return nil, errInvalidTransactionHash
	}
	entry, err := actor.GetTxFromPool(hash)
	if err != nil {
		return nil, errTransactionNotInMempool
	}
	if entry.Tx.Payload == nil {
		return nil, errInvalidTransactionPayload
	}
	invoke, ok := entry.Tx.Payload.(*payload.InvokeCode)
	if !ok {
		return nil, errInvalidTransactionPayload
	}
	xfers, contract, err := chain.ParsePayload(invoke.Code)
	if err != nil {
		return nil, wrapErr(errInvalidTransactionPayload, err)
	}
	info, xerr := s.store.getCurrencyInfo(contract)
	if xerr != nil {
		return nil, xerr
	}
	ops := []*types.Operation{}
	for _, xfer := range xfers {
		ops = s.appendOperations(ops, &transferInfo{
			amount:   xfer.Amount,
			contract: contract,
			currency: info.currency,
			from:     xfer.From,
			to:       xfer.To,
		})
	}
	return &types.MempoolTransactionResponse{
		Transaction: &types.Transaction{
			Operations: ops,
			TransactionIdentifier: &types.TransactionIdentifier{
				Hash: r.TransactionIdentifier.Hash,
			},
		},
	}, nil
}
