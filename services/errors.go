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
	"fmt"

	"github.com/coinbase/rosetta-sdk-go/types"
)

var (
	errorCodes   = map[int32]*types.Error{}
	serverErrors = []*types.Error{}
)

var (
	// base errors
	errNotImplemented = newError(101, "method not implemented", false)
	errOfflineMode    = newError(102, "method not available in offline mode", false)
	// config-related errors
	errCurrencyNotDefined = newError(201, "currency not defined", false)
	// internal errors
	errDatastore             = newError(301, "datastore error", true)
	errDatastoreConflict     = newError(302, "datastore transaction conflict", true)
	errDatastoreConsistency  = newError(303, "datastore consistency failure", true)
	errInternal              = newError(304, "unexpected internal error", true)
	errNonceGenerationFailed = newError(305, "nonce generation failed", true)
	errProtobuf              = newError(306, "protobuf error", false)
	// input validation errors
	errInvalidAccountAddress     = newError(401, "invalid account address", false)
	errInvalidBlockHash          = newError(402, "invalid block hash", false)
	errInvalidBlockIdentifier    = newError(403, "invalid block identifier", false)
	errInvalidBlockIndex         = newError(404, "invalid block index", false)
	errInvalidContractAddress    = newError(405, "invalid contract address", false)
	errInvalidCurrency           = newError(406, "invalid currency", false)
	errInvalidGasLimit           = newError(407, "invalid gas limit", false)
	errInvalidGasPrice           = newError(408, "invalid gas price", false)
	errInvalidOpsIntent          = newError(409, "invalid ops intent", false)
	errInvalidPayerAddress       = newError(410, "invalid payer address", false)
	errInvalidPublicKey          = newError(411, "invalid public key", false)
	errInvalidRequestField       = newError(412, "invalid request field", false)
	errInvalidSignature          = newError(413, "invalid signature", false)
	errInvalidTransactionHash    = newError(414, "invalid transaction hash", false)
	errInvalidTransactionPayload = newError(415, "invalid transaction payload", false)
	// errInvalidSignedTransaction  = newError(411, "invalid signed transaction", false)
	// blockchain errors
	errBroadcastFailed = newError(501, "broadcast failed", true)
	// potentially retriable errors
	errTransactionNotInMempool = newError(601, "transaction not in mempool", true)
	errUnknownBlockHash        = newError(602, "unknown block hash", true)
	errUnknownBlockIndex       = newError(603, "unknown block index", true)
)

var (
	INVALID_PAYLOAD = &types.Error{
		Code:      505,
		Message:   "parse tx payload failed",
		Retriable: false,
	}
	PARAMS_ERROR = &types.Error{
		Code:      507,
		Message:   "params error",
		Retriable: true,
	}
	NO_SIGS_ERROR = &types.Error{
		Code:      516,
		Message:   "no signatures provided",
		Retriable: false,
	}
	PAYER_ERROR = &types.Error{
		Code:      522,
		Message:   "payer address invalid",
		Retriable: false,
	}
	TRANSFER_TX_ERROR = &types.Error{
		Code:      523,
		Message:   "construct transfer tx error",
		Retriable: false,
	}
	TX_INTO_IMMUTABLE_ERROR = &types.Error{
		Code:      524,
		Message:   "tx into immutable error",
		Retriable: false,
	}
	PARSE_GAS_PRICE_ERORR = &types.Error{
		Code:      526,
		Message:   "parse gas price error",
		Retriable: false,
	}
	PARSE_LIMIT_PRICE_ERORR = &types.Error{
		Code:      527,
		Message:   "parse gas limit error",
		Retriable: false,
	}
)

func invalidCurrencyf(format string, args ...interface{}) *types.Error {
	return wrapErr(errInvalidCurrency, fmt.Errorf("services: "+format, args...))
}

func invalidOpsf(format string, args ...interface{}) *types.Error {
	return wrapErr(errInvalidOpsIntent, fmt.Errorf("services: "+format, args...))
}

func newError(code int32, msg string, retriable bool) *types.Error {
	prev, exists := errorCodes[code]
	if exists {
		panic(fmt.Errorf(
			"services: duplicate error %d for %q and %q",
			code, msg, prev.Message,
		))
	}
	err := &types.Error{
		Code:      code,
		Message:   msg,
		Retriable: retriable,
	}
	serverErrors = append(serverErrors, err)
	return err
}

func wrapErr(xerr *types.Error, err error) *types.Error {
	dup := *xerr
	dup.Details = map[string]interface{}{
		"error": err.Error(),
	}
	return &dup
}
