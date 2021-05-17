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
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"
	"strconv"

	"github.com/coinbase/rosetta-sdk-go/types"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology-rosetta/chain"
	"github.com/ontio/ontology-rosetta/log"
	"github.com/ontio/ontology-rosetta/model"
	"github.com/ontio/ontology/cmd/utils"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/payload"
	"github.com/ontio/ontology/core/signature"
	ctypes "github.com/ontio/ontology/core/types"
	"github.com/ontio/ontology/errors"
	"github.com/ontio/ontology/http/base/actor"
	"github.com/ontio/ontology/smartcontract/service/neovm"
	"google.golang.org/protobuf/proto"
)

// ConstructionParse implements the /construction/parse endpoint.
func (s *service) ConstructionParse(ctx context.Context, request *types.ConstructionParseRequest) (*types.ConstructionParseResponse, *types.Error) {
	resp := &types.ConstructionParseResponse{
		Operations:               []*types.Operation{},
		AccountIdentifierSigners: []*types.AccountIdentifier{},
		Metadata:                 make(map[string]interface{}),
	}
	tx, xerr := decodeTransaction(request.Transaction)
	if xerr != nil {
		return nil, xerr
	}
	invokeCode, ok := tx.Payload.(*payload.InvokeCode)
	if !ok {
		log.Errorf("ConstructionParse: invalid tx payload")
		return resp, INVALID_PAYLOAD
	}
	resp.Metadata[PAYER] = tx.Payer.ToBase58()
	transferState, contract, err := chain.ParsePayload(invokeCode.Code)
	if err != nil {
		log.Errorf("ConstructionParse: %s", err)
		return resp, INVALID_PAYLOAD
	}
	cinfo, xerr := s.store.getCurrencyInfo(contract)
	if xerr != nil {
		return nil, xerr
	}
	for i, state := range transferState {
		operationFrom := &types.Operation{
			OperationIdentifier: &types.OperationIdentifier{Index: 2 * int64(i)},
			Type:                opTransfer,
			Status:              &statusSuccess,
			Account: &types.AccountIdentifier{
				Address: state.From.ToBase58(),
			},
			Amount: &types.Amount{
				Value:    fmt.Sprintf("-%d", state.Amount),
				Currency: cinfo.currency,
			},
		}
		if request.Signed {
			resp.AccountIdentifierSigners = append(resp.AccountIdentifierSigners, operationFrom.Account)
		}
		resp.Operations = append(resp.Operations, operationFrom)
		operationTo := &types.Operation{
			OperationIdentifier: &types.OperationIdentifier{Index: 2*int64(i) + 1},
			RelatedOperations: []*types.OperationIdentifier{
				{Index: operationFrom.OperationIdentifier.Index},
			},
			Type:   opTransfer,
			Status: &statusSuccess,
			Account: &types.AccountIdentifier{
				Address: state.To.ToBase58(),
			},
			Amount: &types.Amount{
				Value:    fmt.Sprint(state.Amount),
				Currency: cinfo.currency,
			},
			Metadata: make(map[string]interface{}),
		}
		operationTo.Metadata[GAS_PRICE] = tx.GasLimit
		operationTo.Metadata[GAS_LIMIT] = tx.GasPrice
		resp.Operations = append(resp.Operations, operationTo)
	}
	return resp, nil
}

// ConstructionPayloads implements the /construction/payloads endpoint.
func (s *service) ConstructionPayloads(ctx context.Context, request *types.ConstructionPayloadsRequest) (*types.ConstructionPayloadsResponse, *types.Error) {
	resp := &types.ConstructionPayloadsResponse{
		Payloads: make([]*types.SigningPayload, 0),
	}
	// TODO(tav)
	payerAddr := request.Metadata[PAYER].(string)
	var gasPrice, gasLimit float64
	var fromAddr, toAddr, fromAmount, toAmount, fromSymbol, toSymbol string
	var fromDecimals, toDecimals int32
	for _, operation := range request.Operations {
		if operation.OperationIdentifier.Index == 0 {
			fromAddr = operation.Account.Address
			fromAmount = operation.Amount.Value
			fromSymbol = operation.Amount.Currency.Symbol
			fromDecimals = operation.Amount.Currency.Decimals
		}
		if operation.OperationIdentifier.Index == 1 {
			for _, relatedOperation := range operation.RelatedOperations {
				if relatedOperation.Index == 0 {
					continue
				}
			}
			gasprice := operation.Metadata[GAS_PRICE]
			var ok bool
			gasPrice, ok = gasprice.(float64)
			if !ok {
				return resp, PARSE_GAS_PRICE_ERORR
			}
			gaslimit := operation.Metadata[GAS_LIMIT]
			gasLimit, ok = gaslimit.(float64)
			if !ok {
				return resp, PARSE_LIMIT_PRICE_ERORR
			}
			toAddr = operation.Account.Address
			toAmount = operation.Amount.Value
			toSymbol = operation.Amount.Currency.Symbol
			toDecimals = operation.Amount.Currency.Decimals
		}
	}
	if fromSymbol != toSymbol || fromDecimals != toDecimals || fromAmount[1:] != toAmount {
		return resp, PARAMS_ERROR
	}
	amount, err := strconv.ParseUint(toAmount, 10, 64)
	if err != nil {
		return resp, PARAMS_ERROR
	}
	mutTx, err := utils.TransferTx(uint64(gasPrice), uint64(gasLimit), toSymbol, fromAddr, toAddr, amount)
	if err != nil {
		return resp, TRANSFER_TX_ERROR
	}
	if payerAddr != "" {
		payer, err := common.AddressFromBase58(payerAddr)
		if err != nil {
			return resp, PAYER_ERROR
		}
		mutTx.Payer = payer
	}
	tx, err := mutTx.IntoImmutable()
	if err != nil {
		return resp, TX_INTO_IMMUTABLE_ERROR
	}
	sink := common.ZeroCopySink{}
	tx.Serialization(&sink)
	txHash := tx.Hash()
	resp.UnsignedTransaction = hex.EncodeToString(sink.Bytes())
	resp.Payloads = append(resp.Payloads, &types.SigningPayload{
		AccountIdentifier: &types.AccountIdentifier{
			Address: fromAddr,
		},
		Bytes:         txHash.ToArray(),
		SignatureType: types.Ecdsa,
	})
	if payerAddr != "" && payerAddr != fromAddr {
		resp.Payloads = append(resp.Payloads, &types.SigningPayload{
			AccountIdentifier: &types.AccountIdentifier{
				Address: payerAddr,
			},
			Bytes:         txHash.ToArray(),
			SignatureType: types.Ecdsa,
		})
	}

	return resp, nil
}

// ConstructionCombine implements the /construction/combine endpoint.
func (s *service) ConstructionCombine(ctx context.Context, req *types.ConstructionCombineRequest) (*types.ConstructionCombineResponse, *types.Error) {
	txn, xerr := decodeTransaction(req.UnsignedTransaction)
	if xerr != nil {
		return nil, xerr
	}
	mut, err := txn.IntoMutable()
	if err != nil {
		return nil, wrapErr(errInvalidTransactionPayload, err)
	}
	if len(mut.Sigs) > 0 {
		return nil, wrapErr(
			errInvalidTransactionPayload,
			fmt.Errorf("services: unexpected signature found in unsigned transaction"),
		)
	}
	sigs := req.Signatures
	if len(sigs) == 0 {
		return nil, errInvalidSignature
	}
	// TODO(ZhouPW): How to solve the multi-sig address case?
	for _, sig := range sigs {
		if sig.PublicKey == nil {
			return nil, errInvalidPublicKey
		}
		if len(sig.PublicKey.Bytes) < 1 {
			return nil, errInvalidPublicKey
		}
		// TODO(tav): Validate the curve type for the public key.
		switch keypair.KeyType(sig.PublicKey.Bytes[0]) {
		case keypair.PK_ECDSA:
		}
		pk, err := keypair.DeserializePublicKey(sig.PublicKey.Bytes)
		if err != nil {
			return nil, errInvalidPublicKey
		}
		// TODO(tav): Validate the key signature scheme.
		switch sig.SignatureType {
		}
		if sig.SigningPayload == nil {
			return nil, errInvalidSignature
		}
		// sig.SigningPayload.SignatureType
		err = signature.Verify(pk, sig.SigningPayload.Bytes, sig.Bytes)
		if err != nil {
			return nil, errInvalidSignature
		}
		mut.Sigs = append(mut.Sigs, ctypes.Sig{
			M:       1,
			PubKeys: []keypair.PublicKey{pk},
			SigData: [][]byte{sig.Bytes},
		})
	}
	txn, err = mut.IntoImmutable()
	if err != nil {
		return nil, wrapErr(errInternal, err)
	}
	sink := common.ZeroCopySink{}
	txn.Serialization(&sink)
	return &types.ConstructionCombineResponse{
		SignedTransaction: hex.EncodeToString(sink.Bytes()),
	}, nil
}

// ConstructionDerive implements the /construction/derive endpoint.
func (s *service) ConstructionDerive(ctx context.Context, r *types.ConstructionDeriveRequest) (*types.ConstructionDeriveResponse, *types.Error) {
	if r.PublicKey == nil {
		return nil, errInvalidPublicKey
	}
	pk, err := keypair.DeserializePublicKey(r.PublicKey.Bytes)
	if err != nil {
		return nil, errInvalidPublicKey
	}
	addr := ctypes.AddressFromPubKey(pk)
	return &types.ConstructionDeriveResponse{
		AccountIdentifier: &types.AccountIdentifier{
			Address: addr.ToBase58(),
		},
	}, nil
}

// ConstructionHash implements the /construction/hash endpoint.
func (s *service) ConstructionHash(ctx context.Context, r *types.ConstructionHashRequest) (*types.TransactionIdentifierResponse, *types.Error) {
	txn, xerr := decodeTransaction(r.SignedTransaction)
	if xerr != nil {
		return nil, xerr
	}
	return txhash2response(txn.Hash())
}

// ConstructionMetadata implements the /construction/metadata endpoint.
func (s *service) ConstructionMetadata(ctx context.Context, r *types.ConstructionMetadataRequest) (*types.ConstructionMetadataResponse, *types.Error) {
	if s.offline {
		return nil, errOfflineMode
	}
	opts := &model.MetadataOptions{}
	if xerr := decodeProtobuf(r.Options, opts); xerr != nil {
		return nil, xerr
	}
	// TODO(tav): We should get the current gas fee from seed nodes, and
	// generate an unused nonce for the payer.
	buf := make([]byte, 8)
	n, err := rand.Read(buf)
	if err != nil || n != 8 {
		return nil, errNonceGenerationFailed
	}
	nonce := binary.LittleEndian.Uint32(buf)
	return &types.ConstructionMetadataResponse{
		Metadata: map[string]interface{}{
			"gas_limit": opts.GasLimit,
			"gas_price": opts.GasPrice,
			"nonce":     nonce,
		},
	}, nil
}

// ConstructionPreprocess implements the /construction/preprocess endpoint.
func (s *service) ConstructionPreprocess(ctx context.Context, r *types.ConstructionPreprocessRequest) (*types.ConstructionPreprocessResponse, *types.Error) {
	if len(r.MaxFee) > 0 {
		return nil, wrapErr(
			errInvalidRequestField,
			fmt.Errorf("services: unsupported field: max_fee"),
		)
	}
	if r.SuggestedFeeMultiplier != nil {
		return nil, wrapErr(
			errInvalidRequestField,
			fmt.Errorf("services: unsupported field: suggested_fee_multiplier"),
		)
	}
	gasLimit, err := getUint64Field(r.Metadata, "gas_limit")
	if err != nil {
		return nil, wrapErr(errInvalidGasLimit, err)
	}
	gasPrice, err := getUint64Field(r.Metadata, "gas_price")
	if err != nil {
		return nil, wrapErr(errInvalidGasPrice, err)
	}
	if gasPrice == 0 {
		gasPrice = 2000
	}
	payer, xerr := getPayer(r.Metadata)
	if xerr != nil {
		return nil, xerr
	}
	xfer, xerr := s.validateOps(r.Operations)
	if xerr != nil {
		return nil, xerr
	}
	if payer != common.ADDRESS_EMPTY {
		payer = xfer.from
	}
	enc, err := proto.Marshal(&model.MetadataOptions{
		GasLimit: gasLimit,
		GasPrice: gasPrice,
		Payer:    payer.ToBase58(),
	})
	if err != nil {
		return nil, wrapErr(errProtobuf, err)
	}
	return &types.ConstructionPreprocessResponse{
		Options: map[string]interface{}{
			"protobuf": hex.EncodeToString(enc),
		},
	}, nil
}

// ConstructionSubmit implements the /construction/submit endpoint.
func (s *service) ConstructionSubmit(ctx context.Context, r *types.ConstructionSubmitRequest) (*types.TransactionIdentifierResponse, *types.Error) {
	if s.offline {
		return nil, errOfflineMode
	}
	txn, xerr := decodeTransaction(r.SignedTransaction)
	if xerr != nil {
		return nil, xerr
	}
	if err, desc := actor.AppendTxToPool(txn); err != errors.ErrNoError {
		log.Errorf("Failed to broadcast transaction: %s (%s)", err, desc)
		return nil, wrapErr(errBroadcastFailed, err)
	}
	return txhash2response(txn.Hash())
}

// NOTE(tav): We currently only support a simple transfer of an asset from one
// account to another.
func (s *service) validateOps(ops []*types.Operation) (*transferInfo, *types.Error) {
	if ops == nil {
		return nil, invalidOpsf("missing operations field")
	}
	if len(ops) != 2 {
		return nil, invalidOpsf("unexpected number of operations: %d", len(ops))
	}
	addrs := make([]common.Address, 2)
	amounts := make([]*big.Int, 2)
	zero := big.NewInt(0)
	var cinfo *currencyInfo
	for i, op := range ops {
		if op.Account == nil {
			return nil, invalidOpsf("missing operations[%d].account", i)
		}
		addr, err := common.AddressFromBase58(op.Account.Address)
		if err != nil {
			return nil, invalidOpsf(
				"unable to parse operations[%d].account.address: %s",
				i, err,
			)
		}
		addrs[i] = addr
		if op.Amount == nil {
			return nil, invalidOpsf("missing operations[%d].amount", i)
		}
		amount, ok := (&big.Int{}).SetString(op.Amount.Value, 10)
		if !ok {
			return nil, invalidOpsf(
				"invalid operations[%d].amount.value: %s",
				i, op.Amount.Value,
			)
		}
		if amount.Cmp(zero) == 0 {
			return nil, invalidOpsf("operations[%d].amount.value is zero", i)
		}
		amounts[i] = amount
		token, xerr := s.store.validateCurrency(op.Amount.Currency)
		if xerr != nil {
			return nil, xerr
		}
		if token.isNative() {
			if op.Account.SubAccount == nil {
				return nil, invalidOpsf("missing operations[%d].account.sub_account", i)
			}
			caddr, err := common.AddressFromHexString(op.Account.SubAccount.Address)
			if err != nil {
				return nil, invalidOpsf(
					"unable to parse operations[%d].account.sub_account.address: %s",
					i, err,
				)
			}
			if token.contract != caddr {
				return nil, invalidOpsf(
					"operations[%d].account.sub_account.address does not match currency",
					i,
				)
			}
		}
		if cinfo == nil {
			cinfo = token
		} else if cinfo != token {
			return nil, invalidOpsf("operations must be in the same currency")
		}
		if op.OperationIdentifier == nil {
			return nil, invalidOpsf("missing operations[%d].operation_identifier", i)
		}
		if op.Type != opTransfer {
			return nil, invalidOpsf("unsupported operation type: %q", op.Type)
		}
	}
	switch {
	case len(ops[0].RelatedOperations) > 0:
		xerr := validateRelation(ops, 0, 1)
		if xerr != nil {
			return nil, xerr
		}
	case len(ops[1].RelatedOperations) > 0:
		xerr := validateRelation(ops, 1, 0)
		if xerr != nil {
			return nil, xerr
		}
	default:
		return nil, invalidOpsf("invalid related_operations on operations")
	}
	sum := (&big.Int{}).Add(amounts[0], amounts[1])
	if sum.Cmp(zero) != 0 {
		return nil, invalidOpsf("amount values in operations do not sum to zero")
	}
	xfer := &transferInfo{
		contract: cinfo.contract,
		currency: cinfo.currency,
	}
	switch amounts[0].Cmp(zero) {
	case 1:
		xfer.amount = amounts[0]
		xfer.from = addrs[1]
		xfer.to = addrs[0]
		return xfer, nil
	case -1:
		xfer.amount = amounts[1]
		xfer.from = addrs[0]
		xfer.to = addrs[1]
		return xfer, nil
	default:
		return nil, invalidOpsf("amount values in operations cannot be zero")
	}
}

func decodeProtobuf(md map[string]interface{}, m proto.Message) *types.Error {
	data, ok := md["protobuf"]
	if !ok {
		return wrapErr(errProtobuf, fmt.Errorf("services: protobuf metadata field is missing"))
	}
	raw, ok := data.(string)
	if !ok {
		return wrapErr(errProtobuf, fmt.Errorf("services: protobuf metadata field is not a string"))
	}
	val, err := hex.DecodeString(raw)
	if err != nil {
		return wrapErr(errProtobuf, err)
	}
	if err := proto.Unmarshal(val, m); err != nil {
		return wrapErr(errProtobuf, err)
	}
	return nil
}

func decodeTransaction(data string) (*ctypes.Transaction, *types.Error) {
	if len(data) == 0 {
		return nil, errInvalidTransactionPayload
	}
	raw, err := hex.DecodeString(data)
	if err != nil {
		return nil, wrapErr(errInvalidTransactionPayload, err)
	}
	txn, err := ctypes.TransactionFromRawBytes(raw)
	if err != nil {
		return nil, wrapErr(errInvalidTransactionPayload, err)
	}
	if txn == nil {
		return nil, wrapErr(
			errInvalidTransactionPayload,
			fmt.Errorf("transaction is nil when decoded"),
		)
	}
	return txn, nil
}

func getUint64Field(md map[string]interface{}, field string) (uint64, error) {
	if md == nil {
		return 0, nil
	}
	val, ok := md[field]
	if !ok {
		return 0, nil
	}
	raw, ok := val.(float64)
	if !ok {
		return 0, fmt.Errorf("services: unexpected datatype for metadata.%s: %s", field, val)
	}
	v := uint64(raw)
	if float64(v) != raw {
		return 0, fmt.Errorf(
			"services: cannot accurately cast metadata.%s value to uint64: %v",
			field, raw,
		)
	}
	switch field {
	case "gas_limit":
		if v == 0 {
			v = neovm.MIN_TRANSACTION_GAS
		}
		if v < neovm.MIN_TRANSACTION_GAS {
			return 0, fmt.Errorf(
				"services: gas limit of %d is below the minimum value of %d",
				v, neovm.MIN_TRANSACTION_GAS,
			)
		}
		return v, nil
	case "gas_price":
		return 2500, nil
	}
	return v, nil
}

func getPayer(md map[string]interface{}) (common.Address, *types.Error) {
	if md == nil {
		return common.ADDRESS_EMPTY, nil
	}
	val, ok := md["payer"]
	if !ok {
		return common.ADDRESS_EMPTY, nil
	}
	raw, ok := val.(string)
	if !ok {
		return common.ADDRESS_EMPTY, wrapErr(
			errInvalidPayerAddress,
			fmt.Errorf(
				"services: unexpected datatype for metadata.payer: %s",
				reflect.TypeOf(val),
			),
		)
	}
	addr, err := common.AddressFromBase58(raw)
	if err != nil {
		return common.ADDRESS_EMPTY, wrapErr(
			errInvalidPayerAddress,
			fmt.Errorf("services: unable to parse metadata.payer: %s", err),
		)
	}
	return addr, nil
}

func txhash2response(hash common.Uint256) (*types.TransactionIdentifierResponse, *types.Error) {
	return &types.TransactionIdentifierResponse{
		TransactionIdentifier: &types.TransactionIdentifier{
			Hash: hash.ToHexString(),
		},
	}, nil
}

func validateRelation(ops []*types.Operation, ifrom int, ito int) *types.Error {
	if len(ops[ito].RelatedOperations) > 0 {
		return invalidOpsf(
			"cannot have related_operations on both operations[%d] and operations[%d]",
			ifrom, ito,
		)
	}
	rel := ops[ifrom].RelatedOperations[0]
	if rel == nil {
		return invalidOpsf("invalid operations[%d].related_operations", ifrom)
	}
	src := ops[ito].OperationIdentifier.Index
	if rel.Index != src {
		return invalidOpsf(
			"operations[%d].related_operations does not match operations[%d].operation_identifier",
			ifrom, ito,
		)
	}
	diff := ops[ifrom].OperationIdentifier.Index - src
	if diff != 1 {
		return invalidOpsf(
			"operations[%d].related_operations does not follow from operations[%d]",
			ifrom, ito,
		)
	}
	return nil
}
