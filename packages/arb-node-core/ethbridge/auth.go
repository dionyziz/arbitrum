/*
 * Copyright 2021, Offchain Labs, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ethbridge

import (
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/offchainlabs/arbitrum/packages/arb-util/configuration"
	"github.com/offchainlabs/arbitrum/packages/arb-util/ethutils"
	"github.com/offchainlabs/arbitrum/packages/arb-util/fireblocks"
	"github.com/offchainlabs/arbitrum/packages/arb-util/fireblocks/accounttype"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

var logger = log.With().Caller().Stack().Str("component", "ethbridge").Logger()

const (
	smallNonceRepeatCount = 100
	smallNonceError       = "Try increasing the gas price or incrementing the nonce."
)

type TransactAuth struct {
	sync.Mutex
	auth        *bind.TransactOpts
	gasPriceUrl string
	sendTx      func(ctx context.Context, tx *types.Transaction) error
}

func NewTransactAuth(ctx context.Context, client ethutils.EthClient, auth *bind.TransactOpts, config *configuration.Config) (*TransactAuth, error) {
	if auth.Nonce == nil {
		nonce, err := client.PendingNonceAt(ctx, auth.From)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to get nonce")
		}
		auth.Nonce = new(big.Int).SetUint64(nonce)
	}
	var sendTx func(ctx context.Context, tx *types.Transaction) error

	if len(config.Fireblocks.PrivateKey) != 0 {
		signKey, err := jwt.ParseRSAPrivateKeyFromPEMWithPassword([]byte(config.Fireblocks.PrivateKey), config.Fireblocks.KeyPassword)
		if err != nil {
			return nil, errors.Wrap(err, "problem with fireblocks privatekey")
		}
		// Config already validated so error will not happen
		sourceType, _ := accounttype.New(config.Fireblocks.SourceId)
		fb := fireblocks.New("ETH", config.Fireblocks.BaseURL, *sourceType, config.Fireblocks.SourceId, config.Fireblocks.APIKey, signKey)
		sendTx = func(ctx context.Context, tx *types.Transaction) error {
			response, err := fb.CreateNewContractCall(accounttype.OneTimeAddress, tx.To().Hex(), "", ethcommon.Bytes2Hex(tx.Data()))
			if err != nil {
				return err
			}

			if response.Status == "CANCELLED" || response.Status == "REJECTED" || response.Status == "BLOCKED" || response.Status == "FAILED" {
				logger.Error().Hex("data", tx.Data()).Str("status", response.Status).Msg("fireblocks transaction failed")
				return errors.New("fireblocks transaction failed")
			}

			logger.Debug().Hex("data", tx.Data()).Str("status", response.Status).Msg("fireblocks transaction submitted")
			return nil
		}
	} else {
		// Send transaction normally
		sendTx = func(ctx context.Context, tx *types.Transaction) error {
			err := client.SendTransaction(ctx, tx)
			if err != nil {
				logger.Error().Err(err).Hex("data", tx.Data()).Msg("error sending transaction")
				return err
			}

			logger.Debug().Hex("data", tx.Data()).Msg("sent transaction")
			return nil
		}
	}
	return &TransactAuth{
		auth:        auth,
		gasPriceUrl: config.GasPriceUrl,
		sendTx:      sendTx,
	}, nil
}

func (t *TransactAuth) makeContract(ctx context.Context, contractFunc func(auth *bind.TransactOpts) (ethcommon.Address, *types.Transaction, interface{}, error)) (ethcommon.Address, *types.Transaction, error) {
	auth, err := t.getAuth(ctx)
	if err != nil {
		return ethcommon.Address{}, nil, err
	}

	origNoSend := t.auth.NoSend
	t.auth.NoSend = true
	defer func(t *TransactAuth) {
		t.auth.NoSend = origNoSend
	}(t)

	// Form transaction without sending it
	addr, tx, _, err := contractFunc(auth)
	err = errors.WithStack(err)
	if err != nil {
		// Error occurred before sending, so don't need retry logic below
		logger.Error().Err(err).Msg("error forming transaction")
		return addr, nil, err
	}

	// Actually send transaction
	err = t.sendTx(ctx, tx)

	if auth.Nonce == nil {
		// Not incrementing nonce, so nothing else to do
		if err != nil {
			logger.Error().Err(err).Str("nonce", "nil").Msg("error when nonce not set")
			return addr, nil, err
		}

		logger.Info().Str("nonce", "nil").Hex("sender", t.auth.From.Bytes()).Send()
		return addr, tx, err
	}

	for i := 0; i < smallNonceRepeatCount && err != nil && strings.Contains(err.Error(), smallNonceError); i++ {
		// Increment nonce and try again
		logger.Error().Err(err).Str("nonce", auth.Nonce.String()).Msg("incrementing nonce and submitting tx again")

		t.auth.Nonce = t.auth.Nonce.Add(t.auth.Nonce, big.NewInt(1))
		auth.Nonce = t.auth.Nonce
		addr, tx, _, err = contractFunc(auth)
		err = t.sendTx(ctx, tx)
		err = errors.WithStack(err)

		time.Sleep(100 * time.Millisecond)
	}

	if err != nil {
		logger.Error().Err(err).Str("nonce", auth.Nonce.String()).Send()
		return addr, nil, err
	}

	// Transaction successful, increment nonce for next time
	logger.Info().Str("nonce", auth.Nonce.String()).Hex("sender", t.auth.From.Bytes()).Send()

	t.auth.Nonce = t.auth.Nonce.Add(t.auth.Nonce, big.NewInt(1))
	return addr, tx, err
}

func (t *TransactAuth) makeTx(ctx context.Context, txFunc func(auth *bind.TransactOpts) (*types.Transaction, error)) (*types.Transaction, error) {
	_, tx, err := t.makeContract(ctx, func(auth *bind.TransactOpts) (ethcommon.Address, *types.Transaction, interface{}, error) {
		tx, err := txFunc(auth)
		return ethcommon.BigToAddress(big.NewInt(0)), tx, nil, err
	})

	return tx, err
}

type gasPriceResult struct {
	SafeGasPrice    string `json:"SafeGasPrice"`
	ProposeGasPrice string `json:"ProposeGasPrice"`
	FastGasPrice    string `json:"FastGasPrice"`
}

type gasPriceInfo struct {
	Result gasPriceResult `json:"result"`
}

// May use Etherscan's API to get gas price: https://etherscan.io/apis
func (t *TransactAuth) getAuth(ctx context.Context) (*bind.TransactOpts, error) {
	gasPrice := t.auth.GasPrice
	if t.gasPriceUrl != "" {
		resp, err := http.Get(t.gasPriceUrl)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get gas price")
		}
		defer func(Body io.ReadCloser) {
			_ = resp.Body.Close()
		}(resp.Body)
		text, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get gas price")
		}
		info := gasPriceInfo{}
		err = json.Unmarshal(text, &info)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get gas price")
		}
		gasPriceFloat, ok := new(big.Float).SetString(info.Result.ProposeGasPrice)
		if !ok {
			return nil, errors.New("failed to parse gas price")
		}
		gasPrice, _ = gasPriceFloat.Mul(gasPriceFloat, big.NewFloat(1e9)).Int(new(big.Int))
	}
	return &bind.TransactOpts{
		From:     t.auth.From,
		Nonce:    t.auth.Nonce,
		Signer:   t.auth.Signer,
		Value:    t.auth.Value,
		GasPrice: gasPrice,
		GasLimit: t.auth.GasLimit,
		Context:  ctx,
	}, nil
}
