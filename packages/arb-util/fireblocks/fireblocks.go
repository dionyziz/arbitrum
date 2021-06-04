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

package fireblocks

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/rs/zerolog/log"
)

var logger = log.With().Caller().Stack().Str("component", "configuration").Logger()

type Fireblocks struct {
	apiKey   string
	assetId  string
	baseUrl  string
	signKey  *rsa.PrivateKey
	sourceId string
}

type CreateNewTransactionBody struct {
	AssetId         string                          `json:"assetId"`
	Source          TransferPeerPath                `json:"source"`
	Destination     DestinationTransferPeerPath     `json:"destination"`
	Amount          string                          `json:"amount"`
	Fee             string                          `json:"fee,omitempty"`
	GasPrice        string                          `json:"gasPrice,omitempty"`
	GasLimit        string                          `json:"gasLimit,omitempty"`
	NetworkFee      string                          `json:"networkFee,omitempty"`
	FeeLevel        string                          `json:"feeLevel,omitempty"`
	MaxFee          string                          `json:"maxFee,omitempty"`
	FailOnLowFee    bool                            `json:"failOnLowFee,omitempty"`
	Note            string                          `json:"note,omitempty"`
	Operation       string                          `json:"operation,omitempty"`
	CustomerRefId   string                          `json:"customerRefId,omitempty"`
	Destinations    []TransactionRequestDestination `json:"destinations,omitempty"`
	ExtraParameters TransactionExtraParameters      `json:"extraParameters"`
}

type TransactionExtraParameters struct {
	ContractCallData string `json:"contractCallData"`
}

type TransferPeerPath struct {
	Type string `json:"type"`
	Id   string `json:"id"`
}

type DestinationTransferPeerPath struct {
	Type           string         `json:"type"`
	Id             string         `json:"id"`
	OneTimeAddress OneTimeAddress `json:"oneTimeAddress,omitempty"`
}

type OneTimeAddress struct {
	Address string `json:"address"`
	Tag     string `json:"tag"`
}

type CreateTransactionResponse struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

type ListVaultAccountsResult struct {
	VaultAccounts []VaultAccount `json:"vaultAccounts"`
}

type VaultAccount struct {
	Id            string       `json:"id"`
	Name          string       `json:"name"`
	HiddenOnUI    bool         `json:"hiddenOnUI"`
	CustomerRefId string       `json:"customerRefId,omitempty"`
	AutoFuel      bool         `json:"autoFuel"`
	Assets        []VaultAsset `json:"assets"`
}

type VaultAsset struct {
	Id                   string `json:"id"`
	Total                string `json:"total"`
	Balance              string `json:"balance"`
	Available            string `json:"available"`
	Pending              string `json:"pending"`
	LockedAmount         string `json:"lockedAmount"`
	TotalStakedCPU       string `json:"totalStakedCPU"`
	SelfStakedCPU        string `json:"selfStakedCPU"`
	SelfStakedNetwork    string `json:"selfStakedNetwork"`
	PendingRefundCPU     string `json:"pendingRefundCPU"`
	PendingRefundNetwork string `json:"pendingRefundNetwork"`
}

type TransactionRequestDestination struct {
	Amount      string `json:"amount"`
	Destination string `json:"destination"`
}

type fireblocksClaims struct {
	Uri      string `json:"url"`
	Nonce    int64  `json:"nonce"`
	Iat      int64  `json:"iat"`
	Exp      int64  `json:"exp"`
	Sub      string `json:"sub"`
	BodyHash string `json:"bodyHash"`
	jwt.StandardClaims
}

func New(assetId string, baseUrl string, sourceId string, apiKey string, signKey *rsa.PrivateKey) *Fireblocks {
	return &Fireblocks{
		apiKey:   apiKey,
		assetId:  assetId,
		baseUrl:  baseUrl,
		signKey:  signKey,
		sourceId: sourceId,
	}
}

func (fb *Fireblocks) ListVaultAccounts() (*ListVaultAccountsResult, error) {
	resp, err := fb.postRequest("/v1/vault/accounts", nil)
	if err != nil {
		return nil, err
	}

	var result ListVaultAccountsResult
	err = json.NewDecoder(resp.Body).Decode(&result.VaultAccounts)
	if err != nil {
		return nil, err
	}

	return &result, err
}

func (fb *Fireblocks) CreateNewTransaction(destinationId string, callData string) (*CreateTransactionResponse, error) {

	body := &CreateNewTransactionBody{
		AssetId:         fb.assetId,
		Source:          TransferPeerPath{Type: "VAULT_ACCOUNT", Id: fb.sourceId},
		Destination:     DestinationTransferPeerPath{Type: "EXTERNAL_WALLET", Id: destinationId},
		Amount:          "0",
		Operation:       "CONTRACT_CALL",
		ExtraParameters: TransactionExtraParameters{ContractCallData: callData},
	}

	jsonData, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	resp, err := fb.postRequest("/v1/transactions", jsonData)
	if err != nil {
		return nil, err
	}

	var result CreateTransactionResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, err
	}

	return &result, err
}

func (fb *Fireblocks) postRequest(path string, body []byte) (*http.Response, error) {
	token, err := fb.signJWT(path, body)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	url := fb.baseUrl + path
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		logger.
			Error().
			Err(err).
			Str("url", fb.baseUrl).
			Msg("error creating new fireblocks request")
		return nil, err
	}
	req.Header.Add("X-API-Key", fb.apiKey)
	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		logger.
			Error().
			Err(err).
			Str("url", fb.baseUrl).
			Str("status", resp.Status).
			Msg("error doing fireblocks request")
		return nil, err
	}

	if resp.StatusCode >= 300 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			logger.
				Error().
				Err(err).
				Str("url", url).
				Str("status", resp.Status).
				Msg("error reading body after posting fireblocks request")
			return nil, fmt.Errorf("status '%s' posting fireblocks request", resp.Status)
		}

		bodyStr := string(body)
		logger.
			Error().
			Str("url", url).
			Str("status", resp.Status).
			Str("body", bodyStr).
			Msg("error returned when posting fireblocks request")
		return nil, fmt.Errorf("status '%s' posting fireblocks request", resp.Status)
	}

	return resp, nil
}

func (fb *Fireblocks) signJWT(path string, body []byte) (string, error) {
	newPath := strings.Replace(path, "[", "%5B", -1)
	newPath = strings.Replace(newPath, "]", "%5D", -1)
	now := time.Now().Unix()
	bodyHash := sha256.Sum256(body)

	claims := fireblocksClaims{
		Uri:      newPath,
		Nonce:    rand.Int63(),
		Iat:      now,
		Exp:      now + 55,
		Sub:      fb.apiKey,
		BodyHash: hex.EncodeToString(bodyHash[:]),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	return token.SignedString(fb.signKey)
}
