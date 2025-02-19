package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type NextToken struct {
	SecretToken string `json:"secret_token"`
	LambdaToken string `json:"lambda_token"`
}

func decodeNextToken(token string) (*NextToken, error) {
	b, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("failed to decode token: %v", err)
	}

	t := &NextToken{}
	if err := json.Unmarshal(b, t); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token %v", err)
	}
	return t, nil
}

func createNextToken(secretToken string, lambdaToken string) (string, error) {
	token := &NextToken{
		SecretToken: secretToken,
		LambdaToken: lambdaToken,
	}
	return token.encode()
}
func (t *NextToken) encode() (string, error) {
	if t.SecretToken == "" && t.LambdaToken == "" {
		return "", nil
	}
	b, err := json.Marshal(t)
	if err != nil {
		return "", fmt.Errorf("failed to json marshalling %v", err)
	}

	return base64.StdEncoding.EncodeToString(b), nil
}
