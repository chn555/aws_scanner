package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"strings"
)

func getAllSecretValues(ctx context.Context, cfg aws.Config, nextToken string) ([]*Secret, string, error) {

	// Create Secrets Manager client
	svc := secretsmanager.NewFromConfig(cfg)

	// Call to list secrets
	input := &secretsmanager.ListSecretsInput{}
	if nextToken != "" {
		input.NextToken = aws.String(nextToken)
	}
	listSecretsOutput, err := svc.ListSecrets(ctx, input)
	if err != nil {
		return nil, "", fmt.Errorf("unable to list secrets, %v", err)
	}

	secrets := make([]*Secret, 0)

	// Iterate over the secret names
	for _, secret := range listSecretsOutput.SecretList {
		s, err := getSecretFromSecret(ctx, svc, secret)
		if err != nil {
			return nil, "", fmt.Errorf("failed to get secrets, %v", err)
		}

		secrets = append(secrets, s...)
	}

	return secrets, aws.ToString(listSecretsOutput.NextToken), nil
}

func getSecretFromSecret(ctx context.Context, svc *secretsmanager.Client, secret types.SecretListEntry) ([]*Secret, error) {

	// Get the secret value
	getSecretValueOutput, err := svc.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: secret.ARN,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to get secret %s value, %v", *secret.Name, err)
	}

	// Print the secret value (JSON, plaintext, or binary)
	if getSecretValueOutput.SecretString == nil {
		return nil, nil
	}

	secrets := make([]*Secret, 0)

	secretKVs, err := getSecretsFromJSONString(*getSecretValueOutput.SecretString)
	if err != nil {
		return nil, fmt.Errorf("error reading secrets: %v", err)
	}

	for _, kv := range secretKVs {
		secrets = append(secrets, &Secret{
			Name:     *secret.Name,
			ARN:      *secret.ARN,
			keyValue: kv,
		})
	}

	return secrets, nil
}

func getSecretsFromJSONString(secretString string) ([]SecretKeyValue, error) {
	// Parse the JSON and extract specific Key-value pairs
	var secretsMap map[string]string
	err := json.Unmarshal([]byte(secretString), &secretsMap)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling json: %v", err)
	}

	secretValue := make([]SecretKeyValue, 0)

	for k, v := range secretsMap {
		secretValue = append(secretValue, SecretKeyValue{
			Key: k,
			val: v,
		})
	}
	return secretValue, nil
}

type Secret struct {
	Name     string
	ARN      string
	keyValue SecretKeyValue
}

type SecretKeyValue struct {
	Key string
	val string
}

func findExistingSecretsInValue(value string, secrets []*Secret) []*Secret {
	found := make([]*Secret, 0)
	for _, secret := range secrets {
		if strings.Contains(value, secret.keyValue.val) {
			found = append(found, secret)
		}
	}
	return found
}
