package main

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

type LambdaEnv struct {
	name string
	ARN  string
	env  map[string]string
}

func getAllLambdaEnvs(ctx context.Context, cfg aws.Config, nextToken string) ([]*LambdaEnv, string, error) {
	// Create Lambda client
	svc := lambda.NewFromConfig(cfg)

	// List all Lambda functions (with pagination if needed)
	input := &lambda.ListFunctionsInput{}
	if nextToken != "" {
		input.Marker = aws.String(nextToken)
	}

	listFunctionsOutput, err := svc.ListFunctions(ctx, input)
	if err != nil {
		return nil, "", fmt.Errorf("unable to list lambda functions, %v", err)
	}

	res := make([]*LambdaEnv, 0)
	// Iterate over each function
	for _, function := range listFunctionsOutput.Functions {
		env, err := getEnvForLambda(ctx, svc, function)
		if err != nil {
			return nil, "", fmt.Errorf("failed to get env for function %s, %v", *function.FunctionName, err)
		}
		if env == nil {
			continue
		}
		res = append(res, env)
	}

	return res, aws.ToString(listFunctionsOutput.NextMarker), nil
}

func getEnvForLambda(ctx context.Context, lambdaSvc *lambda.Client, function types.FunctionConfiguration) (*LambdaEnv, error) {
	// Get the function configuration (including environment variables)
	getFunctionConfigOutput, err := lambdaSvc.GetFunctionConfiguration(ctx, &lambda.GetFunctionConfigurationInput{
		FunctionName: function.FunctionName,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to get function env for %s, %v", *function.FunctionName, err)
	}

	// Print the environment variables for the function
	if getFunctionConfigOutput.Environment == nil || getFunctionConfigOutput.Environment.Variables == nil {
		return nil, nil
	}
	return &LambdaEnv{
		name: *function.FunctionName,
		ARN:  *function.FunctionArn,
		env:  getFunctionConfigOutput.Environment.Variables,
	}, nil

}

func (LambdaEnv *LambdaEnv) findExistingSecrets(secrets []*Secret) []*Secret {
	found := make([]*Secret, 0)
	for _, v := range LambdaEnv.env {
		found = append(found, findExistingSecretsInValue(v, secrets)...)
	}

	return found

}
