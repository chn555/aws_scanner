package main

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"io"
	"os"
	"strings"
)

func getAllLambdaCode(ctx context.Context, cfg aws.Config, nextToken string) ([]*LambdaCode, string, error) {
	// Create Lambda and S3 clients
	lambdaSvc := lambda.NewFromConfig(cfg)

	// List all Lambda functions (with pagination if needed)
	input := &lambda.ListFunctionsInput{
		MaxItems: aws.Int32(1), // Put here as a makeshift rate limiter and to force a next token to appear in manual testing
	}
	if nextToken != "" {
		input.Marker = aws.String(nextToken)
	}
	listFunctionsOutput, err := lambdaSvc.ListFunctions(ctx, input)
	if err != nil {
		return nil, "", fmt.Errorf("unable to list lambda functions, %v", err)
	}

	res := make([]*LambdaCode, 0)
	// Iterate over each Lambda function
	for _, function := range listFunctionsOutput.Functions {
		code, err := getCodeForLambda(ctx, lambdaSvc, function)
		if err != nil {
			return nil, "", fmt.Errorf("failed to get code for lambda %s, %v", *function.FunctionName, err)
		}
		if code == nil {
			continue
		}
		res = append(res, code)
	}

	return res, aws.ToString(listFunctionsOutput.NextMarker), nil
}

func getCodeForLambda(ctx context.Context, lambdaSvc *lambda.Client, function types.FunctionConfiguration) (*LambdaCode, error) {
	// Get the function details including zipFile location
	getFunctionOutput, err := lambdaSvc.GetFunction(ctx, &lambda.GetFunctionInput{
		FunctionName: function.FunctionName,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to get function details for %s, %v", *function.FunctionName, err)
	}

	// Check if the function zipFile is in S3
	if getFunctionOutput.Code.Location == nil {
		return nil, nil
	}
	// The S3 URL of the Lambda zipFile
	s3URL := *getFunctionOutput.Code.Location

	// Download the zipFile from S3
	file, err := downloadToTempFile(s3URL)
	if err != nil {
		return nil, fmt.Errorf("unable to download zip for function %s, %v", *function.FunctionName, err)
	}

	return &LambdaCode{
		name:    *function.FunctionName,
		arn:     *function.FunctionArn,
		zipFile: file,
	}, nil
}

type LambdaCode struct {
	name    string
	arn     string
	zipFile string
}

func (c *LambdaCode) cleanupFile() error {
	return os.Remove(c.zipFile)
}

func (c *LambdaCode) findExistingSecrets(secrets []*Secret) ([]*Secret, error) {
	var found []*Secret

	found, err := findSecretsInZip(c.zipFile, secrets)
	if err != nil {
		return nil, fmt.Errorf("error reading zip file file %s, %v", c.zipFile, err)
	}

	return found, nil
}

// findSecretsInZip opens a ZIP file and searches for the given string inside it
func findSecretsInZip(zipFile string, secrets []*Secret) ([]*Secret, error) {
	// Open the ZIP file
	zipReader, err := zip.OpenReader(zipFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open ZIP file: %v", err)
	}
	defer zipReader.Close()

	res := make([]*Secret, 0)
	// Iterate over all the files in the ZIP archive
	for _, file := range zipReader.File {
		r, err := findSecretInFile(file, secrets)
		if err != nil {
			return nil, fmt.Errorf("failed to read file from ZIP: %v", err)
		}
		res = append(res, r...)
	}

	return res, nil
}

func findSecretInFile(file *zip.File, secrets []*Secret) ([]*Secret, error) {
	// Open the file inside the ZIP archive
	fileReader, err := file.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open file inside ZIP: %v", err)
	}
	defer fileReader.Close()

	res := make([]*Secret, 0)
	// Read the file contents and search for the string
	found, err := findSecretInReader(fileReader, secrets)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}

	res = append(res, found...)
	return res, nil
}

// findSecretInReader reads the contents of a file and searches for the string
func findSecretInReader(reader io.Reader, secrets []*Secret) ([]*Secret, error) {
	// Read the file contents into a buffer
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read file contents: %v", err)
	}

	code := buf.String()
	res := make([]*Secret, 0)

	for _, s := range secrets {
		if strings.Contains(code, s.keyValue.val) {
			res = append(res, s)
		}
	}

	return res, nil
}
