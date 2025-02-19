package main

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/labstack/echo-contrib/echoprometheus"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/time/rate"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

import (
	"github.com/labstack/echo/v4"
)

func main() {
	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion("eu-north-1"))
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	h := handler{cfg: cfg}

	startEchoSrv(h)
}

func startEchoSrv(h handler) {
	e := echo.New()
	e.Use(middleware.RecoverWithConfig(middleware.RecoverConfig{
		StackSize: 1 << 10, // 1 KB
	}))
	e.Use(middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(rate.Limit(5))))
	e.Use(echoprometheus.NewMiddleware("myapp"))   // adds middleware to gather metrics
	e.GET("/metrics", echoprometheus.NewHandler()) // adds route to serve gathered metrics

	e.GET("/getExposedSecretsInEnv", func(c echo.Context) error {
		return getExposedSecretInEnvHandler(c, h)
	})
	e.GET("/getExposedSecretsInCode", func(c echo.Context) error {
		return getExposedSecretsInCodeHandler(c, h)
	})
	e.Logger.Fatal(e.Start(":1323"))
}

func getExposedSecretInEnvHandler(c echo.Context, h handler) error {
	var err error
	token := &NextToken{}
	t := c.QueryParam("next_token")
	if t != "" {
		token, err = decodeNextToken(t)
		if err != nil {
			return c.JSON(500, err.Error())
		}
	}

	secrets, err := h.getExposedSecretsInEnv(context.Background(), token)
	if err != nil {
		return c.JSON(500, err.Error())
	}

	return c.JSON(200, secrets)
}

func getExposedSecretsInCodeHandler(c echo.Context, h handler) error {
	var err error
	token := &NextToken{}
	t := c.QueryParam("next_token")
	if t != "" {
		token, err = decodeNextToken(t)
		if err != nil {
			return c.JSON(500, err.Error())
		}
	}

	secrets, err := h.getExposedSecretsInLambdaCode(context.Background(), token)
	if err != nil {
		return c.JSON(500, err.Error())
	}

	return c.JSON(200, secrets)
}

type handler struct {
	cfg aws.Config
}
type FoundSecretInLambda struct {
	Secrets    []*Secret `json:"secrets"`
	LambdaName string    `json:"lambda_name"`
	LambdaArn  string    `json:"lambda_arn"`
}

type SecretsInLambda struct {
	FoundSecrets []FoundSecretInLambda `json:"found_secrets"`
	NextToken    string                `json:"next_token"`
}

func (h *handler) getExposedSecretsInEnv(ctx context.Context, token *NextToken) (*SecretsInLambda, error) {
	secrets, secretNext, err := getAllSecretValues(ctx, h.cfg, token.SecretToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get secrets: %w", err)
	}
	envs, lambdaNext, err := getAllLambdaEnvs(ctx, h.cfg, token.LambdaToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get envs: %w", err)
	}

	resp := &SecretsInLambda{
		//SecretsPerEnv: make(map[*LambdaEnv][]*Secret),
		FoundSecrets: make([]FoundSecretInLambda, 0),
	}
	for _, e := range envs {
		//resp.SecretsPerEnv[e] = e.findExistingSecrets(secrets)
		found := e.findExistingSecrets(secrets)
		if len(found) == 0 {
			continue
		}
		resp.FoundSecrets = append(resp.FoundSecrets, FoundSecretInLambda{
			Secrets:    found,
			LambdaName: e.name,
			LambdaArn:  e.ARN,
		})
	}

	next, err := createNextToken(secretNext, lambdaNext)
	if err != nil {
		return nil, fmt.Errorf("error encoding next token: %v", err)
	}
	resp.NextToken = next

	return resp, nil
}

func (h *handler) getExposedSecretsInLambdaCode(ctx context.Context, token *NextToken) (*SecretsInLambda, error) {
	secrets, secretNext, err := getAllSecretValues(ctx, h.cfg, token.SecretToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get secrets: %w", err)
	}
	code, lambdaNext, err := getAllLambdaCode(ctx, h.cfg, token.LambdaToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get code: %w", err)
	}

	resp := &SecretsInLambda{
		FoundSecrets: make([]FoundSecretInLambda, 0),
	}

	for _, c := range code {
		found, err := c.findExistingSecrets(secrets)
		if err != nil {
			return nil, fmt.Errorf("failed to find secrets for code: %w", err)
		}
		if len(found) == 0 {
			continue
		}
		resp.FoundSecrets = append(resp.FoundSecrets, FoundSecretInLambda{
			Secrets:    found,
			LambdaName: c.name,
			LambdaArn:  c.arn,
		})
		_ = c.cleanupFile()
	}

	next, err := createNextToken(secretNext, lambdaNext)
	if err != nil {
		return nil, fmt.Errorf("error encoding next token: %v", err)
	}
	resp.NextToken = next

	return resp, nil
}

// Download an S3 object and save it to a local file
func downloadToTempFile(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to make HTTP request: %v", err)
	}
	defer resp.Body.Close()

	// Check if the request was successful (status zipFile 200)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to download file: %s", resp.Status)
	}

	// Create the output file
	outFile, err := os.CreateTemp("", "entro-scanner-lambda-zipFile")
	if err != nil {
		return "", fmt.Errorf("unable to create file: %v", err)
	}
	defer outFile.Close()

	// Copy the content from the S3 object to the local file
	_, err = io.Copy(outFile, resp.Body)
	if err != nil {
		return "", fmt.Errorf("unable to copy content to file: %v", err)
	}

	abs, err := filepath.Abs(outFile.Name())
	if err != nil {
		return "", fmt.Errorf("unable to get abs path for temp file: %v", err)
	}

	return abs, nil

}
