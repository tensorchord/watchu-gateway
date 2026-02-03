package s3

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// Client is an S3 client for downloading skill artifacts using AWS SDK v2
type Client struct {
	bucket    string
	region    string
	accessKey string
	secretKey string
	client    *s3.Client
	presign   *s3.PresignClient
}

// NewClient creates a new S3 client with AWS SDK v2
func NewClient(bucket, region, _, accessKey, secretKey string) (*Client, error) {
	c := &Client{
		bucket:    bucket,
		region:    region,
		accessKey: accessKey,
		secretKey: secretKey,
	}

	// Build AWS configuration
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	c.client = s3.NewFromConfig(cfg)
	c.presign = s3.NewPresignClient(c.client)

	return c, nil
}

// DownloadFile downloads a file from S3 to a local path
func (c *Client) DownloadFile(ctx context.Context, key, localPath string) error {
	if c.client == nil {
		return fmt.Errorf("S3 client not initialized")
	}
	if key == "" {
		return fmt.Errorf("S3 key is required")
	}
	if localPath == "" {
		return fmt.Errorf("local path is required")
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(localPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Get object from S3
	resp, err := c.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("failed to get object from S3: %w", err)
	}
	defer resp.Body.Close()

	// Create local file
	file, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("failed to create local file: %w", err)
	}
	defer file.Close()

	// Copy content from S3 to local file
	if _, err := io.Copy(file, resp.Body); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// DownloadToTemp downloads a file from S3 to a temporary file
// Returns the path to the temporary file
func (c *Client) DownloadToTemp(ctx context.Context, key string) (string, error) {
	tempDir := os.TempDir()
	filename := filepath.Base(key)
	localPath := filepath.Join(tempDir, "skill-security", filename)

	if err := c.DownloadFile(ctx, key, localPath); err != nil {
		return "", err
	}

	return localPath, nil
}

// GetPresignedURL generates a presigned URL for downloading a file
// This is useful when you want to pass the URL to another service
func (c *Client) GetPresignedURL(key string, expiry time.Duration) (string, error) {
	if c.presign == nil {
		return "", fmt.Errorf("S3 presign client not initialized")
	}

	presignResult, err := c.presign.PresignGetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
	}, s3.WithPresignExpires(expiry))
	if err != nil {
		return "", fmt.Errorf("failed to generate presigned URL: %w", err)
	}

	return presignResult.URL, nil
}

// Exists checks if a file exists in S3
func (c *Client) Exists(ctx context.Context, key string) (bool, error) {
	if c.client == nil {
		return false, fmt.Errorf("S3 client not initialized")
	}

	_, err := c.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
	})

	if err != nil {
		var nfe *types.NotFound
		if AsError(err, &nfe) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

// AsError is a helper function to check if an error is of a specific type
func AsError(err error, target interface{}) bool {
	switch t := target.(type) {
	case **types.NotFound:
		var notFound *types.NotFound
		return AsError(err, &notFound) && t != nil
	case **types.NoSuchKey:
		var noSuchKey *types.NoSuchKey
		return AsError(err, &noSuchKey) && t != nil
	default:
		return false
	}
}

// Delete deletes a file from S3
func (c *Client) Delete(ctx context.Context, key string) error {
	if c.client == nil {
		return fmt.Errorf("S3 client not initialized")
	}

	_, err := c.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("failed to delete object from S3: %w", err)
	}

	return nil
}

// Upload uploads a file to S3
func (c *Client) Upload(ctx context.Context, key string, reader io.Reader) error {
	if c.client == nil {
		return fmt.Errorf("S3 client not initialized")
	}

	_, err := c.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
		Body:   reader,
	})
	if err != nil {
		return fmt.Errorf("failed to upload object to S3: %w", err)
	}

	return nil
}

// GetBucket returns the bucket name
func (c *Client) GetBucket() string {
	return c.bucket
}

// GetEndpoint returns the S3 endpoint (empty for AWS S3)
func (c *Client) GetEndpoint() string {
	return ""
}

// Close closes the S3 client (no-op for AWS SDK v2, included for interface compatibility)
func (c *Client) Close() error {
	return nil
}
