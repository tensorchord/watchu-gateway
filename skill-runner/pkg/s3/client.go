package s3

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Client is an S3 client for downloading skill artifacts
type Client struct {
	bucket    string
	region    string
	accessKey string
	secretKey string
	client    *s3.Client
}

// ParseS3Path parses an S3 URI (s3://bucket/key) and returns bucket and key
func ParseS3Path(s3Path string) (bucket, key string, err error) {
	if !strings.HasPrefix(s3Path, "s3://") {
		return "", "", fmt.Errorf("invalid S3 path: %s (must start with s3://)", s3Path)
	}

	// Remove s3:// prefix
	path := strings.TrimPrefix(s3Path, "s3://")

	// Split on first / to separate bucket from key
	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid S3 path: %s (must be s3://bucket/key)", s3Path)
	}

	bucket = parts[0]
	key = parts[1]

	if bucket == "" {
		return "", "", fmt.Errorf("bucket is empty in S3 path: %s", s3Path)
	}
	if key == "" {
		return "", "", fmt.Errorf("key is empty in S3 path: %s", s3Path)
	}

	return bucket, key, nil
}

// IsS3Path checks if a path is an S3 URI
func IsS3Path(path string) bool {
	return strings.HasPrefix(path, "s3://")
}

// NewClient creates a new S3 client with AWS SDK v2
func NewClient(region, accessKey, secretKey string) (*Client, error) {
	if region == "" {
		return nil, fmt.Errorf("S3 region is required")
	}
	if accessKey == "" {
		return nil, fmt.Errorf("S3 access key is required")
	}
	if secretKey == "" {
		return nil, fmt.Errorf("S3 secret key is required")
	}

	c := &Client{
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

	return c, nil
}

// DownloadFile downloads a file from S3 to a local path
func (c *Client) DownloadFile(ctx context.Context, bucket, key, localPath string) error {
	if c.client == nil {
		return fmt.Errorf("S3 client not initialized")
	}
	if bucket == "" {
		return fmt.Errorf("S3 bucket is required")
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

	// Double-check directory exists and is writable
	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf("directory verification failed: %w", err)
	}

	// Get object from S3
	resp, err := c.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
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
func (c *Client) DownloadToTemp(ctx context.Context, bucket, key string) (string, func(), error) {
	tempDir := os.TempDir()
	filename := filepath.Base(key)
	skillRunnerDir := filepath.Join(tempDir, "skill-runner-s3")
	localPath := filepath.Join(skillRunnerDir, filename)

	// Ensure the skill-runner-s3 directory exists and is a directory
	if err := os.MkdirAll(skillRunnerDir, 0755); err != nil {
		return "", nil, fmt.Errorf("failed to create base directory: %w", err)
	}

	if err := c.DownloadFile(ctx, bucket, key, localPath); err != nil {
		return "", nil, err
	}

	// Return cleanup function
	cleanup := func() {
		_ = os.RemoveAll(skillRunnerDir)
	}

	return localPath, cleanup, nil
}
