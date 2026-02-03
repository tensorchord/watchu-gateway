package skillsecurity

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
)

const maxRegistryArtifactSize = 200 << 20

func downloadRegistryArtifact(ctx context.Context, downloadURL string) (string, error) {
	if downloadURL == "" {
		return "", fmt.Errorf("download URL is empty")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("download failed: status %d", resp.StatusCode)
	}

	if resp.ContentLength > maxRegistryArtifactSize {
		return "", fmt.Errorf("artifact too large: %d bytes", resp.ContentLength)
	}

	tmpFile, err := os.CreateTemp("", "skill-registry-*")
	if err != nil {
		return "", err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpFile.Name())
		}
	}()

	limited := io.LimitReader(resp.Body, maxRegistryArtifactSize+1)
	written, err := io.Copy(tmpFile, limited)
	if err != nil {
		_ = tmpFile.Close()
		return "", err
	}
	if err := tmpFile.Close(); err != nil {
		return "", err
	}
	if written > maxRegistryArtifactSize {
		return "", fmt.Errorf("artifact too large: %d bytes", written)
	}
	cleanup = false
	return tmpFile.Name(), nil
}
