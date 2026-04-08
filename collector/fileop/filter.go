//go:build amd64 && linux

package fileop

import (
	"strings"

	"github.com/tensorchord/watchu/collector/export"
)

func shouldDropFileOp(raw *export.RawFileOp) bool {
	if raw == nil {
		return true
	}
	if isSystemdCleanupNoise(raw) {
		return true
	}
	if isBrowserStorageNoise(raw.Path) {
		return true
	}
	if isBrowserCacheNoise(raw.Path) {
		return true
	}
	if isFirefoxTelemetryNoise(raw) {
		return true
	}
	if isLowValueRuntimeAccess(raw) {
		return true
	}
	return false
}

func isBrowserStorageNoise(path string) bool {
	if path == "" {
		return true
	}
	if isFirefoxBrowserStorage(path) {
		return true
	}
	if isChromiumBrowserStorage(path) {
		return true
	}
	return false
}

func isFirefoxBrowserStorage(path string) bool {
	if !strings.Contains(path, "/.mozilla/firefox/") {
		return false
	}
	return strings.Contains(path, "/storage/default/")
}

func isChromiumBrowserStorage(path string) bool {
	if !strings.Contains(path, "/.config/") && !strings.Contains(path, "/.cache/") {
		return false
	}
	chromiumStorageMarkers := [...]string{
		"/IndexedDB/",
		"/Local Storage/",
		"/Code Cache/",
		"/Service Worker/",
		"/File System/",
	}
	for _, marker := range chromiumStorageMarkers {
		if strings.Contains(path, marker) {
			return true
		}
	}
	return false
}

func isBrowserCacheNoise(path string) bool {
	if path == "" {
		return false
	}
	if isFirefoxBrowserCache(path) {
		return true
	}
	if isChromiumBrowserCache(path) {
		return true
	}
	return false
}

func isFirefoxBrowserCache(path string) bool {
	if strings.Contains(path, "/.cache/mozilla/firefox/") && strings.Contains(path, "/cache2/") {
		return true
	}
	if strings.Contains(path, "/.mozilla/firefox/") && strings.Contains(path, "/cache2/") {
		return true
	}
	return false
}

func isSystemdCleanupNoise(raw *export.RawFileOp) bool {
	if raw.Op != "delete" {
		return false
	}
	if raw.Comm != "(sd-rmrf)" {
		return false
	}
	if raw.Path == "tmp" {
		return true
	}
	return strings.Contains(raw.Path, "/systemd-private-")
}

func isFirefoxTelemetryNoise(raw *export.RawFileOp) bool {
	if raw.Path == "" {
		return false
	}
	if !strings.Contains(raw.Path, "/.mozilla/firefox/") {
		return false
	}
	return strings.Contains(raw.Path, "/datareporting/glean/")
}

func isLowValueRuntimeAccess(raw *export.RawFileOp) bool {
	if raw.Op != "read" && raw.Op != "open" {
		return false
	}
	if raw.Op == "open" && raw.Access != "read" {
		return false
	}
	if isCommonSystemConfigRead(raw.Path) {
		return true
	}
	if isLocaleRuntimeRead(raw.Path) {
		return true
	}
	return isSharedObjectRead(raw.Path)
}

func isCommonSystemConfigRead(path string) bool {
	switch path {
	case "/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf":
		return true
	case "/etc/ssl/certs/ca-certificates.crt":
		return true
	case "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem":
		return true
	default:
		return strings.HasPrefix(path, "/etc/crypto-policies/") ||
			strings.HasPrefix(path, "/etc/pki/")
	}
}

func isSharedObjectRead(path string) bool {
	if !strings.HasSuffix(path, ".so") && !strings.Contains(path, ".so.") {
		return false
	}
	sharedObjectRoots := [...]string{
		"/lib/",
		"/lib64/",
		"/usr/lib/",
		"/usr/lib64/",
		"/usr/local/lib/",
		"/usr/local/lib64/",
	}
	for _, root := range sharedObjectRoots {
		if strings.HasPrefix(path, root) {
			return true
		}
	}
	return false
}

func isLocaleRuntimeRead(path string) bool {
	return strings.HasPrefix(path, "/usr/lib/locale/") ||
		strings.HasPrefix(path, "/usr/share/locale/") ||
		strings.HasPrefix(path, "/usr/lib64/gconv/")
}

func isChromiumBrowserCache(path string) bool {
	chromiumCacheMarkers := [...]string{
		"/Cache/",
		"/Code Cache/",
		"/GPUCache/",
		"/GrShaderCache/",
		"/GraphiteDawnCache/",
		"/ShaderCache/",
	}
	chromiumRoots := [...]string{
		"/.cache/google-chrome/",
		"/.config/google-chrome/",
		"/.cache/chromium/",
		"/.config/chromium/",
		"/.cache/BraveSoftware/Brave-Browser/",
		"/.config/BraveSoftware/Brave-Browser/",
		"/.cache/microsoft-edge/",
		"/.config/microsoft-edge/",
		"/.cache/vivaldi/",
		"/.config/vivaldi/",
	}
	for _, root := range chromiumRoots {
		if !strings.Contains(path, root) {
			continue
		}
		for _, marker := range chromiumCacheMarkers {
			if strings.Contains(path, marker) {
				return true
			}
		}
	}
	return false
}
