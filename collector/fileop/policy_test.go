package fileop

import (
	"testing"

	"github.com/tensorchord/watchu/collector/export"
)

func TestPolicyMatchesReadPathAcrossHomes(t *testing.T) {
	t.Parallel()

	policy := Policy{
		ReadPrefixes:     []string{"/etc/"},
		ReadHomePrefixes: []string{".config/", ".ssh/"},
		ReadSuffixes:     []string{".service", ".bashrc", ".zsh_history"},
	}

	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "global prefix", path: "/etc/shadow", want: true},
		{name: "global suffix", path: "/usr/lib/systemd/user/demo.service", want: true},
		{name: "root home prefix", path: "/root/.config/app/config.toml", want: true},
		{name: "user home prefix", path: "/home/alice/.ssh/id_ed25519", want: true},
		{name: "root home suffix", path: "/root/.bashrc", want: true},
		{name: "user home suffix", path: "/home/bob/.zsh_history", want: true},
		{name: "non home hidden path", path: "/tmp/.config/app", want: false},
		{name: "home path not allowed", path: "/home/alice/.cache/app/data", want: false},
		{name: "home root dir", path: "/root", want: false},
		{name: "root prefix collision", path: "/rooted/.config/app", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			raw := &export.RawFileOp{
				Op:     "open",
				Access: "read",
				Path:   tt.path,
			}
			if got := policy.Matches(raw); got != tt.want {
				t.Fatalf("Matches(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestPolicyMatchesWriteSuffixesAndRenameTargets(t *testing.T) {
	t.Parallel()

	policy := Policy{
		WritePrefixes:     []string{"/etc/", "/var/log/"},
		WriteHomePrefixes: []string{".config/"},
		WriteSuffixes:     []string{".so", ".bashrc"},
	}

	tests := []struct {
		name string
		raw  *export.RawFileOp
		want bool
	}{
		{
			name: "write home suffix",
			raw:  &export.RawFileOp{Op: "write", Path: "/home/alice/.bashrc"},
			want: true,
		},
		{
			name: "write root home prefix",
			raw:  &export.RawFileOp{Op: "write", Path: "/root/.config/app/state.json"},
			want: true,
		},
		{
			name: "rename into allowed home path",
			raw:  &export.RawFileOp{Op: "rename", Path: "/tmp/tmpfile", NewPath: "/home/alice/.config/app/config.toml"},
			want: true,
		},
		{
			name: "rename from allowed global path",
			raw:  &export.RawFileOp{Op: "rename", Path: "/etc/app.conf", NewPath: "/tmp/app.conf"},
			want: true,
		},
		{
			name: "global suffix",
			raw:  &export.RawFileOp{Op: "write", Path: "/usr/local/lib/plugin.so"},
			want: true,
		},
		{
			name: "unmatched write",
			raw:  &export.RawFileOp{Op: "write", Path: "/home/alice/.cache/app/data"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := policy.Matches(tt.raw); got != tt.want {
				t.Fatalf("Matches(%+v) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}

func TestLoadPolicyReadsExpandedFields(t *testing.T) {
	t.Parallel()

	policy, err := loadPolicyBytes([]byte(`
read_prefixes = ["/etc/"]
read_home_prefixes = [".ssh/"]
read_suffixes = [".pem", ".bash_history"]
write_prefixes = ["/var/log/"]
write_home_prefixes = [".config/"]
write_suffixes = [".log", ".zshrc"]
`), ".toml")
	if err != nil {
		t.Fatalf("loadPolicyBytes returned error: %v", err)
	}

	if len(policy.ReadHomePrefixes) != 1 || policy.ReadHomePrefixes[0] != ".ssh/" {
		t.Fatalf("unexpected read_home_prefixes: %#v", policy.ReadHomePrefixes)
	}
	if len(policy.WriteSuffixes) != 2 || policy.WriteSuffixes[1] != ".zshrc" {
		t.Fatalf("unexpected write_suffixes: %#v", policy.WriteSuffixes)
	}
}

func TestLoadPolicyNormalizesLegacyHomePrefixes(t *testing.T) {
	t.Parallel()

	policy, err := loadPolicyBytes([]byte(`
read_home_prefixes = ["/.ssh/"]
write_home_prefixes = ["/.config/"]
`), ".toml")
	if err != nil {
		t.Fatalf("loadPolicyBytes returned error: %v", err)
	}

	if len(policy.ReadHomePrefixes) != 1 || policy.ReadHomePrefixes[0] != ".ssh/" {
		t.Fatalf("unexpected normalized read_home_prefixes: %#v", policy.ReadHomePrefixes)
	}
	if len(policy.WriteHomePrefixes) != 1 || policy.WriteHomePrefixes[0] != ".config/" {
		t.Fatalf("unexpected normalized write_home_prefixes: %#v", policy.WriteHomePrefixes)
	}
}

func TestDefaultPolicyCoversHighValueFiles(t *testing.T) {
	t.Parallel()

	policy, err := loadPolicyBytes(defaultPolicyBytes, ".toml")
	if err != nil {
		t.Fatalf("loadPolicyBytes returned error: %v", err)
	}

	tests := []struct {
		name string
		raw  *export.RawFileOp
		want bool
	}{
		{
			name: "read passwd",
			raw:  &export.RawFileOp{Op: "open", Access: "read", Path: "/etc/passwd"},
			want: true,
		},
		{
			name: "read env file",
			raw:  &export.RawFileOp{Op: "open", Access: "read", Path: "/srv/app/.env.production"},
			want: true,
		},
		{
			name: "write env file",
			raw:  &export.RawFileOp{Op: "write", Path: "/home/alice/project/.env.local"},
			want: true,
		},
		{
			name: "read ssh config",
			raw:  &export.RawFileOp{Op: "open", Access: "read", Path: "/etc/ssh/sshd_config"},
			want: true,
		},
		{
			name: "read pem file",
			raw:  &export.RawFileOp{Op: "open", Access: "read", Path: "/srv/certs/tls.pem"},
			want: true,
		},
		{
			name: "write netrc file",
			raw:  &export.RawFileOp{Op: "write", Path: "/root/.netrc"},
			want: true,
		},
		{
			name: "write npmrc file",
			raw:  &export.RawFileOp{Op: "write", Path: "/home/alice/.npmrc"},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := policy.Matches(tt.raw); got != tt.want {
				t.Fatalf("Matches(%+v) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}
