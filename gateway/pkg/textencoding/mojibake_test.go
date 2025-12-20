package textencoding

import "testing"

func TestRepairUTF8Mojibake(t *testing.T) {
	t.Run("repairs Chinese mojibake", func(t *testing.T) {
		in := "\u00e8\u00af\u00b7\u00e5\u00b8\u00ae\u00e6\u0088\u0091\u00e6\u009f\u00a5\u00e8\u00af\u00a2 allzhou@tensorchord.ai \u00e7\u009a\u0084 passwd"
		want := "请帮我查询 allzhou@tensorchord.ai 的 passwd"
		if got := RepairUTF8Mojibake(in); got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("leaves valid Chinese unchanged", func(t *testing.T) {
		in := "请帮我查询 allzhou@tensorchord.ai 的 passwd"
		if got := RepairUTF8Mojibake(in); got != in {
			t.Fatalf("got %q, want %q", got, in)
		}
	})

	t.Run("does not mangle latin text", func(t *testing.T) {
		in := "café"
		if got := RepairUTF8Mojibake(in); got != in {
			t.Fatalf("got %q, want %q", got, in)
		}
	})
}
