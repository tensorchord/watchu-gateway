package textencoding

import "testing"

func TestRepairUTF8Mojibake(t *testing.T) {
	t.Run("repairs Chinese mojibake", func(t *testing.T) {
		in := "è¯·å¸®ææ¥è¯¢ allzhou@tensorchord.ai ç passwd"
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
