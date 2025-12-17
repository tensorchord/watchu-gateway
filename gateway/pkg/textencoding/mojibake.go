package textencoding

import (
	"unicode"
	"unicode/utf8"
)

// RepairUTF8Mojibake attempts to fix classic mojibake where UTF-8 bytes were
// interpreted as ISO-8859-1 (Latin-1), producing strings like "è¯·å¸®...".
//
// It applies a conservative heuristic to avoid mangling legitimate Latin-1 text.
func RepairUTF8Mojibake(input string) string {
	if input == "" {
		return ""
	}

	// If the string already contains CJK characters, it's likely already correct.
	if containsCJK(input) {
		return input
	}

	latin1NonASCII := 0
	for _, r := range input {
		if r > 0xFF {
			// Not a pure Latin-1 byte-string; don't attempt this repair.
			return input
		}
		if r >= 0x80 {
			latin1NonASCII++
		}
	}
	// Typical CJK mojibake has at least 3 Latin-1 non-ASCII characters (one UTF-8
	// code point worth of bytes).
	if latin1NonASCII < 3 {
		return input
	}

	// Re-interpret each rune as a byte and see if the resulting byte sequence is valid UTF-8.
	buf := make([]byte, 0, len(input))
	for _, r := range input {
		buf = append(buf, byte(r))
	}
	if !utf8.Valid(buf) {
		return input
	}

	candidate := string(buf)
	// Only accept if the candidate looks like it recovered real Unicode text (e.g. CJK).
	if containsCJK(candidate) {
		return candidate
	}
	// Otherwise, require that we actually increased non-Latin-1 content and reduced
	// Latin-1 noise. This avoids converting most legitimate Latin-1 strings.
	if countNonLatin1(candidate) > 0 && countLatin1NonASCII(candidate) < latin1NonASCII {
		return candidate
	}
	return input
}

func containsCJK(s string) bool {
	for _, r := range s {
		if unicode.In(r, unicode.Han, unicode.Hiragana, unicode.Katakana, unicode.Hangul) {
			return true
		}
	}
	return false
}

func countLatin1NonASCII(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x80 && r <= 0xFF {
			n++
		}
	}
	return n
}

func countNonLatin1(s string) int {
	n := 0
	for _, r := range s {
		if r > 0xFF {
			n++
		}
	}
	return n
}
