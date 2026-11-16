package main

import (
	"strings"
	"testing"
)

func TestCronetCgoLDFlagsUseArchivePath(t *testing.T) {
	flags := cronetCgoLDFlags(
		"${SRCDIR}/lib/android_arm64/libcronet.a",
		LinkFlags{
			LDFlags:    []string{"-Wl,-wrap,malloc"},
			Libs:       []string{"-llog"},
			Frameworks: []string{"-framework Foundation"},
		},
		true,
	)

	if len(flags) == 0 {
		t.Fatal("empty LDFLAGS")
	}
	if flags[0] != "${SRCDIR}/lib/android_arm64/libcronet.a" {
		t.Fatalf("archive must be the first input, got %q", flags[0])
	}
	joined := strings.Join(flags, " ")
	if strings.Contains(joined, "-l:") {
		t.Fatalf("Go 1.27.4 rejects '-l:<filename>' in #cgo LDFLAGS: %q", joined)
	}
	for _, want := range []string{"-Wl,-wrap,malloc", "-llog", "-framework Foundation"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("LDFLAGS lost %q: %q", want, joined)
		}
	}
	if flags[len(flags)-1] != "-static" {
		t.Fatalf("-static must be last for musl, got %q", flags[len(flags)-1])
	}
}

func TestCronetCgoLDFlagsNonStatic(t *testing.T) {
	flags := cronetCgoLDFlags("${SRCDIR}/libcronet.a", LinkFlags{}, false)
	joined := strings.Join(flags, " ")
	if strings.Contains(joined, "-static") {
		t.Fatalf("non-musl build must not use -static: %q", joined)
	}
	if len(flags) != 1 || flags[0] != "${SRCDIR}/libcronet.a" {
		t.Fatalf("unexpected LDFLAGS: %q", joined)
	}
}
