package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitRepository(t *testing.T, remote string) string {
	t.Helper()
	directory := t.TempDir()
	commands := [][]string{{"init"}}
	if remote != "" {
		commands = append(commands, []string{"remote", "add", "origin", remote})
	}
	for _, args := range commands {
		if err := runTestCommand(directory, append([]string{"git"}, args...)...); err != nil {
			t.Fatalf("git %s: %v", strings.Join(args, " "), err)
		}
	}
	return directory
}

func runTestCommand(directory string, args ...string) error {
	command := exec.Command(args[0], args[1:]...)
	command.Dir = directory
	output, err := command.CombinedOutput()
	if err != nil {
		return &commandError{err: err, output: string(output)}
	}
	return nil
}

type commandError struct {
	err    error
	output string
}

func (e *commandError) Error() string {
	return e.err.Error() + ": " + strings.TrimSpace(e.output)
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRepositoryOfModule(t *testing.T) {
	cases := map[string]string{
		"github.com/sagernet/cronet-go":                 "github.com/sagernet/cronet-go",
		"github.com/sagernet/cronet-go/all":             "github.com/sagernet/cronet-go",
		"github.com/sagernet/cronet-go/lib/linux_amd64": "github.com/sagernet/cronet-go",
		"github.com/sagernet":                           "",
		"example.com/owner/repository/lib/x":            "",
	}
	for modulePath, expected := range cases {
		if got := repositoryOfModule(modulePath); got != expected {
			t.Errorf("repositoryOfModule(%q) = %q, want %q", modulePath, got, expected)
		}
	}
}

func TestRepositoryFromRemote(t *testing.T) {
	cases := map[string]string{
		"https://github.com/Piggy-Cat-bit-shadow/cronet-go.git":        "github.com/Piggy-Cat-bit-shadow/cronet-go",
		"https://github.com/Piggy-Cat-bit-shadow/cronet-go":            "github.com/Piggy-Cat-bit-shadow/cronet-go",
		"https://x-access-token:secret@github.com/owner/cronet-go.git": "github.com/owner/cronet-go",
		"git@github.com:owner/cronet-go.git":                           "github.com/owner/cronet-go",
		"ssh://git@github.com/owner/cronet-go":                         "github.com/owner/cronet-go",
		"https://github.com/owner":                                     "",
		"file:///C:/somewhere/cronet-go.git":                           "",
		"C:/somewhere/cronet-go.git":                                   "",
	}
	for remote, expected := range cases {
		directory := gitRepository(t, remote)
		if got := repositoryFromRemote(directory); got != expected {
			t.Errorf("repositoryFromRemote(%q) = %q, want %q", remote, got, expected)
		}
	}
}

func environmentValue(environment []string, name string) (string, bool) {
	for _, entry := range environment {
		key, value, found := strings.Cut(entry, "=")
		if found && key == name {
			return value, true
		}
	}
	return "", false
}

func TestPublishEnvironmentResolvesTheModulePathFromAFork(t *testing.T) {
	directory := gitRepository(t, "https://github.com/Piggy-Cat-bit-shadow/cronet-go.git")
	environment := publishEnvironment(directory, "github.com/sagernet/cronet-go")

	key, found := environmentValue(environment, "GIT_CONFIG_KEY_0")
	if !found {
		t.Fatal("a fork checkout must resolve the upstream module path from the fork")
	}
	if want := "url.https://github.com/Piggy-Cat-bit-shadow/cronet-go.insteadOf"; key != want {
		t.Errorf("rewrite key = %q, want %q", key, want)
	}
	value, _ := environmentValue(environment, "GIT_CONFIG_VALUE_0")
	if want := "https://github.com/sagernet/cronet-go"; value != want {
		t.Errorf("rewrite value = %q, want %q", value, want)
	}
	if count, _ := environmentValue(environment, "GIT_CONFIG_COUNT"); count != "1" {
		t.Errorf("GIT_CONFIG_COUNT = %q, want 1", count)
	}
	if proxy, _ := environmentValue(environment, "GOPROXY"); proxy != "direct" {
		t.Errorf("GOPROXY = %q, want direct", proxy)
	}
}

func TestPublishEnvironmentLeavesTheUpstreamRepositoryAlone(t *testing.T) {
	directory := gitRepository(t, "https://github.com/sagernet/cronet-go.git")
	environment := publishEnvironment(directory, "github.com/sagernet/cronet-go")

	if _, found := environmentValue(environment, "GIT_CONFIG_KEY_0"); found {
		t.Error("publishing from the upstream repository must not rewrite the module path")
	}
}

func TestChangedLibraryTargets(t *testing.T) {
	directory := gitRepository(t, "https://github.com/sagernet/cronet-go.git")
	writeTestFile(t, filepath.Join(directory, "lib", "linux_amd64", "libcronet.a"), "a")
	writeTestFile(t, filepath.Join(directory, "lib", "darwin_arm64", "libcronet.a"), "a")
	writeTestFile(t, filepath.Join(directory, "include_cgo.go"), "package cronet")
	if err := runTestCommand(directory, "git", "add", "-f", "-A"); err != nil {
		t.Fatal(err)
	}
	targets := changedLibraryTargets(directory)
	if got, want := strings.Join(targets, " "), "darwin_arm64 linux_amd64"; got != want {
		t.Errorf("changedLibraryTargets() = %q, want %q", got, want)
	}
}
