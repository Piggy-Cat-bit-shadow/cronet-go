package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var publishBranch string

var commandPublish = &cobra.Command{
	Use:   "publish",
	Short: "Commit to go branch and push",
	Run: func(cmd *cobra.Command, args []string) {
		publish()
	},
}

func init() {
	commandPublish.Flags().StringVar(&publishBranch, "branch", "go", "Target branch to publish to")
	mainCommand.AddCommand(commandPublish)
}

func publish() {
	log.Printf("Publishing to %s branch...", publishBranch)

	mainCommit := strings.TrimSpace(runCommandOutput(projectRoot, "git", "rev-parse", "HEAD"))
	// The module paths stay those of the upstream project: consumers pin github.com/sagernet/cronet-go
	// and replace it with this repository, and a replacement module has to declare the path it is
	// replaced *as*. The repository that hosts the commits is a different question, and publishing
	// answers it with the environment below rather than by renaming the module.
	modulePath := readModulePath(projectRoot)
	environment := publishEnvironment(projectRoot, modulePath)

	temporaryDirectory, err := os.MkdirTemp("", "cronet-go-publish-")
	if err != nil {
		log.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() {
		runCommand(projectRoot, "git", "worktree", "remove", "--force", temporaryDirectory)
		os.RemoveAll(temporaryDirectory)
	}()

	runCommand(projectRoot, "git", "worktree", "add", temporaryDirectory, "HEAD")

	// === Step 1: Push main module + lib submodules ===
	log.Print("Step 1: Publishing main module and lib submodules...")

	copyDirectory(filepath.Join(projectRoot, "lib"), filepath.Join(temporaryDirectory, "lib"))
	copyDirectory(filepath.Join(projectRoot, "include"), filepath.Join(temporaryDirectory, "include"))
	copyFile(filepath.Join(projectRoot, "include_cgo.go"), filepath.Join(temporaryDirectory, "include_cgo.go"))

	// Use -f (force add) to include .gitignore'd files
	runCommand(temporaryDirectory, "git", "add", "-f", "-A")

	// The libraries this run actually rebuilt are the ones that differ from the parent commit. A
	// profile publishes the whole module tree, so the commit is also the only place that records
	// which targets are new in it and which are carried over from earlier builds.
	refreshedTargets := changedLibraryTargets(temporaryDirectory)

	commitMessage := fmt.Sprintf("Build from %s", mainCommit[:8])
	if len(refreshedTargets) > 0 {
		commitMessage += "\n\nRebuilt native libraries: " + strings.Join(refreshedTargets, ", ")
	}
	runCommand(temporaryDirectory, "git", "commit", "-m", commitMessage)

	runCommand(temporaryDirectory, "git", "push", "-f", "origin", "HEAD:refs/heads/"+publishBranch)

	firstCommit := strings.TrimSpace(runCommandOutput(temporaryDirectory, "git", "rev-parse", "HEAD"))
	commitTime := getCommitTime(temporaryDirectory, firstCommit)

	// The lib submodules have no tags of their own - a tag such as v0.0.1-143.0.7499.109-2 belongs to
	// the root module - so their canonical pseudo-version is always the v0.0.0 form.
	libVersion := formatPseudoVersion(commitTime, firstCommit)

	// The root module does carry tags, so its pseudo-version has to be built on the highest tag that is
	// reachable from the commit. v0.0.0-<time>-<sha> is not that version: it sorts *below* the
	// v0.0.1-<chromium>-<n>.0.<time>-<sha> pin a consumer already holds, and a module graph that mixes
	// the two would keep the older commit and silently ignore this build. Ask the go command, which
	// computes the canonical version and, in doing so, proves the pushed commit is fetchable.
	rootVersion := resolveModuleVersion(temporaryDirectory, environment, modulePath, firstCommit)

	log.Printf("First commit: %s, root module %s, lib submodules %s", firstCommit[:12], rootVersion, libVersion)

	// === Step 2: Generate and push all package ===
	log.Print("Step 2: Generating all package...")

	libDirectory := filepath.Join(temporaryDirectory, "lib")
	libEntries, err := os.ReadDir(libDirectory)
	if err != nil {
		log.Fatalf("failed to read lib directory: %v", err)
	}

	var builtTargets []string
	for _, entry := range libEntries {
		if entry.IsDir() {
			builtTargets = append(builtTargets, entry.Name())
		}
	}

	if len(builtTargets) == 0 {
		log.Fatal("no lib directories found")
	}

	generateAllPackage(temporaryDirectory, modulePath, rootVersion, libVersion, builtTargets)

	// Pin every lib submodule at the root module version it is published with. The submodules do not
	// import the root module, but a consumer that fetches a lib module alone then still sees which
	// binding release it belongs to.
	fixLibSubmoduleVersions(libDirectory, builtTargets, rootVersion)

	allDirectory := filepath.Join(temporaryDirectory, "all")
	runGoModTidy(allDirectory, environment)

	// tidy is allowed to choose versions; it is not allowed to choose a different one than the
	// commit that was just pushed. If it did, the branch would advertise a revision it was not built
	// from, which is exactly the situation that this step exists to rule out.
	assertSelectedVersion(allDirectory, environment, modulePath, rootVersion)

	runCommand(temporaryDirectory, "git", "add", "-f", "-A")
	runCommand(temporaryDirectory, "git", "commit", "-m", fmt.Sprintf("Generate all package for %s", rootVersion))
	runCommand(temporaryDirectory, "git", "push", "origin", "HEAD:"+publishBranch)

	secondCommit := strings.TrimSpace(runCommandOutput(temporaryDirectory, "git", "rev-parse", "HEAD"))

	// Resolve the head again from the commit alone, the way a consumer does. This is not a cache
	// lookup: the version is new, so the go command has to ask the repository for that commit.
	publishedVersion := resolveModuleVersion(temporaryDirectory, environment, modulePath, secondCommit)

	log.Printf("Published %s branch at %s", publishBranch, secondCommit)
	log.Printf("  root module %s", publishedVersion)
	log.Printf("  lib submodules %s", libVersion)
	log.Printf("  native targets: %s", strings.Join(builtTargets, " "))
	if len(refreshedTargets) > 0 {
		log.Printf("  rebuilt in this run: %s", strings.Join(refreshedTargets, " "))
	}
}

// readModulePath returns the module path declared by the go.mod at the project root.
func readModulePath(directory string) string {
	content, err := os.ReadFile(filepath.Join(directory, "go.mod"))
	if err != nil {
		log.Fatalf("failed to read go.mod: %v", err)
	}
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}
	log.Fatal("go.mod has no module directive")
	return ""
}

// repositoryOfModule returns the repository that hosts a module path, e.g. github.com/sagernet/cronet-go
// for github.com/sagernet/cronet-go/lib/linux_amd64.
func repositoryOfModule(modulePath string) string {
	parts := strings.Split(modulePath, "/")
	if len(parts) < 3 || parts[0] != "github.com" {
		return ""
	}
	return strings.Join(parts[:3], "/")
}

// repositoryFromRemote returns the repository the origin remote points at, or "" when the remote is
// not a repository path this tool can name (a local path, for example).
func repositoryFromRemote(directory string) string {
	remote := strings.TrimSpace(runCommandOutput(directory, "git", "remote", "get-url", "origin"))
	if remote == "" {
		return ""
	}
	if strings.HasPrefix(remote, "git@") {
		remote = strings.TrimPrefix(remote, "git@")
		remote = strings.Replace(remote, ":", "/", 1)
	} else if index := strings.Index(remote, "://"); index >= 0 {
		remote = remote[index+3:]
		if index := strings.Index(remote, "@"); index >= 0 {
			remote = remote[index+1:]
		}
	}
	remote = strings.TrimSuffix(remote, ".git")
	remote = strings.TrimSuffix(remote, "/")
	parts := strings.Split(remote, "/")
	if len(parts) < 3 || parts[0] != "github.com" {
		return ""
	}
	return strings.Join(parts[:3], "/")
}

// publishEnvironment returns the environment the go command runs under while publishing.
//
// The released versions do not exist yet, so they cannot be fetched from a module proxy: the go
// command has to talk to the repository directly. When this repository is a fork, the module paths
// still name the upstream project, and the upstream repository does not have the commits that were
// just pushed to the fork - which is the "unknown revision" that used to fail go mod tidy here. The
// git configuration below resolves the upstream module path against the repository that actually
// publishes it, without changing what the published go.mod files say.
func publishEnvironment(directory, modulePath string) []string {
	environment := append(os.Environ(),
		"GOPROXY=direct",
		"GOSUMDB=off",
		"GOFLAGS=-mod=mod",
		"GIT_TERMINAL_PROMPT=0",
	)

	moduleRepository := repositoryOfModule(modulePath)
	originRepository := repositoryFromRemote(directory)
	if originRepository == "" || moduleRepository == "" || originRepository == moduleRepository {
		return environment
	}

	log.Printf("Module path %s is served by %s, but this checkout publishes it from %s", moduleRepository, moduleRepository, originRepository)
	return append(environment,
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=url.https://"+originRepository+".insteadOf",
		"GIT_CONFIG_VALUE_0=https://"+moduleRepository,
	)
}

// resolveModuleVersion asks the go command for the canonical version of a commit, and fails the
// publish when the commit cannot be resolved at all.
func resolveModuleVersion(directory string, environment []string, modulePath, revision string) string {
	log.Printf("Resolving %s@%s...", modulePath, revision[:12])
	output := publishCommandOutput(directory, environment, "go", "mod", "download", "-json", modulePath+"@"+revision)
	var download struct {
		Version string
		Error   string
	}
	err := json.Unmarshal([]byte(output), &download)
	if err != nil {
		log.Fatalf("failed to parse go mod download output for %s@%s: %v\n%s", modulePath, revision, err, output)
	}
	if download.Error != "" {
		log.Fatalf("failed to resolve %s@%s: %s", modulePath, revision, download.Error)
	}
	if download.Version == "" {
		log.Fatalf("go mod download returned no version for %s@%s:\n%s", modulePath, revision, output)
	}
	return download.Version
}

func formatPseudoVersion(commitTime time.Time, commitHash string) string {
	timestamp := commitTime.UTC().Format("20060102150405")
	return fmt.Sprintf("v0.0.0-%s-%s", timestamp, commitHash[:12])
}

func getCommitTime(directory, commitHash string) time.Time {
	output := runCommandOutput(directory, "git", "show", "-s", "--format=%cI", commitHash)
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(output))
	if err != nil {
		log.Fatalf("failed to parse commit time: %v", err)
	}
	return t
}

func generateAllPackage(directory, modulePath, rootVersion, libVersion string, builtTargets []string) {
	allDirectory := filepath.Join(directory, "all")
	err := os.MkdirAll(allDirectory, 0o755)
	if err != nil {
		log.Fatalf("failed to create all directory: %v", err)
	}

	generateAllGoMod(allDirectory, modulePath, rootVersion, libVersion, builtTargets)

	for _, targetName := range builtTargets {
		generatePlatformImportFile(allDirectory, modulePath, targetName)
	}

	log.Printf("Generated all package with %d platforms", len(builtTargets))
}

func generateAllGoMod(allDirectory, modulePath, rootVersion, libVersion string, builtTargets []string) {
	var builder strings.Builder
	builder.WriteString("module " + modulePath + "/all\n\n")
	builder.WriteString("go 1.20\n\n")
	builder.WriteString("require (\n")
	fmt.Fprintf(&builder, "\t%s %s\n", modulePath, rootVersion)
	for _, targetName := range builtTargets {
		fmt.Fprintf(&builder, "\t%s/lib/%s %s\n", modulePath, targetName, libVersion)
	}
	builder.WriteString(")\n")

	goModPath := filepath.Join(allDirectory, "go.mod")
	err := os.WriteFile(goModPath, []byte(builder.String()), 0o644)
	if err != nil {
		log.Fatalf("failed to write go.mod: %v", err)
	}
}

func generatePlatformImportFile(allDirectory, modulePath, targetName string) {
	buildTag := getBuildTagForTarget(targetName)
	packageName := strings.ReplaceAll(targetName, "-", "_")

	content := fmt.Sprintf(`//go:build %s

package all

import (
	_ "%s"
	_ "%s/lib/%s"
)
`, buildTag, modulePath, modulePath, targetName)

	fileName := packageName + ".go"
	filePath := filepath.Join(allDirectory, fileName)
	err := os.WriteFile(filePath, []byte(content), 0o644)
	if err != nil {
		log.Fatalf("failed to write %s: %v", fileName, err)
	}
}

// getBuildTagForTarget returns the build tag for a given target directory name.
// Directory names follow the pattern: {platform}_{goarch}[_simulator][_musl]
// where platform is goos (linux, darwin, windows, android) or tvos/ios for Apple platforms.
func getBuildTagForTarget(targetName string) string {
	parts := strings.Split(targetName, "_")
	if len(parts) < 2 {
		log.Fatalf("invalid target name: %s", targetName)
	}

	goos := parts[0]
	goarch := parts[1]

	isSimulator := false
	isMusl := false
	isTvOS := false

	for i := 2; i < len(parts); i++ {
		switch parts[i] {
		case "simulator":
			isSimulator = true
		case "musl":
			isMusl = true
		}
	}

	// Handle tvOS: directory prefix is "tvos" but GOOS is "ios"
	if goos == "tvos" {
		isTvOS = true
		goos = "ios"
	}

	// Handle iOS/tvOS with gomobile-compatible tags
	if goos == "ios" {
		tagParts := []string{"ios", goarch}

		if isTvOS {
			tagParts = append(tagParts, "tvos")
			if isSimulator {
				tagParts = append(tagParts, "tvossimulator")
			} else {
				tagParts = append(tagParts, "!tvossimulator")
			}
		} else {
			tagParts = append(tagParts, "!tvos")
			if isSimulator {
				tagParts = append(tagParts, "iossimulator")
			} else {
				tagParts = append(tagParts, "!iossimulator")
			}
		}

		return strings.Join(tagParts, " && ")
	}

	if isMusl {
		return fmt.Sprintf("%s && !android && %s && with_musl", goos, goarch)
	}

	if goos == "linux" {
		return fmt.Sprintf("%s && !android && %s && !with_musl", goos, goarch)
	}

	if goos == "darwin" {
		return fmt.Sprintf("%s && !ios && %s", goos, goarch)
	}

	// Windows: purego only
	if goos == "windows" {
		return fmt.Sprintf("%s && %s && with_purego", goos, goarch)
	}

	return fmt.Sprintf("%s && %s", goos, goarch)
}

// publishCommand and publishCommandOutput run a command with the environment publishing needs. They
// stay in this file because the build cache is keyed by the other command sources: publishing must not
// invalidate the toolchain and build caches of the platforms it ships.
func publishCommand(directory string, environment []string, name string, args ...string) {
	command := exec.Command(name, args...)
	command.Dir = directory
	command.Env = environment
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	err := command.Run()
	if err != nil {
		log.Fatalf("command failed: %s %s: %v", name, strings.Join(args, " "), err)
	}
}

func publishCommandOutput(directory string, environment []string, name string, args ...string) string {
	command := exec.Command(name, args...)
	command.Dir = directory
	command.Env = environment
	var stdout bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = os.Stderr
	err := command.Run()
	if err != nil {
		log.Fatalf("command failed: %s %s: %v", name, strings.Join(args, " "), err)
	}
	return stdout.String()
}

func runGoModTidy(directory string, environment []string) {
	log.Printf("Running go mod tidy in %s with GOPROXY=direct...", directory)
	publishCommand(directory, environment, "go", "mod", "tidy")
}

// assertSelectedVersion fails the publish when the module graph did not end up on the commit that was
// pushed. It reads the selected version only; it never rewrites go.mod to make the check pass.
func assertSelectedVersion(directory string, environment []string, modulePath, expected string) {
	selected := strings.TrimSpace(publishCommandOutput(directory, environment, "go", "list", "-m", "-f", "{{.Version}}", modulePath))
	if selected != expected {
		log.Fatalf("go mod tidy resolved %s to %s, but this run published %s", modulePath, selected, expected)
	}
	log.Printf("go mod tidy kept %s at %s", modulePath, selected)
}

// changedLibraryTargets lists the lib/<target> directories that the staged commit changes, i.e. the
// native libraries this publish actually refreshes.
func changedLibraryTargets(directory string) []string {
	output := runCommandOutput(directory, "git", "status", "--porcelain")
	seen := make(map[string]bool)
	var targets []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		path := strings.Trim(fields[len(fields)-1], "\"")
		if !strings.HasPrefix(path, "lib/") {
			continue
		}
		remainder := strings.TrimPrefix(path, "lib/")
		target := remainder
		if index := strings.Index(remainder, "/"); index >= 0 {
			target = remainder[:index]
		}
		if target == "" || seen[target] {
			continue
		}
		seen[target] = true
		targets = append(targets, target)
	}
	sort.Strings(targets)
	return targets
}

func fixLibSubmoduleVersions(libDirectory string, targets []string, version string) {
	log.Printf("Fixing lib submodule versions to %s...", version)
	for _, targetName := range targets {
		submoduleDirectory := filepath.Join(libDirectory, targetName)
		goModPath := filepath.Join(submoduleDirectory, "go.mod")

		// Check if go.mod exists
		if _, err := os.Stat(goModPath); os.IsNotExist(err) {
			continue
		}

		// Check if this submodule depends on main module
		content, err := os.ReadFile(goModPath)
		if err != nil {
			log.Fatalf("failed to read %s: %v", goModPath, err)
		}

		if !strings.Contains(string(content), "github.com/sagernet/cronet-go") {
			continue
		}

		// Force correct version
		runCommand(submoduleDirectory, "go", "mod", "edit", "-require=github.com/sagernet/cronet-go@"+version)
		log.Printf("  Fixed lib/%s", targetName)
	}
}
