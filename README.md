# cronet-go

> **这是 JiejieBox 使用的自定义 Cronet fork，也是唯一的源码维护和依赖入口。**
> 原有自定义改动保留；v154-patch5 是在原有源码上追加的维护补丁。

## 仓库与分支

| 位置 | 用途 |
| --- | --- |
| 本仓库 `main` | 开发源码、Go 绑定、自定义拨号与构建脚本 |
| 本仓库 `go` | 已发布的 Go 模块和原生库；供消费方锁定版本，不用于日常开发 |
| [naiveproxy](https://github.com/Piggy-Cat-bit-shadow/naiveproxy) 子模块 | 定制的 Chromium/Cronet 源码；具体提交以本仓库的 gitlink 为准 |
| [cronet-go-build](https://github.com/Piggy-Cat-bit-shadow/cronet-go-build) | 临时 CI 辅助镜像，仅用于原仓库 Actions 受限期间的构建与验证 |

**消费方应引用本仓库，不要引用 `cronet-go-build`。** 模块声明仍沿用
`github.com/sagernet/cronet-go`，消费方用精确的 `replace` 指向本 fork；
`lib` 子模块需要逐个列出，Go 不支持 `lib/*` 通配符替换。

当前维护 Chromium `154.0.8037.49`，已适配 NaiveProxy `v154.0.8037.49-5`
的证书封锁与 QUIC 补丁。原生库此次更新覆盖 Linux/amd64、Windows/amd64、
Android/arm64、macOS/arm64、iOS/arm64；其他架构的模块存在不代表本次已重建。

历史 native 分支保存在 naiveproxy 仓库的 `archive/2026-11-05/*` 标签中，
活动分支为 `cronet-go-dev-v154-patch5`。临时 CI 仓库不改变本仓库的自定义 fork 身份。

[![Reference](https://pkg.go.dev/badge/github.com/sagernet/cronet-go.svg)](https://pkg.go.dev/github.com/sagernet/cronet-go)

Go bindings for [naiveproxy](https://github.com/klzgrad/naiveproxy).

## Supported Platforms

| Target        | OS      | CPU   |
|---------------|---------|-------|
| android/386   | android | x86   |
| android/amd64 | android | x64   |
| android/arm   | android | arm   |
| android/arm64 | android | arm64 |
| darwin/amd64  | mac     | x64   |
| darwin/arm64  | mac     | arm64 |
| ios/arm64     | ios     | arm64 |
| ios/amd64     | ios     | amd64 |
| linux/386     | linux   | x86   |
| linux/amd64   | linux   | x64   |
| linux/arm     | linux   | arm   |
| linux/arm64   | linux   | arm64   |
| linux/loong64 | linux   | loong64 |
| windows/amd64 | win     | x64     |
| windows/arm64 | win     | arm64 |

## System Requirements

| Platform      | Minimum Version |
|---------------|-----------------|
| macOS         | 12.0 (Monterey) |
| iOS/tvOS      | 15.0            |
| Windows       | 10              |
| Android       | 5.0 (API 21)    |
| Linux (glibc)       | glibc 2.31 (loong64: 2.36) |
| Linux (musl)        | any (loong64: 1.2.5)       |

## Downstream Build Requirements

| Platform                             | Requirements                    | Go Build Flags                    |
|--------------------------------------|---------------------------------|-----------------------------------|
| Linux (glibc)                        | Chromium toolchain              | -                                 |
| Linux (musl)                         | Chromium toolchain              | `-tags with_musl`                 |
| macOS / iOS                          | macOS Xcode                     | -                                 |
| iOS simulator/ tvOS / tvOS simulator | macOS Xcode + SagerNet/gomobile | -                                 |
| Windows                              | -                               | `CGO_ENABLED=0 -tags with_purego` |
| Android                              | Android NDK                     | -                                 |

## Linux Build instructions

```bash
git clone --recursive --depth=1 https://github.com/sagernet/cronet-go.git
cd cronet-go
go run ./cmd/build-naive --target=linux/amd64 download-toolchain
#go run ./cmd/build-naive --target=linux/amd64 --libc=musl download-toolchain

# Outputs CC, CXX, and CGO_LDFLAGS=-fuse-ld=lld
export $(go run ./cmd/build-naive --target=linux/amd64 env)
#export $(go run ./cmd/build-naive --target=linux/amd64 --libc=musl env)

cd /path/to/your/project
go build
# go build -tags with_musl
```

### Directories to cache

```yaml
- cronet-go/naiveproxy/src/third_party/llvm-build/
- cronet-go/naiveproxy/src/gn/out/
- cronet-go/naiveproxy/src/chrome/build/pgo_profiles/
- cronet-go/naiveproxy/src/out/sysroot-build/
```

## Windows / purego Build Instructions

For Windows or pure Go builds (no CGO), you need to distribute the dynamic library alongside your binary.

### Download Library

Download `libcronet.dll` (Windows) or `libcronet.so` (Linux) from [GitHub Releases](https://github.com/sagernet/cronet-go/releases).

### Build with purego

```bash
# Windows (purego is required)
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -tags with_purego -o myapp.exe

# Linux with purego (optional, for dynamic linking)
CGO_ENABLED=0 go build -tags with_purego -o myapp
```

### Distribution

Place the library file in the same directory as your executable:
- Windows: `libcronet.dll`
- Linux: `libcronet.so`

### For Downstream Developers

The `go` branch holds the libraries. The same commit supplies the
`github.com/sagernet/cronet-go/lib/*` modules. Pin this commit. Read the library file from it:

```bash
git init cronet-go-lib
git -C cronet-go-lib remote add origin https://github.com/sagernet/cronet-go.git
git -C cronet-go-lib sparse-checkout set --no-cone /lib/windows_amd64/libcronet.dll
git -C cronet-go-lib fetch --depth=1 --filter=blob:none origin "$CRONET_GO_VERSION"
git -C cronet-go-lib checkout FETCH_HEAD
```

