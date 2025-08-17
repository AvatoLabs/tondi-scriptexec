# Tondi Script Executor

一个专为Tondi网络设计的脚本执行工具。

**注意：这是一个私有实现，仅供内部使用！**

## 项目状态

本项目是一个正在进行中的Tondi脚本执行器，旨在为Tondi网络提供完整的脚本执行能力。
目前尚未完全实现所有操作码，但作为库已经能够提供良好的脚本执行洞察。

## 功能特性

- 完整的Tondi脚本执行引擎
- 支持WASM和CLI接口
- 逐步执行脚本，便于调试
- 私有化实现，确保安全性

## 使用方法

### CLI

你可以使用 `cargo run` 或构建/安装二进制文件：

```bash
# 调试模式构建
$ cargo build --locked
# 发布模式构建（优化）
$ cargo build --locked --release
# 安装到 ~/.cargo/bin
$ cargo install --locked --path .
```

#### 使用说明

CLI目前只接受一个参数：ASM脚本文件的路径：

```bash
# 使用二进制文件
$ tondiexec <script.bs>
# 使用cargo run
$ cargo run -- <script.bs>
```

### WASM

提供了WASM绑定。API文档请参见 `src/wasm.rs` 文件。

要构建WASM绑定，请[安装wasm-pack](https://rustwasm.github.io/wasm-pack/installer/)，
然后运行以下脚本：

```bash
./build-wasm.sh
```

## 开发

这是一个私有项目，仅供Tondi团队内部使用。

## 许可证

MIT License - 私有使用
# tondi-scriptexec
# tondi-scriptexec
