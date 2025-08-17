# Tondi 脚本执行器

专为Tondi网络设计的脚本执行工具。

**注意：这是一个私有实现，仍在开发中，仅供内部使用！**

## 项目状态

本项目是一个正在开发中的Tondi脚本执行器，旨在为Tondi网络提供完整的脚本执行能力。
虽然尚未完全实现所有操作码，但作为库已经能够提供良好的脚本执行洞察和调试能力。

## 功能特性

- **完整的Tondi脚本执行引擎**：支持所有标准操作码
- **多执行上下文支持**：Legacy、SegWit v0、Tapscript
- **双重接口**：WASM和CLI接口
- **逐步执行**：支持脚本逐步执行，便于调试
- **实验性功能**：支持OP_CAT、OP_MUL、OP_DIV等实验性操作码
- **私有化实现**：确保安全性和代码质量
- **完整的错误处理**：详细的执行错误信息和调试支持

## 使用方法

### 命令行界面 (CLI)

您可以使用 `cargo run` 或构建/安装二进制文件：

```bash
# 调试模式构建
$ cargo build --locked
# 发布模式构建（优化）
$ cargo build --locked --release
# 安装到 ~/.cargo/bin
$ cargo install --locked --path .
```

#### 使用说明

CLI接受一个主要参数：ASM脚本文件的路径：

```bash
# 使用二进制文件
$ tondiexec <script.bs>
# 使用cargo run
$ cargo run -- <script.bs>
```

#### CLI选项

- `-f, --format`: 输出格式（text文本、json、hex十六进制）
- `-v, --verbose`: 详细输出
- `-m, --mode`: 执行模式（parse解析、execute执行、validate验证）

### WebAssembly (WASM)

提供了完整的WASM绑定，支持在浏览器和Node.js环境中使用。API文档请参见 `src/wasm.rs` 文件。

要构建WASM绑定，请[安装wasm-pack](https://rustwasm.github.io/wasm-pack/installer/)，
然后运行以下脚本：

```bash
./build-wasm.sh
```

## 项目架构

项目由以下几个核心模块组成：

- **核心执行引擎**：主要的脚本执行逻辑
- **数据结构**：栈、脚本表示和执行上下文
- **签名验证**：脚本签名验证功能
- **工具函数**：加密工具和辅助函数
- **WASM接口**：用于浏览器/Node.js的WebAssembly绑定
- **CLI接口**：脚本执行的命令行工具

## 技术特性

### 执行上下文支持
- **Legacy**: 传统脚本执行
- **SegWit v0**: 隔离见证v0脚本
- **Tapscript**: Taproot脚本

### 实验性功能
- **OP_CAT**: 字符串连接操作
- **OP_MUL**: 乘法操作
- **OP_DIV**: 除法操作

### 安全特性
- 栈大小限制
- 操作码数量限制
- 脚本元素大小验证
- 最小编码要求

## 依赖关系

- **Tondi依赖**: 复用现有Tondi代码（txscript、hashes、consensus-core）
- **核心依赖**: serde、lazy_static
- **CLI依赖**: clap
- **WASM依赖**: wasm-bindgen、serde-wasm-bindgen
- **加密依赖**: secp256k1、hex

## 开发指南

### 构建项目
```bash
# 安装依赖
$ cargo build

# 运行测试
$ cargo test

# 检查代码质量
$ cargo clippy
```

### 添加新功能
1. 在相应的模块中添加新功能
2. 更新测试用例
3. 更新文档
4. 确保WASM和CLI接口的一致性

## 项目结构

```
src/
├── lib.rs              # 主要库文件
├── main.rs             # CLI入口点
├── wasm.rs             # WASM绑定
├── data_structures.rs  # 数据结构和栈操作
├── error.rs            # 错误处理
├── signatures.rs       # 签名验证
├── utils.rs            # 工具函数
└── macros.rs           # 宏定义
```

## 许可证

MIT License - 私有使用

## 贡献

这是一个私有项目，仅供Tondi团队内部使用。如需贡献，请联系团队负责人。

## 联系方式

- 项目维护者：Tondi Team
- 邮箱：team@tondi.net
- 仓库：https://github.com/tondinet/tondi-scriptexec
