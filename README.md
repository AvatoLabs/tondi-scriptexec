# Tondi Script Executor

A script execution tool designed specifically for the Tondi network.

**Note: This is a private implementation still under development, for internal use only!**

## Project Status

This project is a work-in-progress Tondi script executor that aims to provide complete script execution capabilities for the Tondi network.
While not all opcodes are fully implemented yet, it already provides good script execution insights as a library.

## Features

- Complete Tondi script execution engine
- Support for WASM and CLI interfaces
- Step-by-step script execution for debugging
- Private implementation ensuring security
- Support for multiple execution contexts (Legacy, SegWit v0, Tapscript)
- Experimental opcode support (OP_CAT, OP_MUL, OP_DIV)

## Usage

### CLI

You can use `cargo run` or build/install the binary:

```bash
# Debug build
$ cargo build --locked
# Release build (optimized)
$ cargo build --locked --release
# Install to ~/.cargo/bin
$ cargo install --locked --path .
```

#### Usage Instructions

The CLI currently accepts one argument: the path to an ASM script file:

```bash
# Using binary
$ tondiexec <script.bs>
# Using cargo run
$ cargo run -- <script.bs>
```

#### CLI Options

- `-f, --format`: Output format (text, json, hex)
- `-v, --verbose`: Verbose output
- `-m, --mode`: Execution mode (parse, execute, validate)

### WASM

WASM bindings are provided. See the `src/wasm.rs` file for API documentation.

To build WASM bindings, [install wasm-pack](https://rustwasm.github.io/wasm-pack/installer/),
then run the following script:

```bash
./build-wasm.sh
```

## Architecture

The project consists of several key modules:

- **Core Execution Engine**: Main script execution logic
- **Data Structures**: Stack, script representation, and execution context
- **Signatures**: Script signature verification
- **Utils**: Cryptographic utilities and helper functions
- **WASM Interface**: WebAssembly bindings for browser/Node.js usage
- **CLI Interface**: Command-line tool for script execution

## Dependencies

- **Tondi Dependencies**: Reuses existing Tondi code (txscript, hashes, consensus-core)
- **Core**: serde, lazy_static
- **CLI**: clap
- **WASM**: wasm-bindgen, serde-wasm-bindgen
- **Crypto**: secp256k1, hex

## Development

This is a private project for internal use by the Tondi team.

## License

MIT License - Private Use




