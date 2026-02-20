# ghostptr 👻

[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![crates.io](https://img.shields.io/crates/v/ghostptr.svg)](https://crates.io/crates/ghostptr)
[![docs.rs](https://docs.rs/ghostptr/badge.svg)](https://docs.rs/ghostptr)

Lightweight, ergonomic library for low‑level Windows process interaction.

## Design

The purpose of this library is to provide simple, minimal abstractions over Windows NT primitives. The API offers ergonomic access to process handles and memory while preserving safety wherever it can be guaranteed.

## Installation

```toml
[dependencies]
ghostptr = "0.2.5"
```

## Quick Start

```rust
fn main() -> ghostptr::Result<()> {
    let process = Process::current();
	let pid = process.pid()?;

	println!("{}", pid);

	Ok(())
}
```
