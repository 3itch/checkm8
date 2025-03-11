# Rust bindings for vboot_reference

This path contains the vboot_reference-sys crate which uses bindgen to generate
Rust bindings for the vboot_reference C library.

Each header is included as its own submodule. To use these bindings:
 * Add `vboot_reference-sys` to your `Cargo.toml` for example:
```toml
[dependencies]
vboot_reference-sys = { path = "../../vboot_reference/rust/vboot_reference-sys" }
```
 * Include the symbols you need for example:
```rust
use vboot_reference_sys::crossystem::*;
```

The `build.rs` in `vboot_reference-sys` takes care of adding the necessary
includes and linker flags for `vboot_host` through the `pkg-config` crate.
