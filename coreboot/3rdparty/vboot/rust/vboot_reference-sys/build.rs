// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// Minijail's build script invoked by cargo.
///
/// This script prefers linking against a pkg-config provided libminijail, but will fall back to
/// building libminijail statically.
use std::env;
use std::fs::remove_file;
use std::path::Path;

use anyhow::{Context, Result};
use bindgen::{Builder, EnumVariation};

static COMMON_CFLAGS: &[&str] = &[
    "-DUSE_BINDGEN",
    "-D_FILE_OFFSET_BITS=64",
    "-D_LARGEFILE_SOURCE",
    "-D_LARGEFILE64_SOURCE",
];

fn get_bindgen_builder() -> Builder {
    bindgen::builder()
        .default_enum_style(EnumVariation::Rust {
            non_exhaustive: false,
        })
        .layout_tests(false)
        .disable_header_comment()
}

fn generate_crossystem_bindings() -> Result<()> {
    let out_dir = env::var("OUT_DIR").unwrap();
    let gen_file = Path::new(&out_dir).join("./crossystem.rs");
    if gen_file.exists() {
        remove_file(&gen_file).expect("Failed to remove generated file.");
    }
    let header_dir = Path::new(".");
    let header_path = header_dir.join("crossystem.h");
    println!("cargo:rerun-if-changed={}", header_path.display());

    let bindings = get_bindgen_builder()
        .allowlist_function("Vb.*")
        .clang_args(COMMON_CFLAGS)
        .header(header_path.display().to_string())
        .generate()
        .context("unable to generate bindings for crossystem.h")?;

    bindings
        .write_to_file(gen_file.display().to_string())
        .context("unable to write bindings to file")?;

    Ok(())
}

fn generate_vboot_host_binding() -> Result<()> {
    let out_dir = env::var("OUT_DIR").unwrap();
    let gen_file = Path::new(&out_dir).join("./vboot_host.rs");
    if gen_file.exists() {
        remove_file(&gen_file).expect("Failed to remove generated file.");
    }
    let header_dir = Path::new(".");
    let header_path = header_dir.join("vboot_host.h");
    println!("cargo:rerun-if-changed={}", header_path.display());
    for file in std::fs::read_dir("include")? {
        println!("cargo:rerun-if-changed={}", file?.path().display());
    }

    let bindings = get_bindgen_builder()
        .allowlist_function("Cgpt.*")
        .allowlist_function(".*Guid.*")
        .allowlist_function("FindKernelConfig")
        .allowlist_function("ExtractVmlinuz")
        .allowlist_function("vb2_.*")
        .size_t_is_usize(false)
        .clang_args(COMMON_CFLAGS)
        .clang_arg("-Iinclude")
        .header(header_path.display().to_string())
        .generate()
        .context("unable to generate bindings for vboot_host.h")?;

    bindings
        .write_to_file(gen_file.display().to_string())
        .context("unable to write bindings to file")?;

    Ok(())
}

fn main() -> Result<()> {
    if pkg_config::Config::new().probe("vboot_host").is_err() {
        // Fallback to generate bindings even if the library is not installed.
        println!("cargo:rustc-link-lib=dylib=vboot_host");
        println!("cargo:rustc-link-lib=dylib=dl");
    }
    generate_crossystem_bindings()?;
    generate_vboot_host_binding()
}
