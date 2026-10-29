use std::env;
use std::path::PathBuf;
use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/skb_tracer.bpf.c";

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set"))
        .join("skb_tracer.skel.rs");

    let arch = match env::consts::ARCH {
        "x86_64" => "x86",
        "aarch64" => "arm64",
        "arm" => "arm",
        "riscv64" => "riscv",
        arch => arch,
    };

    let target_def = format!("-D__TARGET_ARCH_{arch}");

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args([
            target_def.as_str(),
            "-Isrc/bpf",
            "-I/usr/include",
        ])
        .build_and_generate(&out)
        .unwrap_or_else(|err| panic!("Failed to build and generate BPF skeleton: {:?}", err));

    println!("cargo:rerun-if-changed={SRC}");
    println!("cargo:rerun-if-changed=src/bpf/skb_event.h");
    println!("cargo:rerun-if-changed=src/bpf/skb_filter.h");
}
