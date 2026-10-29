use anyhow::{bail, Result};
use std::path::Path;
use tracing::{info, warn};

pub struct SystemCapability {
    pub is_root: bool,
    pub btf_available: bool,
    pub kernel_release: String,
    pub kernel_version: (u32, u32, u32),
}

pub fn check_system_requirements() -> Result<SystemCapability> {
    let uid = nix::unistd::geteuid();
    let is_root = uid.is_root();

    if !is_root {
        warn!(
            "Running without root privileges (UID={}). Ensure CAP_BPF and CAP_PERFMON are granted.",
            uid
        );
    }

    // When running inside network namespaces (e.g. `ip netns exec`), a private /sys
    // is mounted without tracefs/debugfs. Ensure tracefs is mounted so libbpf can
    // discover tracepoint perf event IDs.
    let events_path = Path::new("/sys/kernel/tracing/events");
    if !events_path.exists() && is_root {
        let _ = std::process::Command::new("mount")
            .args(["-t", "tracefs", "nodev", "/sys/kernel/tracing"])
            .output();
        if !events_path.exists() {
            let _ = std::process::Command::new("mount")
                .args(["-t", "debugfs", "nodev", "/sys/kernel/debug"])
                .output();
        }
    }

    let btf_path = Path::new("/sys/kernel/btf/vmlinux");
    let btf_available = btf_path.exists();

    if !btf_available {
        bail!(
            "Kernel BTF not found at /sys/kernel/btf/vmlinux.\n\
             eBPF CO-RE requires a kernel built with CONFIG_DEBUG_INFO_BTF=y (Linux 5.8+ recommended)."
        );
    }

    let uname = nix::sys::utsname::uname()?;
    let kernel_release = uname.release().to_string_lossy().to_string();
    let kernel_version = parse_kernel_version(&kernel_release);

    if kernel_version.0 < 5 || (kernel_version.0 == 5 && kernel_version.1 < 8) {
        warn!(
            "Kernel version {}.{}.{} detected. skb-tracer is optimized for Linux 5.8+ (CO-RE, BPF ringbuf, fentry/fexit).",
            kernel_version.0, kernel_version.1, kernel_version.2
        );
    }

    info!(
        "System check passed: Kernel {} ({}.{}.{}), BTF available, UID={}",
        kernel_release, kernel_version.0, kernel_version.1, kernel_version.2, uid
    );

    Ok(SystemCapability {
        is_root,
        btf_available,
        kernel_release,
        kernel_version,
    })
}

fn parse_kernel_version(release: &str) -> (u32, u32, u32) {
    let mut parts = release.split('.').map(|p| {
        p.chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse::<u32>()
            .unwrap_or(0)
    });

    let major = parts.next().unwrap_or(0);
    let minor = parts.next().unwrap_or(0);
    let patch = parts.next().unwrap_or(0);

    (major, minor, patch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_kernel_version() {
        assert_eq!(parse_kernel_version("6.18.55-2-cachyos-lts"), (6, 18, 55));
        assert_eq!(parse_kernel_version("5.15.0-78-generic"), (5, 15, 0));
        assert_eq!(parse_kernel_version("6.5.12"), (6, 5, 12));
    }
}
