use crate::types::FilterConfig;
use anyhow::{Context, Result};
use libbpf_rs::MapCore;
use std::ffi::CString;
use tracing::info;

pub struct FilterManager;

impl FilterManager {
    /// Resolves an interface name (e.g. "eth0") to its Linux kernel ifindex.
    pub fn ifname_to_index(ifname: &str) -> Result<u32> {
        let c_str = CString::new(ifname).context("Invalid interface name")?;
        let idx = unsafe { nix::libc::if_nametoindex(c_str.as_ptr()) };
        if idx == 0 {
            anyhow::bail!("Interface '{}' not found", ifname);
        }
        Ok(idx)
    }

    /// Updates the in-kernel BPF config map with active filter settings.
    pub fn apply_to_bpf_map(map: &libbpf_rs::Map, filter: &FilterConfig) -> Result<()> {
        let key: u32 = 0;
        let key_bytes = key.to_ne_bytes();
        let val_bytes = unsafe { plain::as_bytes(filter) };

        map.update(&key_bytes, val_bytes, libbpf_rs::MapFlags::ANY)
            .context("Failed to update BPF config_map")?;

        info!(
            "Applied in-kernel filter: port={}, ifindex={}, netns_ino={}",
            filter.target_port, filter.target_ifindex, filter.target_netns_ino
        );
        Ok(())
    }
}
