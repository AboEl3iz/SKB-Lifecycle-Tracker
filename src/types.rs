use serde::{Deserialize, Serialize};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SkbOp {
    Alloc = 1,
    GroMerge = 2,
    TcpCoalesce = 3,
    GsoSegment = 4,
    ExpandHead = 5,
    Consume = 6,
    Drop = 7,
    Unknown = 255,
}

impl From<u8> for SkbOp {
    fn from(v: u8) -> Self {
        match v {
            1 => SkbOp::Alloc,
            2 => SkbOp::GroMerge,
            3 => SkbOp::TcpCoalesce,
            4 => SkbOp::GsoSegment,
            5 => SkbOp::ExpandHead,
            6 => SkbOp::Consume,
            7 => SkbOp::Drop,
            _ => SkbOp::Unknown,
        }
    }
}

impl std::fmt::Display for SkbOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SkbOp::Alloc => write!(f, "ALLOC"),
            SkbOp::GroMerge => write!(f, "GRO_MERGE"),
            SkbOp::TcpCoalesce => write!(f, "TCP_COALESCE"),
            SkbOp::GsoSegment => write!(f, "GSO_SEGMENT"),
            SkbOp::ExpandHead => write!(f, "EXPAND_HEAD"),
            SkbOp::Consume => write!(f, "CONSUME"),
            SkbOp::Drop => write!(f, "DROP"),
            SkbOp::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Binary layout matches C struct skb_lifecycle_event (64 bytes, 8-byte aligned)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkbLifecycleEvent {
    pub timestamp_ns: u64,
    pub skb_addr: u64,
    pub peer_skb_addr: u64,
    pub len: u32,
    pub data_len: u32,
    pub truesize: u32,
    pub drop_reason: u32,
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub gso_size: u16,
    pub gso_segs: u16,
    pub nr_frags: u8,
    pub op: u8,
    pub protocol: u8,
    pub _pad: [u8; 5],
}

// Safety: SkbLifecycleEvent contains only primitive integers and array padding,
// with no references or uninitialized memory invariants.
unsafe impl plain::Plain for SkbLifecycleEvent {}

impl SkbLifecycleEvent {
    pub fn operation(&self) -> SkbOp {
        SkbOp::from(self.op)
    }

    pub fn saddr_str(&self) -> String {
        let ip = std::net::Ipv4Addr::from(self.saddr.to_ne_bytes());
        format!("{}", ip)
    }

    pub fn daddr_str(&self) -> String {
        let ip = std::net::Ipv4Addr::from(self.daddr.to_ne_bytes());
        format!("{}", ip)
    }

    pub fn protocol_str(&self) -> &'static str {
        match self.protocol {
            6 => "TCP",
            17 => "UDP",
            1 => "ICMP",
            _ => "OTHER",
        }
    }

    pub fn flow_str(&self) -> String {
        if self.saddr == 0 && self.daddr == 0 {
            return "-".to_string();
        }
        format!(
            "{}:{} -> {}:{} ({})",
            self.saddr_str(),
            self.sport,
            self.daddr_str(),
            self.dport,
            self.protocol_str()
        )
    }

    pub fn drop_reason_str(&self) -> &'static str {
        match self.drop_reason {
            0 => "NOT_SPECIFIED",
            1 => "NO_SOCKET",
            2 => "PKT_TOO_SMALL",
            3 => "TCP_CSUM",
            4 => "SOCKET_FILTER",
            5 => "UDP_CSUM",
            6 => "NETFILTER_DROP",
            7 => "OTHERHOST",
            8 => "IP_CSUM",
            9 => "IP_INHDR",
            10 => "IP_RPFILTER",
            11 => "XFRM_POLICY",
            12 => "BPF_CGROUP_EGRESS",
            13 => "TCP_MINTTL",
            14 => "TCP_RESET",
            15 => "TCP_OLD_ACK",
            16 => "TCP_TOO_EARLY",
            17 => "TCP_FLAGS",
            18 => "TCP_ZEROWINDOW",
            19 => "TCP_OLD_DATA",
            20 => "TCP_OVERCOMMIT",
            _ => "UNKNOWN_REASON",
        }
    }
}

/// Binary layout matches C struct filter_config
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterConfig {
    pub target_port: u32,
    pub target_ifindex: u32,
    pub target_netns_ino: u64,
}

unsafe impl plain::Plain for FilterConfig {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, size_of};

    #[test]
    fn test_struct_size_and_alignment() {
        assert_eq!(size_of::<SkbLifecycleEvent>(), 64);
        assert_eq!(align_of::<SkbLifecycleEvent>(), 8);
    }
}
