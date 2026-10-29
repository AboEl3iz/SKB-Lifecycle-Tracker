pub mod compat;
pub mod consumer;
pub mod filter;
pub mod stats;
pub mod tracker;
pub mod tui;
pub mod types;

pub mod bpf {
    #[allow(clippy::all)]
    #[allow(non_upper_case_globals)]
    #[allow(non_camel_case_types)]
    #[allow(non_snake_case)]
    #[allow(unused)]
    pub mod skel {
        include!(concat!(env!("OUT_DIR"), "/skb_tracer.skel.rs"));
    }
}
