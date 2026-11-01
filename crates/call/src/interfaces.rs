//! Local interfaces (docs/02 §4): which of our addresses serves which peers.
//!
//! A PBX on several networks has one address per network — a phone on the LAN
//! must see the LAN address in Via, Contact and SDP, a phone on the VPN the VPN
//! one. An [`Interface`] pairs our addresses with the peer [`Network`] they
//! serve; [`interface_for`] picks one per peer: the most specific network that
//! contains the peer's address.

use std::net::{IpAddr, SocketAddr};

/// A peer network ("192.168.1.0/24"): which peers an interface serves. A bare
/// address ("192.168.1.5") is a network of one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network {
    /// The network address.
    pub addr: IpAddr,
    /// How many leading bits are the network part (0..=32 / 0..=128).
    pub prefix: u8,
}

impl Network {
    /// Parses "192.168.1.0/24", or a bare address as a single-host network.
    /// `None` for anything else: bad addresses, prefixes wider than the
    /// address family allows.
    pub fn parse(text: &str) -> Option<Network> {
        let (addr, prefix) = match text.trim().split_once('/') {
            Some((addr, prefix)) => (addr.trim(), Some(prefix.trim())),
            None => (text.trim(), None),
        };
        let addr: IpAddr = addr.parse().ok()?;
        let width = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(prefix) => prefix.parse::<u8>().ok()?,
            None => width,
        };
        if prefix > width {
            return None;
        }
        Some(Network { addr, prefix })
    }

    /// Whether `peer` is inside this network. Addresses of different families
    /// are never in the same network.
    pub fn contains(&self, peer: IpAddr) -> bool {
        match (self.addr, peer) {
            (IpAddr::V4(network), IpAddr::V4(peer)) => same_prefix(
                u32::from(network).into(),
                u32::from(peer).into(),
                self.prefix,
                32,
            ),
            (IpAddr::V6(network), IpAddr::V6(peer)) => {
                same_prefix(network.into(), peer.into(), self.prefix, 128)
            }
            _ => false,
        }
    }
}

/// Whether two addresses share their first `prefix` bits (of `bits` total).
fn same_prefix(network: u128, peer: u128, prefix: u8, bits: u32) -> bool {
    if prefix == 0 {
        return true;
    }
    let shift = bits - u32::from(prefix);
    (network >> shift) == (peer >> shift)
}

/// One local interface: the peers in `network` are served from `sip`/`rtp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    /// The peers served here ("192.168.1.0/24").
    pub network: Network,
    /// The SIP address these peers see in Via/Contact. The daemon listens
    /// on its *port*, on all local addresses — the address itself need not
    /// be ours (NAT'd or routed addresses work).
    pub sip: SocketAddr,
    /// The media address these peers see in SDP.
    pub rtp: IpAddr,
}

/// The interface that serves `peer`: the network containing its address with
/// the longest prefix (first one wins on a tie). `None` when no configured
/// network contains it — callers fall back to their first interface.
pub fn interface_for(interfaces: &[Interface], peer: IpAddr) -> Option<&Interface> {
    let mut best: Option<&Interface> = None;
    for interface in interfaces {
        if interface.network.contains(peer)
            && best.is_none_or(|best| interface.network.prefix > best.network.prefix)
        {
            best = Some(interface);
        }
    }
    best
}
