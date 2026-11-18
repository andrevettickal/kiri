//! ARP on the uplink, for when DHCP gets no answer: finding the NAT
//! network's gateway (the Mac) and a free address beside it, with no
//! address of our own yet. ARP sits below the IP layer where software on the
//! Mac drops the DHCP broadcast, and it needs nothing configured, so it
//! still gets an answer.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

const ETH_P_ARP: u16 = 0x0806;
const BROADCAST: [u8; 6] = [0xff; 6];
const FRAME: usize = 42;

/// How long the replies to a burst of requests are waited for.
const GATEWAY_WAIT: Duration = Duration::from_millis(1000);
const ADDRESS_WAIT: Duration = Duration::from_millis(400);

/// An ARP request for `target`, broadcast from `mac`. `sender` is the
/// sender protocol address (0.0.0.0 while we have none).
pub fn request_frame(mac: [u8; 6], sender: [u8; 4], target: [u8; 4]) -> [u8; FRAME] {
    let mut f = [0u8; FRAME];
    f[0..6].copy_from_slice(&BROADCAST);
    f[6..12].copy_from_slice(&mac);
    f[12..14].copy_from_slice(&ETH_P_ARP.to_be_bytes());
    f[14..16].copy_from_slice(&1u16.to_be_bytes()); // Ethernet
    f[16..18].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4
    f[18] = 6;
    f[19] = 4;
    f[20..22].copy_from_slice(&1u16.to_be_bytes()); // request
    f[22..28].copy_from_slice(&mac);
    f[28..32].copy_from_slice(&sender);
    f[38..42].copy_from_slice(&target);
    f
}

/// The sender's (IPv4 address, MAC) of an ARP reply frame.
pub fn parse_reply(f: &[u8]) -> Option<([u8; 4], [u8; 6])> {
    if f.len() < FRAME || f[12..14] != ETH_P_ARP.to_be_bytes() || f[20..22] != 2u16.to_be_bytes() {
        return None;
    }
    Some((f[28..32].try_into().ok()?, f[22..28].try_into().ok()?))
}

/// Where Apple's NAT may have put the Mac: x.1 of 192.168.x.0/24, the
/// default network (64) first, then the ones macOS moves to when it is taken
/// or that are configured, in order.
pub fn gateway_candidates() -> impl Iterator<Item = [u8; 4]> {
    (64u8..=255).chain(0..64).map(|third| [192, 168, third, 1])
}

/// Four addresses to try in the gateway's /24, starting by `mac` so VMs
/// without a lease are unlikely to choose alike: .2 to .254, never the
/// gateway's.
pub fn own_candidates(mac: [u8; 6], gateway: [u8; 4]) -> Vec<[u8; 4]> {
    let start = u16::from_be_bytes([mac[4], mac[5]]) % 253;
    (0..253u16).map(|i| 2 + ((start + i) % 253) as u8).filter(|h| *h != gateway[3]).take(4).map(|h| [gateway[0], gateway[1], gateway[2], h]).collect()
}

pub struct Arp {
    sock: OwnedFd,
    index: i32,
    mac: [u8; 6],
}

impl Arp {
    pub fn open(index: i32, mac: [u8; 6]) -> io::Result<Arp> {
        // SAFETY: plain socket creation; owned at once.
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, ETH_P_ARP.to_be() as libc::c_int) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is fresh and ours.
        let sock = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut sll = Self::addr(index);
        sll.sll_halen = 0;
        // SAFETY: bind with a sockaddr_ll of its size.
        if unsafe { libc::bind(fd, (&sll as *const libc::sockaddr_ll).cast(), std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Arp { sock, index, mac })
    }

    fn addr(index: i32) -> libc::sockaddr_ll {
        // SAFETY: sockaddr_ll is plain data; all-zero is valid, then filled in.
        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = ETH_P_ARP.to_be();
        sll.sll_ifindex = index;
        sll.sll_halen = 6;
        sll.sll_addr[..6].copy_from_slice(&BROADCAST);
        sll
    }

    fn send(&self, frame: &[u8; FRAME]) {
        let to = Self::addr(self.index);
        // SAFETY: sending a buffer we own to a valid sockaddr_ll. A request
        // that is not sent is one less guess, so the result is not needed.
        unsafe {
            libc::sendto(
                self.sock.as_raw_fd(),
                frame.as_ptr().cast(),
                frame.len(),
                0,
                (&to as *const libc::sockaddr_ll).cast(),
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
    }

    /// The replies that come in the next `wait`.
    fn replies(&self, wait: Duration) -> Vec<[u8; 4]> {
        let deadline = Instant::now() + wait;
        let mut found = Vec::new();
        let mut buf = [0u8; 256];
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return found;
            }
            let mut pfd = libc::pollfd { fd: self.sock.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            // SAFETY: one valid pollfd.
            unsafe { libc::poll(&mut pfd, 1, left.as_millis().max(1) as libc::c_int) };
            loop {
                // SAFETY: receiving into a buffer we own.
                let n = unsafe { libc::recv(self.sock.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
                if n <= 0 {
                    break;
                }
                if let Some((ip, mac)) = parse_reply(&buf[..n as usize])
                    && mac != self.mac
                {
                    found.push(ip);
                }
            }
        }
    }

    /// The Mac's address on the NAT network: the first candidate that
    /// answers ARP.
    pub fn find_gateway(&self) -> Option<[u8; 4]> {
        for g in gateway_candidates() {
            self.send(&request_frame(self.mac, [0; 4], g));
        }
        let answered = self.replies(GATEWAY_WAIT);
        gateway_candidates().find(|g| answered.contains(g))
    }

    /// An address in the gateway's network that nothing answers for.
    pub fn free_address(&self, gateway: [u8; 4]) -> Option<[u8; 4]> {
        let candidates = own_candidates(self.mac, gateway);
        for c in &candidates {
            self.send(&request_frame(self.mac, [0; 4], *c));
        }
        let taken = self.replies(ADDRESS_WAIT);
        candidates.into_iter().find(|c| !taken.contains(c))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_is_a_broadcast_who_has() {
        let f = request_frame([2, 0, 0, 0, 0, 9], [0; 4], [192, 168, 64, 1]);
        assert_eq!(&f[0..6], &[0xff; 6]);
        assert_eq!(&f[6..12], &[2, 0, 0, 0, 0, 9]);
        assert_eq!(&f[12..14], &[0x08, 0x06]);
        assert_eq!(&f[20..22], &[0, 1]);
        assert_eq!(&f[38..42], &[192, 168, 64, 1]);
        assert_eq!(f.len(), 42);
    }

    #[test]
    fn replies_give_the_sender() {
        let mut f = request_frame([2, 0, 0, 0, 0, 9], [0; 4], [192, 168, 64, 1]);
        // A request is not a reply.
        assert_eq!(parse_reply(&f), None);
        f[20..22].copy_from_slice(&2u16.to_be_bytes());
        f[22..28].copy_from_slice(&[0x86, 0x2f, 0x57, 0x93, 0x7d, 0x64]);
        f[28..32].copy_from_slice(&[192, 168, 64, 1]);
        assert_eq!(parse_reply(&f), Some(([192, 168, 64, 1], [0x86, 0x2f, 0x57, 0x93, 0x7d, 0x64])));
        assert_eq!(parse_reply(&f[..30]), None);
    }

    #[test]
    fn gateways_are_asked_default_first_and_all_once() {
        let all: Vec<_> = gateway_candidates().collect();
        assert_eq!(all[0], [192, 168, 64, 1]);
        assert_eq!(all[1], [192, 168, 65, 1]);
        assert_eq!(all.len(), 256);
        assert_eq!(all.iter().collect::<std::collections::HashSet<_>>().len(), 256);
        assert!(all.contains(&[192, 168, 0, 1]) && all.contains(&[192, 168, 255, 1]));
    }

    #[test]
    fn own_addresses_stay_in_the_gateways_network_and_never_its_own() {
        for mac in [[0; 6], [0, 0, 0, 0, 0, 1], [0xbe, 0x05, 0xf6, 0xc6, 0xa6, 0xb0], [0xff; 6]] {
            for gateway in [[192, 168, 64, 1], [192, 168, 100, 2], [192, 168, 7, 254]] {
                let c = own_candidates(mac, gateway);
                assert_eq!(c.len(), 4, "{mac:?} {gateway:?}");
                for a in &c {
                    assert_eq!(&a[..3], &gateway[..3]);
                    assert!((2..=254).contains(&a[3]) && a[3] != gateway[3], "{a:?}");
                }
                assert_eq!(c.iter().collect::<std::collections::HashSet<_>>().len(), 4);
            }
        }
        assert_ne!(own_candidates([0, 0, 0, 0, 0, 1], [192, 168, 64, 1])[0], own_candidates([0, 0, 0, 0, 0, 2], [192, 168, 64, 1])[0]);
    }
}
