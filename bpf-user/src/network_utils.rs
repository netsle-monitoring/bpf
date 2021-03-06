use std::net::Ipv4Addr;
// An IP is being represented as a unsigned 32.
// In order to decode it back to it's original form we
// will need to take each 8 bytes out of the 32 and convert
// them back to an unsigned 8 (their original form in the address).
pub fn u32_to_ipv4(rawip: u32) -> Ipv4Addr {
    let d = (rawip >> 24) as u8;
    let c = (rawip >> 16) as u8;
    let b = (rawip >> 8) as u8;
    let a = rawip as u8;

    Ipv4Addr::new(a, b, c, d)
}

pub fn ipv4_to_u32(ip: Vec<u8>) -> u32 {
    let mut d = (ip[3] as u32) << 24;
    d += (ip[2] as u32) << 16;
    d += (ip[1] as u32) << 8;
    d += ip[0] as u32;

    d
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn should_convert_ip_correctly() {
        assert_eq!("10.0.0.28", u32_to_ipv4(469762058).to_string())
    }
}
