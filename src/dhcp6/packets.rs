// SPDX-License-Identifier: MIT
// Copyright(c) 2026 Masakazu Asama

use std::net::Ipv6Addr;

const HW_TYPE_ETHERNET: u16 = 1;
const OPT_HDR_LEN: usize = 4;

// DUID: Unknown type
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnknownDuid {
    pub duid: Vec<u8>,
}

impl UnknownDuid {
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < self.duid.len() {
            return Err(format!("Too short buffer"));
        }
        buf[0..self.duid.len()].copy_from_slice(&self.duid);
        Ok(self.duid.len())
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let duid = Vec::<u8>::from(bytes);
        Ok(Self { duid: duid })
    }
}

// DUID: Link-layer address plus time
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LltDuid {
    pub time: u32,
    pub ll_addr: [u8; 6],
}

impl LltDuid {
    const DUID_TYPE: u16 = 1;
    const FIXED_LEN: usize = 14;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0..2].copy_from_slice(&Self::DUID_TYPE.to_be_bytes());
        buf[2..4].copy_from_slice(&HW_TYPE_ETHERNET.to_be_bytes());
        buf[4..8].copy_from_slice(&self.time.to_be_bytes());
        buf[8..14].copy_from_slice(&self.ll_addr);
        Ok(Self::FIXED_LEN)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short duid"));
        }
        let duid_type = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        if duid_type != Self::DUID_TYPE {
            return Err(format!("Invalid duid type"));
        }
        let hw_type = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
        if hw_type != HW_TYPE_ETHERNET {
            return Err(format!("Invalid hardware type"));
        }
        let time = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        let ll_addr = bytes[8..14].try_into().unwrap();
        Ok(Self {
            time: time,
            ll_addr: ll_addr,
        })
    }
}

// DUID: Vendor-assigned unique ID based on Enterprise Number
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VendorDuid {
    pub enterprise_num: u32,
    pub identifier: Vec<u8>,
}

impl VendorDuid {
    const DUID_TYPE: u16 = 2;
    const FIXED_LEN: usize = 6;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN + self.identifier.len() {
            return Err(format!("Too short buffer"));
        }
        buf[0..2].copy_from_slice(&Self::DUID_TYPE.to_be_bytes());
        buf[2..6].copy_from_slice(&self.enterprise_num.to_be_bytes());
        buf[6..6 + self.identifier.len()].copy_from_slice(&self.identifier);
        Ok(Self::FIXED_LEN + self.identifier.len())
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short duid"));
        }
        let duid_type = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        if duid_type != Self::DUID_TYPE {
            return Err(format!("Invalid duid type"));
        }
        let enterprise_num = u32::from_be_bytes(bytes[2..6].try_into().unwrap());
        let identifier = Vec::<u8>::from(&bytes[6..]);
        Ok(Self {
            enterprise_num: enterprise_num,
            identifier: identifier,
        })
    }
}

// DUID: Link-layer address
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LlDuid {
    pub ll_addr: [u8; 6],
}

impl LlDuid {
    const DUID_TYPE: u16 = 3;
    const FIXED_LEN: usize = 10;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0..2].copy_from_slice(&Self::DUID_TYPE.to_be_bytes());
        buf[2..4].copy_from_slice(&HW_TYPE_ETHERNET.to_be_bytes());
        buf[4..10].copy_from_slice(&self.ll_addr);
        Ok(Self::FIXED_LEN)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short duid"));
        }
        let duid_type = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        if duid_type != Self::DUID_TYPE {
            return Err(format!("Invalid duid type"));
        }
        let hw_type = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
        if hw_type != HW_TYPE_ETHERNET {
            return Err(format!("Invalid hardware type"));
        }
        let ll_addr = bytes[4..10].try_into().unwrap();
        Ok(Self { ll_addr: ll_addr })
    }
}

// DUID: Universally Unique Identifier (UUID)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UuidDuid {
    pub uuid: [u8; 16],
}

impl UuidDuid {
    const DUID_TYPE: u16 = 4;
    const FIXED_LEN: usize = 18;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0..2].copy_from_slice(&Self::DUID_TYPE.to_be_bytes());
        buf[2..18].copy_from_slice(&self.uuid);
        Ok(Self::FIXED_LEN)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short duid"));
        }
        let duid_type = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        if duid_type != Self::DUID_TYPE {
            return Err(format!("Invalid duid type"));
        }
        let uuid = bytes[2..18].try_into().unwrap();
        Ok(Self { uuid: uuid })
    }
}

// DHCP Unique Identifier (DUID)
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Duid {
    Unknown(UnknownDuid),
    Llt(LltDuid),
    Vendor(VendorDuid),
    Ll(LlDuid),
    Uuid(UuidDuid),
}

impl Duid {
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        match self {
            Duid::Unknown(duid) => duid.serialize(buf),
            Duid::Llt(duid) => duid.serialize(buf),
            Duid::Vendor(duid) => duid.serialize(buf),
            Duid::Ll(duid) => duid.serialize(buf),
            Duid::Uuid(duid) => duid.serialize(buf),
        }
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 4 {
            return Err(format!("Too short duid"));
        }
        let duid_type = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        let hw_type = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
        match (duid_type, hw_type) {
            (LltDuid::DUID_TYPE, HW_TYPE_ETHERNET) => Ok(Duid::Llt(LltDuid::parse(bytes)?)),
            (VendorDuid::DUID_TYPE, _) => Ok(Duid::Vendor(VendorDuid::parse(bytes)?)),
            (LlDuid::DUID_TYPE, HW_TYPE_ETHERNET) => Ok(Duid::Ll(LlDuid::parse(bytes)?)),
            (UuidDuid::DUID_TYPE, _) => Ok(Duid::Uuid(UuidDuid::parse(bytes)?)),
            _ => Ok(Duid::Unknown(UnknownDuid::parse(bytes)?)),
        }
    }
}

// UnknownOpt
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnknownOpt {
    pub opt_code: u16,
    pub opt_data: Vec<u8>,
}

impl UnknownOpt {
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        let opt_buf_len = OPT_HDR_LEN + self.opt_data.len();
        if buf.len() < opt_buf_len {
            return Err(format!("Too short buffer"));
        }
        buf[0..2].copy_from_slice(&self.opt_code.to_be_bytes());
        let opt_len = self.opt_data.len();
        if opt_len > u16::MAX.into() {
            return Err(format!("option length overflow"));
        }
        let opt_len = opt_len as u16;
        buf[2..4].copy_from_slice(&opt_len.to_be_bytes());
        buf[4..opt_buf_len].copy_from_slice(&self.opt_data);
        Ok(opt_buf_len)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < OPT_HDR_LEN {
            return Err(format!("Too short option"));
        }
        let opt_code = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        let opt_len = u16::from_be_bytes(bytes[2..4].try_into().unwrap()) as usize;
        let opt_bytes_len = OPT_HDR_LEN + opt_len;
        if bytes.len() != opt_bytes_len {
            return Err(format!("Too short option"));
        }
        let opt_data = Vec::<u8>::from(&bytes[4..opt_bytes_len]);
        Ok(Self {
            opt_code: opt_code,
            opt_data: opt_data,
        })
    }
}

// Client Identifier Option
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientIdOpt {
    pub duid: Duid,
}

impl ClientIdOpt {
    const OPT_CODE: u16 = 1;
    const FIXED_LEN: usize = 4;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0..2].copy_from_slice(&Self::OPT_CODE.to_be_bytes());
        let duid_len = self.duid.serialize(&mut buf[4..])?;
        if duid_len > u16::MAX.into() {
            return Err(format!("duid length overflow"));
        }
        let opt_len = duid_len as u16;
        buf[2..4].copy_from_slice(&opt_len.to_be_bytes());
        Ok(Self::FIXED_LEN + duid_len)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short option"));
        }
        let opt_code = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        if opt_code != Self::OPT_CODE {
            return Err(format!("Invalid option code"));
        }
        let opt_len = u16::from_be_bytes(bytes[2..4].try_into().unwrap()) as usize;
        let opt_bytes_len = OPT_HDR_LEN + opt_len;
        if bytes.len() != opt_bytes_len {
            return Err(format!("Invalid option length"));
        }
        let duid = Duid::parse(&bytes[4..opt_bytes_len])?;
        Ok(Self { duid: duid })
    }
}

// Server Identifier Option
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerIdOpt {
    pub duid: Duid,
}

impl ServerIdOpt {
    const OPT_CODE: u16 = 2;
    const FIXED_LEN: usize = 4;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0..2].copy_from_slice(&Self::OPT_CODE.to_be_bytes());
        let duid_len = self.duid.serialize(&mut buf[4..])?;
        if duid_len > u16::MAX.into() {
            return Err(format!("duid length overflow"));
        }
        let opt_len = duid_len as u16;
        buf[2..4].copy_from_slice(&opt_len.to_be_bytes());
        Ok(Self::FIXED_LEN + duid_len)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short option"));
        }
        let opt_code = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        if opt_code != Self::OPT_CODE {
            return Err(format!("Invalid option code"));
        }
        let opt_len = u16::from_be_bytes(bytes[2..4].try_into().unwrap()) as usize;
        let opt_bytes_len = OPT_HDR_LEN + opt_len;
        if bytes.len() != opt_bytes_len {
            return Err(format!("Invalid option length"));
        }
        let duid = Duid::parse(&bytes[4..opt_bytes_len])?;
        Ok(Self { duid: duid })
    }
}

// Identity Association for Non-temporary Addresses Option
// (non-singleton)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IaNaOpt {
    pub iaid: [u8; 4],
    pub t1: u32,
    pub t2: u32,
    pub ia_addrs: Vec<IaAddrOpt>,
    pub status_code: Option<StatusCodeOpt>,
    pub unknown_opts: Vec<Dhcp6Opt>,
}

impl IaNaOpt {
    const OPT_CODE: u16 = 3;
    const FIXED_LEN: usize = 16;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0..2].copy_from_slice(&Self::OPT_CODE.to_be_bytes());
        buf[4..8].copy_from_slice(&self.iaid);
        buf[8..12].copy_from_slice(&self.t1.to_be_bytes());
        buf[12..16].copy_from_slice(&self.t2.to_be_bytes());
        let mut pos = Self::FIXED_LEN;
        for ia_addr in &self.ia_addrs {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += ia_addr.serialize(&mut buf[pos..])?;
        }
        if let Some(status_code) = &self.status_code {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += status_code.serialize(&mut buf[pos..])?;
        }
        for unknown_opt in &self.unknown_opts {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += unknown_opt.serialize(&mut buf[pos..])?;
        }
        let opt_len = pos - OPT_HDR_LEN;
        if opt_len > u16::MAX.into() {
            return Err(format!("Option length overflow"));
        }
        let opt_len = opt_len as u16;
        buf[2..4].copy_from_slice(&opt_len.to_be_bytes());
        Ok(pos)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short option"));
        }
        let opt_code = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        if opt_code != Self::OPT_CODE {
            return Err(format!("Invalid option code"));
        }
        let opt_len = u16::from_be_bytes(bytes[2..4].try_into().unwrap()) as usize;
        if bytes.len() != OPT_HDR_LEN + opt_len {
            return Err(format!("Invalid option length"));
        }
        let iaid = bytes[4..8].try_into().unwrap();
        let t1 = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
        let t2 = u32::from_be_bytes(bytes[12..16].try_into().unwrap());
        let mut ia_addrs = Vec::<IaAddrOpt>::new();
        let mut status_code: Option<StatusCodeOpt> = None;
        let mut unknown_opts = Vec::<Dhcp6Opt>::new();
        let mut pos = Self::FIXED_LEN;
        while pos < bytes.len() {
            if bytes.len() < pos + OPT_HDR_LEN {
                return Err(format!("Too short option"));
            }
            let subopt_type_bytes = &bytes[pos..pos + 2];
            let subopt_type = u16::from_be_bytes(subopt_type_bytes.try_into().unwrap());
            let subopt_len_bytes = &bytes[pos + 2..pos + 4];
            let subopt_len = u16::from_be_bytes(subopt_len_bytes.try_into().unwrap()) as usize;
            let subopt_bytes_len = OPT_HDR_LEN + subopt_len;
            if bytes.len() < pos + subopt_bytes_len {
                return Err(format!("Too short option"));
            }
            let subopt_bytes = &bytes[pos..pos + subopt_bytes_len];
            match subopt_type {
                IaAddrOpt::OPT_CODE => {
                    ia_addrs.push(IaAddrOpt::parse(subopt_bytes)?);
                }
                StatusCodeOpt::OPT_CODE => {
                    status_code = Some(StatusCodeOpt::parse(subopt_bytes)?);
                }
                _ => {
                    unknown_opts.push(Dhcp6Opt::parse(subopt_bytes)?);
                }
            }
            pos += subopt_bytes_len;
        }
        if pos != bytes.len() {
            return Err(format!("Invalid option length"));
        }
        Ok(Self {
            iaid: iaid,
            t1: t1,
            t2: t2,
            ia_addrs: ia_addrs,
            status_code: status_code,
            unknown_opts: unknown_opts,
        })
    }
}

// IA Address Option
// (non-singleton)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IaAddrOpt {
    pub ipv6_addr: Ipv6Addr,
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
    pub unknown_opts: Vec<Dhcp6Opt>,
}

impl IaAddrOpt {
    const OPT_CODE: u16 = 5;
    const FIXED_LEN: usize = 28;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0..2].copy_from_slice(&Self::OPT_CODE.to_be_bytes());
        buf[4..20].copy_from_slice(&self.ipv6_addr.octets());
        buf[20..24].copy_from_slice(&self.preferred_lifetime.to_be_bytes());
        buf[24..28].copy_from_slice(&self.valid_lifetime.to_be_bytes());
        let mut pos = Self::FIXED_LEN;
        for unknown_opt in &self.unknown_opts {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += unknown_opt.serialize(&mut buf[pos..])?;
        }
        let opt_len = pos - OPT_HDR_LEN;
        if opt_len > u16::MAX.into() {
            return Err(format!("Option length overflow"));
        }
        let opt_len = opt_len as u16;
        buf[2..4].copy_from_slice(&opt_len.to_be_bytes());
        Ok(pos)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short option"));
        }
        let opt_code = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        if opt_code != Self::OPT_CODE {
            return Err(format!("Invalid option code"));
        }
        let opt_len = u16::from_be_bytes(bytes[2..4].try_into().unwrap()) as usize;
        if bytes.len() != OPT_HDR_LEN + opt_len {
            return Err(format!("Invalid option length"));
        }
        let ipv6_addr: [u8; 16] = bytes[4..20].try_into().unwrap();
        let ipv6_addr = Ipv6Addr::from_octets(ipv6_addr);
        let preferred_lifetime = u32::from_be_bytes(bytes[20..24].try_into().unwrap());
        let valid_lifetime = u32::from_be_bytes(bytes[24..28].try_into().unwrap());
        let mut unknown_opts = Vec::<Dhcp6Opt>::new();
        let mut pos = Self::FIXED_LEN;
        while pos < bytes.len() {
            if bytes.len() < pos + OPT_HDR_LEN {
                return Err(format!("Too short option"));
            }
            let subopt_type_bytes = &bytes[pos..pos + 2];
            let subopt_type = u16::from_be_bytes(subopt_type_bytes.try_into().unwrap());
            let subopt_len_bytes = &bytes[pos + 2..pos + 4];
            let subopt_len = u16::from_be_bytes(subopt_len_bytes.try_into().unwrap()) as usize;
            let subopt_bytes_len = OPT_HDR_LEN + subopt_len;
            if bytes.len() < pos + subopt_bytes_len {
                return Err(format!("Too short option"));
            }
            let subopt_bytes = &bytes[pos..pos + subopt_bytes_len];
            match subopt_type {
                _ => {
                    unknown_opts.push(Dhcp6Opt::parse(subopt_bytes)?);
                }
            }
            pos += subopt_bytes_len;
        }
        if pos != bytes.len() {
            return Err(format!("Invalid option length"));
        }
        Ok(Self {
            ipv6_addr: ipv6_addr,
            preferred_lifetime: preferred_lifetime,
            valid_lifetime: valid_lifetime,
            unknown_opts: unknown_opts,
        })
    }
}

// Option Request Option
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OptReqOpt {
    pub requested_opt_codes: Vec<u16>,
}

impl OptReqOpt {
    const OPT_CODE: u16 = 6;
    const FIXED_LEN: usize = 4;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0..2].copy_from_slice(&Self::OPT_CODE.to_be_bytes());
        let mut pos = Self::FIXED_LEN;
        for requested_opt_code in &self.requested_opt_codes {
            if buf.len() < pos + 2 {
                return Err(format!("Too short buffer"));
            }
            buf[pos..pos + 2].copy_from_slice(&requested_opt_code.to_be_bytes());
            pos += 2;
        }
        let opt_len = pos - OPT_HDR_LEN;
        if opt_len > u16::MAX.into() {
            return Err(format!("Option length overflow"));
        }
        let opt_len = opt_len as u16;
        buf[2..4].copy_from_slice(&opt_len.to_be_bytes());
        Ok(pos)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short option"));
        }
        let opt_code = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        if opt_code != Self::OPT_CODE {
            return Err(format!("Invalid option code"));
        }
        let opt_len = u16::from_be_bytes(bytes[2..4].try_into().unwrap()) as usize;
        if bytes.len() != OPT_HDR_LEN + opt_len {
            return Err(format!("Invalid option length"));
        }
        let mut requested_opt_codes = Vec::<u16>::new();
        let mut pos = Self::FIXED_LEN;
        while pos < bytes.len() {
            if bytes.len() < pos + 2 {
                return Err(format!("Too short option"));
            }
            let requested_opt_code = &bytes[pos..pos + 2];
            let requested_opt_code = u16::from_be_bytes(requested_opt_code.try_into().unwrap());
            requested_opt_codes.push(requested_opt_code);
            pos += 2;
        }
        if pos != bytes.len() {
            return Err(format!("Invalid option length"));
        }
        Ok(Self {
            requested_opt_codes: requested_opt_codes,
        })
    }
}

// Preference Option
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrefOpt {
    pub pref_value: u8,
}

impl PrefOpt {
    const OPT_CODE: u16 = 7;
    const FIXED_LEN: usize = 5;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        let opt_len = (Self::FIXED_LEN - OPT_HDR_LEN) as u16;
        buf[0..2].copy_from_slice(&Self::OPT_CODE.to_be_bytes());
        buf[2..4].copy_from_slice(&opt_len.to_be_bytes());
        buf[4] = self.pref_value;
        Ok(Self::FIXED_LEN)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != Self::FIXED_LEN {
            return Err(format!("Invalid option length"));
        }
        let opt_code = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        if opt_code != Self::OPT_CODE {
            return Err(format!("Invalid option code"));
        }
        let opt_len = u16::from_be_bytes(bytes[2..4].try_into().unwrap()) as usize;
        if opt_len != Self::FIXED_LEN - OPT_HDR_LEN {
            return Err(format!("Invalid option length"));
        }
        let pref_value = bytes[4];
        Ok(Self {
            pref_value: pref_value,
        })
    }
}

// Elapsed Time Option
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElapsedTimeOpt {
    pub elapsed_time: u16,
}

impl ElapsedTimeOpt {
    const OPT_CODE: u16 = 8;
    const FIXED_LEN: usize = 6;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        let opt_len = (Self::FIXED_LEN - OPT_HDR_LEN) as u16;
        buf[0..2].copy_from_slice(&Self::OPT_CODE.to_be_bytes());
        buf[2..4].copy_from_slice(&opt_len.to_be_bytes());
        buf[4..6].copy_from_slice(&self.elapsed_time.to_be_bytes());
        Ok(Self::FIXED_LEN)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != Self::FIXED_LEN {
            return Err(format!("Invalid option length"));
        }
        let opt_code = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        if opt_code != Self::OPT_CODE {
            return Err(format!("Invalid option code"));
        }
        let opt_len = u16::from_be_bytes(bytes[2..4].try_into().unwrap()) as usize;
        if opt_len != Self::FIXED_LEN - OPT_HDR_LEN {
            return Err(format!("Invalid option length"));
        }
        let elapsed_time = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
        Ok(Self {
            elapsed_time: elapsed_time,
        })
    }
}

// Relay Message Option
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayMsgOpt {
    pub dhcp_relay_msg: Vec<u8>,
}

impl RelayMsgOpt {
    const OPT_CODE: u16 = 9;
    const FIXED_LEN: usize = 4;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        let opt_buf_len = Self::FIXED_LEN + self.dhcp_relay_msg.len();
        if buf.len() < opt_buf_len {
            return Err(format!("Too short buffer"));
        }
        let opt_len = opt_buf_len - OPT_HDR_LEN;
        if opt_len > u16::MAX.into() {
            return Err(format!("Option length overflow"));
        }
        let opt_len = opt_len as u16;
        buf[0..2].copy_from_slice(&Self::OPT_CODE.to_be_bytes());
        buf[2..4].copy_from_slice(&opt_len.to_be_bytes());
        buf[4..4 + self.dhcp_relay_msg.len()].copy_from_slice(&self.dhcp_relay_msg);
        Ok(opt_buf_len)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short option"));
        }
        let opt_code = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        if opt_code != Self::OPT_CODE {
            return Err(format!("Invalid option code"));
        }
        let opt_len = u16::from_be_bytes(bytes[2..4].try_into().unwrap()) as usize;
        if bytes.len() != OPT_HDR_LEN + opt_len {
            return Err(format!("Invalid option length"));
        }
        let dhcp_relay_msg = Vec::<u8>::from(&bytes[4..]);
        Ok(Self {
            dhcp_relay_msg: dhcp_relay_msg,
        })
    }
}

// Authentication Option
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthOpt {
    pub protocol: u8,
    pub algorithm: u8,
    pub rdm: u8,
    pub replay_detection: u64,
    pub auth_info: Vec<u8>,
}

impl AuthOpt {
    const OPT_CODE: u16 = 11;
    const FIXED_LEN: usize = 15;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        let opt_buf_len = Self::FIXED_LEN + self.auth_info.len();
        if buf.len() < opt_buf_len {
            return Err(format!("Too short buffer"));
        }
        let opt_len = opt_buf_len - OPT_HDR_LEN;
        if opt_len > u16::MAX.into() {
            return Err(format!("Option length overflow"));
        }
        let opt_len = opt_len as u16;
        buf[0..2].copy_from_slice(&Self::OPT_CODE.to_be_bytes());
        buf[2..4].copy_from_slice(&opt_len.to_be_bytes());
        buf[4] = self.protocol;
        buf[5] = self.algorithm;
        buf[6] = self.rdm;
        buf[7..15].copy_from_slice(&self.replay_detection.to_be_bytes());
        buf[15..15 + self.auth_info.len()].copy_from_slice(&self.auth_info);
        Ok(opt_buf_len)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short option"));
        }
        let opt_code = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        if opt_code != Self::OPT_CODE {
            return Err(format!("Invalid option code"));
        }
        let opt_len = u16::from_be_bytes(bytes[2..4].try_into().unwrap()) as usize;
        if bytes.len() != OPT_HDR_LEN + opt_len {
            return Err(format!("Invalid option length"));
        }
        let protocol = bytes[4];
        let algorithm = bytes[5];
        let rdm = bytes[6];
        let replay_detection = u64::from_be_bytes(bytes[7..15].try_into().unwrap());
        let auth_info = Vec::<u8>::from(&bytes[15..]);
        Ok(Self {
            protocol: protocol,
            algorithm: algorithm,
            rdm: rdm,
            replay_detection: replay_detection,
            auth_info: auth_info,
        })
    }
}

// Server Unicast Option
// (obsolete)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerUcastOpt {
    pub server_addr: Ipv6Addr,
}

impl ServerUcastOpt {
    const OPT_CODE: u16 = 12;
    const FIXED_LEN: usize = 20;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        let opt_len = (Self::FIXED_LEN - OPT_HDR_LEN) as u16;
        buf[0..2].copy_from_slice(&Self::OPT_CODE.to_be_bytes());
        buf[2..4].copy_from_slice(&opt_len.to_be_bytes());
        buf[4..20].copy_from_slice(&self.server_addr.octets());
        Ok(Self::FIXED_LEN)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != Self::FIXED_LEN {
            return Err(format!("Too short option"));
        }
        let opt_code = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        if opt_code != Self::OPT_CODE {
            return Err(format!("Invalid option code"));
        }
        let opt_len = u16::from_be_bytes(bytes[2..4].try_into().unwrap()) as usize;
        if opt_len != Self::FIXED_LEN - OPT_HDR_LEN {
            return Err(format!("Invalid option length"));
        }
        let server_addr: [u8; 16] = bytes[4..20].try_into().unwrap();
        let server_addr = Ipv6Addr::from_octets(server_addr);
        Ok(Self {
            server_addr: server_addr,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StatusCode {
    Unknown(u16),
    Success,
    UnspecFail,
    NoAddrsAvail,
    NoBinding,
    NotOnLink,
    UseMulticast,
    NoPrefixAvail,
}

impl From<u16> for StatusCode {
    fn from(status_code: u16) -> Self {
        match status_code {
            0 => StatusCode::Success,
            1 => StatusCode::UnspecFail,
            2 => StatusCode::NoAddrsAvail,
            3 => StatusCode::NoBinding,
            4 => StatusCode::NotOnLink,
            5 => StatusCode::UseMulticast,
            6 => StatusCode::NoPrefixAvail,
            _ => StatusCode::Unknown(status_code),
        }
    }
}

impl Into<u16> for StatusCode {
    fn into(self) -> u16 {
        match self {
            StatusCode::Success => 0,
            StatusCode::UnspecFail => 1,
            StatusCode::NoAddrsAvail => 2,
            StatusCode::NoBinding => 3,
            StatusCode::NotOnLink => 4,
            StatusCode::UseMulticast => 5,
            StatusCode::NoPrefixAvail => 6,
            StatusCode::Unknown(status_code) => status_code,
        }
    }
}

// Status Code Option
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusCodeOpt {
    pub status_code: StatusCode,
    pub status_msg: String,
}

impl StatusCodeOpt {
    const OPT_CODE: u16 = 13;
    const FIXED_LEN: usize = 6;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        let opt_buf_len = Self::FIXED_LEN + self.status_msg.len();
        if buf.len() < opt_buf_len {
            return Err(format!("Too short buffer"));
        }
        let opt_len = opt_buf_len - OPT_HDR_LEN;
        if opt_len > u16::MAX.into() {
            return Err(format!("Option length overflow"));
        }
        let opt_len = opt_len as u16;
        let status_code = Into::<u16>::into(self.status_code.clone());
        buf[0..2].copy_from_slice(&Self::OPT_CODE.to_be_bytes());
        buf[2..4].copy_from_slice(&opt_len.to_be_bytes());
        buf[4..6].copy_from_slice(&status_code.to_be_bytes());
        buf[6..6 + self.status_msg.len()].copy_from_slice(self.status_msg.as_bytes());
        Ok(opt_buf_len)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short option"));
        }
        let opt_code = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        if opt_code != Self::OPT_CODE {
            return Err(format!("Invalid option code"));
        }
        let opt_len = u16::from_be_bytes(bytes[2..4].try_into().unwrap()) as usize;
        if bytes.len() != OPT_HDR_LEN + opt_len {
            return Err(format!("Invalid option length"));
        }
        let status_code = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
        let status_code = StatusCode::from(status_code);
        let status_msg = String::from_utf8_lossy(&bytes[6..]);
        let status_msg = String::from(status_msg);
        Ok(Self {
            status_code: status_code,
            status_msg: status_msg,
        })
    }
}

// Rapid Commit Option
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RapidCommitOpt {}

impl RapidCommitOpt {
    const OPT_CODE: u16 = 14;
    const FIXED_LEN: usize = 4;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        let opt_len = (Self::FIXED_LEN - OPT_HDR_LEN) as u16;
        buf[0..2].copy_from_slice(&Self::OPT_CODE.to_be_bytes());
        buf[2..4].copy_from_slice(&opt_len.to_be_bytes());
        Ok(Self::FIXED_LEN)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != Self::FIXED_LEN {
            return Err(format!("Too short option"));
        }
        let opt_code = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        if opt_code != Self::OPT_CODE {
            return Err(format!("Invalid option code"));
        }
        let opt_len = u16::from_be_bytes(bytes[2..4].try_into().unwrap()) as usize;
        if opt_len != Self::FIXED_LEN - OPT_HDR_LEN {
            return Err(format!("Invalid option length"));
        }
        Ok(Self {})
    }
}

// User Class Option
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserClassOpt {
    pub user_class_data: Vec<u8>,
}

impl UserClassOpt {
    const OPT_CODE: u16 = 15;
    const FIXED_LEN: usize = 4;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        let opt_buf_len = Self::FIXED_LEN + self.user_class_data.len();
        if buf.len() < opt_buf_len {
            return Err(format!("Too short buffer"));
        }
        let opt_len = opt_buf_len - OPT_HDR_LEN;
        if opt_len > u16::MAX.into() {
            return Err(format!("Option length overflow"));
        }
        let opt_len = opt_len as u16;
        buf[0..2].copy_from_slice(&Self::OPT_CODE.to_be_bytes());
        buf[2..4].copy_from_slice(&opt_len.to_be_bytes());
        buf[4..4 + self.user_class_data.len()].copy_from_slice(&self.user_class_data);
        Ok(opt_buf_len)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short option"));
        }
        let opt_code = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        if opt_code != Self::OPT_CODE {
            return Err(format!("Invalid option code"));
        }
        let opt_len = u16::from_be_bytes(bytes[2..4].try_into().unwrap()) as usize;
        if bytes.len() != OPT_HDR_LEN + opt_len {
            return Err(format!("Invalid option length"));
        }
        let user_class_data = Vec::<u8>::from(&bytes[4..]);
        Ok(Self {
            user_class_data: user_class_data,
        })
    }
}

// Vendor Class Option
// (non-singleton)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VendorClassOpt {
    pub enterprise_num: u32,
    pub vendor_class_data: Vec<u8>,
}

impl VendorClassOpt {
    const OPT_CODE: u16 = 16;
    const FIXED_LEN: usize = 8;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        let opt_buf_len = Self::FIXED_LEN + self.vendor_class_data.len();
        if buf.len() < opt_buf_len {
            return Err(format!("Too short buffer"));
        }
        let opt_len = opt_buf_len - OPT_HDR_LEN;
        if opt_len > u16::MAX.into() {
            return Err(format!("Option length overflow"));
        }
        let opt_len = opt_len as u16;
        buf[0..2].copy_from_slice(&Self::OPT_CODE.to_be_bytes());
        buf[2..4].copy_from_slice(&opt_len.to_be_bytes());
        buf[4..8].copy_from_slice(&self.enterprise_num.to_be_bytes());
        buf[8..8 + self.vendor_class_data.len()].copy_from_slice(&self.vendor_class_data);
        Ok(opt_buf_len)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short option"));
        }
        let opt_code = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        if opt_code != Self::OPT_CODE {
            return Err(format!("Invalid option code"));
        }
        let opt_len = u16::from_be_bytes(bytes[2..4].try_into().unwrap()) as usize;
        if bytes.len() != OPT_HDR_LEN + opt_len {
            return Err(format!("Invalid option length"));
        }
        let enterprise_num = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        let vendor_class_data = Vec::<u8>::from(&bytes[8..]);
        Ok(Self {
            enterprise_num: enterprise_num,
            vendor_class_data: vendor_class_data,
        })
    }
}

// Vendor-specific Information Option
// (non-singleton)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VendorInfoOpt {
    pub enterprise_num: u32,
    pub vendor_option_data: Vec<u8>,
}

impl VendorInfoOpt {
    const OPT_CODE: u16 = 17;
    const FIXED_LEN: usize = 8;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        let opt_buf_len = Self::FIXED_LEN + self.vendor_option_data.len();
        if buf.len() < opt_buf_len {
            return Err(format!("Too short buffer"));
        }
        let opt_len = opt_buf_len - OPT_HDR_LEN;
        if opt_len > u16::MAX.into() {
            return Err(format!("Option length overflow"));
        }
        let opt_len = opt_len as u16;
        buf[0..2].copy_from_slice(&Self::OPT_CODE.to_be_bytes());
        buf[2..4].copy_from_slice(&opt_len.to_be_bytes());
        buf[4..8].copy_from_slice(&self.enterprise_num.to_be_bytes());
        buf[8..8 + self.vendor_option_data.len()].copy_from_slice(&self.vendor_option_data);
        Ok(opt_buf_len)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short option"));
        }
        let opt_code = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        if opt_code != Self::OPT_CODE {
            return Err(format!("Invalid option code"));
        }
        let opt_len = u16::from_be_bytes(bytes[2..4].try_into().unwrap()) as usize;
        if bytes.len() != OPT_HDR_LEN + opt_len {
            return Err(format!("Invalid option length"));
        }
        let enterprise_num = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        let vendor_option_data = Vec::<u8>::from(&bytes[8..]);
        Ok(Self {
            enterprise_num: enterprise_num,
            vendor_option_data: vendor_option_data,
        })
    }
}

// Interface-Id Option
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceIdOpt {
    pub interface_id: Vec<u8>,
}

impl InterfaceIdOpt {
    const OPT_CODE: u16 = 18;
    const FIXED_LEN: usize = 4;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        let opt_buf_len = Self::FIXED_LEN + self.interface_id.len();
        if buf.len() < opt_buf_len {
            return Err(format!("Too short buffer"));
        }
        let opt_len = opt_buf_len - OPT_HDR_LEN;
        if opt_len > u16::MAX.into() {
            return Err(format!("Option length overflow"));
        }
        let opt_len = opt_len as u16;
        buf[0..2].copy_from_slice(&Self::OPT_CODE.to_be_bytes());
        buf[2..4].copy_from_slice(&opt_len.to_be_bytes());
        buf[4..4 + self.interface_id.len()].copy_from_slice(&self.interface_id);
        Ok(opt_buf_len)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short option"));
        }
        let opt_code = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        if opt_code != Self::OPT_CODE {
            return Err(format!("Invalid option code"));
        }
        let opt_len = u16::from_be_bytes(bytes[2..4].try_into().unwrap()) as usize;
        if bytes.len() != OPT_HDR_LEN + opt_len {
            return Err(format!("Invalid option length"));
        }
        let interface_id = Vec::<u8>::from(&bytes[4..]);
        Ok(Self {
            interface_id: interface_id,
        })
    }
}

// Reconfigure Message Option
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconfMsgOpt {
    pub msg_type: u8,
}

impl ReconfMsgOpt {
    const OPT_CODE: u16 = 19;
    const FIXED_LEN: usize = 5;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        let opt_len = (Self::FIXED_LEN - OPT_HDR_LEN) as u16;
        buf[0..2].copy_from_slice(&Self::OPT_CODE.to_be_bytes());
        buf[2..4].copy_from_slice(&opt_len.to_be_bytes());
        buf[4] = self.msg_type;
        Ok(Self::FIXED_LEN)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != Self::FIXED_LEN {
            return Err(format!("Too short option"));
        }
        let opt_code = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        if opt_code != Self::OPT_CODE {
            return Err(format!("Invalid option code"));
        }
        let opt_len = u16::from_be_bytes(bytes[2..4].try_into().unwrap()) as usize;
        if opt_len != Self::FIXED_LEN - OPT_HDR_LEN {
            return Err(format!("Invalid option length"));
        }
        let msg_type = bytes[4];
        Ok(Self { msg_type: msg_type })
    }
}

// Reconfigure Accept Option
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconfAcceptOpt {}

impl ReconfAcceptOpt {
    const OPT_CODE: u16 = 20;
    const FIXED_LEN: usize = 4;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        let opt_len = (Self::FIXED_LEN - OPT_HDR_LEN) as u16;
        buf[0..2].copy_from_slice(&Self::OPT_CODE.to_be_bytes());
        buf[2..4].copy_from_slice(&opt_len.to_be_bytes());
        Ok(Self::FIXED_LEN)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != Self::FIXED_LEN {
            return Err(format!("Too short option"));
        }
        let opt_code = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        if opt_code != Self::OPT_CODE {
            return Err(format!("Invalid option code"));
        }
        let opt_len = u16::from_be_bytes(bytes[2..4].try_into().unwrap()) as usize;
        if opt_len != Self::FIXED_LEN - OPT_HDR_LEN {
            return Err(format!("Invalid option length"));
        }
        Ok(Self {})
    }
}

// DNS Recursive Name Server option
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsRecursiveNameServerOpt {
    pub dns_recursive_name_servers: Vec<Ipv6Addr>,
}

impl DnsRecursiveNameServerOpt {
    pub const OPT_CODE: u16 = 23;
    const FIXED_LEN: usize = 4;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0..2].copy_from_slice(&Self::OPT_CODE.to_be_bytes());
        let mut pos = Self::FIXED_LEN;
        for dns_recursive_name_server in &self.dns_recursive_name_servers {
            if buf.len() < pos + 16 {
                return Err(format!("Too short buffer"));
            }
            buf[pos..pos + 16].copy_from_slice(&dns_recursive_name_server.octets());
            pos += 16;
        }
        let opt_len = pos - OPT_HDR_LEN;
        if opt_len > u16::MAX.into() {
            return Err(format!("Option length overflow"));
        }
        let opt_len = opt_len as u16;
        buf[2..4].copy_from_slice(&opt_len.to_be_bytes());
        Ok(pos)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short option"));
        }
        let opt_code = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        if opt_code != Self::OPT_CODE {
            return Err(format!("Invalid option code"));
        }
        let opt_len = u16::from_be_bytes(bytes[2..4].try_into().unwrap()) as usize;
        if bytes.len() != OPT_HDR_LEN + opt_len {
            return Err(format!("Invalid option length"));
        }
        let mut dns_recursive_name_servers = Vec::<Ipv6Addr>::new();
        let mut pos = Self::FIXED_LEN;
        while pos < bytes.len() {
            if bytes.len() < pos + 16 {
                return Err(format!("Too short option"));
            }
            let dns_recursive_name_server: [u8; 16] = bytes[pos..pos + 16].try_into().unwrap();
            let dns_recursive_name_server = Ipv6Addr::from_octets(dns_recursive_name_server);
            dns_recursive_name_servers.push(dns_recursive_name_server);
            pos += 16;
        }
        if pos != bytes.len() {
            return Err(format!("Invalid option length"));
        }
        Ok(Self {
            dns_recursive_name_servers: dns_recursive_name_servers,
        })
    }
}

// Domain Search List option
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainSearchListOpt {
    pub searchs: Vec<String>,
}

impl DomainSearchListOpt {
    const OPT_CODE: u16 = 24;
    const FIXED_LEN: usize = 4;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0..2].copy_from_slice(&Self::OPT_CODE.to_be_bytes());
        let mut pos = Self::FIXED_LEN;
        for search in &self.searchs {
            if buf.len() < pos + search.len() {
                return Err(format!("Too short buffer"));
            }
            for label in search.split('.') {
                if label.len() > u8::MAX.into() {
                    return Err(format!("Invalid label length"));
                }
                buf[pos] = label.len() as u8;
                pos += 1;
                if buf.len() < pos + label.len() {
                    return Err(format!("Too short buffer"));
                }
                buf[pos..pos + label.len()].copy_from_slice(&label.as_bytes());
                pos += label.len();
            }
            buf[pos] = 0u8;
            pos += 1;
        }
        let opt_len = pos - OPT_HDR_LEN;
        if opt_len > u16::MAX.into() {
            return Err(format!("Option length overflow"));
        }
        let opt_len = opt_len as u16;
        buf[2..4].copy_from_slice(&opt_len.to_be_bytes());
        Ok(pos)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short option"));
        }
        let opt_code = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        if opt_code != Self::OPT_CODE {
            return Err(format!("Invalid option code"));
        }
        let opt_len = u16::from_be_bytes(bytes[2..4].try_into().unwrap()) as usize;
        if bytes.len() != OPT_HDR_LEN + opt_len {
            return Err(format!("Invalid option length"));
        }
        let mut searchs = Vec::<String>::new();
        let mut labels = Vec::<String>::new();
        let mut pos = Self::FIXED_LEN;
        while pos < bytes.len() {
            if bytes.len() < pos + 1 {
                return Err(format!("Too short option"));
            }
            let label_len = bytes[pos] as usize;
            pos += 1;
            if label_len == 0 {
                searchs.push(labels.join("."));
                labels = Vec::<String>::new();
            } else {
                match std::str::from_utf8(&bytes[pos..pos + label_len]) {
                    Ok(label) => labels.push(label.to_string()),
                    Err(_) => return Err(format!("Inavlid label")),
                }
                pos += label_len;
            }
        }
        if pos != bytes.len() {
            return Err(format!("Invalid option length"));
        }
        Ok(Self { searchs: searchs })
    }
}

// Identity Association for Prefix Delegation Option
// (non-singleton)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IaPdOpt {
    pub iaid: [u8; 4],
    pub t1: u32,
    pub t2: u32,
    pub ia_prefixes: Vec<IaPrefixOpt>,
    pub status_code: Option<StatusCodeOpt>,
    pub unknown_opts: Vec<Dhcp6Opt>,
}

impl IaPdOpt {
    const OPT_CODE: u16 = 25;
    const FIXED_LEN: usize = 16;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0..2].copy_from_slice(&Self::OPT_CODE.to_be_bytes());
        buf[4..8].copy_from_slice(&self.iaid);
        buf[8..12].copy_from_slice(&self.t1.to_be_bytes());
        buf[12..16].copy_from_slice(&self.t2.to_be_bytes());
        let mut pos = Self::FIXED_LEN;
        for ia_prefix in &self.ia_prefixes {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += ia_prefix.serialize(&mut buf[pos..])?;
        }
        if let Some(status_code) = &self.status_code {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += status_code.serialize(&mut buf[pos..])?;
        }
        for unknown_opt in &self.unknown_opts {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += unknown_opt.serialize(&mut buf[pos..])?;
        }
        let opt_len = pos - OPT_HDR_LEN;
        if opt_len > u16::MAX.into() {
            return Err(format!("Option length overflow"));
        }
        let opt_len = opt_len as u16;
        buf[2..4].copy_from_slice(&opt_len.to_be_bytes());
        Ok(pos)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short option"));
        }
        let opt_code = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        if opt_code != Self::OPT_CODE {
            return Err(format!("Invalid option code"));
        }
        let opt_len = u16::from_be_bytes(bytes[2..4].try_into().unwrap()) as usize;
        if bytes.len() != OPT_HDR_LEN + opt_len {
            return Err(format!("Invalid option length"));
        }
        let iaid = bytes[4..8].try_into().unwrap();
        let t1 = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
        let t2 = u32::from_be_bytes(bytes[12..16].try_into().unwrap());
        let mut ia_prefixes = Vec::<IaPrefixOpt>::new();
        let mut status_code: Option<StatusCodeOpt> = None;
        let mut unknown_opts = Vec::<Dhcp6Opt>::new();
        let mut pos = Self::FIXED_LEN;
        while pos < bytes.len() {
            if bytes.len() < pos + OPT_HDR_LEN {
                return Err(format!("Too short option"));
            }
            let subopt_type_bytes = &bytes[pos..pos + 2];
            let subopt_type = u16::from_be_bytes(subopt_type_bytes.try_into().unwrap());
            let subopt_len_bytes = &bytes[pos + 2..pos + 4];
            let subopt_len = u16::from_be_bytes(subopt_len_bytes.try_into().unwrap()) as usize;
            let subopt_bytes_len = OPT_HDR_LEN + subopt_len;
            if bytes.len() < pos + subopt_bytes_len {
                return Err(format!("Too short option"));
            }
            let subopt_bytes = &bytes[pos..pos + subopt_bytes_len];
            match subopt_type {
                IaPrefixOpt::OPT_CODE => {
                    ia_prefixes.push(IaPrefixOpt::parse(subopt_bytes)?);
                }
                StatusCodeOpt::OPT_CODE => {
                    status_code = Some(StatusCodeOpt::parse(subopt_bytes)?);
                }
                _ => {
                    unknown_opts.push(Dhcp6Opt::parse(subopt_bytes)?);
                }
            }
            pos += subopt_bytes_len;
        }
        if pos != bytes.len() {
            return Err(format!("Invalid option length"));
        }
        Ok(Self {
            iaid: iaid,
            t1: t1,
            t2: t2,
            ia_prefixes: ia_prefixes,
            status_code: status_code,
            unknown_opts: unknown_opts,
        })
    }
}

// IA Prefix Option
// (non-singleton)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IaPrefixOpt {
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
    pub prefix_len: u8,
    pub ipv6_prefix: Ipv6Addr,
    pub unknown_opts: Vec<Dhcp6Opt>,
}

impl IaPrefixOpt {
    const OPT_CODE: u16 = 26;
    const FIXED_LEN: usize = 29;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0..2].copy_from_slice(&Self::OPT_CODE.to_be_bytes());
        buf[4..8].copy_from_slice(&self.preferred_lifetime.to_be_bytes());
        buf[8..12].copy_from_slice(&self.valid_lifetime.to_be_bytes());
        buf[12] = self.prefix_len;
        buf[13..29].copy_from_slice(&self.ipv6_prefix.octets());
        let mut pos = Self::FIXED_LEN;
        for unknown_opt in &self.unknown_opts {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += unknown_opt.serialize(&mut buf[pos..])?;
        }
        let opt_len = pos - OPT_HDR_LEN;
        if opt_len > u16::MAX.into() {
            return Err(format!("Option length overflow"));
        }
        let opt_len = opt_len as u16;
        buf[2..4].copy_from_slice(&opt_len.to_be_bytes());
        Ok(pos)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short option"));
        }
        let opt_code = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        if opt_code != Self::OPT_CODE {
            return Err(format!("Invalid option code"));
        }
        let opt_len = u16::from_be_bytes(bytes[2..4].try_into().unwrap()) as usize;
        if bytes.len() != OPT_HDR_LEN + opt_len {
            return Err(format!("Invalid option length"));
        }
        let preferred_lifetime = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        let valid_lifetime = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
        let prefix_len = bytes[12];
        let ipv6_prefix: [u8; 16] = bytes[13..29].try_into().unwrap();
        let ipv6_prefix = Ipv6Addr::from_octets(ipv6_prefix);
        let mut unknown_opts = Vec::<Dhcp6Opt>::new();
        let mut pos = Self::FIXED_LEN;
        while pos < bytes.len() {
            if bytes.len() < pos + OPT_HDR_LEN {
                return Err(format!("Too short option"));
            }
            let subopt_type_bytes = &bytes[pos..pos + 2];
            let subopt_type = u16::from_be_bytes(subopt_type_bytes.try_into().unwrap());
            let subopt_len_bytes = &bytes[pos + 2..pos + 4];
            let subopt_len = u16::from_be_bytes(subopt_len_bytes.try_into().unwrap()) as usize;
            let subopt_bytes_len = OPT_HDR_LEN + subopt_len;
            if bytes.len() < pos + subopt_bytes_len {
                return Err(format!("Too short option"));
            }
            let subopt_bytes = &bytes[pos..pos + subopt_bytes_len];
            match subopt_type {
                _ => {
                    unknown_opts.push(Dhcp6Opt::parse(subopt_bytes)?);
                }
            }
            pos += subopt_bytes_len;
        }
        if pos != bytes.len() {
            return Err(format!("Invalid option length"));
        }
        Ok(Self {
            preferred_lifetime: preferred_lifetime,
            valid_lifetime: valid_lifetime,
            prefix_len: prefix_len,
            ipv6_prefix: ipv6_prefix,
            unknown_opts: unknown_opts,
        })
    }
}

// Information Refresh Time Option
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InfoRefreshTimeOpt {
    pub information_refresh_time: u32,
}

impl InfoRefreshTimeOpt {
    const OPT_CODE: u16 = 32;
    const FIXED_LEN: usize = 8;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        let opt_len = (Self::FIXED_LEN - OPT_HDR_LEN) as u16;
        buf[0..2].copy_from_slice(&Self::OPT_CODE.to_be_bytes());
        buf[2..4].copy_from_slice(&opt_len.to_be_bytes());
        buf[4..8].copy_from_slice(&self.information_refresh_time.to_be_bytes());
        Ok(Self::FIXED_LEN)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != Self::FIXED_LEN {
            return Err(format!("Too short option"));
        }
        let opt_code = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        if opt_code != Self::OPT_CODE {
            return Err(format!("Invalid option code"));
        }
        let opt_len = u16::from_be_bytes(bytes[2..4].try_into().unwrap()) as usize;
        if opt_len != Self::FIXED_LEN - OPT_HDR_LEN {
            return Err(format!("Invalid option length"));
        }
        let information_refresh_time = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        Ok(Self {
            information_refresh_time: information_refresh_time,
        })
    }
}

// SOL_MAX_RT Option
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SolMaxRtOpt {
    pub sol_max_rt_val: u32,
}

impl SolMaxRtOpt {
    const OPT_CODE: u16 = 82;
    const FIXED_LEN: usize = 8;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        let opt_len = (Self::FIXED_LEN - OPT_HDR_LEN) as u16;
        buf[0..2].copy_from_slice(&Self::OPT_CODE.to_be_bytes());
        buf[2..4].copy_from_slice(&opt_len.to_be_bytes());
        buf[4..8].copy_from_slice(&self.sol_max_rt_val.to_be_bytes());
        Ok(Self::FIXED_LEN)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != Self::FIXED_LEN {
            return Err(format!("Too short option"));
        }
        let opt_code = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        if opt_code != Self::OPT_CODE {
            return Err(format!("Invalid option code"));
        }
        let opt_len = u16::from_be_bytes(bytes[2..4].try_into().unwrap()) as usize;
        if opt_len != Self::FIXED_LEN - OPT_HDR_LEN {
            return Err(format!("Invalid option length"));
        }
        let sol_max_rt_val = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        Ok(Self {
            sol_max_rt_val: sol_max_rt_val,
        })
    }
}

// INF_MAX_RT Option
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InfMaxRtOpt {
    pub inf_max_rt_val: u32,
}

impl InfMaxRtOpt {
    const OPT_CODE: u16 = 83;
    const FIXED_LEN: usize = 8;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        let opt_len = (Self::FIXED_LEN - OPT_HDR_LEN) as u16;
        buf[0..2].copy_from_slice(&Self::OPT_CODE.to_be_bytes());
        buf[2..4].copy_from_slice(&opt_len.to_be_bytes());
        buf[4..8].copy_from_slice(&self.inf_max_rt_val.to_be_bytes());
        Ok(Self::FIXED_LEN)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short option"));
        }
        let opt_code = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        if opt_code != Self::OPT_CODE {
            return Err(format!("Invalid option code"));
        }
        let opt_len = u16::from_be_bytes(bytes[2..4].try_into().unwrap()) as usize;
        if opt_len != Self::FIXED_LEN - OPT_HDR_LEN {
            return Err(format!("Invalid option length"));
        }
        let inf_max_rt_val = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        Ok(Self {
            inf_max_rt_val: inf_max_rt_val,
        })
    }
}

// Dhcp6Opt
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Dhcp6Opt {
    Unknown(UnknownOpt),
    ClientId(ClientIdOpt),
    ServerId(ServerIdOpt),
    IaNa(IaNaOpt),
    IaAddr(IaAddrOpt),
    OptReq(OptReqOpt),
    Pref(PrefOpt),
    ElapsedTime(ElapsedTimeOpt),
    RelayMsg(RelayMsgOpt),
    Auth(AuthOpt),
    ServerUcast(ServerUcastOpt),
    StatusCode(StatusCodeOpt),
    RapidCommit(RapidCommitOpt),
    UserClass(UserClassOpt),
    VendorClass(VendorClassOpt),
    VendorInfo(VendorInfoOpt),
    InterfaceId(InterfaceIdOpt),
    ReconfMsg(ReconfMsgOpt),
    ReconfAccept(ReconfAcceptOpt),
    DnsRecursiveNameServer(DnsRecursiveNameServerOpt),
    DomainSearchList(DomainSearchListOpt),
    IaPd(IaPdOpt),
    IaPrefix(IaPrefixOpt),
    InfoRefreshTime(InfoRefreshTimeOpt),
    SolMaxRt(SolMaxRtOpt),
    InfMaxRt(InfMaxRtOpt),
}

impl Dhcp6Opt {
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        match self {
            Dhcp6Opt::Unknown(opt) => opt.serialize(buf),
            Dhcp6Opt::ClientId(opt) => opt.serialize(buf),
            Dhcp6Opt::ServerId(opt) => opt.serialize(buf),
            Dhcp6Opt::IaNa(opt) => opt.serialize(buf),
            Dhcp6Opt::IaAddr(opt) => opt.serialize(buf),
            Dhcp6Opt::OptReq(opt) => opt.serialize(buf),
            Dhcp6Opt::Pref(opt) => opt.serialize(buf),
            Dhcp6Opt::ElapsedTime(opt) => opt.serialize(buf),
            Dhcp6Opt::RelayMsg(opt) => opt.serialize(buf),
            Dhcp6Opt::Auth(opt) => opt.serialize(buf),
            Dhcp6Opt::ServerUcast(opt) => opt.serialize(buf),
            Dhcp6Opt::StatusCode(opt) => opt.serialize(buf),
            Dhcp6Opt::RapidCommit(opt) => opt.serialize(buf),
            Dhcp6Opt::UserClass(opt) => opt.serialize(buf),
            Dhcp6Opt::VendorClass(opt) => opt.serialize(buf),
            Dhcp6Opt::VendorInfo(opt) => opt.serialize(buf),
            Dhcp6Opt::InterfaceId(opt) => opt.serialize(buf),
            Dhcp6Opt::ReconfMsg(opt) => opt.serialize(buf),
            Dhcp6Opt::ReconfAccept(opt) => opt.serialize(buf),
            Dhcp6Opt::DnsRecursiveNameServer(opt) => opt.serialize(buf),
            Dhcp6Opt::DomainSearchList(opt) => opt.serialize(buf),
            Dhcp6Opt::IaPd(opt) => opt.serialize(buf),
            Dhcp6Opt::IaPrefix(opt) => opt.serialize(buf),
            Dhcp6Opt::InfoRefreshTime(opt) => opt.serialize(buf),
            Dhcp6Opt::SolMaxRt(opt) => opt.serialize(buf),
            Dhcp6Opt::InfMaxRt(opt) => opt.serialize(buf),
        }
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 4 {
            return Err(format!("Too short duid"));
        }
        let opt_code = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        match opt_code {
            ClientIdOpt::OPT_CODE => Ok(Dhcp6Opt::ClientId(ClientIdOpt::parse(bytes)?)),
            ServerIdOpt::OPT_CODE => Ok(Dhcp6Opt::ServerId(ServerIdOpt::parse(bytes)?)),
            IaNaOpt::OPT_CODE => Ok(Dhcp6Opt::IaNa(IaNaOpt::parse(bytes)?)),
            IaAddrOpt::OPT_CODE => Ok(Dhcp6Opt::IaAddr(IaAddrOpt::parse(bytes)?)),
            OptReqOpt::OPT_CODE => Ok(Dhcp6Opt::OptReq(OptReqOpt::parse(bytes)?)),
            PrefOpt::OPT_CODE => Ok(Dhcp6Opt::Pref(PrefOpt::parse(bytes)?)),
            ElapsedTimeOpt::OPT_CODE => Ok(Dhcp6Opt::ElapsedTime(ElapsedTimeOpt::parse(bytes)?)),
            RelayMsgOpt::OPT_CODE => Ok(Dhcp6Opt::RelayMsg(RelayMsgOpt::parse(bytes)?)),
            AuthOpt::OPT_CODE => Ok(Dhcp6Opt::Auth(AuthOpt::parse(bytes)?)),
            ServerUcastOpt::OPT_CODE => Ok(Dhcp6Opt::ServerUcast(ServerUcastOpt::parse(bytes)?)),
            StatusCodeOpt::OPT_CODE => Ok(Dhcp6Opt::StatusCode(StatusCodeOpt::parse(bytes)?)),
            RapidCommitOpt::OPT_CODE => Ok(Dhcp6Opt::RapidCommit(RapidCommitOpt::parse(bytes)?)),
            UserClassOpt::OPT_CODE => Ok(Dhcp6Opt::UserClass(UserClassOpt::parse(bytes)?)),
            VendorClassOpt::OPT_CODE => Ok(Dhcp6Opt::VendorClass(VendorClassOpt::parse(bytes)?)),
            VendorInfoOpt::OPT_CODE => Ok(Dhcp6Opt::VendorInfo(VendorInfoOpt::parse(bytes)?)),
            InterfaceIdOpt::OPT_CODE => Ok(Dhcp6Opt::InterfaceId(InterfaceIdOpt::parse(bytes)?)),
            ReconfMsgOpt::OPT_CODE => Ok(Dhcp6Opt::ReconfMsg(ReconfMsgOpt::parse(bytes)?)),
            ReconfAcceptOpt::OPT_CODE => Ok(Dhcp6Opt::ReconfAccept(ReconfAcceptOpt::parse(bytes)?)),
            DnsRecursiveNameServerOpt::OPT_CODE => Ok(Dhcp6Opt::DnsRecursiveNameServer(
                DnsRecursiveNameServerOpt::parse(bytes)?,
            )),
            DomainSearchListOpt::OPT_CODE => Ok(Dhcp6Opt::DomainSearchList(
                DomainSearchListOpt::parse(bytes)?,
            )),
            IaPdOpt::OPT_CODE => Ok(Dhcp6Opt::IaPd(IaPdOpt::parse(bytes)?)),
            IaPrefixOpt::OPT_CODE => Ok(Dhcp6Opt::IaPrefix(IaPrefixOpt::parse(bytes)?)),
            InfoRefreshTimeOpt::OPT_CODE => {
                Ok(Dhcp6Opt::InfoRefreshTime(InfoRefreshTimeOpt::parse(bytes)?))
            }
            SolMaxRtOpt::OPT_CODE => Ok(Dhcp6Opt::SolMaxRt(SolMaxRtOpt::parse(bytes)?)),
            InfMaxRtOpt::OPT_CODE => Ok(Dhcp6Opt::InfMaxRt(InfMaxRtOpt::parse(bytes)?)),
            _ => Ok(Dhcp6Opt::Unknown(UnknownOpt::parse(bytes)?)),
        }
    }
}

// Solicit Message
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SolicitMsg {
    pub transaction_id: u32,
    pub client_id: Option<ClientIdOpt>,
    pub ia_nas: Vec<IaNaOpt>,
    pub ia_pds: Vec<IaPdOpt>,
    pub opt_req: Option<OptReqOpt>,
    pub elapsed_time: Option<ElapsedTimeOpt>,
    pub rapid_commit: Option<RapidCommitOpt>,
    pub user_class: Option<UserClassOpt>,
    pub vendor_classes: Vec<VendorClassOpt>,
    pub vendor_infos: Vec<VendorInfoOpt>,
    pub reconf_accept: Option<ReconfAcceptOpt>,
    pub unknown_opts: Vec<Dhcp6Opt>,
}

impl SolicitMsg {
    const MSG_TYPE: u8 = 1;
    const FIXED_LEN: usize = 4;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0..4].copy_from_slice(&self.transaction_id.to_be_bytes());
        buf[0] = Self::MSG_TYPE; // Type
        let mut pos = Self::FIXED_LEN;
        if let Some(client_id) = &self.client_id {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += client_id.serialize(&mut buf[pos..])?;
        }
        for ia_na in &self.ia_nas {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += ia_na.serialize(&mut buf[pos..])?;
        }
        for ia_pd in &self.ia_pds {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += ia_pd.serialize(&mut buf[pos..])?;
        }
        if let Some(opt_req) = &self.opt_req {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += opt_req.serialize(&mut buf[pos..])?;
        }
        if let Some(elapsed_time) = &self.elapsed_time {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += elapsed_time.serialize(&mut buf[pos..])?;
        }
        if let Some(rapid_commit) = &self.rapid_commit {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += rapid_commit.serialize(&mut buf[pos..])?;
        }
        if let Some(user_class) = &self.user_class {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += user_class.serialize(&mut buf[pos..])?;
        }
        for vendor_class in &self.vendor_classes {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += vendor_class.serialize(&mut buf[pos..])?;
        }
        for vendor_info in &self.vendor_infos {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += vendor_info.serialize(&mut buf[pos..])?;
        }
        if let Some(reconf_accept) = &self.reconf_accept {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += reconf_accept.serialize(&mut buf[pos..])?;
        }
        for unknown_opt in &self.unknown_opts {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += unknown_opt.serialize(&mut buf[pos..])?;
        }
        Ok(pos)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short message"));
        }
        let msg_type = bytes[0];
        if msg_type != Self::MSG_TYPE {
            return Err(format!("Invalid message type"));
        }
        let mut tidbuf = [0u8; 4];
        tidbuf[1..4].copy_from_slice(&bytes[1..4]);
        let transaction_id = u32::from_be_bytes(tidbuf);
        let mut client_id: Option<ClientIdOpt> = None;
        let mut ia_nas = Vec::<IaNaOpt>::new();
        let mut ia_pds = Vec::<IaPdOpt>::new();
        let mut opt_req: Option<OptReqOpt> = None;
        let mut elapsed_time: Option<ElapsedTimeOpt> = None;
        let mut rapid_commit: Option<RapidCommitOpt> = None;
        let mut user_class: Option<UserClassOpt> = None;
        let mut vendor_classes = Vec::<VendorClassOpt>::new();
        let mut vendor_infos = Vec::<VendorInfoOpt>::new();
        let mut reconf_accept: Option<ReconfAcceptOpt> = None;
        let mut unknown_opts = Vec::<Dhcp6Opt>::new();
        let mut pos = Self::FIXED_LEN;
        while pos < bytes.len() {
            if bytes.len() < pos + OPT_HDR_LEN {
                return Err(format!("Too short option"));
            }
            let opt_type = u16::from_be_bytes(bytes[pos..pos + 2].try_into().unwrap());
            let opt_len = u16::from_be_bytes(bytes[pos + 2..pos + 4].try_into().unwrap()) as usize;
            let opt_bytes_len = OPT_HDR_LEN + opt_len;
            if bytes.len() < pos + opt_bytes_len {
                return Err(format!("Too short option"));
            }
            let opt_bytes = &bytes[pos..pos + opt_bytes_len];
            match opt_type {
                ClientIdOpt::OPT_CODE => {
                    client_id = Some(ClientIdOpt::parse(opt_bytes)?);
                }
                IaNaOpt::OPT_CODE => {
                    ia_nas.push(IaNaOpt::parse(opt_bytes)?);
                }
                IaPdOpt::OPT_CODE => {
                    ia_pds.push(IaPdOpt::parse(opt_bytes)?);
                }
                OptReqOpt::OPT_CODE => {
                    opt_req = Some(OptReqOpt::parse(opt_bytes)?);
                }
                ElapsedTimeOpt::OPT_CODE => {
                    elapsed_time = Some(ElapsedTimeOpt::parse(opt_bytes)?);
                }
                RapidCommitOpt::OPT_CODE => {
                    rapid_commit = Some(RapidCommitOpt::parse(opt_bytes)?);
                }
                UserClassOpt::OPT_CODE => {
                    user_class = Some(UserClassOpt::parse(opt_bytes)?);
                }
                VendorClassOpt::OPT_CODE => {
                    vendor_classes.push(VendorClassOpt::parse(opt_bytes)?);
                }
                VendorInfoOpt::OPT_CODE => {
                    vendor_infos.push(VendorInfoOpt::parse(opt_bytes)?);
                }
                ReconfAcceptOpt::OPT_CODE => {
                    reconf_accept = Some(ReconfAcceptOpt::parse(opt_bytes)?);
                }
                _ => {
                    unknown_opts.push(Dhcp6Opt::parse(opt_bytes)?);
                }
            }
            pos += opt_bytes_len;
        }
        if pos != bytes.len() {
            return Err(format!("Invalid option length"));
        }
        Ok(Self {
            transaction_id: transaction_id,
            client_id: client_id,
            ia_nas: ia_nas,
            ia_pds: ia_pds,
            opt_req: opt_req,
            elapsed_time: elapsed_time,
            rapid_commit: rapid_commit,
            user_class: user_class,
            vendor_classes: vendor_classes,
            vendor_infos: vendor_infos,
            reconf_accept: reconf_accept,
            unknown_opts: unknown_opts,
        })
    }
}

// Advertise Message
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdvertiseMsg {
    pub transaction_id: u32,
    pub client_id: Option<ClientIdOpt>,
    pub server_id: Option<ServerIdOpt>,
    pub ia_nas: Vec<IaNaOpt>,
    pub ia_pds: Vec<IaPdOpt>,
    pub pref: Option<PrefOpt>,
    pub status_code: Option<StatusCodeOpt>,
    pub user_class: Option<UserClassOpt>,
    pub vendor_classes: Vec<VendorClassOpt>,
    pub vendor_infos: Vec<VendorInfoOpt>,
    pub reconf_accept: Option<ReconfAcceptOpt>,
    pub sol_max_rt: Option<SolMaxRtOpt>,
    pub unknown_opts: Vec<Dhcp6Opt>,
}

impl AdvertiseMsg {
    const MSG_TYPE: u8 = 2;
    const FIXED_LEN: usize = 4;

    #[allow(unused)]
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0..4].copy_from_slice(&self.transaction_id.to_be_bytes());
        buf[0] = Self::MSG_TYPE; // Type
        let mut pos = Self::FIXED_LEN;
        if let Some(client_id) = &self.client_id {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += client_id.serialize(&mut buf[pos..])?;
        }
        if let Some(server_id) = &self.server_id {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += server_id.serialize(&mut buf[pos..])?;
        }
        for ia_na in &self.ia_nas {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += ia_na.serialize(&mut buf[pos..])?;
        }
        for ia_pd in &self.ia_pds {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += ia_pd.serialize(&mut buf[pos..])?;
        }
        if let Some(pref) = &self.pref {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += pref.serialize(&mut buf[pos..])?;
        }
        if let Some(status_code) = &self.status_code {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += status_code.serialize(&mut buf[pos..])?;
        }
        if let Some(user_class) = &self.user_class {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += user_class.serialize(&mut buf[pos..])?;
        }
        for vendor_class in &self.vendor_classes {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += vendor_class.serialize(&mut buf[pos..])?;
        }
        for vendor_info in &self.vendor_infos {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += vendor_info.serialize(&mut buf[pos..])?;
        }
        if let Some(reconf_accept) = &self.reconf_accept {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += reconf_accept.serialize(&mut buf[pos..])?;
        }
        if let Some(sol_max_rt) = &self.sol_max_rt {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += sol_max_rt.serialize(&mut buf[pos..])?;
        }
        for unknown_opt in &self.unknown_opts {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += unknown_opt.serialize(&mut buf[pos..])?;
        }
        Ok(pos)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short message"));
        }
        let msg_type = bytes[0];
        if msg_type != Self::MSG_TYPE {
            return Err(format!("Invalid message type"));
        }
        let mut tidbuf = [0u8; 4];
        tidbuf[1..4].copy_from_slice(&bytes[1..4]);
        let transaction_id = u32::from_be_bytes(tidbuf);
        let mut client_id: Option<ClientIdOpt> = None;
        let mut server_id: Option<ServerIdOpt> = None;
        let mut ia_nas = Vec::<IaNaOpt>::new();
        let mut ia_pds = Vec::<IaPdOpt>::new();
        let mut pref: Option<PrefOpt> = None;
        let mut status_code: Option<StatusCodeOpt> = None;
        let mut user_class: Option<UserClassOpt> = None;
        let mut vendor_classes = Vec::<VendorClassOpt>::new();
        let mut vendor_infos = Vec::<VendorInfoOpt>::new();
        let mut reconf_accept: Option<ReconfAcceptOpt> = None;
        let mut sol_max_rt: Option<SolMaxRtOpt> = None;
        let mut unknown_opts = Vec::<Dhcp6Opt>::new();
        let mut pos = Self::FIXED_LEN;
        while pos < bytes.len() {
            if bytes.len() < pos + OPT_HDR_LEN {
                return Err(format!("Too short option"));
            }
            let opt_type = u16::from_be_bytes(bytes[pos..pos + 2].try_into().unwrap());
            let opt_len = u16::from_be_bytes(bytes[pos + 2..pos + 4].try_into().unwrap()) as usize;
            let opt_bytes_len = OPT_HDR_LEN + opt_len;
            if bytes.len() < pos + opt_bytes_len {
                return Err(format!("Too short option"));
            }
            let opt_bytes = &bytes[pos..pos + opt_bytes_len];
            match opt_type {
                ClientIdOpt::OPT_CODE => {
                    client_id = Some(ClientIdOpt::parse(opt_bytes)?);
                }
                ServerIdOpt::OPT_CODE => {
                    server_id = Some(ServerIdOpt::parse(opt_bytes)?);
                }
                IaNaOpt::OPT_CODE => {
                    ia_nas.push(IaNaOpt::parse(opt_bytes)?);
                }
                IaPdOpt::OPT_CODE => {
                    ia_pds.push(IaPdOpt::parse(opt_bytes)?);
                }
                PrefOpt::OPT_CODE => {
                    pref = Some(PrefOpt::parse(opt_bytes)?);
                }
                StatusCodeOpt::OPT_CODE => {
                    status_code = Some(StatusCodeOpt::parse(opt_bytes)?);
                }
                UserClassOpt::OPT_CODE => {
                    user_class = Some(UserClassOpt::parse(opt_bytes)?);
                }
                VendorClassOpt::OPT_CODE => {
                    vendor_classes.push(VendorClassOpt::parse(opt_bytes)?);
                }
                VendorInfoOpt::OPT_CODE => {
                    vendor_infos.push(VendorInfoOpt::parse(opt_bytes)?);
                }
                ReconfAcceptOpt::OPT_CODE => {
                    reconf_accept = Some(ReconfAcceptOpt::parse(opt_bytes)?);
                }
                SolMaxRtOpt::OPT_CODE => {
                    sol_max_rt = Some(SolMaxRtOpt::parse(opt_bytes)?);
                }
                _ => {
                    unknown_opts.push(Dhcp6Opt::parse(opt_bytes)?);
                }
            }
            pos += opt_bytes_len;
        }
        if pos != bytes.len() {
            return Err(format!("Invalid option length"));
        }
        Ok(Self {
            transaction_id: transaction_id,
            client_id: client_id,
            server_id: server_id,
            ia_nas: ia_nas,
            ia_pds: ia_pds,
            pref: pref,
            status_code: status_code,
            user_class: user_class,
            vendor_classes: vendor_classes,
            vendor_infos: vendor_infos,
            reconf_accept: reconf_accept,
            sol_max_rt: sol_max_rt,
            unknown_opts: unknown_opts,
        })
    }
}

// Request Message
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestMsg {
    pub transaction_id: u32,
    pub client_id: Option<ClientIdOpt>,
    pub server_id: Option<ServerIdOpt>,
    pub ia_nas: Vec<IaNaOpt>,
    pub ia_pds: Vec<IaPdOpt>,
    pub opt_req: Option<OptReqOpt>,
    pub elapsed_time: Option<ElapsedTimeOpt>,
    pub user_class: Option<UserClassOpt>,
    pub vendor_classes: Vec<VendorClassOpt>,
    pub vendor_infos: Vec<VendorInfoOpt>,
    pub reconf_accept: Option<ReconfAcceptOpt>,
    pub unknown_opts: Vec<Dhcp6Opt>,
}

impl RequestMsg {
    const MSG_TYPE: u8 = 3;
    const FIXED_LEN: usize = 4;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0..4].copy_from_slice(&self.transaction_id.to_be_bytes());
        buf[0] = Self::MSG_TYPE; // Type
        let mut pos = Self::FIXED_LEN;
        if let Some(client_id) = &self.client_id {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += client_id.serialize(&mut buf[pos..])?;
        }
        if let Some(server_id) = &self.server_id {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += server_id.serialize(&mut buf[pos..])?;
        }
        for ia_na in &self.ia_nas {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += ia_na.serialize(&mut buf[pos..])?;
        }
        for ia_pd in &self.ia_pds {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += ia_pd.serialize(&mut buf[pos..])?;
        }
        if let Some(opt_req) = &self.opt_req {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += opt_req.serialize(&mut buf[pos..])?;
        }
        if let Some(elapsed_time) = &self.elapsed_time {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += elapsed_time.serialize(&mut buf[pos..])?;
        }
        if let Some(user_class) = &self.user_class {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += user_class.serialize(&mut buf[pos..])?;
        }
        for vendor_class in &self.vendor_classes {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += vendor_class.serialize(&mut buf[pos..])?;
        }
        for vendor_info in &self.vendor_infos {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += vendor_info.serialize(&mut buf[pos..])?;
        }
        if let Some(reconf_accept) = &self.reconf_accept {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += reconf_accept.serialize(&mut buf[pos..])?;
        }
        for unknown_opt in &self.unknown_opts {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += unknown_opt.serialize(&mut buf[pos..])?;
        }
        Ok(pos)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short message"));
        }
        let msg_type = bytes[0];
        if msg_type != Self::MSG_TYPE {
            return Err(format!("Invalid message type"));
        }
        let mut tidbuf = [0u8; 4];
        tidbuf[1..4].copy_from_slice(&bytes[1..4]);
        let transaction_id = u32::from_be_bytes(tidbuf);
        let mut client_id: Option<ClientIdOpt> = None;
        let mut server_id: Option<ServerIdOpt> = None;
        let mut ia_nas = Vec::<IaNaOpt>::new();
        let mut ia_pds = Vec::<IaPdOpt>::new();
        let mut opt_req: Option<OptReqOpt> = None;
        let mut elapsed_time: Option<ElapsedTimeOpt> = None;
        let mut user_class: Option<UserClassOpt> = None;
        let mut vendor_classes = Vec::<VendorClassOpt>::new();
        let mut vendor_infos = Vec::<VendorInfoOpt>::new();
        let mut reconf_accept: Option<ReconfAcceptOpt> = None;
        let mut unknown_opts = Vec::<Dhcp6Opt>::new();
        let mut pos = Self::FIXED_LEN;
        while pos < bytes.len() {
            if bytes.len() < pos + OPT_HDR_LEN {
                return Err(format!("Too short option"));
            }
            let opt_type = u16::from_be_bytes(bytes[pos..pos + 2].try_into().unwrap());
            let opt_len = u16::from_be_bytes(bytes[pos + 2..pos + 4].try_into().unwrap()) as usize;
            let opt_bytes_len = OPT_HDR_LEN + opt_len;
            if bytes.len() < pos + opt_bytes_len {
                return Err(format!("Too short option"));
            }
            let opt_bytes = &bytes[pos..pos + opt_bytes_len];
            match opt_type {
                ClientIdOpt::OPT_CODE => {
                    client_id = Some(ClientIdOpt::parse(opt_bytes)?);
                }
                ServerIdOpt::OPT_CODE => {
                    server_id = Some(ServerIdOpt::parse(opt_bytes)?);
                }
                IaNaOpt::OPT_CODE => {
                    ia_nas.push(IaNaOpt::parse(opt_bytes)?);
                }
                IaPdOpt::OPT_CODE => {
                    ia_pds.push(IaPdOpt::parse(opt_bytes)?);
                }
                OptReqOpt::OPT_CODE => {
                    opt_req = Some(OptReqOpt::parse(opt_bytes)?);
                }
                ElapsedTimeOpt::OPT_CODE => {
                    elapsed_time = Some(ElapsedTimeOpt::parse(opt_bytes)?);
                }
                UserClassOpt::OPT_CODE => {
                    user_class = Some(UserClassOpt::parse(opt_bytes)?);
                }
                VendorClassOpt::OPT_CODE => {
                    vendor_classes.push(VendorClassOpt::parse(opt_bytes)?);
                }
                VendorInfoOpt::OPT_CODE => {
                    vendor_infos.push(VendorInfoOpt::parse(opt_bytes)?);
                }
                ReconfAcceptOpt::OPT_CODE => {
                    reconf_accept = Some(ReconfAcceptOpt::parse(opt_bytes)?);
                }
                _ => {
                    unknown_opts.push(Dhcp6Opt::parse(opt_bytes)?);
                }
            }
            pos += opt_bytes_len;
        }
        if pos != bytes.len() {
            return Err(format!("Invalid option length"));
        }
        Ok(Self {
            transaction_id: transaction_id,
            client_id: client_id,
            server_id: server_id,
            ia_nas: ia_nas,
            ia_pds: ia_pds,
            opt_req: opt_req,
            elapsed_time: elapsed_time,
            user_class: user_class,
            vendor_classes: vendor_classes,
            vendor_infos: vendor_infos,
            reconf_accept: reconf_accept,
            unknown_opts: unknown_opts,
        })
    }
}

// Confirm Message
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfirmMsg {
    pub transaction_id: u32,
    pub client_id: Option<ClientIdOpt>,
    pub ia_nas: Vec<IaNaOpt>,
    pub elapsed_time: Option<ElapsedTimeOpt>,
    pub user_class: Option<UserClassOpt>,
    pub vendor_classes: Vec<VendorClassOpt>,
    pub vendor_infos: Vec<VendorInfoOpt>,
    pub unknown_opts: Vec<Dhcp6Opt>,
}

impl ConfirmMsg {
    const MSG_TYPE: u8 = 4;
    const FIXED_LEN: usize = 4;

    #[allow(unused)]
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0..4].copy_from_slice(&self.transaction_id.to_be_bytes());
        buf[0] = Self::MSG_TYPE; // Type
        let mut pos = Self::FIXED_LEN;
        if let Some(client_id) = &self.client_id {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += client_id.serialize(&mut buf[pos..])?;
        }
        for ia_na in &self.ia_nas {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += ia_na.serialize(&mut buf[pos..])?;
        }
        if let Some(elapsed_time) = &self.elapsed_time {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += elapsed_time.serialize(&mut buf[pos..])?;
        }
        if let Some(user_class) = &self.user_class {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += user_class.serialize(&mut buf[pos..])?;
        }
        for vendor_class in &self.vendor_classes {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += vendor_class.serialize(&mut buf[pos..])?;
        }
        for vendor_info in &self.vendor_infos {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += vendor_info.serialize(&mut buf[pos..])?;
        }
        for unknown_opt in &self.unknown_opts {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += unknown_opt.serialize(&mut buf[pos..])?;
        }
        Ok(pos)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short message"));
        }
        let msg_type = bytes[0];
        if msg_type != Self::MSG_TYPE {
            return Err(format!("Invalid message type"));
        }
        let mut tidbuf = [0u8; 4];
        tidbuf[1..4].copy_from_slice(&bytes[1..4]);
        let transaction_id = u32::from_be_bytes(tidbuf);
        let mut client_id: Option<ClientIdOpt> = None;
        let mut ia_nas = Vec::<IaNaOpt>::new();
        let mut elapsed_time: Option<ElapsedTimeOpt> = None;
        let mut user_class: Option<UserClassOpt> = None;
        let mut vendor_classes = Vec::<VendorClassOpt>::new();
        let mut vendor_infos = Vec::<VendorInfoOpt>::new();
        let mut unknown_opts = Vec::<Dhcp6Opt>::new();
        let mut pos = Self::FIXED_LEN;
        while pos < bytes.len() {
            if bytes.len() < pos + OPT_HDR_LEN {
                return Err(format!("Too short option"));
            }
            let opt_type = u16::from_be_bytes(bytes[pos..pos + 2].try_into().unwrap());
            let opt_len = u16::from_be_bytes(bytes[pos + 2..pos + 4].try_into().unwrap()) as usize;
            let opt_bytes_len = OPT_HDR_LEN + opt_len;
            if bytes.len() < pos + opt_bytes_len {
                return Err(format!("Too short option"));
            }
            let opt_bytes = &bytes[pos..pos + opt_bytes_len];
            match opt_type {
                ClientIdOpt::OPT_CODE => {
                    client_id = Some(ClientIdOpt::parse(opt_bytes)?);
                }
                IaNaOpt::OPT_CODE => {
                    ia_nas.push(IaNaOpt::parse(opt_bytes)?);
                }
                ElapsedTimeOpt::OPT_CODE => {
                    elapsed_time = Some(ElapsedTimeOpt::parse(opt_bytes)?);
                }
                UserClassOpt::OPT_CODE => {
                    user_class = Some(UserClassOpt::parse(opt_bytes)?);
                }
                VendorClassOpt::OPT_CODE => {
                    vendor_classes.push(VendorClassOpt::parse(opt_bytes)?);
                }
                VendorInfoOpt::OPT_CODE => {
                    vendor_infos.push(VendorInfoOpt::parse(opt_bytes)?);
                }
                _ => {
                    unknown_opts.push(Dhcp6Opt::parse(opt_bytes)?);
                }
            }
            pos += opt_bytes_len;
        }
        if pos != bytes.len() {
            return Err(format!("Invalid option length"));
        }
        Ok(Self {
            transaction_id: transaction_id,
            client_id: client_id,
            ia_nas: ia_nas,
            elapsed_time: elapsed_time,
            user_class: user_class,
            vendor_classes: vendor_classes,
            vendor_infos: vendor_infos,
            unknown_opts: unknown_opts,
        })
    }
}

// Renew Message
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenewMsg {
    pub transaction_id: u32,
    pub client_id: Option<ClientIdOpt>,
    pub server_id: Option<ServerIdOpt>,
    pub ia_nas: Vec<IaNaOpt>,
    pub ia_pds: Vec<IaPdOpt>,
    pub opt_req: Option<OptReqOpt>,
    pub elapsed_time: Option<ElapsedTimeOpt>,
    pub user_class: Option<UserClassOpt>,
    pub vendor_classes: Vec<VendorClassOpt>,
    pub vendor_infos: Vec<VendorInfoOpt>,
    pub reconf_accept: Option<ReconfAcceptOpt>,
    pub unknown_opts: Vec<Dhcp6Opt>,
}

impl RenewMsg {
    const MSG_TYPE: u8 = 5;
    const FIXED_LEN: usize = 4;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0..4].copy_from_slice(&self.transaction_id.to_be_bytes());
        buf[0] = Self::MSG_TYPE; // Type
        let mut pos = Self::FIXED_LEN;
        if let Some(client_id) = &self.client_id {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += client_id.serialize(&mut buf[pos..])?;
        }
        if let Some(server_id) = &self.server_id {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += server_id.serialize(&mut buf[pos..])?;
        }
        for ia_na in &self.ia_nas {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += ia_na.serialize(&mut buf[pos..])?;
        }
        for ia_pd in &self.ia_pds {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += ia_pd.serialize(&mut buf[pos..])?;
        }
        if let Some(opt_req) = &self.opt_req {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += opt_req.serialize(&mut buf[pos..])?;
        }
        if let Some(elapsed_time) = &self.elapsed_time {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += elapsed_time.serialize(&mut buf[pos..])?;
        }
        if let Some(user_class) = &self.user_class {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += user_class.serialize(&mut buf[pos..])?;
        }
        for vendor_class in &self.vendor_classes {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += vendor_class.serialize(&mut buf[pos..])?;
        }
        for vendor_info in &self.vendor_infos {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += vendor_info.serialize(&mut buf[pos..])?;
        }
        if let Some(reconf_accept) = &self.reconf_accept {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += reconf_accept.serialize(&mut buf[pos..])?;
        }
        for unknown_opt in &self.unknown_opts {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += unknown_opt.serialize(&mut buf[pos..])?;
        }
        Ok(pos)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short message"));
        }
        let msg_type = bytes[0];
        if msg_type != Self::MSG_TYPE {
            return Err(format!("Invalid message type"));
        }
        let mut tidbuf = [0u8; 4];
        tidbuf[1..4].copy_from_slice(&bytes[1..4]);
        let transaction_id = u32::from_be_bytes(tidbuf);
        let mut client_id: Option<ClientIdOpt> = None;
        let mut server_id: Option<ServerIdOpt> = None;
        let mut ia_nas = Vec::<IaNaOpt>::new();
        let mut ia_pds = Vec::<IaPdOpt>::new();
        let mut opt_req: Option<OptReqOpt> = None;
        let mut elapsed_time: Option<ElapsedTimeOpt> = None;
        let mut user_class: Option<UserClassOpt> = None;
        let mut vendor_classes = Vec::<VendorClassOpt>::new();
        let mut vendor_infos = Vec::<VendorInfoOpt>::new();
        let mut reconf_accept: Option<ReconfAcceptOpt> = None;
        let mut unknown_opts = Vec::<Dhcp6Opt>::new();
        let mut pos = Self::FIXED_LEN;
        while pos < bytes.len() {
            if bytes.len() < pos + OPT_HDR_LEN {
                return Err(format!("Too short option"));
            }
            let opt_type = u16::from_be_bytes(bytes[pos..pos + 2].try_into().unwrap());
            let opt_len = u16::from_be_bytes(bytes[pos + 2..pos + 4].try_into().unwrap()) as usize;
            let opt_bytes_len = OPT_HDR_LEN + opt_len;
            if bytes.len() < pos + opt_bytes_len {
                return Err(format!("Too short option"));
            }
            let opt_bytes = &bytes[pos..pos + opt_bytes_len];
            match opt_type {
                ClientIdOpt::OPT_CODE => {
                    client_id = Some(ClientIdOpt::parse(opt_bytes)?);
                }
                ServerIdOpt::OPT_CODE => {
                    server_id = Some(ServerIdOpt::parse(opt_bytes)?);
                }
                IaNaOpt::OPT_CODE => {
                    ia_nas.push(IaNaOpt::parse(opt_bytes)?);
                }
                IaPdOpt::OPT_CODE => {
                    ia_pds.push(IaPdOpt::parse(opt_bytes)?);
                }
                OptReqOpt::OPT_CODE => {
                    opt_req = Some(OptReqOpt::parse(opt_bytes)?);
                }
                ElapsedTimeOpt::OPT_CODE => {
                    elapsed_time = Some(ElapsedTimeOpt::parse(opt_bytes)?);
                }
                UserClassOpt::OPT_CODE => {
                    user_class = Some(UserClassOpt::parse(opt_bytes)?);
                }
                VendorClassOpt::OPT_CODE => {
                    vendor_classes.push(VendorClassOpt::parse(opt_bytes)?);
                }
                VendorInfoOpt::OPT_CODE => {
                    vendor_infos.push(VendorInfoOpt::parse(opt_bytes)?);
                }
                ReconfAcceptOpt::OPT_CODE => {
                    reconf_accept = Some(ReconfAcceptOpt::parse(opt_bytes)?);
                }
                _ => {
                    unknown_opts.push(Dhcp6Opt::parse(opt_bytes)?);
                }
            }
            pos += opt_bytes_len;
        }
        if pos != bytes.len() {
            return Err(format!("Invalid option length"));
        }
        Ok(Self {
            transaction_id: transaction_id,
            client_id: client_id,
            server_id: server_id,
            ia_nas: ia_nas,
            ia_pds: ia_pds,
            opt_req: opt_req,
            elapsed_time: elapsed_time,
            user_class: user_class,
            vendor_classes: vendor_classes,
            vendor_infos: vendor_infos,
            reconf_accept: reconf_accept,
            unknown_opts: unknown_opts,
        })
    }
}

// Rebind Message
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RebindMsg {
    pub transaction_id: u32,
    pub client_id: Option<ClientIdOpt>,
    pub ia_nas: Vec<IaNaOpt>,
    pub ia_pds: Vec<IaPdOpt>,
    pub opt_req: Option<OptReqOpt>,
    pub elapsed_time: Option<ElapsedTimeOpt>,
    pub user_class: Option<UserClassOpt>,
    pub vendor_classes: Vec<VendorClassOpt>,
    pub vendor_infos: Vec<VendorInfoOpt>,
    pub reconf_accept: Option<ReconfAcceptOpt>,
    pub unknown_opts: Vec<Dhcp6Opt>,
}

impl RebindMsg {
    const MSG_TYPE: u8 = 6;
    const FIXED_LEN: usize = 4;

    #[allow(unused)]
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0..4].copy_from_slice(&self.transaction_id.to_be_bytes());
        buf[0] = Self::MSG_TYPE; // Type
        let mut pos = Self::FIXED_LEN;
        if let Some(client_id) = &self.client_id {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += client_id.serialize(&mut buf[pos..])?;
        }
        for ia_na in &self.ia_nas {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += ia_na.serialize(&mut buf[pos..])?;
        }
        for ia_pd in &self.ia_pds {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += ia_pd.serialize(&mut buf[pos..])?;
        }
        if let Some(opt_req) = &self.opt_req {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += opt_req.serialize(&mut buf[pos..])?;
        }
        if let Some(elapsed_time) = &self.elapsed_time {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += elapsed_time.serialize(&mut buf[pos..])?;
        }
        if let Some(user_class) = &self.user_class {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += user_class.serialize(&mut buf[pos..])?;
        }
        for vendor_class in &self.vendor_classes {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += vendor_class.serialize(&mut buf[pos..])?;
        }
        for vendor_info in &self.vendor_infos {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += vendor_info.serialize(&mut buf[pos..])?;
        }
        if let Some(reconf_accept) = &self.reconf_accept {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += reconf_accept.serialize(&mut buf[pos..])?;
        }
        for unknown_opt in &self.unknown_opts {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += unknown_opt.serialize(&mut buf[pos..])?;
        }
        Ok(pos)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short message"));
        }
        let msg_type = bytes[0];
        if msg_type != Self::MSG_TYPE {
            return Err(format!("Invalid message type"));
        }
        let mut tidbuf = [0u8; 4];
        tidbuf[1..4].copy_from_slice(&bytes[1..4]);
        let transaction_id = u32::from_be_bytes(tidbuf);
        let mut client_id: Option<ClientIdOpt> = None;
        let mut ia_nas = Vec::<IaNaOpt>::new();
        let mut ia_pds = Vec::<IaPdOpt>::new();
        let mut opt_req: Option<OptReqOpt> = None;
        let mut elapsed_time: Option<ElapsedTimeOpt> = None;
        let mut user_class: Option<UserClassOpt> = None;
        let mut vendor_classes = Vec::<VendorClassOpt>::new();
        let mut vendor_infos = Vec::<VendorInfoOpt>::new();
        let mut reconf_accept: Option<ReconfAcceptOpt> = None;
        let mut unknown_opts = Vec::<Dhcp6Opt>::new();
        let mut pos = Self::FIXED_LEN;
        while pos < bytes.len() {
            if bytes.len() < pos + OPT_HDR_LEN {
                return Err(format!("Too short option"));
            }
            let opt_type = u16::from_be_bytes(bytes[pos..pos + 2].try_into().unwrap());
            let opt_len = u16::from_be_bytes(bytes[pos + 2..pos + 4].try_into().unwrap()) as usize;
            let opt_bytes_len = OPT_HDR_LEN + opt_len;
            if bytes.len() < pos + opt_bytes_len {
                return Err(format!("Too short option"));
            }
            let opt_bytes = &bytes[pos..pos + opt_bytes_len];
            match opt_type {
                ClientIdOpt::OPT_CODE => {
                    client_id = Some(ClientIdOpt::parse(opt_bytes)?);
                }
                IaNaOpt::OPT_CODE => {
                    ia_nas.push(IaNaOpt::parse(opt_bytes)?);
                }
                IaPdOpt::OPT_CODE => {
                    ia_pds.push(IaPdOpt::parse(opt_bytes)?);
                }
                OptReqOpt::OPT_CODE => {
                    opt_req = Some(OptReqOpt::parse(opt_bytes)?);
                }
                ElapsedTimeOpt::OPT_CODE => {
                    elapsed_time = Some(ElapsedTimeOpt::parse(opt_bytes)?);
                }
                UserClassOpt::OPT_CODE => {
                    user_class = Some(UserClassOpt::parse(opt_bytes)?);
                }
                VendorClassOpt::OPT_CODE => {
                    vendor_classes.push(VendorClassOpt::parse(opt_bytes)?);
                }
                VendorInfoOpt::OPT_CODE => {
                    vendor_infos.push(VendorInfoOpt::parse(opt_bytes)?);
                }
                ReconfAcceptOpt::OPT_CODE => {
                    reconf_accept = Some(ReconfAcceptOpt::parse(opt_bytes)?);
                }
                _ => {
                    unknown_opts.push(Dhcp6Opt::parse(opt_bytes)?);
                }
            }
            pos += opt_bytes_len;
        }
        if pos != bytes.len() {
            return Err(format!("Invalid option length"));
        }
        Ok(Self {
            transaction_id: transaction_id,
            client_id: client_id,
            ia_nas: ia_nas,
            ia_pds: ia_pds,
            opt_req: opt_req,
            elapsed_time: elapsed_time,
            user_class: user_class,
            vendor_classes: vendor_classes,
            vendor_infos: vendor_infos,
            reconf_accept: reconf_accept,
            unknown_opts: unknown_opts,
        })
    }
}

// Decline Message
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeclineMsg {
    pub transaction_id: u32,
    pub client_id: Option<ClientIdOpt>,
    pub server_id: Option<ServerIdOpt>,
    pub ia_nas: Vec<IaNaOpt>,
    pub ia_pds: Vec<IaPdOpt>,
    pub elapsed_time: Option<ElapsedTimeOpt>,
    pub user_class: Option<UserClassOpt>,
    pub vendor_classes: Vec<VendorClassOpt>,
    pub vendor_infos: Vec<VendorInfoOpt>,
    pub unknown_opts: Vec<Dhcp6Opt>,
}

impl DeclineMsg {
    const MSG_TYPE: u8 = 9;
    const FIXED_LEN: usize = 4;

    #[allow(unused)]
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0..4].copy_from_slice(&self.transaction_id.to_be_bytes());
        buf[0] = Self::MSG_TYPE; // Type
        let mut pos = Self::FIXED_LEN;
        if let Some(client_id) = &self.client_id {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += client_id.serialize(&mut buf[pos..])?;
        }
        if let Some(server_id) = &self.server_id {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += server_id.serialize(&mut buf[pos..])?;
        }
        for ia_na in &self.ia_nas {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += ia_na.serialize(&mut buf[pos..])?;
        }
        for ia_pd in &self.ia_pds {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += ia_pd.serialize(&mut buf[pos..])?;
        }
        if let Some(elapsed_time) = &self.elapsed_time {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += elapsed_time.serialize(&mut buf[pos..])?;
        }
        if let Some(user_class) = &self.user_class {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += user_class.serialize(&mut buf[pos..])?;
        }
        for vendor_class in &self.vendor_classes {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += vendor_class.serialize(&mut buf[pos..])?;
        }
        for vendor_info in &self.vendor_infos {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += vendor_info.serialize(&mut buf[pos..])?;
        }
        for unknown_opt in &self.unknown_opts {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += unknown_opt.serialize(&mut buf[pos..])?;
        }
        Ok(pos)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short message"));
        }
        let msg_type = bytes[0];
        if msg_type != Self::MSG_TYPE {
            return Err(format!("Invalid message type"));
        }
        let mut tidbuf = [0u8; 4];
        tidbuf[1..4].copy_from_slice(&bytes[1..4]);
        let transaction_id = u32::from_be_bytes(tidbuf);
        let mut client_id: Option<ClientIdOpt> = None;
        let mut server_id: Option<ServerIdOpt> = None;
        let mut ia_nas = Vec::<IaNaOpt>::new();
        let mut ia_pds = Vec::<IaPdOpt>::new();
        let mut elapsed_time: Option<ElapsedTimeOpt> = None;
        let mut user_class: Option<UserClassOpt> = None;
        let mut vendor_classes = Vec::<VendorClassOpt>::new();
        let mut vendor_infos = Vec::<VendorInfoOpt>::new();
        let mut unknown_opts = Vec::<Dhcp6Opt>::new();
        let mut pos = Self::FIXED_LEN;
        while pos < bytes.len() {
            if bytes.len() < pos + OPT_HDR_LEN {
                return Err(format!("Too short option"));
            }
            let opt_type = u16::from_be_bytes(bytes[pos..pos + 2].try_into().unwrap());
            let opt_len = u16::from_be_bytes(bytes[pos + 2..pos + 4].try_into().unwrap()) as usize;
            let opt_bytes_len = OPT_HDR_LEN + opt_len;
            if bytes.len() < pos + opt_bytes_len {
                return Err(format!("Too short option"));
            }
            let opt_bytes = &bytes[pos..pos + opt_bytes_len];
            match opt_type {
                ClientIdOpt::OPT_CODE => {
                    client_id = Some(ClientIdOpt::parse(opt_bytes)?);
                }
                ServerIdOpt::OPT_CODE => {
                    server_id = Some(ServerIdOpt::parse(opt_bytes)?);
                }
                IaNaOpt::OPT_CODE => {
                    ia_nas.push(IaNaOpt::parse(opt_bytes)?);
                }
                IaPdOpt::OPT_CODE => {
                    ia_pds.push(IaPdOpt::parse(opt_bytes)?);
                }
                ElapsedTimeOpt::OPT_CODE => {
                    elapsed_time = Some(ElapsedTimeOpt::parse(opt_bytes)?);
                }
                UserClassOpt::OPT_CODE => {
                    user_class = Some(UserClassOpt::parse(opt_bytes)?);
                }
                VendorClassOpt::OPT_CODE => {
                    vendor_classes.push(VendorClassOpt::parse(opt_bytes)?);
                }
                VendorInfoOpt::OPT_CODE => {
                    vendor_infos.push(VendorInfoOpt::parse(opt_bytes)?);
                }
                _ => {
                    unknown_opts.push(Dhcp6Opt::parse(opt_bytes)?);
                }
            }
            pos += opt_bytes_len;
        }
        if pos != bytes.len() {
            return Err(format!("Invalid option length"));
        }
        Ok(Self {
            transaction_id: transaction_id,
            client_id: client_id,
            server_id: server_id,
            ia_nas: ia_nas,
            ia_pds: ia_pds,
            elapsed_time: elapsed_time,
            user_class: user_class,
            vendor_classes: vendor_classes,
            vendor_infos: vendor_infos,
            unknown_opts: unknown_opts,
        })
    }
}

// Release Message
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseMsg {
    pub transaction_id: u32,
    pub client_id: Option<ClientIdOpt>,
    pub server_id: Option<ServerIdOpt>,
    pub ia_nas: Vec<IaNaOpt>,
    pub ia_pds: Vec<IaPdOpt>,
    pub elapsed_time: Option<ElapsedTimeOpt>,
    pub user_class: Option<UserClassOpt>,
    pub vendor_classes: Vec<VendorClassOpt>,
    pub vendor_infos: Vec<VendorInfoOpt>,
    pub unknown_opts: Vec<Dhcp6Opt>,
}

impl ReleaseMsg {
    const MSG_TYPE: u8 = 8;
    const FIXED_LEN: usize = 4;

    #[allow(unused)]
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0..4].copy_from_slice(&self.transaction_id.to_be_bytes());
        buf[0] = Self::MSG_TYPE; // Type
        let mut pos = Self::FIXED_LEN;
        if let Some(client_id) = &self.client_id {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += client_id.serialize(&mut buf[pos..])?;
        }
        if let Some(server_id) = &self.server_id {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += server_id.serialize(&mut buf[pos..])?;
        }
        for ia_na in &self.ia_nas {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += ia_na.serialize(&mut buf[pos..])?;
        }
        for ia_pd in &self.ia_pds {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += ia_pd.serialize(&mut buf[pos..])?;
        }
        if let Some(elapsed_time) = &self.elapsed_time {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += elapsed_time.serialize(&mut buf[pos..])?;
        }
        if let Some(user_class) = &self.user_class {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += user_class.serialize(&mut buf[pos..])?;
        }
        for vendor_class in &self.vendor_classes {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += vendor_class.serialize(&mut buf[pos..])?;
        }
        for vendor_info in &self.vendor_infos {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += vendor_info.serialize(&mut buf[pos..])?;
        }
        for unknown_opt in &self.unknown_opts {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += unknown_opt.serialize(&mut buf[pos..])?;
        }
        Ok(pos)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short message"));
        }
        let msg_type = bytes[0];
        if msg_type != Self::MSG_TYPE {
            return Err(format!("Invalid message type"));
        }
        let mut tidbuf = [0u8; 4];
        tidbuf[1..4].copy_from_slice(&bytes[1..4]);
        let transaction_id = u32::from_be_bytes(tidbuf);
        let mut client_id: Option<ClientIdOpt> = None;
        let mut server_id: Option<ServerIdOpt> = None;
        let mut ia_nas = Vec::<IaNaOpt>::new();
        let mut ia_pds = Vec::<IaPdOpt>::new();
        let mut elapsed_time: Option<ElapsedTimeOpt> = None;
        let mut user_class: Option<UserClassOpt> = None;
        let mut vendor_classes = Vec::<VendorClassOpt>::new();
        let mut vendor_infos = Vec::<VendorInfoOpt>::new();
        let mut unknown_opts = Vec::<Dhcp6Opt>::new();
        let mut pos = Self::FIXED_LEN;
        while pos < bytes.len() {
            if bytes.len() < pos + OPT_HDR_LEN {
                return Err(format!("Too short option"));
            }
            let opt_type = u16::from_be_bytes(bytes[pos..pos + 2].try_into().unwrap());
            let opt_len = u16::from_be_bytes(bytes[pos + 2..pos + 4].try_into().unwrap()) as usize;
            let opt_bytes_len = OPT_HDR_LEN + opt_len;
            if bytes.len() < pos + opt_bytes_len {
                return Err(format!("Too short option"));
            }
            let opt_bytes = &bytes[pos..pos + opt_bytes_len];
            match opt_type {
                ClientIdOpt::OPT_CODE => {
                    client_id = Some(ClientIdOpt::parse(opt_bytes)?);
                }
                ServerIdOpt::OPT_CODE => {
                    server_id = Some(ServerIdOpt::parse(opt_bytes)?);
                }
                IaNaOpt::OPT_CODE => {
                    ia_nas.push(IaNaOpt::parse(opt_bytes)?);
                }
                IaPdOpt::OPT_CODE => {
                    ia_pds.push(IaPdOpt::parse(opt_bytes)?);
                }
                ElapsedTimeOpt::OPT_CODE => {
                    elapsed_time = Some(ElapsedTimeOpt::parse(opt_bytes)?);
                }
                UserClassOpt::OPT_CODE => {
                    user_class = Some(UserClassOpt::parse(opt_bytes)?);
                }
                VendorClassOpt::OPT_CODE => {
                    vendor_classes.push(VendorClassOpt::parse(opt_bytes)?);
                }
                VendorInfoOpt::OPT_CODE => {
                    vendor_infos.push(VendorInfoOpt::parse(opt_bytes)?);
                }
                _ => {
                    unknown_opts.push(Dhcp6Opt::parse(opt_bytes)?);
                }
            }
            pos += opt_bytes_len;
        }
        if pos != bytes.len() {
            return Err(format!("Invalid option length"));
        }
        Ok(Self {
            transaction_id: transaction_id,
            client_id: client_id,
            server_id: server_id,
            ia_nas: ia_nas,
            ia_pds: ia_pds,
            elapsed_time: elapsed_time,
            user_class: user_class,
            vendor_classes: vendor_classes,
            vendor_infos: vendor_infos,
            unknown_opts: unknown_opts,
        })
    }
}

// Reply Message
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplyMsg {
    pub transaction_id: u32,
    pub client_id: Option<ClientIdOpt>,
    pub server_id: Option<ServerIdOpt>,
    pub ia_nas: Vec<IaNaOpt>,
    pub ia_pds: Vec<IaPdOpt>,
    pub auth: Option<AuthOpt>,
    pub status_code: Option<StatusCodeOpt>,
    pub rapid_commit: Option<RapidCommitOpt>,
    pub user_class: Option<UserClassOpt>,
    pub vendor_classes: Vec<VendorClassOpt>,
    pub vendor_infos: Vec<VendorInfoOpt>,
    pub reconf_accept: Option<ReconfAcceptOpt>,
    pub info_refresh_time: Option<InfoRefreshTimeOpt>,
    pub sol_max_rt: Option<SolMaxRtOpt>,
    pub inf_max_rt: Option<InfMaxRtOpt>,
    pub dns_recursive_name_server: Option<DnsRecursiveNameServerOpt>,
    pub domain_search_list: Option<DomainSearchListOpt>,
    pub unknown_opts: Vec<Dhcp6Opt>,
}

impl ReplyMsg {
    const MSG_TYPE: u8 = 7;
    const FIXED_LEN: usize = 4;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0..4].copy_from_slice(&self.transaction_id.to_be_bytes());
        buf[0] = Self::MSG_TYPE; // Type
        let mut pos = Self::FIXED_LEN;
        if let Some(client_id) = &self.client_id {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += client_id.serialize(&mut buf[pos..])?;
        }
        if let Some(server_id) = &self.server_id {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += server_id.serialize(&mut buf[pos..])?;
        }
        for ia_na in &self.ia_nas {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += ia_na.serialize(&mut buf[pos..])?;
        }
        for ia_pd in &self.ia_pds {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += ia_pd.serialize(&mut buf[pos..])?;
        }
        if let Some(auth) = &self.auth {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += auth.serialize(&mut buf[pos..])?;
        }
        if let Some(status_code) = &self.status_code {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += status_code.serialize(&mut buf[pos..])?;
        }
        if let Some(rapid_commit) = &self.rapid_commit {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += rapid_commit.serialize(&mut buf[pos..])?;
        }
        if let Some(user_class) = &self.user_class {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += user_class.serialize(&mut buf[pos..])?;
        }
        for vendor_class in &self.vendor_classes {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += vendor_class.serialize(&mut buf[pos..])?;
        }
        for vendor_info in &self.vendor_infos {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += vendor_info.serialize(&mut buf[pos..])?;
        }
        if let Some(reconf_accept) = &self.reconf_accept {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += reconf_accept.serialize(&mut buf[pos..])?;
        }
        if let Some(info_refresh_time) = &self.info_refresh_time {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += info_refresh_time.serialize(&mut buf[pos..])?;
        }
        if let Some(sol_max_rt) = &self.sol_max_rt {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += sol_max_rt.serialize(&mut buf[pos..])?;
        }
        if let Some(inf_max_rt) = &self.inf_max_rt {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += inf_max_rt.serialize(&mut buf[pos..])?;
        }
        if let Some(dns_recursive_name_server) = &self.dns_recursive_name_server {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += dns_recursive_name_server.serialize(&mut buf[pos..])?;
        }
        if let Some(domain_search_list) = &self.domain_search_list {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += domain_search_list.serialize(&mut buf[pos..])?;
        }
        for unknown_opt in &self.unknown_opts {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += unknown_opt.serialize(&mut buf[pos..])?;
        }
        Ok(pos)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short message"));
        }
        let msg_type = bytes[0];
        if msg_type != Self::MSG_TYPE {
            return Err(format!("Invalid message type"));
        }
        let mut tidbuf = [0u8; 4];
        tidbuf[1..4].copy_from_slice(&bytes[1..4]);
        let transaction_id = u32::from_be_bytes(tidbuf);
        let mut client_id: Option<ClientIdOpt> = None;
        let mut server_id: Option<ServerIdOpt> = None;
        let mut ia_nas = Vec::<IaNaOpt>::new();
        let mut ia_pds = Vec::<IaPdOpt>::new();
        let mut auth: Option<AuthOpt> = None;
        let mut status_code: Option<StatusCodeOpt> = None;
        let mut rapid_commit: Option<RapidCommitOpt> = None;
        let mut user_class: Option<UserClassOpt> = None;
        let mut vendor_classes = Vec::<VendorClassOpt>::new();
        let mut vendor_infos = Vec::<VendorInfoOpt>::new();
        let mut reconf_accept: Option<ReconfAcceptOpt> = None;
        let mut info_refresh_time: Option<InfoRefreshTimeOpt> = None;
        let mut sol_max_rt: Option<SolMaxRtOpt> = None;
        let mut inf_max_rt: Option<InfMaxRtOpt> = None;
        let mut dns_recursive_name_server: Option<DnsRecursiveNameServerOpt> = None;
        let mut domain_search_list: Option<DomainSearchListOpt> = None;
        let mut unknown_opts = Vec::<Dhcp6Opt>::new();
        let mut pos = Self::FIXED_LEN;
        while pos < bytes.len() {
            if bytes.len() < pos + OPT_HDR_LEN {
                return Err(format!("Too short option"));
            }
            let opt_type = u16::from_be_bytes(bytes[pos..pos + 2].try_into().unwrap());
            let opt_len = u16::from_be_bytes(bytes[pos + 2..pos + 4].try_into().unwrap()) as usize;
            let opt_bytes_len = OPT_HDR_LEN + opt_len;
            if bytes.len() < pos + opt_bytes_len {
                return Err(format!("Too short option"));
            }
            let opt_bytes = &bytes[pos..pos + opt_bytes_len];
            match opt_type {
                ClientIdOpt::OPT_CODE => {
                    client_id = Some(ClientIdOpt::parse(opt_bytes)?);
                }
                ServerIdOpt::OPT_CODE => {
                    server_id = Some(ServerIdOpt::parse(opt_bytes)?);
                }
                IaNaOpt::OPT_CODE => {
                    ia_nas.push(IaNaOpt::parse(opt_bytes)?);
                }
                IaPdOpt::OPT_CODE => {
                    ia_pds.push(IaPdOpt::parse(opt_bytes)?);
                }
                AuthOpt::OPT_CODE => {
                    auth = Some(AuthOpt::parse(opt_bytes)?);
                }
                StatusCodeOpt::OPT_CODE => {
                    status_code = Some(StatusCodeOpt::parse(opt_bytes)?);
                }
                RapidCommitOpt::OPT_CODE => {
                    rapid_commit = Some(RapidCommitOpt::parse(opt_bytes)?);
                }
                UserClassOpt::OPT_CODE => {
                    user_class = Some(UserClassOpt::parse(opt_bytes)?);
                }
                VendorClassOpt::OPT_CODE => {
                    vendor_classes.push(VendorClassOpt::parse(opt_bytes)?);
                }
                VendorInfoOpt::OPT_CODE => {
                    vendor_infos.push(VendorInfoOpt::parse(opt_bytes)?);
                }
                ReconfAcceptOpt::OPT_CODE => {
                    reconf_accept = Some(ReconfAcceptOpt::parse(opt_bytes)?);
                }
                InfoRefreshTimeOpt::OPT_CODE => {
                    info_refresh_time = Some(InfoRefreshTimeOpt::parse(opt_bytes)?);
                }
                SolMaxRtOpt::OPT_CODE => {
                    sol_max_rt = Some(SolMaxRtOpt::parse(opt_bytes)?);
                }
                InfMaxRtOpt::OPT_CODE => {
                    inf_max_rt = Some(InfMaxRtOpt::parse(opt_bytes)?);
                }
                DnsRecursiveNameServerOpt::OPT_CODE => {
                    dns_recursive_name_server = Some(DnsRecursiveNameServerOpt::parse(opt_bytes)?);
                }
                DomainSearchListOpt::OPT_CODE => {
                    domain_search_list = Some(DomainSearchListOpt::parse(opt_bytes)?);
                }
                _ => {
                    unknown_opts.push(Dhcp6Opt::parse(opt_bytes)?);
                }
            }
            pos += opt_bytes_len;
        }
        if pos != bytes.len() {
            return Err(format!("Invalid option length"));
        }
        Ok(Self {
            transaction_id: transaction_id,
            client_id: client_id,
            server_id: server_id,
            ia_nas: ia_nas,
            ia_pds: ia_pds,
            auth: auth,
            status_code: status_code,
            rapid_commit: rapid_commit,
            user_class: user_class,
            vendor_classes: vendor_classes,
            vendor_infos: vendor_infos,
            reconf_accept: reconf_accept,
            info_refresh_time: info_refresh_time,
            sol_max_rt: sol_max_rt,
            inf_max_rt: inf_max_rt,
            dns_recursive_name_server: dns_recursive_name_server,
            domain_search_list: domain_search_list,
            unknown_opts: unknown_opts,
        })
    }
}

// Reconfigure Message
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconfMsg {
    pub transaction_id: u32,
    pub client_id: Option<ClientIdOpt>,
    pub server_id: Option<ServerIdOpt>,
    pub auth: Option<AuthOpt>,
    pub reconf_msg: Option<ReconfMsgOpt>,
    pub unknown_opts: Vec<Dhcp6Opt>,
}

impl ReconfMsg {
    const MSG_TYPE: u8 = 10;
    const FIXED_LEN: usize = 4;

    #[allow(unused)]
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0..4].copy_from_slice(&self.transaction_id.to_be_bytes());
        buf[0] = Self::MSG_TYPE; // Type
        let mut pos = Self::FIXED_LEN;
        if let Some(client_id) = &self.client_id {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += client_id.serialize(&mut buf[pos..])?;
        }
        if let Some(server_id) = &self.server_id {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += server_id.serialize(&mut buf[pos..])?;
        }
        if let Some(auth) = &self.auth {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += auth.serialize(&mut buf[pos..])?;
        }
        if let Some(reconf_msg) = &self.reconf_msg {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += reconf_msg.serialize(&mut buf[pos..])?;
        }
        for unknown_opt in &self.unknown_opts {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += unknown_opt.serialize(&mut buf[pos..])?;
        }
        Ok(pos)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short message"));
        }
        let msg_type = bytes[0];
        if msg_type != Self::MSG_TYPE {
            return Err(format!("Invalid message type"));
        }
        let mut tidbuf = [0u8; 4];
        tidbuf[1..4].copy_from_slice(&bytes[1..4]);
        let transaction_id = u32::from_be_bytes(tidbuf);
        let mut client_id: Option<ClientIdOpt> = None;
        let mut server_id: Option<ServerIdOpt> = None;
        let mut auth: Option<AuthOpt> = None;
        let mut reconf_msg: Option<ReconfMsgOpt> = None;
        let mut unknown_opts = Vec::<Dhcp6Opt>::new();
        let mut pos = Self::FIXED_LEN;
        while pos < bytes.len() {
            if bytes.len() < pos + OPT_HDR_LEN {
                return Err(format!("Too short option"));
            }
            let opt_type = u16::from_be_bytes(bytes[pos..pos + 2].try_into().unwrap());
            let opt_len = u16::from_be_bytes(bytes[pos + 2..pos + 4].try_into().unwrap()) as usize;
            let opt_bytes_len = OPT_HDR_LEN + opt_len;
            if bytes.len() < pos + opt_bytes_len {
                return Err(format!("Too short option"));
            }
            let opt_bytes = &bytes[pos..pos + opt_bytes_len];
            match opt_type {
                ClientIdOpt::OPT_CODE => {
                    client_id = Some(ClientIdOpt::parse(opt_bytes)?);
                }
                ServerIdOpt::OPT_CODE => {
                    server_id = Some(ServerIdOpt::parse(opt_bytes)?);
                }
                AuthOpt::OPT_CODE => {
                    auth = Some(AuthOpt::parse(opt_bytes)?);
                }
                ReconfMsgOpt::OPT_CODE => {
                    reconf_msg = Some(ReconfMsgOpt::parse(opt_bytes)?);
                }
                _ => {
                    unknown_opts.push(Dhcp6Opt::parse(opt_bytes)?);
                }
            }
            pos += opt_bytes_len;
        }
        if pos != bytes.len() {
            return Err(format!("Invalid option length"));
        }
        Ok(Self {
            transaction_id: transaction_id,
            client_id: client_id,
            server_id: server_id,
            auth: auth,
            reconf_msg: reconf_msg,
            unknown_opts: unknown_opts,
        })
    }
}

// Information-request Message
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InfoReqMsg {
    pub transaction_id: u32,
    pub client_id: Option<ClientIdOpt>,
    pub server_id: Option<ServerIdOpt>,
    pub opt_req: Option<OptReqOpt>,
    pub elapsed_time: Option<ElapsedTimeOpt>,
    pub user_class: Option<UserClassOpt>,
    pub vendor_classes: Vec<VendorClassOpt>,
    pub vendor_infos: Vec<VendorInfoOpt>,
    pub reconf_accept: Option<ReconfAcceptOpt>,
    pub unknown_opts: Vec<Dhcp6Opt>,
}

impl InfoReqMsg {
    const MSG_TYPE: u8 = 11;
    const FIXED_LEN: usize = 4;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0..4].copy_from_slice(&self.transaction_id.to_be_bytes());
        buf[0] = Self::MSG_TYPE; // Type
        let mut pos = Self::FIXED_LEN;
        if let Some(client_id) = &self.client_id {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += client_id.serialize(&mut buf[pos..])?;
        }
        if let Some(server_id) = &self.server_id {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += server_id.serialize(&mut buf[pos..])?;
        }
        if let Some(opt_req) = &self.opt_req {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += opt_req.serialize(&mut buf[pos..])?;
        }
        if let Some(elapsed_time) = &self.elapsed_time {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += elapsed_time.serialize(&mut buf[pos..])?;
        }
        if let Some(user_class) = &self.user_class {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += user_class.serialize(&mut buf[pos..])?;
        }
        for vendor_class in &self.vendor_classes {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += vendor_class.serialize(&mut buf[pos..])?;
        }
        for vendor_info in &self.vendor_infos {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += vendor_info.serialize(&mut buf[pos..])?;
        }
        if let Some(reconf_accept) = &self.reconf_accept {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += reconf_accept.serialize(&mut buf[pos..])?;
        }
        for unknown_opt in &self.unknown_opts {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += unknown_opt.serialize(&mut buf[pos..])?;
        }
        Ok(pos)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short message"));
        }
        let msg_type = bytes[0];
        if msg_type != Self::MSG_TYPE {
            return Err(format!("Invalid message type"));
        }
        let mut tidbuf = [0u8; 4];
        tidbuf[1..4].copy_from_slice(&bytes[1..4]);
        let transaction_id = u32::from_be_bytes(tidbuf);
        let mut client_id: Option<ClientIdOpt> = None;
        let mut server_id: Option<ServerIdOpt> = None;
        let mut opt_req: Option<OptReqOpt> = None;
        let mut elapsed_time: Option<ElapsedTimeOpt> = None;
        let mut user_class: Option<UserClassOpt> = None;
        let mut vendor_classes = Vec::<VendorClassOpt>::new();
        let mut vendor_infos = Vec::<VendorInfoOpt>::new();
        let mut reconf_accept: Option<ReconfAcceptOpt> = None;
        let mut unknown_opts = Vec::<Dhcp6Opt>::new();
        let mut pos = Self::FIXED_LEN;
        while pos < bytes.len() {
            if bytes.len() < pos + OPT_HDR_LEN {
                return Err(format!("Too short option"));
            }
            let opt_type = u16::from_be_bytes(bytes[pos..pos + 2].try_into().unwrap());
            let opt_len = u16::from_be_bytes(bytes[pos + 2..pos + 4].try_into().unwrap()) as usize;
            let opt_bytes_len = OPT_HDR_LEN + opt_len;
            if bytes.len() < pos + opt_bytes_len {
                return Err(format!("Too short option"));
            }
            let opt_bytes = &bytes[pos..pos + opt_bytes_len];
            match opt_type {
                ClientIdOpt::OPT_CODE => {
                    client_id = Some(ClientIdOpt::parse(opt_bytes)?);
                }
                ServerIdOpt::OPT_CODE => {
                    server_id = Some(ServerIdOpt::parse(opt_bytes)?);
                }
                OptReqOpt::OPT_CODE => {
                    opt_req = Some(OptReqOpt::parse(opt_bytes)?);
                }
                ElapsedTimeOpt::OPT_CODE => {
                    elapsed_time = Some(ElapsedTimeOpt::parse(opt_bytes)?);
                }
                UserClassOpt::OPT_CODE => {
                    user_class = Some(UserClassOpt::parse(opt_bytes)?);
                }
                VendorClassOpt::OPT_CODE => {
                    vendor_classes.push(VendorClassOpt::parse(opt_bytes)?);
                }
                VendorInfoOpt::OPT_CODE => {
                    vendor_infos.push(VendorInfoOpt::parse(opt_bytes)?);
                }
                ReconfAcceptOpt::OPT_CODE => {
                    reconf_accept = Some(ReconfAcceptOpt::parse(opt_bytes)?);
                }
                _ => {
                    unknown_opts.push(Dhcp6Opt::parse(opt_bytes)?);
                }
            }
            pos += opt_bytes_len;
        }
        if pos != bytes.len() {
            return Err(format!("Invalid option length"));
        }
        Ok(Self {
            transaction_id: transaction_id,
            client_id: client_id,
            server_id: server_id,
            opt_req: opt_req,
            elapsed_time: elapsed_time,
            user_class: user_class,
            vendor_classes: vendor_classes,
            vendor_infos: vendor_infos,
            reconf_accept: reconf_accept,
            unknown_opts: unknown_opts,
        })
    }
}

// Relay-forward Message
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayForwardMsg {
    pub hop_count: u8,
    pub link_addr: Ipv6Addr,
    pub peer_addr: Ipv6Addr,
    pub relay_msg: Option<RelayMsgOpt>,
    pub vendor_infos: Vec<VendorInfoOpt>,
    pub interface_id: Option<InterfaceIdOpt>,
    pub unknown_opts: Vec<Dhcp6Opt>,
}

impl RelayForwardMsg {
    const MSG_TYPE: u8 = 12;
    const FIXED_LEN: usize = 34;

    #[allow(unused)]
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0] = Self::MSG_TYPE; // Type
        buf[1] = self.hop_count;
        buf[2..18].copy_from_slice(&self.link_addr.octets());
        buf[18..34].copy_from_slice(&self.peer_addr.octets());
        let mut pos = Self::FIXED_LEN;
        if let Some(relay_msg) = &self.relay_msg {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += relay_msg.serialize(&mut buf[pos..])?;
        }
        for vendor_info in &self.vendor_infos {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += vendor_info.serialize(&mut buf[pos..])?;
        }
        if let Some(interface_id) = &self.interface_id {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += interface_id.serialize(&mut buf[pos..])?;
        }
        for unknown_opt in &self.unknown_opts {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += unknown_opt.serialize(&mut buf[pos..])?;
        }
        Ok(pos)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short message"));
        }
        let msg_type = bytes[0];
        if msg_type != Self::MSG_TYPE {
            return Err(format!("Invalid message type"));
        }
        let hop_count = bytes[1];
        let link_addr: [u8; 16] = bytes[2..18].try_into().unwrap();
        let link_addr = Ipv6Addr::from_octets(link_addr);
        let peer_addr: [u8; 16] = bytes[18..34].try_into().unwrap();
        let peer_addr = Ipv6Addr::from_octets(peer_addr);
        let mut relay_msg: Option<RelayMsgOpt> = None;
        let mut vendor_infos = Vec::<VendorInfoOpt>::new();
        let mut interface_id: Option<InterfaceIdOpt> = None;
        let mut unknown_opts = Vec::<Dhcp6Opt>::new();
        let mut pos = Self::FIXED_LEN;
        while pos < bytes.len() {
            if bytes.len() < pos + OPT_HDR_LEN {
                return Err(format!("Too short option"));
            }
            let opt_type = u16::from_be_bytes(bytes[pos..pos + 2].try_into().unwrap());
            let opt_len = u16::from_be_bytes(bytes[pos + 2..pos + 4].try_into().unwrap()) as usize;
            let opt_bytes_len = OPT_HDR_LEN + opt_len;
            if bytes.len() < pos + opt_bytes_len {
                return Err(format!("Too short option"));
            }
            let opt_bytes = &bytes[pos..pos + opt_bytes_len];
            match opt_type {
                RelayMsgOpt::OPT_CODE => {
                    relay_msg = Some(RelayMsgOpt::parse(opt_bytes)?);
                }
                VendorInfoOpt::OPT_CODE => {
                    vendor_infos.push(VendorInfoOpt::parse(opt_bytes)?);
                }
                InterfaceIdOpt::OPT_CODE => {
                    interface_id = Some(InterfaceIdOpt::parse(opt_bytes)?);
                }
                _ => {
                    unknown_opts.push(Dhcp6Opt::parse(opt_bytes)?);
                }
            }
            pos += opt_bytes_len;
        }
        if pos != bytes.len() {
            return Err(format!("Invalid option length"));
        }
        Ok(Self {
            hop_count: hop_count,
            link_addr: link_addr,
            peer_addr: peer_addr,
            relay_msg: relay_msg,
            vendor_infos: vendor_infos,
            interface_id: interface_id,
            unknown_opts: unknown_opts,
        })
    }
}

// Relay-reply Message
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayReplyMsg {
    pub hop_count: u8,
    pub link_addr: Ipv6Addr,
    pub peer_addr: Ipv6Addr,
    pub relay_msg: Option<RelayMsgOpt>,
    pub vendor_infos: Vec<VendorInfoOpt>,
    pub interface_id: Option<InterfaceIdOpt>,
    pub unknown_opts: Vec<Dhcp6Opt>,
}

impl RelayReplyMsg {
    const MSG_TYPE: u8 = 13;
    const FIXED_LEN: usize = 34;

    #[allow(unused)]
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0] = Self::MSG_TYPE; // Type
        buf[1] = self.hop_count;
        buf[2..18].copy_from_slice(&self.link_addr.octets());
        buf[18..34].copy_from_slice(&self.peer_addr.octets());
        let mut pos = Self::FIXED_LEN;
        if let Some(relay_msg) = &self.relay_msg {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += relay_msg.serialize(&mut buf[pos..])?;
        }
        for vendor_info in &self.vendor_infos {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += vendor_info.serialize(&mut buf[pos..])?;
        }
        if let Some(interface_id) = &self.interface_id {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += interface_id.serialize(&mut buf[pos..])?;
        }
        for unknown_opt in &self.unknown_opts {
            if buf.len() < pos {
                return Err(format!("Too short buffer"));
            }
            pos += unknown_opt.serialize(&mut buf[pos..])?;
        }
        Ok(pos)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short message"));
        }
        let msg_type = bytes[0];
        if msg_type != Self::MSG_TYPE {
            return Err(format!("Invalid message type"));
        }
        let hop_count = bytes[1];
        let link_addr: [u8; 16] = bytes[2..18].try_into().unwrap();
        let link_addr = Ipv6Addr::from_octets(link_addr);
        let peer_addr: [u8; 16] = bytes[18..34].try_into().unwrap();
        let peer_addr = Ipv6Addr::from_octets(peer_addr);
        let mut relay_msg: Option<RelayMsgOpt> = None;
        let mut vendor_infos = Vec::<VendorInfoOpt>::new();
        let mut interface_id: Option<InterfaceIdOpt> = None;
        let mut unknown_opts = Vec::<Dhcp6Opt>::new();
        let mut pos = Self::FIXED_LEN;
        while pos < bytes.len() {
            if bytes.len() < pos + OPT_HDR_LEN {
                return Err(format!("Too short option"));
            }
            let opt_type = u16::from_be_bytes(bytes[pos..pos + 2].try_into().unwrap());
            let opt_len = u16::from_be_bytes(bytes[pos + 2..pos + 4].try_into().unwrap()) as usize;
            let opt_bytes_len = OPT_HDR_LEN + opt_len;
            if bytes.len() < pos + opt_bytes_len {
                return Err(format!("Too short option"));
            }
            let opt_bytes = &bytes[pos..pos + opt_bytes_len];
            match opt_type {
                RelayMsgOpt::OPT_CODE => {
                    relay_msg = Some(RelayMsgOpt::parse(opt_bytes)?);
                }
                VendorInfoOpt::OPT_CODE => {
                    vendor_infos.push(VendorInfoOpt::parse(opt_bytes)?);
                }
                InterfaceIdOpt::OPT_CODE => {
                    interface_id = Some(InterfaceIdOpt::parse(opt_bytes)?);
                }
                _ => {
                    unknown_opts.push(Dhcp6Opt::parse(opt_bytes)?);
                }
            }
            pos += opt_bytes_len;
        }
        if pos != bytes.len() {
            return Err(format!("Invalid option length"));
        }
        Ok(Self {
            hop_count: hop_count,
            link_addr: link_addr,
            peer_addr: peer_addr,
            relay_msg: relay_msg,
            vendor_infos: vendor_infos,
            interface_id: interface_id,
            unknown_opts: unknown_opts,
        })
    }
}

// DHCPv6 Packet
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Dhcp6Msg {
    Solicit(SolicitMsg),
    Advertise(AdvertiseMsg),
    Request(RequestMsg),
    Confirm(ConfirmMsg),
    Renew(RenewMsg),
    Rebind(RebindMsg),
    Decline(DeclineMsg),
    Release(ReleaseMsg),
    Reply(ReplyMsg),
    Reconf(ReconfMsg),
    InfoReq(InfoReqMsg),
    RelayForward(RelayForwardMsg),
    RelayReply(RelayReplyMsg),
}

impl Dhcp6Msg {
    #[allow(unused)]
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        match self {
            Dhcp6Msg::Solicit(msg) => msg.serialize(buf),
            Dhcp6Msg::Advertise(msg) => msg.serialize(buf),
            Dhcp6Msg::Request(msg) => msg.serialize(buf),
            Dhcp6Msg::Confirm(msg) => msg.serialize(buf),
            Dhcp6Msg::Renew(msg) => msg.serialize(buf),
            Dhcp6Msg::Rebind(msg) => msg.serialize(buf),
            Dhcp6Msg::Decline(msg) => msg.serialize(buf),
            Dhcp6Msg::Release(msg) => msg.serialize(buf),
            Dhcp6Msg::Reply(msg) => msg.serialize(buf),
            Dhcp6Msg::Reconf(msg) => msg.serialize(buf),
            Dhcp6Msg::InfoReq(msg) => msg.serialize(buf),
            Dhcp6Msg::RelayForward(msg) => msg.serialize(buf),
            Dhcp6Msg::RelayReply(msg) => msg.serialize(buf),
        }
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 1 {
            return Err(format!("Too short message"));
        }
        let msg_type = bytes[0];
        match msg_type {
            SolicitMsg::MSG_TYPE => Ok(Dhcp6Msg::Solicit(SolicitMsg::parse(bytes)?)),
            AdvertiseMsg::MSG_TYPE => Ok(Dhcp6Msg::Advertise(AdvertiseMsg::parse(bytes)?)),
            RequestMsg::MSG_TYPE => Ok(Dhcp6Msg::Request(RequestMsg::parse(bytes)?)),
            ConfirmMsg::MSG_TYPE => Ok(Dhcp6Msg::Confirm(ConfirmMsg::parse(bytes)?)),
            RenewMsg::MSG_TYPE => Ok(Dhcp6Msg::Renew(RenewMsg::parse(bytes)?)),
            RebindMsg::MSG_TYPE => Ok(Dhcp6Msg::Rebind(RebindMsg::parse(bytes)?)),
            DeclineMsg::MSG_TYPE => Ok(Dhcp6Msg::Decline(DeclineMsg::parse(bytes)?)),
            ReleaseMsg::MSG_TYPE => Ok(Dhcp6Msg::Release(ReleaseMsg::parse(bytes)?)),
            ReplyMsg::MSG_TYPE => Ok(Dhcp6Msg::Reply(ReplyMsg::parse(bytes)?)),
            ReconfMsg::MSG_TYPE => Ok(Dhcp6Msg::Reconf(ReconfMsg::parse(bytes)?)),
            InfoReqMsg::MSG_TYPE => Ok(Dhcp6Msg::InfoReq(InfoReqMsg::parse(bytes)?)),
            RelayForwardMsg::MSG_TYPE => Ok(Dhcp6Msg::RelayForward(RelayForwardMsg::parse(bytes)?)),
            RelayReplyMsg::MSG_TYPE => Ok(Dhcp6Msg::RelayReply(RelayReplyMsg::parse(bytes)?)),
            _ => Err(format!("Unknown message")),
        }
    }
}
