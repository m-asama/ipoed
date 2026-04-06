// SPDX-License-Identifier: MIT
// Copyright(c) 2026 Masakazu Asama

use std::net::Ipv6Addr;

use crate::dhcp6::packets::*;

#[test]
fn unknown_duid() -> Result<(), String> {
    let orgraw = [
        0x00, 0xff, // DUID-Type
        0x11, 0x22, 0x33, 0x44,
    ];
    let orgopt = UnknownDuid {
        duid: vec![0x00, 0xff, 0x11, 0x22, 0x33, 0x44],
    };
    let resopt = match UnknownDuid::parse(&orgraw) {
        Ok(resopt) => resopt,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resopt: {:?}", resopt);
    println!("orgopt: {:?}", orgopt);
    if resopt != orgopt {
        return Err(format!("resopt not eq"));
    }
    let mut resraw = [0u8; 6];
    if let Err(e) = resopt.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn llt_duid() -> Result<(), String> {
    let orgraw = [
        0x00, 0x01, // DUID-Type
        0x00, 0x01, // hardware type (Ethernet)
        0x66, 0xa5, 0x23, 0xb2, // time
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // link-layer address
    ];
    let orgopt = LltDuid {
        time: 1722098610,
        ll_addr: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
    };
    let resopt = match LltDuid::parse(&orgraw) {
        Ok(resopt) => resopt,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resopt: {:?}", resopt);
    println!("orgopt: {:?}", orgopt);
    if resopt != orgopt {
        return Err(format!("resopt not eq"));
    }
    let mut resraw = [0u8; 14];
    if let Err(e) = resopt.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn vendor_duid() -> Result<(), String> {
    let orgraw = [
        0x00, 0x02, // DUID-Type
        0x12, 0x34, 0x56, 0x78, // enterprise-number
        0x11, 0x22, 0x33, 0x44, // identifier
    ];
    let orgopt = VendorDuid {
        enterprise_num: 305419896,
        identifier: vec![0x11, 0x22, 0x33, 0x44],
    };
    let resopt = match VendorDuid::parse(&orgraw) {
        Ok(resopt) => resopt,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resopt: {:?}", resopt);
    println!("orgopt: {:?}", orgopt);
    if resopt != orgopt {
        return Err(format!("resopt not eq"));
    }
    let mut resraw = [0u8; 10];
    if let Err(e) = resopt.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn ll_duid() -> Result<(), String> {
    let orgraw = [
        0x00, 0x03, // DUID-Type
        0x00, 0x01, // hardware type (Ethernet)
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // link-layer address
    ];
    let orgopt = LlDuid {
        ll_addr: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
    };
    let resopt = match LlDuid::parse(&orgraw) {
        Ok(resopt) => resopt,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resopt: {:?}", resopt);
    println!("orgopt: {:?}", orgopt);
    if resopt != orgopt {
        return Err(format!("resopt not eq"));
    }
    let mut resraw = [0u8; 10];
    if let Err(e) = resopt.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn uuid_duid() -> Result<(), String> {
    let orgraw = [
        0x00, 0x04, // DUID-Type
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // UUID
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, // UUID
    ];
    let orgopt = UuidDuid {
        uuid: [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // UUID
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, // UUID
        ],
    };
    let resopt = match UuidDuid::parse(&orgraw) {
        Ok(resopt) => resopt,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resopt: {:?}", resopt);
    println!("orgopt: {:?}", orgopt);
    if resopt != orgopt {
        return Err(format!("resopt not eq"));
    }
    let mut resraw = [0u8; 18];
    if let Err(e) = resopt.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn duid() -> Result<(), String> {
    let orgraw = [
        0x00, 0x01, // DUID-Type
        0x00, 0x01, // hardware type (Ethernet)
        0x66, 0xa5, 0x23, 0xb2, // time
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // link-layer address
    ];
    let orgopt = Duid::Llt(LltDuid {
        time: 1722098610,
        ll_addr: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
    });
    let resopt = match Duid::parse(&orgraw) {
        Ok(resopt) => resopt,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resopt: {:?}", resopt);
    println!("orgopt: {:?}", orgopt);
    if resopt != orgopt {
        return Err(format!("resopt not eq"));
    }
    let mut resraw = [0u8; 14];
    if let Err(e) = resopt.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn unknown_opt() -> Result<(), String> {
    let orgraw = [
        0x00, 0xff, // option-code
        0x00, 0x04, // option-len
        0x01, 0x02, 0x03, 0x04,
    ];
    let orgopt = UnknownOpt {
        opt_code: 255,
        opt_data: vec![0x01, 0x02, 0x03, 0x04],
    };
    let resopt = match UnknownOpt::parse(&orgraw) {
        Ok(resopt) => resopt,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resopt: {:?}", resopt);
    println!("orgopt: {:?}", orgopt);
    if resopt != orgopt {
        return Err(format!("resopt not eq"));
    }
    let mut resraw = [0u8; 8];
    if let Err(e) = resopt.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn client_id_opt() -> Result<(), String> {
    let orgraw = [
        0x00, 0x01, // option-code
        0x00, 0x0a, // option-len
        0x00, 0x03, // DUID-Type
        0x00, 0x01, // hardware type (Ethernet)
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // link-layer address
    ];
    let orgopt = ClientIdOpt {
        duid: Duid::Ll(LlDuid {
            ll_addr: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        }),
    };
    let resopt = match ClientIdOpt::parse(&orgraw) {
        Ok(resopt) => resopt,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resopt: {:?}", resopt);
    println!("orgopt: {:?}", orgopt);
    if resopt != orgopt {
        return Err(format!("resopt not eq"));
    }
    let mut resraw = [0u8; 14];
    if let Err(e) = resopt.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn server_id_opt() -> Result<(), String> {
    let orgraw = [
        0x00, 0x02, // option-code
        0x00, 0x0a, // option-len
        0x00, 0x03, // DUID-Type
        0x00, 0x01, // hardware type (Ethernet)
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // link-layer address
    ];
    let orgopt = ServerIdOpt {
        duid: Duid::Ll(LlDuid {
            ll_addr: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        }),
    };
    let resopt = match ServerIdOpt::parse(&orgraw) {
        Ok(resopt) => resopt,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resopt: {:?}", resopt);
    println!("orgopt: {:?}", orgopt);
    if resopt != orgopt {
        return Err(format!("resopt not eq"));
    }
    let mut resraw = [0u8; 14];
    if let Err(e) = resopt.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn ia_na_opt() -> Result<(), String> {
    let orgraw = [
        0x00, 0x03, // option-code
        0x00, 0x51, // option-len
        0x01, 0x02, 0x03, 0x04, // IAID
        0x00, 0x00, 0x04, 0xd2, // T1
        0x00, 0x00, 0x09, 0x29, // T2
        0x00, 0x05, // option-code
        0x00, 0x18, // option-len
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x6f, //
        0x00, 0x00, 0x00, 0xde, //
        0x00, 0x05, // option-code
        0x00, 0x18, // option-len
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x02, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x01, 0x4d, //
        0x00, 0x00, 0x01, 0xbc, //
        0x00, 0x0d, // option-code
        0x00, 0x09, // option-len
        0x00, 0x00, // status-code
        0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, // "Success"
    ];
    let orgopt = IaNaOpt {
        iaid: [0x01, 0x02, 0x03, 0x04],
        t1: 1234,
        t2: 2345,
        ia_addrs: vec![
            IaAddrOpt {
                ipv6_addr: Ipv6Addr::from([0x2001, 0xdb8, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0]),
                preferred_lifetime: 111,
                valid_lifetime: 222,
                unknown_opts: vec![],
            },
            IaAddrOpt {
                ipv6_addr: Ipv6Addr::from([0x2001, 0xdb8, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0]),
                preferred_lifetime: 333,
                valid_lifetime: 444,
                unknown_opts: vec![],
            },
        ],
        status_code: Some(StatusCodeOpt {
            status_code: StatusCode::Success,
            status_msg: String::from("Success"),
        }),
        unknown_opts: vec![],
    };
    let resopt = match IaNaOpt::parse(&orgraw) {
        Ok(resopt) => resopt,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resopt: {:?}", resopt);
    println!("orgopt: {:?}", orgopt);
    if resopt != orgopt {
        return Err(format!("resopt not eq"));
    }
    let mut resraw = [0u8; 85];
    if let Err(e) = resopt.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn ia_addr_opt() -> Result<(), String> {
    let orgraw = [
        0x00, 0x05, // option-code
        0x00, 0x18, // option-len
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x6f, //
        0x00, 0x00, 0x00, 0xde, //
    ];
    let orgopt = IaAddrOpt {
        ipv6_addr: Ipv6Addr::from([0x2001, 0xdb8, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0]),
        preferred_lifetime: 111,
        valid_lifetime: 222,
        unknown_opts: vec![],
    };
    let resopt = match IaAddrOpt::parse(&orgraw) {
        Ok(resopt) => resopt,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resopt: {:?}", resopt);
    println!("orgopt: {:?}", orgopt);
    if resopt != orgopt {
        return Err(format!("resopt not eq"));
    }
    let mut resraw = [0u8; 28];
    if let Err(e) = resopt.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn opt_req_opt() -> Result<(), String> {
    let orgraw = [
        0x00, 0x06, // option-code
        0x00, 0x04, // option-len
        0x00, 0x17, //
        0x00, 0x18, //
    ];
    let orgopt = OptReqOpt {
        requested_opt_codes: vec![23, 24],
    };
    let resopt = match OptReqOpt::parse(&orgraw) {
        Ok(resopt) => resopt,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resopt: {:?}", resopt);
    println!("orgopt: {:?}", orgopt);
    if resopt != orgopt {
        return Err(format!("resopt not eq"));
    }
    let mut resraw = [0u8; 8];
    if let Err(e) = resopt.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn pref_opt() -> Result<(), String> {
    let orgraw = [
        0x00, 0x07, // option-code
        0x00, 0x01, // option-len
        0x7b,
    ];
    let orgopt = PrefOpt { pref_value: 123 };
    let resopt = match PrefOpt::parse(&orgraw) {
        Ok(resopt) => resopt,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resopt: {:?}", resopt);
    println!("orgopt: {:?}", orgopt);
    if resopt != orgopt {
        return Err(format!("resopt not eq"));
    }
    let mut resraw = [0u8; 5];
    if let Err(e) = resopt.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn elapsed_time_opt() -> Result<(), String> {
    let orgraw = [
        0x00, 0x08, // option-code
        0x00, 0x02, // option-len
        0x00, 0x7b,
    ];
    let orgopt = ElapsedTimeOpt { elapsed_time: 123 };
    let resopt = match ElapsedTimeOpt::parse(&orgraw) {
        Ok(resopt) => resopt,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resopt: {:?}", resopt);
    println!("orgopt: {:?}", orgopt);
    if resopt != orgopt {
        return Err(format!("resopt not eq"));
    }
    let mut resraw = [0u8; 6];
    if let Err(e) = resopt.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn relay_msg_opt() -> Result<(), String> {
    let orgraw = [
        0x00, 0x09, // option-code
        0x00, 0x04, // option-len
        0x01, 0x02, 0x03, 0x04,
    ];
    let orgopt = RelayMsgOpt {
        dhcp_relay_msg: vec![0x01, 0x02, 0x03, 0x04],
    };
    let resopt = match RelayMsgOpt::parse(&orgraw) {
        Ok(resopt) => resopt,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resopt: {:?}", resopt);
    println!("orgopt: {:?}", orgopt);
    if resopt != orgopt {
        return Err(format!("resopt not eq"));
    }
    let mut resraw = [0u8; 8];
    if let Err(e) = resopt.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn auth_opt() -> Result<(), String> {
    let orgraw = [
        0x00, 0x0b, // option-code
        0x00, 0x0f, // option-len
        0x01, // protocol
        0x02, // algorithm
        0x03, // RDM
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, // replay detection
        0x05, 0x06, 0x07, 0x08, // authentication information
    ];
    let orgopt = AuthOpt {
        protocol: 1,
        algorithm: 2,
        rdm: 3,
        replay_detection: 4,
        auth_info: vec![0x05, 0x06, 0x07, 0x08],
    };
    let resopt = match AuthOpt::parse(&orgraw) {
        Ok(resopt) => resopt,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resopt: {:?}", resopt);
    println!("orgopt: {:?}", orgopt);
    if resopt != orgopt {
        return Err(format!("resopt not eq"));
    }
    let mut resraw = [0u8; 19];
    if let Err(e) = resopt.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn server_ucast_opt() -> Result<(), String> {
    let orgraw = [
        0x00, 0x0c, // option-code
        0x00, 0x10, // option-len
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    ];
    let orgopt = ServerUcastOpt {
        server_addr: Ipv6Addr::from([0x2001, 0xdb8, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0]),
    };
    let resopt = match ServerUcastOpt::parse(&orgraw) {
        Ok(resopt) => resopt,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resopt: {:?}", resopt);
    println!("orgopt: {:?}", orgopt);
    if resopt != orgopt {
        return Err(format!("resopt not eq"));
    }
    let mut resraw = [0u8; 20];
    if let Err(e) = resopt.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn status_code_opt() -> Result<(), String> {
    let orgraw = [
        0x00, 0x0d, // option-code
        0x00, 0x09, // option-len
        0x00, 0x00, // status-code
        0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, // "Success"
    ];
    let orgopt = StatusCodeOpt {
        status_code: StatusCode::Success,
        status_msg: String::from("Success"),
    };
    let resopt = match StatusCodeOpt::parse(&orgraw) {
        Ok(resopt) => resopt,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resopt: {:?}", resopt);
    println!("orgopt: {:?}", orgopt);
    if resopt != orgopt {
        return Err(format!("resopt not eq"));
    }
    let mut resraw = [0u8; 13];
    if let Err(e) = resopt.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn rapid_commit_opt() -> Result<(), String> {
    let orgraw = [
        0x00, 0x0e, // option-code
        0x00, 0x00, // option-len
    ];
    let orgopt = RapidCommitOpt {};
    let resopt = match RapidCommitOpt::parse(&orgraw) {
        Ok(resopt) => resopt,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resopt: {:?}", resopt);
    println!("orgopt: {:?}", orgopt);
    if resopt != orgopt {
        return Err(format!("resopt not eq"));
    }
    let mut resraw = [0u8; 4];
    if let Err(e) = resopt.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn user_class_opt() -> Result<(), String> {
    let orgraw = [
        0x00, 0x0f, // option-code
        0x00, 0x04, // option-len
        0x01, 0x02, 0x03, 0x04, // user-class-data
    ];
    let orgopt = UserClassOpt {
        user_class_data: vec![0x01, 0x02, 0x03, 0x04],
    };
    let resopt = match UserClassOpt::parse(&orgraw) {
        Ok(resopt) => resopt,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resopt: {:?}", resopt);
    println!("orgopt: {:?}", orgopt);
    if resopt != orgopt {
        return Err(format!("resopt not eq"));
    }
    let mut resraw = [0u8; 8];
    if let Err(e) = resopt.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn vendor_class_opt() -> Result<(), String> {
    let orgraw = [
        0x00, 0x10, // option-code
        0x00, 0x08, // option-len
        0x00, 0x00, 0x00, 0x7b, // enterprise-number
        0x01, 0x02, 0x03, 0x04, // vendor-class-data
    ];
    let orgopt = VendorClassOpt {
        enterprise_num: 123,
        vendor_class_data: vec![0x01, 0x02, 0x03, 0x04],
    };
    let resopt = match VendorClassOpt::parse(&orgraw) {
        Ok(resopt) => resopt,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resopt: {:?}", resopt);
    println!("orgopt: {:?}", orgopt);
    if resopt != orgopt {
        return Err(format!("resopt not eq"));
    }
    let mut resraw = [0u8; 12];
    if let Err(e) = resopt.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn vendor_info_opt() -> Result<(), String> {
    let orgraw = [
        0x00, 0x11, // option-code
        0x00, 0x08, // option-len
        0x00, 0x00, 0x00, 0x7b, // enterprise-number
        0x01, 0x02, 0x03, 0x04, // vendor-option-data
    ];
    let orgopt = VendorInfoOpt {
        enterprise_num: 123,
        vendor_option_data: vec![0x01, 0x02, 0x03, 0x04],
    };
    let resopt = match VendorInfoOpt::parse(&orgraw) {
        Ok(resopt) => resopt,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resopt: {:?}", resopt);
    println!("orgopt: {:?}", orgopt);
    if resopt != orgopt {
        return Err(format!("resopt not eq"));
    }
    let mut resraw = [0u8; 12];
    if let Err(e) = resopt.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn interface_id_opt() -> Result<(), String> {
    let orgraw = [
        0x00, 0x12, // option-code
        0x00, 0x04, // option-len
        0x01, 0x02, 0x03, 0x04, // interface-id
    ];
    let orgopt = InterfaceIdOpt {
        interface_id: vec![0x01, 0x02, 0x03, 0x04],
    };
    let resopt = match InterfaceIdOpt::parse(&orgraw) {
        Ok(resopt) => resopt,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resopt: {:?}", resopt);
    println!("orgopt: {:?}", orgopt);
    if resopt != orgopt {
        return Err(format!("resopt not eq"));
    }
    let mut resraw = [0u8; 8];
    if let Err(e) = resopt.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn reconf_msg_opt() -> Result<(), String> {
    let orgraw = [
        0x00, 0x13, // option-code
        0x00, 0x01, // option-len
        0x05, // msg-type
    ];
    let orgopt = ReconfMsgOpt { msg_type: 5 };
    let resopt = match ReconfMsgOpt::parse(&orgraw) {
        Ok(resopt) => resopt,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resopt: {:?}", resopt);
    println!("orgopt: {:?}", orgopt);
    if resopt != orgopt {
        return Err(format!("resopt not eq"));
    }
    let mut resraw = [0u8; 5];
    if let Err(e) = resopt.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn reconf_accept_opt() -> Result<(), String> {
    let orgraw = [
        0x00, 0x14, // option-code
        0x00, 0x00, // option-len
    ];
    let orgopt = ReconfAcceptOpt {};
    let resopt = match ReconfAcceptOpt::parse(&orgraw) {
        Ok(resopt) => resopt,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resopt: {:?}", resopt);
    println!("orgopt: {:?}", orgopt);
    if resopt != orgopt {
        return Err(format!("resopt not eq"));
    }
    let mut resraw = [0u8; 4];
    if let Err(e) = resopt.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn ia_pd_opt() -> Result<(), String> {
    let orgraw = [
        0x00, 0x19, // option-code
        0x00, 0x53, // option-len
        0x01, 0x02, 0x03, 0x04, // IAID
        0x00, 0x00, 0x04, 0xd2, // T1
        0x00, 0x00, 0x09, 0x29, // T2
        0x00, 0x1a, // option-code
        0x00, 0x19, // option-len
        0x00, 0x00, 0x00, 0x6f, // preferred-lifetime
        0x00, 0x00, 0x00, 0xde, // valid-lifetime
        0x38, // prefix-length
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x01, 0x00, // IPv6-prefix(1)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // IPv6-prefix(2)
        0x00, 0x1a, // option-code
        0x00, 0x19, // option-len
        0x00, 0x00, 0x01, 0x4d, // preferred-lifetime
        0x00, 0x00, 0x01, 0xbc, // valid-lifetime
        0x38, // prefix-length
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x02, 0x00, // IPv6-prefix(1)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // IPv6-prefix(2)
        0x00, 0x0d, // option-code
        0x00, 0x09, // option-len
        0x00, 0x00, // status-code
        0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, // "Success"
    ];
    let orgopt = IaPdOpt {
        iaid: [0x01, 0x02, 0x03, 0x04],
        t1: 1234,
        t2: 2345,
        ia_prefixes: vec![
            IaPrefixOpt {
                preferred_lifetime: 111,
                valid_lifetime: 222,
                prefix_len: 56,
                ipv6_prefix: Ipv6Addr::from([0x2001, 0xdb8, 0x0, 0x100, 0x0, 0x0, 0x0, 0x0]),
                unknown_opts: vec![],
            },
            IaPrefixOpt {
                preferred_lifetime: 333,
                valid_lifetime: 444,
                prefix_len: 56,
                ipv6_prefix: Ipv6Addr::from([0x2001, 0xdb8, 0x0, 0x200, 0x0, 0x0, 0x0, 0x0]),
                unknown_opts: vec![],
            },
        ],
        status_code: Some(StatusCodeOpt {
            status_code: StatusCode::Success,
            status_msg: String::from("Success"),
        }),
        unknown_opts: vec![],
    };
    let resopt = match IaPdOpt::parse(&orgraw) {
        Ok(resopt) => resopt,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resopt: {:?}", resopt);
    println!("orgopt: {:?}", orgopt);
    if resopt != orgopt {
        return Err(format!("resopt not eq"));
    }
    let mut resraw = [0u8; 87];
    if let Err(e) = resopt.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn ia_prefix_opt() -> Result<(), String> {
    let orgraw = [
        0x00, 0x1a, // option-code
        0x00, 0x19, // option-len
        0x00, 0x00, 0x00, 0x6f, // preferred-lifetime
        0x00, 0x00, 0x00, 0xde, // valid-lifetime
        0x38, // prefix-length
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x01, 0x00, // IPv6-prefix(1)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // IPv6-prefix(2)
    ];
    let orgopt = IaPrefixOpt {
        preferred_lifetime: 111,
        valid_lifetime: 222,
        prefix_len: 56,
        ipv6_prefix: Ipv6Addr::from([0x2001, 0xdb8, 0x0, 0x100, 0x0, 0x0, 0x0, 0x0]),
        unknown_opts: vec![],
    };
    let resopt = match IaPrefixOpt::parse(&orgraw) {
        Ok(resopt) => resopt,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resopt: {:?}", resopt);
    println!("orgopt: {:?}", orgopt);
    if resopt != orgopt {
        return Err(format!("resopt not eq"));
    }
    let mut resraw = [0u8; 29];
    if let Err(e) = resopt.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn info_refresh_time_opt() -> Result<(), String> {
    let orgraw = [
        0x00, 0x20, // option-code
        0x00, 0x04, // option-len
        0x00, 0x00, 0x00, 0x7b, // information-refresh-time
    ];
    let orgopt = InfoRefreshTimeOpt {
        information_refresh_time: 123,
    };
    let resopt = match InfoRefreshTimeOpt::parse(&orgraw) {
        Ok(resopt) => resopt,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resopt: {:?}", resopt);
    println!("orgopt: {:?}", orgopt);
    if resopt != orgopt {
        return Err(format!("resopt not eq"));
    }
    let mut resraw = [0u8; 8];
    if let Err(e) = resopt.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn sol_max_rt_opt() -> Result<(), String> {
    let orgraw = [
        0x00, 0x52, // option-code
        0x00, 0x04, // option-len
        0x00, 0x00, 0x00, 0x7b, // SOL_MAX_RT value
    ];
    let orgopt = SolMaxRtOpt {
        sol_max_rt_val: 123,
    };
    let resopt = match SolMaxRtOpt::parse(&orgraw) {
        Ok(resopt) => resopt,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resopt: {:?}", resopt);
    println!("orgopt: {:?}", orgopt);
    if resopt != orgopt {
        return Err(format!("resopt not eq"));
    }
    let mut resraw = [0u8; 8];
    if let Err(e) = resopt.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn inf_max_rt_opt() -> Result<(), String> {
    let orgraw = [
        0x00, 0x53, // option-code
        0x00, 0x04, // option-len
        0x00, 0x00, 0x00, 0x7b, // INF_MAX_RT value
    ];
    let orgopt = InfMaxRtOpt {
        inf_max_rt_val: 123,
    };
    let resopt = match InfMaxRtOpt::parse(&orgraw) {
        Ok(resopt) => resopt,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resopt: {:?}", resopt);
    println!("orgopt: {:?}", orgopt);
    if resopt != orgopt {
        return Err(format!("resopt not eq"));
    }
    let mut resraw = [0u8; 8];
    if let Err(e) = resopt.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn dns_recursive_name_server_opt() -> Result<(), String> {
    let orgraw = [
        0x00, 0x17, // option-code
        0x00, 0x20, // option-len
        0x24, 0x04, 0x01, 0xa8, 0x7f, 0x01, 0x00, 0x0b, // (1)a
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, // (1)b
        0x24, 0x04, 0x01, 0xa8, 0x7f, 0x01, 0x00, 0x0a, // (2)a
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, // (2)b
    ];
    let orgopt = DnsRecursiveNameServerOpt {
        dns_recursive_name_servers: vec![
            Ipv6Addr::from([0x2404, 0x1a8, 0x7f01, 0xb, 0x0, 0x0, 0x0, 0x3]),
            Ipv6Addr::from([0x2404, 0x1a8, 0x7f01, 0xa, 0x0, 0x0, 0x0, 0x3]),
        ],
    };
    let resopt = match DnsRecursiveNameServerOpt::parse(&orgraw) {
        Ok(resopt) => resopt,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resopt: {:?}", resopt);
    println!("orgopt: {:?}", orgopt);
    if resopt != orgopt {
        return Err(format!("resopt not eq"));
    }
    let mut resraw = [0u8; 36];
    if let Err(e) = resopt.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn comain_search_list_opt() -> Result<(), String> {
    let orgraw = [
        0x00, 0x18, // option-code
        0x00, 0x19, // option-len
        0x0a, 0x66, 0x6c, 0x65, 0x74, 0x73, 0x2d, 0x65, 0x61, 0x73, 0x74, // flets-east
        0x02, 0x6a, 0x70, // jp
        0x00, // .
        0x05, 0x69, 0x70, 0x74, 0x76, 0x66, // iptvf
        0x02, 0x6a, 0x70, // jp
        0x00, // .
    ];
    let orgopt = DomainSearchListOpt {
        searchs: vec![String::from("flets-east.jp"), String::from("iptvf.jp")],
    };
    let resopt = match DomainSearchListOpt::parse(&orgraw) {
        Ok(resopt) => resopt,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resopt: {:?}", resopt);
    println!("orgopt: {:?}", orgopt);
    if resopt != orgopt {
        return Err(format!("resopt not eq"));
    }
    let mut resraw = [0u8; 29];
    if let Err(e) = resopt.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn dhcp6_opt() -> Result<(), String> {
    let orgraw = [
        0x00, 0x01, // option-code
        0x00, 0x0a, // option-len
        0x00, 0x03, // DUID-Type
        0x00, 0x01, // hardware type (Ethernet)
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // link-layer address
    ];
    let orgopt = Dhcp6Opt::ClientId(ClientIdOpt {
        duid: Duid::Ll(LlDuid {
            ll_addr: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        }),
    });
    let resopt = match Dhcp6Opt::parse(&orgraw) {
        Ok(resopt) => resopt,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resopt: {:?}", resopt);
    println!("orgopt: {:?}", orgopt);
    if resopt != orgopt {
        return Err(format!("resopt not eq"));
    }
    let mut resraw = [0u8; 14];
    if let Err(e) = resopt.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn solicit_msg() -> Result<(), String> {
    let orgraw = [
        0x01, // msg-type
        0x01, 0x02, 0x03, // transaction-id
        // client_id
        0x00, 0x01, // option-code
        0x00, 0x0a, // option-len
        0x00, 0x03, // DUID-Type
        0x00, 0x01, // hardware type (Ethernet)
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // link-layer address
        // ia_nas
        0x00, 0x03, // option-code
        0x00, 0x35, // option-len
        0x01, 0x02, 0x03, 0x04, // IAID
        0x00, 0x00, 0x04, 0xd2, // T1
        0x00, 0x00, 0x09, 0x29, // T2
        0x00, 0x05, // option-code
        0x00, 0x18, // option-len
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x6f, //
        0x00, 0x00, 0x00, 0xde, //
        0x00, 0x0d, // option-code
        0x00, 0x09, // option-len
        0x00, 0x00, // status-code
        0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, // "Success"
        // ia_pds
        0x00, 0x19, // option-code
        0x00, 0x36, // option-len
        0x01, 0x02, 0x03, 0x04, // IAID
        0x00, 0x00, 0x04, 0xd2, // T1
        0x00, 0x00, 0x09, 0x29, // T2
        0x00, 0x1a, // option-code
        0x00, 0x19, // option-len
        0x00, 0x00, 0x00, 0x6f, // preferred-lifetime
        0x00, 0x00, 0x00, 0xde, // valid-lifetime
        0x38, // prefix-length
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x01, 0x00, // IPv6-prefix(1)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // IPv6-prefix(2)
        0x00, 0x0d, // option-code
        0x00, 0x09, // option-len
        0x00, 0x00, // status-code
        0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, // "Success"
        // opt_req
        0x00, 0x06, // option-code
        0x00, 0x04, // option-len
        0x00, 0x17, //
        0x00, 0x18, //
        // elapsed_time
        0x00, 0x08, // option-code
        0x00, 0x02, // option-len
        0x00, 0x7b, //
        // rapid_commit
        0x00, 0x0e, // option-code
        0x00, 0x00, // option-len
        // user_class
        0x00, 0x0f, // option-code
        0x00, 0x04, // option-len
        0x01, 0x02, 0x03, 0x04, // user-class-data
        // vendor_classes
        0x00, 0x10, // option-code
        0x00, 0x08, // option-len
        0x00, 0x00, 0x00, 0x7b, // enterprise-number
        0x01, 0x02, 0x03, 0x04, // vendor-class-data
        // vendor_infos
        0x00, 0x11, // option-code
        0x00, 0x08, // option-len
        0x00, 0x00, 0x00, 0x7b, // enterprise-number
        0x01, 0x02, 0x03, 0x04, // vendor-option-data
        // reconf_accept
        0x00, 0x14, // option-code
        0x00, 0x00, // option-len
    ];
    let orgmsg = SolicitMsg {
        transaction_id: 66051,
        client_id: Some(ClientIdOpt {
            duid: Duid::Ll(LlDuid {
                ll_addr: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            }),
        }),
        ia_nas: vec![IaNaOpt {
            iaid: [0x01, 0x02, 0x03, 0x04],
            t1: 1234,
            t2: 2345,
            ia_addrs: vec![IaAddrOpt {
                ipv6_addr: Ipv6Addr::from([0x2001, 0xdb8, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0]),
                preferred_lifetime: 111,
                valid_lifetime: 222,
                unknown_opts: vec![],
            }],
            status_code: Some(StatusCodeOpt {
                status_code: StatusCode::Success,
                status_msg: String::from("Success"),
            }),
            unknown_opts: vec![],
        }],
        ia_pds: vec![IaPdOpt {
            iaid: [0x01, 0x02, 0x03, 0x04],
            t1: 1234,
            t2: 2345,
            ia_prefixes: vec![IaPrefixOpt {
                preferred_lifetime: 111,
                valid_lifetime: 222,
                prefix_len: 56,
                ipv6_prefix: Ipv6Addr::from([0x2001, 0xdb8, 0x0, 0x100, 0x0, 0x0, 0x0, 0x0]),
                unknown_opts: vec![],
            }],
            status_code: Some(StatusCodeOpt {
                status_code: StatusCode::Success,
                status_msg: String::from("Success"),
            }),
            unknown_opts: vec![],
        }],
        opt_req: Some(OptReqOpt {
            requested_opt_codes: vec![23, 24],
        }),
        elapsed_time: Some(ElapsedTimeOpt { elapsed_time: 123 }),
        rapid_commit: Some(RapidCommitOpt {}),
        user_class: Some(UserClassOpt {
            user_class_data: vec![0x01, 0x02, 0x03, 0x04],
        }),
        vendor_classes: vec![VendorClassOpt {
            enterprise_num: 123,
            vendor_class_data: vec![0x01, 0x02, 0x03, 0x04],
        }],
        vendor_infos: vec![VendorInfoOpt {
            enterprise_num: 123,
            vendor_option_data: vec![0x01, 0x02, 0x03, 0x04],
        }],
        reconf_accept: Some(ReconfAcceptOpt {}),
        unknown_opts: vec![],
    };
    let resmsg = match SolicitMsg::parse(&orgraw) {
        Ok(resmsg) => resmsg,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resmsg: {:?}", resmsg);
    println!("orgmsg: {:?}", orgmsg);
    if resmsg != orgmsg {
        return Err(format!("resmsg not eq"));
    }
    let mut resraw = [0u8; 187];
    if let Err(e) = resmsg.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn advertise_msg() -> Result<(), String> {
    let orgraw = [
        0x02, // msg-type
        0x01, 0x02, 0x03, // transaction-id
        // client_id
        0x00, 0x01, // option-code
        0x00, 0x0a, // option-len
        0x00, 0x03, // DUID-Type
        0x00, 0x01, // hardware type (Ethernet)
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // link-layer address
        // server_id
        0x00, 0x02, // option-code
        0x00, 0x0a, // option-len
        0x00, 0x03, // DUID-Type
        0x00, 0x01, // hardware type (Ethernet)
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // link-layer address
        // ia_nas
        0x00, 0x03, // option-code
        0x00, 0x35, // option-len
        0x01, 0x02, 0x03, 0x04, // IAID
        0x00, 0x00, 0x04, 0xd2, // T1
        0x00, 0x00, 0x09, 0x29, // T2
        0x00, 0x05, // option-code
        0x00, 0x18, // option-len
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x6f, //
        0x00, 0x00, 0x00, 0xde, //
        0x00, 0x0d, // option-code
        0x00, 0x09, // option-len
        0x00, 0x00, // status-code
        0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, // "Success"
        // ia_pds
        0x00, 0x19, // option-code
        0x00, 0x36, // option-len
        0x01, 0x02, 0x03, 0x04, // IAID
        0x00, 0x00, 0x04, 0xd2, // T1
        0x00, 0x00, 0x09, 0x29, // T2
        0x00, 0x1a, // option-code
        0x00, 0x19, // option-len
        0x00, 0x00, 0x00, 0x6f, // preferred-lifetime
        0x00, 0x00, 0x00, 0xde, // valid-lifetime
        0x38, // prefix-length
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x01, 0x00, // IPv6-prefix(1)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // IPv6-prefix(2)
        0x00, 0x0d, // option-code
        0x00, 0x09, // option-len
        0x00, 0x00, // status-code
        0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, // "Success"
        // pref
        0x00, 0x07, // option-code
        0x00, 0x01, // option-len
        0x7b, //
        // status_code
        0x00, 0x0d, // option-code
        0x00, 0x09, // option-len
        0x00, 0x00, // status-code
        0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, // "Success"
        // user_class
        0x00, 0x0f, // option-code
        0x00, 0x04, // option-len
        0x01, 0x02, 0x03, 0x04, // user-class-data
        // vendor_classes
        0x00, 0x10, // option-code
        0x00, 0x08, // option-len
        0x00, 0x00, 0x00, 0x7b, // enterprise-number
        0x01, 0x02, 0x03, 0x04, // vendor-class-data
        // vendor_infos
        0x00, 0x11, // option-code
        0x00, 0x08, // option-len
        0x00, 0x00, 0x00, 0x7b, // enterprise-number
        0x01, 0x02, 0x03, 0x04, // vendor-option-data
        // reconf_accept
        0x00, 0x14, // option-code
        0x00, 0x00, // option-len
        // sol_max_rt
        0x00, 0x52, // option-code
        0x00, 0x04, // option-len
        0x00, 0x00, 0x00, 0x7b, // SOL_MAX_RT value
    ];
    let orgmsg = AdvertiseMsg {
        transaction_id: 66051,
        client_id: Some(ClientIdOpt {
            duid: Duid::Ll(LlDuid {
                ll_addr: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            }),
        }),
        server_id: Some(ServerIdOpt {
            duid: Duid::Ll(LlDuid {
                ll_addr: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            }),
        }),
        ia_nas: vec![IaNaOpt {
            iaid: [0x01, 0x02, 0x03, 0x04],
            t1: 1234,
            t2: 2345,
            ia_addrs: vec![IaAddrOpt {
                ipv6_addr: Ipv6Addr::from([0x2001, 0xdb8, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0]),
                preferred_lifetime: 111,
                valid_lifetime: 222,
                unknown_opts: vec![],
            }],
            status_code: Some(StatusCodeOpt {
                status_code: StatusCode::Success,
                status_msg: String::from("Success"),
            }),
            unknown_opts: vec![],
        }],
        ia_pds: vec![IaPdOpt {
            iaid: [0x01, 0x02, 0x03, 0x04],
            t1: 1234,
            t2: 2345,
            ia_prefixes: vec![IaPrefixOpt {
                preferred_lifetime: 111,
                valid_lifetime: 222,
                prefix_len: 56,
                ipv6_prefix: Ipv6Addr::from([0x2001, 0xdb8, 0x0, 0x100, 0x0, 0x0, 0x0, 0x0]),
                unknown_opts: vec![],
            }],
            status_code: Some(StatusCodeOpt {
                status_code: StatusCode::Success,
                status_msg: String::from("Success"),
            }),
            unknown_opts: vec![],
        }],
        pref: Some(PrefOpt { pref_value: 123 }),
        status_code: Some(StatusCodeOpt {
            status_code: StatusCode::Success,
            status_msg: String::from("Success"),
        }),
        user_class: Some(UserClassOpt {
            user_class_data: vec![0x01, 0x02, 0x03, 0x04],
        }),
        vendor_classes: vec![VendorClassOpt {
            enterprise_num: 123,
            vendor_class_data: vec![0x01, 0x02, 0x03, 0x04],
        }],
        vendor_infos: vec![VendorInfoOpt {
            enterprise_num: 123,
            vendor_option_data: vec![0x01, 0x02, 0x03, 0x04],
        }],
        reconf_accept: Some(ReconfAcceptOpt {}),
        sol_max_rt: Some(SolMaxRtOpt {
            sol_max_rt_val: 123,
        }),
        unknown_opts: vec![],
    };
    let resmsg = match AdvertiseMsg::parse(&orgraw) {
        Ok(resmsg) => resmsg,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resmsg: {:?}", resmsg);
    println!("orgmsg: {:?}", orgmsg);
    if resmsg != orgmsg {
        return Err(format!("resmsg not eq"));
    }
    let mut resraw = [0u8; 209];
    if let Err(e) = resmsg.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn request_msg() -> Result<(), String> {
    let orgraw = [
        0x03, // msg-type
        0x01, 0x02, 0x03, // transaction-id
        // client_id
        0x00, 0x01, // option-code
        0x00, 0x0a, // option-len
        0x00, 0x03, // DUID-Type
        0x00, 0x01, // hardware type (Ethernet)
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // link-layer address
        // server_id
        0x00, 0x02, // option-code
        0x00, 0x0a, // option-len
        0x00, 0x03, // DUID-Type
        0x00, 0x01, // hardware type (Ethernet)
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // link-layer address
        // ia_nas
        0x00, 0x03, // option-code
        0x00, 0x35, // option-len
        0x01, 0x02, 0x03, 0x04, // IAID
        0x00, 0x00, 0x04, 0xd2, // T1
        0x00, 0x00, 0x09, 0x29, // T2
        0x00, 0x05, // option-code
        0x00, 0x18, // option-len
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x6f, //
        0x00, 0x00, 0x00, 0xde, //
        0x00, 0x0d, // option-code
        0x00, 0x09, // option-len
        0x00, 0x00, // status-code
        0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, // "Success"
        // ia_pds
        0x00, 0x19, // option-code
        0x00, 0x36, // option-len
        0x01, 0x02, 0x03, 0x04, // IAID
        0x00, 0x00, 0x04, 0xd2, // T1
        0x00, 0x00, 0x09, 0x29, // T2
        0x00, 0x1a, // option-code
        0x00, 0x19, // option-len
        0x00, 0x00, 0x00, 0x6f, // preferred-lifetime
        0x00, 0x00, 0x00, 0xde, // valid-lifetime
        0x38, // prefix-length
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x01, 0x00, // IPv6-prefix(1)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // IPv6-prefix(2)
        0x00, 0x0d, // option-code
        0x00, 0x09, // option-len
        0x00, 0x00, // status-code
        0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, // "Success"
        // opt_req
        0x00, 0x06, // option-code
        0x00, 0x04, // option-len
        0x00, 0x17, //
        0x00, 0x18, //
        // elapsed_time
        0x00, 0x08, // option-code
        0x00, 0x02, // option-len
        0x00, 0x7b, //
        // user_class
        0x00, 0x0f, // option-code
        0x00, 0x04, // option-len
        0x01, 0x02, 0x03, 0x04, // user-class-data
        // vendor_classes
        0x00, 0x10, // option-code
        0x00, 0x08, // option-len
        0x00, 0x00, 0x00, 0x7b, // enterprise-number
        0x01, 0x02, 0x03, 0x04, // vendor-class-data
        // vendor_infos
        0x00, 0x11, // option-code
        0x00, 0x08, // option-len
        0x00, 0x00, 0x00, 0x7b, // enterprise-number
        0x01, 0x02, 0x03, 0x04, // vendor-option-data
        // reconf_accept
        0x00, 0x14, // option-code
        0x00, 0x00, // option-len
    ];
    let orgmsg = RequestMsg {
        transaction_id: 66051,
        client_id: Some(ClientIdOpt {
            duid: Duid::Ll(LlDuid {
                ll_addr: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            }),
        }),
        server_id: Some(ServerIdOpt {
            duid: Duid::Ll(LlDuid {
                ll_addr: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            }),
        }),
        ia_nas: vec![IaNaOpt {
            iaid: [0x01, 0x02, 0x03, 0x04],
            t1: 1234,
            t2: 2345,
            ia_addrs: vec![IaAddrOpt {
                ipv6_addr: Ipv6Addr::from([0x2001, 0xdb8, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0]),
                preferred_lifetime: 111,
                valid_lifetime: 222,
                unknown_opts: vec![],
            }],
            status_code: Some(StatusCodeOpt {
                status_code: StatusCode::Success,
                status_msg: String::from("Success"),
            }),
            unknown_opts: vec![],
        }],
        ia_pds: vec![IaPdOpt {
            iaid: [0x01, 0x02, 0x03, 0x04],
            t1: 1234,
            t2: 2345,
            ia_prefixes: vec![IaPrefixOpt {
                preferred_lifetime: 111,
                valid_lifetime: 222,
                prefix_len: 56,
                ipv6_prefix: Ipv6Addr::from([0x2001, 0xdb8, 0x0, 0x100, 0x0, 0x0, 0x0, 0x0]),
                unknown_opts: vec![],
            }],
            status_code: Some(StatusCodeOpt {
                status_code: StatusCode::Success,
                status_msg: String::from("Success"),
            }),
            unknown_opts: vec![],
        }],
        opt_req: Some(OptReqOpt {
            requested_opt_codes: vec![23, 24],
        }),
        elapsed_time: Some(ElapsedTimeOpt { elapsed_time: 123 }),
        user_class: Some(UserClassOpt {
            user_class_data: vec![0x01, 0x02, 0x03, 0x04],
        }),
        vendor_classes: vec![VendorClassOpt {
            enterprise_num: 123,
            vendor_class_data: vec![0x01, 0x02, 0x03, 0x04],
        }],
        vendor_infos: vec![VendorInfoOpt {
            enterprise_num: 123,
            vendor_option_data: vec![0x01, 0x02, 0x03, 0x04],
        }],
        reconf_accept: Some(ReconfAcceptOpt {}),
        unknown_opts: vec![],
    };
    let resmsg = match RequestMsg::parse(&orgraw) {
        Ok(resmsg) => resmsg,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resmsg: {:?}", resmsg);
    println!("orgmsg: {:?}", orgmsg);
    if resmsg != orgmsg {
        return Err(format!("resmsg not eq"));
    }
    let mut resraw = [0u8; 197];
    if let Err(e) = resmsg.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn confirm_msg() -> Result<(), String> {
    let orgraw = [
        0x04, // msg-type
        0x01, 0x02, 0x03, // transaction-id
        // client_id
        0x00, 0x01, // option-code
        0x00, 0x0a, // option-len
        0x00, 0x03, // DUID-Type
        0x00, 0x01, // hardware type (Ethernet)
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // link-layer address
        // ia_nas
        0x00, 0x03, // option-code
        0x00, 0x35, // option-len
        0x01, 0x02, 0x03, 0x04, // IAID
        0x00, 0x00, 0x04, 0xd2, // T1
        0x00, 0x00, 0x09, 0x29, // T2
        0x00, 0x05, // option-code
        0x00, 0x18, // option-len
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x6f, //
        0x00, 0x00, 0x00, 0xde, //
        0x00, 0x0d, // option-code
        0x00, 0x09, // option-len
        0x00, 0x00, // status-code
        0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, // "Success"
        // elapsed_time
        0x00, 0x08, // option-code
        0x00, 0x02, // option-len
        0x00, 0x7b, //
        // user_class
        0x00, 0x0f, // option-code
        0x00, 0x04, // option-len
        0x01, 0x02, 0x03, 0x04, // user-class-data
        // vendor_classes
        0x00, 0x10, // option-code
        0x00, 0x08, // option-len
        0x00, 0x00, 0x00, 0x7b, // enterprise-number
        0x01, 0x02, 0x03, 0x04, // vendor-class-data
        // vendor_infos
        0x00, 0x11, // option-code
        0x00, 0x08, // option-len
        0x00, 0x00, 0x00, 0x7b, // enterprise-number
        0x01, 0x02, 0x03, 0x04, // vendor-option-data
    ];
    let orgmsg = ConfirmMsg {
        transaction_id: 66051,
        client_id: Some(ClientIdOpt {
            duid: Duid::Ll(LlDuid {
                ll_addr: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            }),
        }),
        ia_nas: vec![IaNaOpt {
            iaid: [0x01, 0x02, 0x03, 0x04],
            t1: 1234,
            t2: 2345,
            ia_addrs: vec![IaAddrOpt {
                ipv6_addr: Ipv6Addr::from([0x2001, 0xdb8, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0]),
                preferred_lifetime: 111,
                valid_lifetime: 222,
                unknown_opts: vec![],
            }],
            status_code: Some(StatusCodeOpt {
                status_code: StatusCode::Success,
                status_msg: String::from("Success"),
            }),
            unknown_opts: vec![],
        }],
        elapsed_time: Some(ElapsedTimeOpt { elapsed_time: 123 }),
        user_class: Some(UserClassOpt {
            user_class_data: vec![0x01, 0x02, 0x03, 0x04],
        }),
        vendor_classes: vec![VendorClassOpt {
            enterprise_num: 123,
            vendor_class_data: vec![0x01, 0x02, 0x03, 0x04],
        }],
        vendor_infos: vec![VendorInfoOpt {
            enterprise_num: 123,
            vendor_option_data: vec![0x01, 0x02, 0x03, 0x04],
        }],
        unknown_opts: vec![],
    };
    let resmsg = match ConfirmMsg::parse(&orgraw) {
        Ok(resmsg) => resmsg,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resmsg: {:?}", resmsg);
    println!("orgmsg: {:?}", orgmsg);
    if resmsg != orgmsg {
        return Err(format!("resmsg not eq"));
    }
    let mut resraw = [0u8; 113];
    if let Err(e) = resmsg.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn renew_msg() -> Result<(), String> {
    let orgraw = [
        0x05, // msg-type
        0x01, 0x02, 0x03, // transaction-id
        // client_id
        0x00, 0x01, // option-code
        0x00, 0x0a, // option-len
        0x00, 0x03, // DUID-Type
        0x00, 0x01, // hardware type (Ethernet)
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // link-layer address
        // server_id
        0x00, 0x02, // option-code
        0x00, 0x0a, // option-len
        0x00, 0x03, // DUID-Type
        0x00, 0x01, // hardware type (Ethernet)
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // link-layer address
        // ia_nas
        0x00, 0x03, // option-code
        0x00, 0x35, // option-len
        0x01, 0x02, 0x03, 0x04, // IAID
        0x00, 0x00, 0x04, 0xd2, // T1
        0x00, 0x00, 0x09, 0x29, // T2
        0x00, 0x05, // option-code
        0x00, 0x18, // option-len
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x6f, //
        0x00, 0x00, 0x00, 0xde, //
        0x00, 0x0d, // option-code
        0x00, 0x09, // option-len
        0x00, 0x00, // status-code
        0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, // "Success"
        // ia_pds
        0x00, 0x19, // option-code
        0x00, 0x36, // option-len
        0x01, 0x02, 0x03, 0x04, // IAID
        0x00, 0x00, 0x04, 0xd2, // T1
        0x00, 0x00, 0x09, 0x29, // T2
        0x00, 0x1a, // option-code
        0x00, 0x19, // option-len
        0x00, 0x00, 0x00, 0x6f, // preferred-lifetime
        0x00, 0x00, 0x00, 0xde, // valid-lifetime
        0x38, // prefix-length
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x01, 0x00, // IPv6-prefix(1)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // IPv6-prefix(2)
        0x00, 0x0d, // option-code
        0x00, 0x09, // option-len
        0x00, 0x00, // status-code
        0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, // "Success"
        // opt_req
        0x00, 0x06, // option-code
        0x00, 0x04, // option-len
        0x00, 0x17, //
        0x00, 0x18, //
        // elapsed_time
        0x00, 0x08, // option-code
        0x00, 0x02, // option-len
        0x00, 0x7b, //
        // user_class
        0x00, 0x0f, // option-code
        0x00, 0x04, // option-len
        0x01, 0x02, 0x03, 0x04, // user-class-data
        // vendor_classes
        0x00, 0x10, // option-code
        0x00, 0x08, // option-len
        0x00, 0x00, 0x00, 0x7b, // enterprise-number
        0x01, 0x02, 0x03, 0x04, // vendor-class-data
        // vendor_infos
        0x00, 0x11, // option-code
        0x00, 0x08, // option-len
        0x00, 0x00, 0x00, 0x7b, // enterprise-number
        0x01, 0x02, 0x03, 0x04, // vendor-option-data
        // reconf_accept
        0x00, 0x14, // option-code
        0x00, 0x00, // option-len
    ];
    let orgmsg = RenewMsg {
        transaction_id: 66051,
        client_id: Some(ClientIdOpt {
            duid: Duid::Ll(LlDuid {
                ll_addr: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            }),
        }),
        server_id: Some(ServerIdOpt {
            duid: Duid::Ll(LlDuid {
                ll_addr: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            }),
        }),
        ia_nas: vec![IaNaOpt {
            iaid: [0x01, 0x02, 0x03, 0x04],
            t1: 1234,
            t2: 2345,
            ia_addrs: vec![IaAddrOpt {
                ipv6_addr: Ipv6Addr::from([0x2001, 0xdb8, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0]),
                preferred_lifetime: 111,
                valid_lifetime: 222,
                unknown_opts: vec![],
            }],
            status_code: Some(StatusCodeOpt {
                status_code: StatusCode::Success,
                status_msg: String::from("Success"),
            }),
            unknown_opts: vec![],
        }],
        ia_pds: vec![IaPdOpt {
            iaid: [0x01, 0x02, 0x03, 0x04],
            t1: 1234,
            t2: 2345,
            ia_prefixes: vec![IaPrefixOpt {
                preferred_lifetime: 111,
                valid_lifetime: 222,
                prefix_len: 56,
                ipv6_prefix: Ipv6Addr::from([0x2001, 0xdb8, 0x0, 0x100, 0x0, 0x0, 0x0, 0x0]),
                unknown_opts: vec![],
            }],
            status_code: Some(StatusCodeOpt {
                status_code: StatusCode::Success,
                status_msg: String::from("Success"),
            }),
            unknown_opts: vec![],
        }],
        opt_req: Some(OptReqOpt {
            requested_opt_codes: vec![23, 24],
        }),
        elapsed_time: Some(ElapsedTimeOpt { elapsed_time: 123 }),
        user_class: Some(UserClassOpt {
            user_class_data: vec![0x01, 0x02, 0x03, 0x04],
        }),
        vendor_classes: vec![VendorClassOpt {
            enterprise_num: 123,
            vendor_class_data: vec![0x01, 0x02, 0x03, 0x04],
        }],
        vendor_infos: vec![VendorInfoOpt {
            enterprise_num: 123,
            vendor_option_data: vec![0x01, 0x02, 0x03, 0x04],
        }],
        reconf_accept: Some(ReconfAcceptOpt {}),
        unknown_opts: vec![],
    };
    let resmsg = match RenewMsg::parse(&orgraw) {
        Ok(resmsg) => resmsg,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resmsg: {:?}", resmsg);
    println!("orgmsg: {:?}", orgmsg);
    if resmsg != orgmsg {
        return Err(format!("resmsg not eq"));
    }
    let mut resraw = [0u8; 197];
    if let Err(e) = resmsg.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn rebind_msg() -> Result<(), String> {
    let orgraw = [
        0x06, // msg-type
        0x01, 0x02, 0x03, // transaction-id
        // client_id
        0x00, 0x01, // option-code
        0x00, 0x0a, // option-len
        0x00, 0x03, // DUID-Type
        0x00, 0x01, // hardware type (Ethernet)
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // link-layer address
        // ia_nas
        0x00, 0x03, // option-code
        0x00, 0x35, // option-len
        0x01, 0x02, 0x03, 0x04, // IAID
        0x00, 0x00, 0x04, 0xd2, // T1
        0x00, 0x00, 0x09, 0x29, // T2
        0x00, 0x05, // option-code
        0x00, 0x18, // option-len
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x6f, //
        0x00, 0x00, 0x00, 0xde, //
        0x00, 0x0d, // option-code
        0x00, 0x09, // option-len
        0x00, 0x00, // status-code
        0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, // "Success"
        // ia_pds
        0x00, 0x19, // option-code
        0x00, 0x36, // option-len
        0x01, 0x02, 0x03, 0x04, // IAID
        0x00, 0x00, 0x04, 0xd2, // T1
        0x00, 0x00, 0x09, 0x29, // T2
        0x00, 0x1a, // option-code
        0x00, 0x19, // option-len
        0x00, 0x00, 0x00, 0x6f, // preferred-lifetime
        0x00, 0x00, 0x00, 0xde, // valid-lifetime
        0x38, // prefix-length
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x01, 0x00, // IPv6-prefix(1)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // IPv6-prefix(2)
        0x00, 0x0d, // option-code
        0x00, 0x09, // option-len
        0x00, 0x00, // status-code
        0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, // "Success"
        // opt_req
        0x00, 0x06, // option-code
        0x00, 0x04, // option-len
        0x00, 0x17, //
        0x00, 0x18, //
        // elapsed_time
        0x00, 0x08, // option-code
        0x00, 0x02, // option-len
        0x00, 0x7b, //
        // user_class
        0x00, 0x0f, // option-code
        0x00, 0x04, // option-len
        0x01, 0x02, 0x03, 0x04, // user-class-data
        // vendor_classes
        0x00, 0x10, // option-code
        0x00, 0x08, // option-len
        0x00, 0x00, 0x00, 0x7b, // enterprise-number
        0x01, 0x02, 0x03, 0x04, // vendor-class-data
        // vendor_infos
        0x00, 0x11, // option-code
        0x00, 0x08, // option-len
        0x00, 0x00, 0x00, 0x7b, // enterprise-number
        0x01, 0x02, 0x03, 0x04, // vendor-option-data
        // reconf_accept
        0x00, 0x14, // option-code
        0x00, 0x00, // option-len
    ];
    let orgmsg = RebindMsg {
        transaction_id: 66051,
        client_id: Some(ClientIdOpt {
            duid: Duid::Ll(LlDuid {
                ll_addr: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            }),
        }),
        ia_nas: vec![IaNaOpt {
            iaid: [0x01, 0x02, 0x03, 0x04],
            t1: 1234,
            t2: 2345,
            ia_addrs: vec![IaAddrOpt {
                ipv6_addr: Ipv6Addr::from([0x2001, 0xdb8, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0]),
                preferred_lifetime: 111,
                valid_lifetime: 222,
                unknown_opts: vec![],
            }],
            status_code: Some(StatusCodeOpt {
                status_code: StatusCode::Success,
                status_msg: String::from("Success"),
            }),
            unknown_opts: vec![],
        }],
        ia_pds: vec![IaPdOpt {
            iaid: [0x01, 0x02, 0x03, 0x04],
            t1: 1234,
            t2: 2345,
            ia_prefixes: vec![IaPrefixOpt {
                preferred_lifetime: 111,
                valid_lifetime: 222,
                prefix_len: 56,
                ipv6_prefix: Ipv6Addr::from([0x2001, 0xdb8, 0x0, 0x100, 0x0, 0x0, 0x0, 0x0]),
                unknown_opts: vec![],
            }],
            status_code: Some(StatusCodeOpt {
                status_code: StatusCode::Success,
                status_msg: String::from("Success"),
            }),
            unknown_opts: vec![],
        }],
        opt_req: Some(OptReqOpt {
            requested_opt_codes: vec![23, 24],
        }),
        elapsed_time: Some(ElapsedTimeOpt { elapsed_time: 123 }),
        user_class: Some(UserClassOpt {
            user_class_data: vec![0x01, 0x02, 0x03, 0x04],
        }),
        vendor_classes: vec![VendorClassOpt {
            enterprise_num: 123,
            vendor_class_data: vec![0x01, 0x02, 0x03, 0x04],
        }],
        vendor_infos: vec![VendorInfoOpt {
            enterprise_num: 123,
            vendor_option_data: vec![0x01, 0x02, 0x03, 0x04],
        }],
        reconf_accept: Some(ReconfAcceptOpt {}),
        unknown_opts: vec![],
    };
    let resmsg = match RebindMsg::parse(&orgraw) {
        Ok(resmsg) => resmsg,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resmsg: {:?}", resmsg);
    println!("orgmsg: {:?}", orgmsg);
    if resmsg != orgmsg {
        return Err(format!("resmsg not eq"));
    }
    let mut resraw = [0u8; 183];
    if let Err(e) = resmsg.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn decline_msg() -> Result<(), String> {
    let orgraw = [
        0x09, // msg-type
        0x01, 0x02, 0x03, // transaction-id
        // client_id
        0x00, 0x01, // option-code
        0x00, 0x0a, // option-len
        0x00, 0x03, // DUID-Type
        0x00, 0x01, // hardware type (Ethernet)
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // link-layer address
        // server_id
        0x00, 0x02, // option-code
        0x00, 0x0a, // option-len
        0x00, 0x03, // DUID-Type
        0x00, 0x01, // hardware type (Ethernet)
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // link-layer address
        // ia_nas
        0x00, 0x03, // option-code
        0x00, 0x35, // option-len
        0x01, 0x02, 0x03, 0x04, // IAID
        0x00, 0x00, 0x04, 0xd2, // T1
        0x00, 0x00, 0x09, 0x29, // T2
        0x00, 0x05, // option-code
        0x00, 0x18, // option-len
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x6f, //
        0x00, 0x00, 0x00, 0xde, //
        0x00, 0x0d, // option-code
        0x00, 0x09, // option-len
        0x00, 0x00, // status-code
        0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, // "Success"
        // ia_pds
        0x00, 0x19, // option-code
        0x00, 0x36, // option-len
        0x01, 0x02, 0x03, 0x04, // IAID
        0x00, 0x00, 0x04, 0xd2, // T1
        0x00, 0x00, 0x09, 0x29, // T2
        0x00, 0x1a, // option-code
        0x00, 0x19, // option-len
        0x00, 0x00, 0x00, 0x6f, // preferred-lifetime
        0x00, 0x00, 0x00, 0xde, // valid-lifetime
        0x38, // prefix-length
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x01, 0x00, // IPv6-prefix(1)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // IPv6-prefix(2)
        0x00, 0x0d, // option-code
        0x00, 0x09, // option-len
        0x00, 0x00, // status-code
        0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, // "Success"
        // elapsed_time
        0x00, 0x08, // option-code
        0x00, 0x02, // option-len
        0x00, 0x7b, //
        // user_class
        0x00, 0x0f, // option-code
        0x00, 0x04, // option-len
        0x01, 0x02, 0x03, 0x04, // user-class-data
        // vendor_classes
        0x00, 0x10, // option-code
        0x00, 0x08, // option-len
        0x00, 0x00, 0x00, 0x7b, // enterprise-number
        0x01, 0x02, 0x03, 0x04, // vendor-class-data
        // vendor_infos
        0x00, 0x11, // option-code
        0x00, 0x08, // option-len
        0x00, 0x00, 0x00, 0x7b, // enterprise-number
        0x01, 0x02, 0x03, 0x04, // vendor-option-data
    ];
    let orgmsg = DeclineMsg {
        transaction_id: 66051,
        client_id: Some(ClientIdOpt {
            duid: Duid::Ll(LlDuid {
                ll_addr: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            }),
        }),
        server_id: Some(ServerIdOpt {
            duid: Duid::Ll(LlDuid {
                ll_addr: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            }),
        }),
        ia_nas: vec![IaNaOpt {
            iaid: [0x01, 0x02, 0x03, 0x04],
            t1: 1234,
            t2: 2345,
            ia_addrs: vec![IaAddrOpt {
                ipv6_addr: Ipv6Addr::from([0x2001, 0xdb8, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0]),
                preferred_lifetime: 111,
                valid_lifetime: 222,
                unknown_opts: vec![],
            }],
            status_code: Some(StatusCodeOpt {
                status_code: StatusCode::Success,
                status_msg: String::from("Success"),
            }),
            unknown_opts: vec![],
        }],
        ia_pds: vec![IaPdOpt {
            iaid: [0x01, 0x02, 0x03, 0x04],
            t1: 1234,
            t2: 2345,
            ia_prefixes: vec![IaPrefixOpt {
                preferred_lifetime: 111,
                valid_lifetime: 222,
                prefix_len: 56,
                ipv6_prefix: Ipv6Addr::from([0x2001, 0xdb8, 0x0, 0x100, 0x0, 0x0, 0x0, 0x0]),
                unknown_opts: vec![],
            }],
            status_code: Some(StatusCodeOpt {
                status_code: StatusCode::Success,
                status_msg: String::from("Success"),
            }),
            unknown_opts: vec![],
        }],
        elapsed_time: Some(ElapsedTimeOpt { elapsed_time: 123 }),
        user_class: Some(UserClassOpt {
            user_class_data: vec![0x01, 0x02, 0x03, 0x04],
        }),
        vendor_classes: vec![VendorClassOpt {
            enterprise_num: 123,
            vendor_class_data: vec![0x01, 0x02, 0x03, 0x04],
        }],
        vendor_infos: vec![VendorInfoOpt {
            enterprise_num: 123,
            vendor_option_data: vec![0x01, 0x02, 0x03, 0x04],
        }],
        unknown_opts: vec![],
    };
    let resmsg = match DeclineMsg::parse(&orgraw) {
        Ok(resmsg) => resmsg,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resmsg: {:?}", resmsg);
    println!("orgmsg: {:?}", orgmsg);
    if resmsg != orgmsg {
        return Err(format!("resmsg not eq"));
    }
    let mut resraw = [0u8; 185];
    if let Err(e) = resmsg.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn release_msg() -> Result<(), String> {
    let orgraw = [
        0x08, // msg-type
        0x01, 0x02, 0x03, // transaction-id
        // client_id
        0x00, 0x01, // option-code
        0x00, 0x0a, // option-len
        0x00, 0x03, // DUID-Type
        0x00, 0x01, // hardware type (Ethernet)
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // link-layer address
        // server_id
        0x00, 0x02, // option-code
        0x00, 0x0a, // option-len
        0x00, 0x03, // DUID-Type
        0x00, 0x01, // hardware type (Ethernet)
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // link-layer address
        // ia_nas
        0x00, 0x03, // option-code
        0x00, 0x35, // option-len
        0x01, 0x02, 0x03, 0x04, // IAID
        0x00, 0x00, 0x04, 0xd2, // T1
        0x00, 0x00, 0x09, 0x29, // T2
        0x00, 0x05, // option-code
        0x00, 0x18, // option-len
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x6f, //
        0x00, 0x00, 0x00, 0xde, //
        0x00, 0x0d, // option-code
        0x00, 0x09, // option-len
        0x00, 0x00, // status-code
        0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, // "Success"
        // ia_pds
        0x00, 0x19, // option-code
        0x00, 0x36, // option-len
        0x01, 0x02, 0x03, 0x04, // IAID
        0x00, 0x00, 0x04, 0xd2, // T1
        0x00, 0x00, 0x09, 0x29, // T2
        0x00, 0x1a, // option-code
        0x00, 0x19, // option-len
        0x00, 0x00, 0x00, 0x6f, // preferred-lifetime
        0x00, 0x00, 0x00, 0xde, // valid-lifetime
        0x38, // prefix-length
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x01, 0x00, // IPv6-prefix(1)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // IPv6-prefix(2)
        0x00, 0x0d, // option-code
        0x00, 0x09, // option-len
        0x00, 0x00, // status-code
        0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, // "Success"
        // elapsed_time
        0x00, 0x08, // option-code
        0x00, 0x02, // option-len
        0x00, 0x7b, //
        // user_class
        0x00, 0x0f, // option-code
        0x00, 0x04, // option-len
        0x01, 0x02, 0x03, 0x04, // user-class-data
        // vendor_classes
        0x00, 0x10, // option-code
        0x00, 0x08, // option-len
        0x00, 0x00, 0x00, 0x7b, // enterprise-number
        0x01, 0x02, 0x03, 0x04, // vendor-class-data
        // vendor_infos
        0x00, 0x11, // option-code
        0x00, 0x08, // option-len
        0x00, 0x00, 0x00, 0x7b, // enterprise-number
        0x01, 0x02, 0x03, 0x04, // vendor-option-data
    ];
    let orgmsg = ReleaseMsg {
        transaction_id: 66051,
        client_id: Some(ClientIdOpt {
            duid: Duid::Ll(LlDuid {
                ll_addr: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            }),
        }),
        server_id: Some(ServerIdOpt {
            duid: Duid::Ll(LlDuid {
                ll_addr: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            }),
        }),
        ia_nas: vec![IaNaOpt {
            iaid: [0x01, 0x02, 0x03, 0x04],
            t1: 1234,
            t2: 2345,
            ia_addrs: vec![IaAddrOpt {
                ipv6_addr: Ipv6Addr::from([0x2001, 0xdb8, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0]),
                preferred_lifetime: 111,
                valid_lifetime: 222,
                unknown_opts: vec![],
            }],
            status_code: Some(StatusCodeOpt {
                status_code: StatusCode::Success,
                status_msg: String::from("Success"),
            }),
            unknown_opts: vec![],
        }],
        ia_pds: vec![IaPdOpt {
            iaid: [0x01, 0x02, 0x03, 0x04],
            t1: 1234,
            t2: 2345,
            ia_prefixes: vec![IaPrefixOpt {
                preferred_lifetime: 111,
                valid_lifetime: 222,
                prefix_len: 56,
                ipv6_prefix: Ipv6Addr::from([0x2001, 0xdb8, 0x0, 0x100, 0x0, 0x0, 0x0, 0x0]),
                unknown_opts: vec![],
            }],
            status_code: Some(StatusCodeOpt {
                status_code: StatusCode::Success,
                status_msg: String::from("Success"),
            }),
            unknown_opts: vec![],
        }],
        elapsed_time: Some(ElapsedTimeOpt { elapsed_time: 123 }),
        user_class: Some(UserClassOpt {
            user_class_data: vec![0x01, 0x02, 0x03, 0x04],
        }),
        vendor_classes: vec![VendorClassOpt {
            enterprise_num: 123,
            vendor_class_data: vec![0x01, 0x02, 0x03, 0x04],
        }],
        vendor_infos: vec![VendorInfoOpt {
            enterprise_num: 123,
            vendor_option_data: vec![0x01, 0x02, 0x03, 0x04],
        }],
        unknown_opts: vec![],
    };
    let resmsg = match ReleaseMsg::parse(&orgraw) {
        Ok(resmsg) => resmsg,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resmsg: {:?}", resmsg);
    println!("orgmsg: {:?}", orgmsg);
    if resmsg != orgmsg {
        return Err(format!("resmsg not eq"));
    }
    let mut resraw = [0u8; 185];
    if let Err(e) = resmsg.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn reply_msg() -> Result<(), String> {
    let orgraw = [
        0x07, // msg-type
        0x01, 0x02, 0x03, // transaction-id
        // client_id
        0x00, 0x01, // option-code
        0x00, 0x0a, // option-len
        0x00, 0x03, // DUID-Type
        0x00, 0x01, // hardware type (Ethernet)
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // link-layer address
        // server_id
        0x00, 0x02, // option-code
        0x00, 0x0a, // option-len
        0x00, 0x03, // DUID-Type
        0x00, 0x01, // hardware type (Ethernet)
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // link-layer address
        // ia_nas
        0x00, 0x03, // option-code
        0x00, 0x35, // option-len
        0x01, 0x02, 0x03, 0x04, // IAID
        0x00, 0x00, 0x04, 0xd2, // T1
        0x00, 0x00, 0x09, 0x29, // T2
        0x00, 0x05, // option-code
        0x00, 0x18, // option-len
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x6f, //
        0x00, 0x00, 0x00, 0xde, //
        0x00, 0x0d, // option-code
        0x00, 0x09, // option-len
        0x00, 0x00, // status-code
        0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, // "Success"
        // ia_pds
        0x00, 0x19, // option-code
        0x00, 0x36, // option-len
        0x01, 0x02, 0x03, 0x04, // IAID
        0x00, 0x00, 0x04, 0xd2, // T1
        0x00, 0x00, 0x09, 0x29, // T2
        0x00, 0x1a, // option-code
        0x00, 0x19, // option-len
        0x00, 0x00, 0x00, 0x6f, // preferred-lifetime
        0x00, 0x00, 0x00, 0xde, // valid-lifetime
        0x38, // prefix-length
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x01, 0x00, // IPv6-prefix(1)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // IPv6-prefix(2)
        0x00, 0x0d, // option-code
        0x00, 0x09, // option-len
        0x00, 0x00, // status-code
        0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, // "Success"
        // auth
        0x00, 0x0b, // option-code
        0x00, 0x0f, // option-len
        0x01, // protocol
        0x02, // algorithm
        0x03, // RDM
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, // replay detection
        0x05, 0x06, 0x07, 0x08, // authentication information
        // status_code
        0x00, 0x0d, // option-code
        0x00, 0x09, // option-len
        0x00, 0x00, // status-code
        0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, // "Success"
        // rapid_commit
        0x00, 0x0e, // option-code
        0x00, 0x00, // option-len
        // user_class
        0x00, 0x0f, // option-code
        0x00, 0x04, // option-len
        0x01, 0x02, 0x03, 0x04, // user-class-data
        // vendor_classes
        0x00, 0x10, // option-code
        0x00, 0x08, // option-len
        0x00, 0x00, 0x00, 0x7b, // enterprise-number
        0x01, 0x02, 0x03, 0x04, // vendor-class-data
        // vendor_infos
        0x00, 0x11, // option-code
        0x00, 0x08, // option-len
        0x00, 0x00, 0x00, 0x7b, // enterprise-number
        0x01, 0x02, 0x03, 0x04, // vendor-option-data
        // reconf_accept
        0x00, 0x14, // option-code
        0x00, 0x00, // option-len
        // info_refresh_time
        0x00, 0x20, // option-code
        0x00, 0x04, // option-len
        0x00, 0x00, 0x00, 0x7b, // information-refresh-time
        // sol_max_rt
        0x00, 0x52, // option-code
        0x00, 0x04, // option-len
        0x00, 0x00, 0x00, 0x7b, // SOL_MAX_RT value
        // inf_max_rt
        0x00, 0x53, // option-code
        0x00, 0x04, // option-len
        0x00, 0x00, 0x00, 0x7b, // INF_MAX_RT value
    ];
    let orgmsg = ReplyMsg {
        transaction_id: 66051,
        client_id: Some(ClientIdOpt {
            duid: Duid::Ll(LlDuid {
                ll_addr: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            }),
        }),
        server_id: Some(ServerIdOpt {
            duid: Duid::Ll(LlDuid {
                ll_addr: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            }),
        }),
        ia_nas: vec![IaNaOpt {
            iaid: [0x01, 0x02, 0x03, 0x04],
            t1: 1234,
            t2: 2345,
            ia_addrs: vec![IaAddrOpt {
                ipv6_addr: Ipv6Addr::from([0x2001, 0xdb8, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0]),
                preferred_lifetime: 111,
                valid_lifetime: 222,
                unknown_opts: vec![],
            }],
            status_code: Some(StatusCodeOpt {
                status_code: StatusCode::Success,
                status_msg: String::from("Success"),
            }),
            unknown_opts: vec![],
        }],
        ia_pds: vec![IaPdOpt {
            iaid: [0x01, 0x02, 0x03, 0x04],
            t1: 1234,
            t2: 2345,
            ia_prefixes: vec![IaPrefixOpt {
                preferred_lifetime: 111,
                valid_lifetime: 222,
                prefix_len: 56,
                ipv6_prefix: Ipv6Addr::from([0x2001, 0xdb8, 0x0, 0x100, 0x0, 0x0, 0x0, 0x0]),
                unknown_opts: vec![],
            }],
            status_code: Some(StatusCodeOpt {
                status_code: StatusCode::Success,
                status_msg: String::from("Success"),
            }),
            unknown_opts: vec![],
        }],
        auth: Some(AuthOpt {
            protocol: 1,
            algorithm: 2,
            rdm: 3,
            replay_detection: 4,
            auth_info: vec![0x05, 0x06, 0x07, 0x08],
        }),
        status_code: Some(StatusCodeOpt {
            status_code: StatusCode::Success,
            status_msg: String::from("Success"),
        }),
        rapid_commit: Some(RapidCommitOpt {}),
        user_class: Some(UserClassOpt {
            user_class_data: vec![0x01, 0x02, 0x03, 0x04],
        }),
        vendor_classes: vec![VendorClassOpt {
            enterprise_num: 123,
            vendor_class_data: vec![0x01, 0x02, 0x03, 0x04],
        }],
        vendor_infos: vec![VendorInfoOpt {
            enterprise_num: 123,
            vendor_option_data: vec![0x01, 0x02, 0x03, 0x04],
        }],
        reconf_accept: Some(ReconfAcceptOpt {}),
        info_refresh_time: Some(InfoRefreshTimeOpt {
            information_refresh_time: 123,
        }),
        sol_max_rt: Some(SolMaxRtOpt {
            sol_max_rt_val: 123,
        }),
        inf_max_rt: Some(InfMaxRtOpt {
            inf_max_rt_val: 123,
        }),
        dns_recursive_name_server: None,
        domain_search_list: None,
        unknown_opts: vec![],
    };
    let resmsg = match ReplyMsg::parse(&orgraw) {
        Ok(resmsg) => resmsg,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resmsg: {:?}", resmsg);
    println!("orgmsg: {:?}", orgmsg);
    if resmsg != orgmsg {
        return Err(format!("resmsg not eq"));
    }
    let mut resraw = [0u8; 243];
    if let Err(e) = resmsg.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn reconf_msg() -> Result<(), String> {
    let orgraw = [
        0x0a, // msg-type
        0x01, 0x02, 0x03, // transaction-id
        // client_id
        0x00, 0x01, // option-code
        0x00, 0x0a, // option-len
        0x00, 0x03, // DUID-Type
        0x00, 0x01, // hardware type (Ethernet)
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // link-layer address
        // server_id
        0x00, 0x02, // option-code
        0x00, 0x0a, // option-len
        0x00, 0x03, // DUID-Type
        0x00, 0x01, // hardware type (Ethernet)
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // link-layer address
        // auth
        0x00, 0x0b, // option-code
        0x00, 0x0f, // option-len
        0x01, // protocol
        0x02, // algorithm
        0x03, // RDM
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, // replay detection
        0x05, 0x06, 0x07, 0x08, // authentication information
        // reconf_msg
        0x00, 0x13, // option-code
        0x00, 0x01, // option-len
        0x05, // msg-type
    ];
    let orgmsg = ReconfMsg {
        transaction_id: 66051,
        client_id: Some(ClientIdOpt {
            duid: Duid::Ll(LlDuid {
                ll_addr: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            }),
        }),
        server_id: Some(ServerIdOpt {
            duid: Duid::Ll(LlDuid {
                ll_addr: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            }),
        }),
        auth: Some(AuthOpt {
            protocol: 1,
            algorithm: 2,
            rdm: 3,
            replay_detection: 4,
            auth_info: vec![0x05, 0x06, 0x07, 0x08],
        }),
        reconf_msg: Some(ReconfMsgOpt { msg_type: 5 }),
        unknown_opts: vec![],
    };
    let resmsg = match ReconfMsg::parse(&orgraw) {
        Ok(resmsg) => resmsg,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resmsg: {:?}", resmsg);
    println!("orgmsg: {:?}", orgmsg);
    if resmsg != orgmsg {
        return Err(format!("resmsg not eq"));
    }
    let mut resraw = [0u8; 56];
    if let Err(e) = resmsg.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn info_req_msg() -> Result<(), String> {
    let orgraw = [
        0x0b, // msg-type
        0x01, 0x02, 0x03, // transaction-id
        // client_id
        0x00, 0x01, // option-code
        0x00, 0x0a, // option-len
        0x00, 0x03, // DUID-Type
        0x00, 0x01, // hardware type (Ethernet)
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // link-layer address
        // server_id
        0x00, 0x02, // option-code
        0x00, 0x0a, // option-len
        0x00, 0x03, // DUID-Type
        0x00, 0x01, // hardware type (Ethernet)
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // link-layer address
        // opt_req
        0x00, 0x06, // option-code
        0x00, 0x04, // option-len
        0x00, 0x17, //
        0x00, 0x18, //
        // elapsed_time
        0x00, 0x08, // option-code
        0x00, 0x02, // option-len
        0x00, 0x7b, //
        // user_class
        0x00, 0x0f, // option-code
        0x00, 0x04, // option-len
        0x01, 0x02, 0x03, 0x04, // user-class-data
        // vendor_classes
        0x00, 0x10, // option-code
        0x00, 0x08, // option-len
        0x00, 0x00, 0x00, 0x7b, // enterprise-number
        0x01, 0x02, 0x03, 0x04, // vendor-class-data
        // vendor_infos
        0x00, 0x11, // option-code
        0x00, 0x08, // option-len
        0x00, 0x00, 0x00, 0x7b, // enterprise-number
        0x01, 0x02, 0x03, 0x04, // vendor-option-data
        // reconf_accept
        0x00, 0x14, // option-code
        0x00, 0x00, // option-len
    ];
    let orgmsg = InfoReqMsg {
        transaction_id: 66051,
        client_id: Some(ClientIdOpt {
            duid: Duid::Ll(LlDuid {
                ll_addr: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            }),
        }),
        server_id: Some(ServerIdOpt {
            duid: Duid::Ll(LlDuid {
                ll_addr: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            }),
        }),
        opt_req: Some(OptReqOpt {
            requested_opt_codes: vec![23, 24],
        }),
        elapsed_time: Some(ElapsedTimeOpt { elapsed_time: 123 }),
        user_class: Some(UserClassOpt {
            user_class_data: vec![0x01, 0x02, 0x03, 0x04],
        }),
        vendor_classes: vec![VendorClassOpt {
            enterprise_num: 123,
            vendor_class_data: vec![0x01, 0x02, 0x03, 0x04],
        }],
        vendor_infos: vec![VendorInfoOpt {
            enterprise_num: 123,
            vendor_option_data: vec![0x01, 0x02, 0x03, 0x04],
        }],
        reconf_accept: Some(ReconfAcceptOpt {}),
        unknown_opts: vec![],
    };
    let resmsg = match InfoReqMsg::parse(&orgraw) {
        Ok(resmsg) => resmsg,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resmsg: {:?}", resmsg);
    println!("orgmsg: {:?}", orgmsg);
    if resmsg != orgmsg {
        return Err(format!("resmsg not eq"));
    }
    let mut resraw = [0u8; 82];
    if let Err(e) = resmsg.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn relay_forward_msg() -> Result<(), String> {
    let orgraw = [
        0x0c, // msg-type
        0x01, // hop_count
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01, // link_addr
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, //
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01, // peer_addr
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, //
        // relay_msg
        0x00, 0x09, // option-code
        0x00, 0x04, // option-len
        0x01, 0x02, 0x03, 0x04, // vendor_infos
        0x00, 0x11, // option-code
        0x00, 0x08, // option-len
        0x00, 0x00, 0x00, 0x7b, // enterprise-number
        0x01, 0x02, 0x03, 0x04, // vendor-option-data
        // interface_id
        0x00, 0x12, // option-code
        0x00, 0x04, // option-len
        0x01, 0x02, 0x03, 0x04, // interface-id
    ];
    let orgmsg = RelayForwardMsg {
        hop_count: 0x01,
        link_addr: Ipv6Addr::from([0x2001, 0xdb8, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1]),
        peer_addr: Ipv6Addr::from([0x2001, 0xdb8, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2]),
        relay_msg: Some(RelayMsgOpt {
            dhcp_relay_msg: vec![0x01, 0x02, 0x03, 0x04],
        }),
        vendor_infos: vec![VendorInfoOpt {
            enterprise_num: 123,
            vendor_option_data: vec![0x01, 0x02, 0x03, 0x04],
        }],
        interface_id: Some(InterfaceIdOpt {
            interface_id: vec![0x01, 0x02, 0x03, 0x04],
        }),
        unknown_opts: vec![],
    };
    let resmsg = match RelayForwardMsg::parse(&orgraw) {
        Ok(resmsg) => resmsg,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resmsg: {:?}", resmsg);
    println!("orgmsg: {:?}", orgmsg);
    if resmsg != orgmsg {
        return Err(format!("resmsg not eq"));
    }
    let mut resraw = [0u8; 62];
    if let Err(e) = resmsg.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn relay_reply_msg() -> Result<(), String> {
    let orgraw = [
        0x0d, // msg-type
        0x01, // hop_count
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01, // link_addr
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, //
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01, // peer_addr
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, //
        // relay_msg
        0x00, 0x09, // option-code
        0x00, 0x04, // option-len
        0x01, 0x02, 0x03, 0x04, // vendor_infos
        0x00, 0x11, // option-code
        0x00, 0x08, // option-len
        0x00, 0x00, 0x00, 0x7b, // enterprise-number
        0x01, 0x02, 0x03, 0x04, // vendor-option-data
        // interface_id
        0x00, 0x12, // option-code
        0x00, 0x04, // option-len
        0x01, 0x02, 0x03, 0x04, // interface-id
    ];
    let orgmsg = RelayReplyMsg {
        hop_count: 0x01,
        link_addr: Ipv6Addr::from([0x2001, 0xdb8, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1]),
        peer_addr: Ipv6Addr::from([0x2001, 0xdb8, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2]),
        relay_msg: Some(RelayMsgOpt {
            dhcp_relay_msg: vec![0x01, 0x02, 0x03, 0x04],
        }),
        vendor_infos: vec![VendorInfoOpt {
            enterprise_num: 123,
            vendor_option_data: vec![0x01, 0x02, 0x03, 0x04],
        }],
        interface_id: Some(InterfaceIdOpt {
            interface_id: vec![0x01, 0x02, 0x03, 0x04],
        }),
        unknown_opts: vec![],
    };
    let resmsg = match RelayReplyMsg::parse(&orgraw) {
        Ok(resmsg) => resmsg,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resmsg: {:?}", resmsg);
    println!("orgmsg: {:?}", orgmsg);
    if resmsg != orgmsg {
        return Err(format!("resmsg not eq"));
    }
    let mut resraw = [0u8; 62];
    if let Err(e) = resmsg.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn dhcp6_msg() -> Result<(), String> {
    let orgraw = [
        0x01, // msg-type
        0x01, 0x02, 0x03, // transaction-id
        // client_id
        0x00, 0x01, // option-code
        0x00, 0x0a, // option-len
        0x00, 0x03, // DUID-Type
        0x00, 0x01, // hardware type (Ethernet)
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // link-layer address
        // ia_nas
        0x00, 0x03, // option-code
        0x00, 0x35, // option-len
        0x01, 0x02, 0x03, 0x04, // IAID
        0x00, 0x00, 0x04, 0xd2, // T1
        0x00, 0x00, 0x09, 0x29, // T2
        0x00, 0x05, // option-code
        0x00, 0x18, // option-len
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x6f, //
        0x00, 0x00, 0x00, 0xde, //
        0x00, 0x0d, // option-code
        0x00, 0x09, // option-len
        0x00, 0x00, // status-code
        0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, // "Success"
        // ia_pds
        0x00, 0x19, // option-code
        0x00, 0x36, // option-len
        0x01, 0x02, 0x03, 0x04, // IAID
        0x00, 0x00, 0x04, 0xd2, // T1
        0x00, 0x00, 0x09, 0x29, // T2
        0x00, 0x1a, // option-code
        0x00, 0x19, // option-len
        0x00, 0x00, 0x00, 0x6f, // preferred-lifetime
        0x00, 0x00, 0x00, 0xde, // valid-lifetime
        0x38, // prefix-length
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x01, 0x00, // IPv6-prefix(1)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // IPv6-prefix(2)
        0x00, 0x0d, // option-code
        0x00, 0x09, // option-len
        0x00, 0x00, // status-code
        0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, // "Success"
        // opt_req
        0x00, 0x06, // option-code
        0x00, 0x04, // option-len
        0x00, 0x17, //
        0x00, 0x18, //
        // elapsed_time
        0x00, 0x08, // option-code
        0x00, 0x02, // option-len
        0x00, 0x7b, //
        // rapid_commit
        0x00, 0x0e, // option-code
        0x00, 0x00, // option-len
        // user_class
        0x00, 0x0f, // option-code
        0x00, 0x04, // option-len
        0x01, 0x02, 0x03, 0x04, // user-class-data
        // vendor_classes
        0x00, 0x10, // option-code
        0x00, 0x08, // option-len
        0x00, 0x00, 0x00, 0x7b, // enterprise-number
        0x01, 0x02, 0x03, 0x04, // vendor-class-data
        // vendor_infos
        0x00, 0x11, // option-code
        0x00, 0x08, // option-len
        0x00, 0x00, 0x00, 0x7b, // enterprise-number
        0x01, 0x02, 0x03, 0x04, // vendor-option-data
        // reconf_accept
        0x00, 0x14, // option-code
        0x00, 0x00, // option-len
    ];
    let orgmsg = Dhcp6Msg::Solicit(SolicitMsg {
        transaction_id: 66051,
        client_id: Some(ClientIdOpt {
            duid: Duid::Ll(LlDuid {
                ll_addr: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            }),
        }),
        ia_nas: vec![IaNaOpt {
            iaid: [0x01, 0x02, 0x03, 0x04],
            t1: 1234,
            t2: 2345,
            ia_addrs: vec![IaAddrOpt {
                ipv6_addr: Ipv6Addr::from([0x2001, 0xdb8, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0]),
                preferred_lifetime: 111,
                valid_lifetime: 222,
                unknown_opts: vec![],
            }],
            status_code: Some(StatusCodeOpt {
                status_code: StatusCode::Success,
                status_msg: String::from("Success"),
            }),
            unknown_opts: vec![],
        }],
        ia_pds: vec![IaPdOpt {
            iaid: [0x01, 0x02, 0x03, 0x04],
            t1: 1234,
            t2: 2345,
            ia_prefixes: vec![IaPrefixOpt {
                preferred_lifetime: 111,
                valid_lifetime: 222,
                prefix_len: 56,
                ipv6_prefix: Ipv6Addr::from([0x2001, 0xdb8, 0x0, 0x100, 0x0, 0x0, 0x0, 0x0]),
                unknown_opts: vec![],
            }],
            status_code: Some(StatusCodeOpt {
                status_code: StatusCode::Success,
                status_msg: String::from("Success"),
            }),
            unknown_opts: vec![],
        }],
        opt_req: Some(OptReqOpt {
            requested_opt_codes: vec![23, 24],
        }),
        elapsed_time: Some(ElapsedTimeOpt { elapsed_time: 123 }),
        rapid_commit: Some(RapidCommitOpt {}),
        user_class: Some(UserClassOpt {
            user_class_data: vec![0x01, 0x02, 0x03, 0x04],
        }),
        vendor_classes: vec![VendorClassOpt {
            enterprise_num: 123,
            vendor_class_data: vec![0x01, 0x02, 0x03, 0x04],
        }],
        vendor_infos: vec![VendorInfoOpt {
            enterprise_num: 123,
            vendor_option_data: vec![0x01, 0x02, 0x03, 0x04],
        }],
        reconf_accept: Some(ReconfAcceptOpt {}),
        unknown_opts: vec![],
    });
    let resmsg = match Dhcp6Msg::parse(&orgraw) {
        Ok(resmsg) => resmsg,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resmsg: {:?}", resmsg);
    println!("orgmsg: {:?}", orgmsg);
    if resmsg != orgmsg {
        return Err(format!("resmsg not eq"));
    }
    let mut resraw = [0u8; 187];
    if let Err(e) = resmsg.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}
