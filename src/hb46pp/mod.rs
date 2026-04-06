// SPDX-License-Identifier: MIT
// Copyright(c) 2026 Masakazu Asama

use std::convert::TryInto;
use std::sync::mpsc;
use std::time::Duration;

use curl::easy::Easy;
use resolv::record::TXT;
use resolv::{Class, RecordType, Resolver};

use crate::IpoedMsg;

mod packets;
pub use packets::*;

mod config;
pub use config::*;

const VENDORID: &str = "246c89";
const PRODUCT: &str = "ipoed";
const VERSION: &str = "1";
const CAPABILITY: &str = "ipip,dslite";

#[derive(Debug)]
pub struct Hb46ppReq {
    pub user: Option<String>,
    pub pass: Option<String>,
}

#[derive(Debug)]
pub struct Hb46ppRep {
    pub config: Result<Hb46ppConfig, String>,
    pub reset: bool,
    pub wait: Duration,
}

fn error(msg: &str, reset: bool, wait_sec_min: u64, wait_sec_max: u64) -> Hb46ppRep {
    let err = Err(msg.to_string());
    let wait = Duration::from_secs(rand::random_range(wait_sec_min..wait_sec_max));
    Hb46ppRep {
        config: err,
        reset: reset,
        wait: wait,
    }
}

fn check(req: Hb46ppReq) -> Hb46ppRep {
    // a) 開始
    // b) DNS クエリーで TXT リソースレコードの情報を取得する
    let mut resolver = match Resolver::new() {
        Some(resolver) => resolver,
        // c.3) NODATA もしくは NXDOMAIN 以外の理由で取得できなかった場合
        None => return error("Resolver error:", false, 60, 600),
    };
    let mut response = match resolver.query(b"4over6.info", Class::IN, RecordType::TXT) {
        Ok(response) => response,
        // c.3) NODATA もしくは NXDOMAIN 以外の理由で取得できなかった場合
        Err(e) => return error(&format!("Query error: {e}"), false, 60, 600),
    };
    let mut txtrr: Option<String> = None;
    for answer in response.answers::<TXT>() {
        if answer.data.dname.starts_with("v=v6mig-1 ") {
            txtrr = Some(answer.data.dname);
            break;
        }
    }
    let txtrr = match txtrr {
        Some(txtrr) => txtrr,
        // c.2) 取得した TXT リソースレコードが3.1節の規定を満たさない、
        //      または NODATA もしくは NXDOMAIN で取得できない場合
        None => return error("TXT RR not found:", true, 3600, 10800),
    };
    let mut url: Option<String> = None;
    let mut insecure: Option<bool> = None;
    let fields: Vec<&str> = txtrr.split(' ').collect::<Vec<&str>>();
    for field in fields {
        let lv: Vec<&str> = field.splitn(2, '=').collect::<Vec<&str>>();
        if lv.len() != 2 {
            continue;
        }
        if lv[0] == "url" {
            url = Some(lv[1].to_string());
        }
        if lv[0] == "t" {
            if lv[1] == "a" {
                insecure = Some(true);
            }
            if lv[1] == "b" {
                insecure = Some(false);
            }
        }
    }
    let url = if let Some(url) = url {
        url
    } else {
        // c.2) 取得した TXT リソースレコードが3.1節の規定を満たさない、
        //      または NODATA もしくは NXDOMAIN で取得できない場合
        return error("TXT RR parse error:", true, 3600, 10800);
    };
    let insecure = if let Some(insecure) = insecure {
        insecure
    } else {
        // c.2) 取得した TXT リソースレコードが3.1節の規定を満たさない、
        //      または NODATA もしくは NXDOMAIN で取得できない場合
        return error("TXT RR parse error:", true, 3600, 10800);
    };
    // d) プロビジョニングサーバへ CPE 情報を送信する
    let mut url = url
        + "?vendorid="
        + VENDORID
        + "&product="
        + PRODUCT
        + "&version="
        + VERSION
        + "&capability="
        + CAPABILITY;
    if let Some(user) = &req.user {
        url = url + "&user=" + user;
    }
    if let Some(pass) = &req.pass {
        url = url + "&pass=" + pass;
    }
    let mut curl = Easy::new();
    if insecure {
        let _ = curl.ssl_verify_peer(false);
        let _ = curl.ssl_verify_host(false);
    }
    if let Err(e) = curl.url(&url) {
        // f.3) HTTP ステータスコードがそれ以外、または応答がない場合
        return error(&format!("URL set failed: {e}:"), false, 600, 1800);
    }
    let mut data = Vec::<u8>::new();
    {
        let mut transfer = curl.transfer();
        let _ = transfer.write_function(|t| {
            data.extend_from_slice(t);
            Ok(t.len())
        });
        let _ = transfer.perform();
    }
    match curl.response_code() {
        Ok(response_code) => {
            if response_code != 200 {
                // f.3) HTTP ステータスコードがそれ以外、または応答がない場合
                return error(
                    &format!("Server response error: {response_code}"),
                    false,
                    600,
                    1800,
                );
            }
        }
        // f.3) HTTP ステータスコードがそれ以外、または応答がない場合
        Err(e) => return error(&format!("Server response error: {e}"), false, 600, 1800),
    }
    let msg: Hb46ppMsg = match serde_json::from_slice(&data) {
        Ok(msg) => msg,
        // g.2) プロビジョニング情報が3.4節の規定を満たさない場合
        Err(e) => return error(&format!("serde json error: {e}"), false, 600, 1800),
    };
    // j) プロビジョニング情報に TTL が設定されているか
    let wait = match msg.ttl {
        // j.1) 設定されている場合
        Some(ttl) => Duration::from_secs(ttl),
        // j.2) 設定されていない場合
        None => Duration::from_secs(rand::random_range(72000..86400)),
    };
    let config = match msg.try_into() {
        Ok(config) => config,
        // g.2) プロビジョニング情報が3.4節の規定を満たさない場合
        Err(e) => return error(&format!("Result parse error: {e}"), false, 600, 1800),
    };
    // g.1) プロビジョニング情報が3.4節の規定を満たす場合
    Hb46ppRep {
        config: Ok(config),
        reset: false,
        wait: wait,
    }
}

fn hb46pp(ch_tx: mpsc::Sender<IpoedMsg>, req_rx: mpsc::Receiver<Hb46ppReq>) {
    while let Ok(req) = req_rx.recv() {
        let rep = check(req);
        if let Err(e) = ch_tx.send(IpoedMsg::Hb46pp(rep)) {
            println!("channel send error: {e}");
            return;
        }
    }
    println!("HB46PP thread exited");
}

pub fn init(ch_tx: mpsc::Sender<IpoedMsg>) -> Result<mpsc::Sender<Hb46ppReq>, String> {
    let (req_tx, req_rx) = mpsc::channel::<Hb46ppReq>();

    std::thread::spawn(move || {
        hb46pp(ch_tx, req_rx);
    });

    Ok(req_tx)
}
