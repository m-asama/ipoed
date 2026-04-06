// SPDX-License-Identifier: MIT
// Copyright(c) 2026 Masakazu Asama

use std::sync::mpsc;
use std::time::Duration;
use std::time::Instant;

use crate::IpoedMsg;

#[derive(Debug, Eq, PartialEq)]
pub enum TimerMsg {
    RsSolicitSendDelayTimeout,
    RsSolicitWaitTimeout,
    Dhcp6AdvertWaitTimeout,
    Dhcp6ReplyWaitTimeout,
    Dhcp6RenewingTimeout,
    PeriodicFire,
}

#[derive(Debug)]
pub struct TimerReq {
    pub msg: TimerMsg,
    pub after: Duration,
}

#[derive(Debug)]
struct ScheduledItem {
    msg: TimerMsg,
    deadline: Instant,
}

fn timer(ch_tx: mpsc::Sender<IpoedMsg>, req_rx: mpsc::Receiver<TimerReq>) {
    let mut tasks: Vec<ScheduledItem> = Vec::new();
    loop {
        tasks.sort_by_key(|t| t.deadline);
        if let Some(next) = tasks.first() {
            let now = Instant::now();
            if next.deadline <= now {
                let mut i = 0;
                while i < tasks.len() {
                    if tasks[i].deadline <= now {
                        let task = tasks.remove(i);
                        let msg = IpoedMsg::Timer(task.msg);
                        if ch_tx.send(msg).is_err() {
                            return;
                        }
                    } else {
                        i += 1;
                    }
                }
                continue;
            }
            let timeout = next.deadline.saturating_duration_since(now);
            match req_rx.recv_timeout(timeout) {
                Ok(req) => {
                    tasks.push(ScheduledItem {
                        msg: req.msg,
                        deadline: Instant::now() + req.after,
                    });
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return;
                }
            }
        } else {
            match req_rx.recv() {
                Ok(req) => {
                    tasks.push(ScheduledItem {
                        msg: req.msg,
                        deadline: Instant::now() + req.after,
                    });
                }
                Err(_) => {
                    return;
                }
            }
        }
    }
}

pub fn init(ch_tx: mpsc::Sender<IpoedMsg>) -> Result<mpsc::Sender<TimerReq>, String> {
    let (req_tx, req_rx) = mpsc::channel::<TimerReq>();

    std::thread::spawn(move || {
        timer(ch_tx, req_rx);
    });

    Ok(req_tx)
}
