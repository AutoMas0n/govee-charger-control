// govee-charger — Govee H5080 plug control for a Gotrax XR Ultra scooter charger.
//
// Purpose: make it impossible to leave the charger energised. Two independent
// stops, in this order of importance:
//
//   1. ON-DEVICE TIMER (the real safety net). The H5080 runs its own auto-off
//      timer (cmd 0xB0) that lives in the plug's non-volatile memory and keeps
//      counting across a power cut. Proven live 2026-11-17: a 30-min timer was
//      armed, the plug was yanked off the wall for ~2 min, and on restore the
//      deadline was unchanged (leftSec 1546 vs 1545 expected uninterrupted).
//      So even if this process, the Pi, or the whole house dies, the charger
//      still goes off at the deadline.
//
//   2. THE RELAY remembers its last state across a power cut (proven: ON->ON,
//      OFF->OFF). That is precisely why (1) matters — a brownout re-energises
//      whatever the plug was doing, so we never leave it ON without a timer.
//
// The H5080 has NO power monitoring (no watts/amps/energy). Charge level is
// therefore a HUMAN INPUT, not a measurement: the rider reads the scooter's
// 4-bar display and picks a preset. Presets are deliberately generous ceilings
// around a 4-5 h full charge, not precise estimates.

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use btleplug::api::{Central, CharPropFlags, Manager as _, Peripheral, ScanFilter, WriteType};
use futures::StreamExt;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;

const KEY_COMM: &[u8; 16] = b"MakingLifeSmarte";
// Sent in 33 B5 SyncTime. Only affects on-device timers, which fire against
// the plug's own clock — so this must be the LOCAL offset or a 4 h timer would
// fire an hour or two off.
const TZ_HOURS: i8 = -4;

// The charger plug. Identity confirmed live 2026-11-17: ON and OFF both
// verified, and E245 is the only other H5080 answering besides the
// dehumidifier's E1DD.
const PLUG_MAC: &str = "D4:AD:FC:42:E2:45";
const PLUG_SKEY: &[u8; 8] = &[0xf6, 0xe0, 0x73, 0x0a, 0x5b, 0xe5, 0x45, 0xe3];

// No single session may ever exceed this, whatever the preset says. 6 h covers
// the worst legitimate case (4.5 h from empty + margin) and still guarantees a
// session cannot run overnight.
const HARD_CAP_MINS: u32 = 360;

// Scooter facts (Gotrax XR Ultra): 36 V 7 Ah = 252 Wh, 42 V 2 A charger.
// 7 Ah / 2 A = 3.5 h constant-current, plus a CV taper -> 4-5 h from empty.
//
// Presets are (bars, minutes). "full" deliberately overshoots: the charger's
// own red->green cutoff is the primary stop, so ending late is harmless and
// guarantees you never return to a half-charged scooter. "long" stops short of
// the CV taper (~80% SoC), which is where Li-ion ages slowest.
const PRESETS_FULL: &[(u8, u32)] = &[(1, 300), (2, 240), (3, 180), (4, 120)];
const PRESETS_LONG: &[(u8, u32)] = &[(1, 150), (2, 90), (3, 60), (4, 0)];

fn preset(bars: u8, mode: &str) -> Option<u32> {
    let table = if mode == "long" { PRESETS_LONG } else { PRESETS_FULL };
    table.iter().find(|(b, _)| *b == bars).map(|(_, m)| *m)
}

// ========================= CRYPTO =========================
fn rc4(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut s: [u8; 256] = std::array::from_fn(|i| i as u8);
    let mut j: u8 = 0;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        (s[i], s[j as usize]) = (s[j as usize], s[i]);
    }
    let (mut i, mut j) = (0u8, 0u8);
    data.iter()
        .map(|&b| {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[i as usize]);
            (s[i as usize], s[j as usize]) = (s[j as usize], s[i as usize]);
            b ^ s[s[i as usize].wrapping_add(s[j as usize]) as usize]
        })
        .collect()
}

fn encrypt(frame: &[u8; 20], key: &[u8; 16]) -> [u8; 20] {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut block = GenericArray::clone_from_slice(&frame[..16]);
    cipher.encrypt_block(&mut block);
    let mut out = [0u8; 20];
    out[..16].copy_from_slice(&block);
    out[16..].copy_from_slice(&rc4(&frame[16..], key));
    out
}

fn decrypt(payload: &[u8; 20], key: &[u8; 16]) -> [u8; 20] {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut block = GenericArray::clone_from_slice(&payload[..16]);
    cipher.decrypt_block(&mut block);
    let mut out = [0u8; 20];
    out[..16].copy_from_slice(&block);
    out[16..].copy_from_slice(&rc4(&payload[16..], key));
    out
}

fn frame_from(cmd: u8, sub: u8, data: &[u8]) -> [u8; 20] {
    let mut f = [0u8; 20];
    f[0] = cmd;
    f[1] = sub;
    let n = data.len().min(17);
    f[2..2 + n].copy_from_slice(&data[..n]);
    f[19] = f[..19].iter().fold(0, |a, b| a ^ b);
    f
}

fn verify(frame: &[u8; 20]) -> bool {
    frame[..19].iter().fold(0, |a, b| a ^ b) == frame[19]
}

// ========================= BLE =========================
async fn adapter() -> btleplug::platform::Adapter {
    let m = btleplug::platform::Manager::new().await.unwrap();
    // The onboard radio is disabled via dtoverlay=disable-bt on the Pi, so the
    // first (only) adapter is the TP-Link USB dongle. See the sibling repo's
    // HANDOVER.md — taking adapters().next() blindly is only safe when the
    // onboard radio is off.
    m.adapters().await.unwrap().into_iter().next().unwrap()
}

async fn find_mac(
    c: &btleplug::platform::Adapter,
    mac: &str,
    secs: u64,
) -> Result<btleplug::platform::Peripheral, String> {
    let mac = mac.to_uppercase();
    c.start_scan(ScanFilter::default())
        .await
        .map_err(|e| format!("scan: {e}"))?;
    let d = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        for p in c.peripherals().await.map_err(|e| format!("periphs: {e}"))? {
            if p.address().to_string().to_uppercase() == mac {
                c.stop_scan().await.ok();
                return Ok(p);
            }
        }
        if tokio::time::Instant::now() >= d {
            break;
        }
        sleep(Duration::from_millis(200)).await;
    }
    c.stop_scan().await.ok();
    Err(format!("{mac} not found"))
}

async fn write_ctrl(per: &btleplug::platform::Peripheral, d: &[u8]) -> Result<(), String> {
    for svc in &per.services() {
        for chr in &svc.characteristics {
            if chr.uuid.to_string().to_lowercase().contains("2b11") {
                let wt = if chr.properties.contains(CharPropFlags::WRITE) {
                    WriteType::WithResponse
                } else {
                    WriteType::WithoutResponse
                };
                per.write(chr, d, wt).await.map_err(|e| format!("write: {e}"))?;
                return Ok(());
            }
        }
    }
    Err("write char 2b11 not found".into())
}

async fn sub_notify(per: &btleplug::platform::Peripheral) -> Result<(), String> {
    for svc in &per.services() {
        for chr in &svc.characteristics {
            if chr.uuid.to_string().to_lowercase().contains("2b10") {
                per.subscribe(chr).await.map_err(|e| format!("sub: {e}"))?;
                return Ok(());
            }
        }
    }
    Err("notify char 2b10 not found".into())
}

async fn handshake(per: &btleplug::platform::Peripheral) -> Result<[u8; 16], String> {
    write_ctrl(per, &encrypt(&frame_from(0xE7, 0x01, &[0u8; 16]), KEY_COMM)).await?;
    let mut s = per.notifications().await.map_err(|e| format!("notif: {e}"))?;
    let d = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut sk = None;
    while sk.is_none() && tokio::time::Instant::now() < d {
        let n = tokio::time::timeout(Duration::from_millis(200), s.next())
            .await
            .ok()
            .and_then(|x| x);
        if let Some(v) = n {
            let mut buf = [0u8; 20];
            let l = v.value.len().min(20);
            buf[..l].copy_from_slice(&v.value[..l]);
            let dec = decrypt(&buf, KEY_COMM);
            if dec[0] == 0xE7 && dec[1] == 0x01 && verify(&dec) {
                let mut k = [0u8; 16];
                k.copy_from_slice(&dec[2..18]);
                sk = Some(k);
            }
        }
    }
    let sk = sk.ok_or("handshake: no response")?;
    write_ctrl(per, &encrypt(&frame_from(0xE7, 0x02, &[0u8; 16]), KEY_COMM)).await?;
    Ok(sk)
}

async fn init_plug(
    per: &btleplug::platform::Peripheral,
    sk: &[u8; 16],
    skey: Option<&[u8; 8]>,
) -> Result<(), String> {
    if let Some(k) = skey {
        write_ctrl(per, &encrypt(&frame_from(0x33, 0xB2, k), sk)).await?;
    } else {
        write_ctrl(
            per,
            &encrypt(
                &frame_from(0x33, 0xB2, &[0x3C, 0x9C, 0x9D, 0x89, 0x09, 0x40, 0xB0, 0x19]),
                sk,
            ),
        )
        .await?;
    }
    write_ctrl(per, &encrypt(&frame_from(0xAA, 0xEF, &[]), sk)).await?;
    sleep(Duration::from_millis(200)).await;
    // SyncTime matters here: it sets the clock the on-device timer counts
    // against. Skip it and the deadline is measured from a stale/zero epoch.
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    let mut t = ts.to_be_bytes().to_vec();
    t.extend_from_slice(&[0x01, TZ_HOURS as u8, 0x00]);
    write_ctrl(per, &encrypt(&frame_from(0x33, 0xB5, &t), sk)).await?;
    sleep(Duration::from_millis(200)).await;
    write_ctrl(per, &encrypt(&frame_from(0xAA, 0xB0, &[]), sk)).await?;
    write_ctrl(per, &encrypt(&frame_from(0xAA, 0xB0, &[0x00, 0x01]), sk)).await?;
    sleep(Duration::from_millis(300)).await;
    Ok(())
}

type NotifStream =
    std::pin::Pin<Box<dyn futures::Stream<Item = btleplug::api::ValueNotification> + Send>>;

async fn wait_frame(s: &mut NotifStream, sk: &[u8; 16], cmd: u8, sub: u8, secs: u64) -> Option<[u8; 20]> {
    let d = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < d {
        if let Ok(Some(v)) = tokio::time::timeout(Duration::from_millis(200), s.next()).await {
            let mut buf = [0u8; 20];
            let l = v.value.len().min(20);
            buf[..l].copy_from_slice(&v.value[..l]);
            let dec = decrypt(&buf, sk);
            if dec[0] == cmd && dec[1] == sub && verify(&dec) {
                return Some(dec);
            }
        }
    }
    None
}

async fn try_plug_inner<T, Fut>(
    c: &btleplug::platform::Adapter,
    plug_mac: &str,
    skey: Option<&[u8; 8]>,
    action: impl FnOnce(btleplug::platform::Peripheral, [u8; 16]) -> Fut,
) -> Result<T, String>
where
    Fut: Future<Output = Result<T, String>>,
{
    let per = find_mac(c, plug_mac, 10).await?;
    tokio::time::timeout(Duration::from_secs(12), per.connect())
        .await
        .map_err(|_| "conn: timeout")?
        .map_err(|e| format!("conn: {e}"))?;
    sleep(Duration::from_millis(500)).await;
    tokio::time::timeout(Duration::from_secs(8), per.discover_services())
        .await
        .map_err(|_| "disc svc: timeout")?
        .map_err(|e| format!("disc svc: {e}"))?;
    tokio::time::timeout(Duration::from_secs(8), sub_notify(&per))
        .await
        .map_err(|_| "sub: timeout")??;
    let sk = tokio::time::timeout(Duration::from_secs(8), handshake(&per))
        .await
        .map_err(|_| "handshake: timeout")??;
    tokio::time::timeout(Duration::from_secs(10), init_plug(&per, &sk, skey))
        .await
        .map_err(|_| "init: timeout")??;
    action(per, sk).await
}

// The plug needs a moment to tear the link down. Without this, an immediately
// following connect (the very next command in a CLI run, or the next step of a
// charge) draws `conn: le-connection-abort-by-local` and burns a whole retry
// round-trip. Every command that does not do its own teardown uses this.
async fn close(per: &btleplug::platform::Peripheral) {
    per.disconnect().await.ok();
    sleep(Duration::from_millis(900)).await;
}

async fn with_retry<T, F, Fut>(label: &str, mut f: F) -> Result<T, String>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, String>>,
{
    let mut err = String::new();
    for a in 0..3 {
        match f().await {
            Ok(r) => return Ok(r),
            Err(e) => {
                err = e;
                log::warn!("{label} retry {}/3: {err}", a + 1);
                if a < 2 {
                    sleep(Duration::from_secs(2u64.pow(a))).await;
                }
            }
        }
    }
    Err(format!("{label} failed: {err}"))
}

// ========================= PLUG OPS =========================

// Toggle: 33 01 11 = ON, 33 01 10 = OFF (note: same sub-command, payload differs).
async fn plug_set(
    c: &btleplug::platform::Adapter,
    on: bool,
    skey: Option<&[u8; 8]>,
) -> Result<(), String> {
    with_retry(if on { "on" } else { "off" }, || {
        let c = c.clone();
        async move {
            try_plug_inner(&c, PLUG_MAC, skey, |per, sk| {
                Box::pin(async move {
                    let r = write_ctrl(
                        &per,
                        &encrypt(&frame_from(0x33, 0x01, &[if on { 0x11 } else { 0x10 }]), &sk),
                    )
                    .await;
                    close(&per).await;
                    r
                })
            })
            .await
        }
    })
    .await
}

// One session, both reads. Two separate connections back-to-back reliably
// draw `conn: le-connection-abort-by-local` on the second connect (the plug's
// link teardown has not settled), which cost a retry round-trip every poll.
// Returns (on, minutes_configured, seconds_remaining); 0 remaining = no timer.
async fn plug_info(
    c: &btleplug::platform::Adapter,
    skey: Option<&[u8; 8]>,
) -> Result<(bool, u32, i32), String> {
    with_retry("info", || {
        let c = c.clone();
        async move {
            try_plug_inner(&c, PLUG_MAC, skey, |per, sk| {
                Box::pin(async move {
                    let mut s: NotifStream =
                        per.notifications().await.map_err(|e| format!("notif: {e}"))?;
                    write_ctrl(&per, &encrypt(&frame_from(0xAA, 0x01, &[]), &sk)).await?;
                    let st = wait_frame(&mut s, &sk, 0xAA, 0x01, 2).await;
                    write_ctrl(&per, &encrypt(&frame_from(0xAA, 0xB0, &[0x00, 0x00]), &sk)).await?;
                    let dl = wait_frame(&mut s, &sk, 0xAA, 0xB0, 2).await;
                    close(&per).await;
                    let on = st.ok_or("no state response")?[2] == 1;
                    match dl {
                        Some(f) => {
                            let mins = (f[4] as u32) * 60 + f[5] as u32;
                            let left = i32::from_be_bytes([0, f[6], f[7], f[8]]);
                            Ok((on, mins, left))
                        }
                        // State read fine but no timer answer = timer cleared.
                        None => Ok((on, 0, 0)),
                    }
                })
            })
            .await
        }
    })
    .await
}

// Arm the ON-DEVICE auto-off: 33 B0 [index, delayType, mins/60, mins%60]
// index 0, delayType 0 = auto-OFF. Proven live to accept up to 1440 min and to
// survive a power cut.
async fn plug_arm(
    c: &btleplug::platform::Adapter,
    mins: u32,
    skey: Option<&[u8; 8]>,
) -> Result<(), String> {
    let mins = mins.min(HARD_CAP_MINS);
    with_retry("arm", || {
        let c = c.clone();
        async move {
            try_plug_inner(&c, PLUG_MAC, skey, |per, sk| {
                Box::pin(async move {
                    let payload = [0u8, 0u8, (mins / 60) as u8, (mins % 60) as u8];
                    let r = write_ctrl(&per, &encrypt(&frame_from(0x33, 0xB0, &payload), &sk)).await;
                    close(&per).await;
                    r
                })
            })
            .await
        }
    })
    .await
}

// Clear the timer (arm 0 minutes).
async fn plug_disarm(c: &btleplug::platform::Adapter, skey: Option<&[u8; 8]>) -> Result<(), String> {
    plug_arm(c, 0, skey).await
}

// ========================= COMMANDS =========================

/// The whole charge sequence. Order matters: ON first, then arm. If we armed
/// first and the ON failed we would leave a timer with the plug off (harmless
/// but confusing); if ON succeeds and arm fails we retry, and the caller is
/// told — never leave the plug ON with no timer silently.
async fn cmd_charge(c: &btleplug::platform::Adapter, mins: u32, skey: Option<&[u8; 8]>) -> Result<u32, String> {
    let mins = mins.clamp(1, HARD_CAP_MINS);
    plug_set(c, true, skey).await?;
    plug_arm(c, mins, skey).await?;
    // Verify: a plug left ON with no timer is the failure this project exists
    // to prevent, so confirm the timer actually took.
    match plug_info(c, skey).await {
        Ok((on, m, left)) if left > 0 && on => {
            log::info!("charge: armed {m}m (left {left}s)");
            Ok(mins)
        }
        Ok((false, _, _)) => Err("verify: plug did not turn ON".into()),
        Ok((_, m, left)) => Err(format!("armed but timer reads {m}m/{left}s — NOT protected")),
        Err(e) => Err(format!("armed, verify failed: {e}")),
    }
}

async fn cmd_stop(c: &btleplug::platform::Adapter, skey: Option<&[u8; 8]>) -> Result<(), String> {
    // Clear the timer BEFORE cutting power, so nothing is pending afterwards.
    plug_disarm(c, skey).await?;
    plug_set(c, false, skey).await?;
    Ok(())
}

// ========================= STATUS =========================
#[derive(Clone, Default)]
struct Status {
    plug: Option<bool>,
    armed_mins: Option<u32>,
    left_sec: Option<i32>,
    mode: String,
    last_cmd: Option<String>,
    last_error: Option<String>,
    last_ok_ts: u64,
}

impl Status {
    fn json(&self) -> String {
        fn o<T: std::fmt::Display>(v: Option<T>) -> String {
            v.map(|x| x.to_string()).unwrap_or_else(|| "null".into())
        }
        format!(
            r#"{{"plug":{},"armed":{},"armed_min":{},"left_sec":{},"mode":"{}","last_cmd":{},"last_error":{},"last_ok_ts":{},"cap_min":{}}}"#,
            match self.plug {
                Some(true) => "\"ON\"".to_string(),
                Some(false) => "\"OFF\"".to_string(),
                None => "null".into(),
            },
            self.left_sec.map(|l| l > 0).unwrap_or(false),
            o(self.armed_mins),
            o(self.left_sec),
            self.mode,
            self.last_cmd
                .as_ref()
                .map(|s| format!("\"{s}\""))
                .unwrap_or_else(|| "null".into()),
            self.last_error
                .as_ref()
                .map(|s| format!("\"{}\"", s.replace('"', "'")))
                .unwrap_or_else(|| "null".into()),
            self.last_ok_ts,
            HARD_CAP_MINS
        )
    }
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

struct Shared {
    st: tokio::sync::Mutex<Status>,
    bus: tokio::sync::Mutex<()>, // serialises all BLE access
}

async fn refresh(c: &btleplug::platform::Adapter, sh: &Arc<Shared>, skey: Option<&[u8; 8]>) {
    let _guard = sh.bus.lock().await;
    let mut st = sh.st.lock().await;
    match plug_info(c, skey).await {
        Ok((on, m, left)) => {
            st.plug = Some(on);
            st.armed_mins = if left > 0 { Some(m) } else { None };
            st.left_sec = Some(left);
            st.last_ok_ts = now_epoch();
            st.last_error = None;
        }
        Err(e) => {
            st.plug = None;
            st.last_error = Some(e);
        }
    }
}

// ========================= HTTP =========================
async fn http_response(code: &str, ctype: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {code}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

const PAGE: &str = r#"<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Scooter Charger</title>
<style>
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;margin:0;padding:16px;background:#0f172a;color:#e2e8f0}
h1{font-size:1.1rem;margin:0 0 4px}
.sub{color:#94a3b8;font-size:.8rem;margin-bottom:14px}
.card{background:#1e293b;border-radius:14px;padding:14px;margin-bottom:12px}
.row{display:flex;justify-content:space-between;align-items:center}
.big{font-size:2.2rem;font-weight:700;letter-spacing:-1px}
.on{color:#4ade80}.off{color:#94a3b8}.unk{color:#fbbf24}
.armed{background:#14532d;border:1px solid #22c55e;border-radius:12px;padding:10px 12px;margin-top:10px;font-weight:600;color:#bbf7d0}
.warn{background:#7f1d1d;border:1px solid #ef4444;border-radius:12px;padding:10px 12px;margin-top:10px;color:#fecaca;font-size:.85rem}
.tabs{display:flex;gap:8px;margin-bottom:12px}
.tab{flex:1;padding:9px;border-radius:10px;border:1px solid #334155;background:#1e293b;color:#cbd5e1;font-size:.85rem;font-weight:600;cursor:pointer}
.tab.act{background:#2563eb;border-color:#2563eb;color:#fff}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.btn{padding:16px 10px;border-radius:12px;border:1px solid #334155;background:#1e293b;color:#e2e8f0;font-size:.95rem;font-weight:600;cursor:pointer;text-align:center}
.btn:active{transform:scale(.97)}
.btn small{display:block;font-weight:400;color:#94a3b8;font-size:.72rem;margin-top:3px}
.stop{grid-column:1/3;background:#7f1d1d;border-color:#ef4444;color:#fecaca}
.note{color:#64748b;font-size:.72rem;line-height:1.5;margin-top:10px}
.mono{font-family:ui-monospace,monospace}
</style></head><body>
<h1>Scooter Charger</h1>
<div class="sub">Gotrax XR Ultra &middot; 42V 2A &middot; plug E245</div>

<div class="card">
  <div class="row"><span>Plug</span><span id="plug" class="big off">—</span></div>
  <div id="armedBox" class="armed" style="display:none">
    <span class="mono" id="armedTxt"></span>
  </div>
  <div id="warnBox" class="warn" style="display:none"></div>
  <div class="note" id="err"></div>
</div>

<div class="tabs">
  <div class="tab act" id="tabFull" onclick="setMode('full')">Charge to full</div>
  <div class="tab" id="tabLong" onclick="setMode('long')">Longevity ~80%</div>
</div>

<div class="card">
  <div class="grid" id="presets"></div>
  <div class="note">
    Read the scooter's battery bars, tap the match. The plug runs its own
    timer and switches off by itself — even if the Pi or the power dies.
  </div>
</div>

<script>
let mode = 'full';
const FULL = [[1,300],[2,240],[3,180],[4,120]];
const LONG = [[1,150],[2,90],[3,60],[4,0]];
function fmt(m){ if(m==0) return 'none'; if(m<60) return m+'m'; const h=Math.floor(m/60), r=m%60; return r? h+'h '+r+'m' : h+'h'; }
function setMode(m){ mode=m;
  document.getElementById('tabFull').className='tab'+(m==='full'?' act':'');
  document.getElementById('tabLong').className='tab'+(m==='long'?' act':'');
  render();
}
function render(){
  const t = mode==='full'?FULL:LONG;
  document.getElementById('presets').innerHTML =
    t.map(([b,m])=>`<div class="btn" onclick="charge(${b})">${b} bar${b>1?'s':''}<small>${fmt(m)}</small></div>`).join('')
    + `<div class="btn stop" onclick="stop()">STOP</div>`;
}
async function charge(bars){
  await fetch('/charge?bars='+bars+'&mode='+mode,{method:'POST'});
  setTimeout(tick,300);
}
async function stop(){ await fetch('/stop',{method:'POST'}); setTimeout(tick,300); }
function fmtDur(s){ s=Math.max(0,Math.round(s)); const h=Math.floor(s/3600),m=Math.floor(s%3600/60); return h? h+'h '+m+'m' : m+'m '+Math.floor(s%60)+'s'; }
// The server polls the plug only every 3 min, so count the deadline down
// locally; otherwise the timer would sit still and look broken.
let base=0, leftAtFetch=null;
function leftNow(){ return leftAtFetch===null? null : leftAtFetch - (Date.now()-base)/1000; }
async function tick(){
  try{
    const st = await (await fetch('/state.json')).json();
    base=Date.now(); leftAtFetch=st.left_sec;
    const p = document.getElementById('plug');
    if(st.plug==='ON'){p.textContent='ON';p.className='big on';}
    else if(st.plug==='OFF'){p.textContent='OFF';p.className='big off';}
    else {p.textContent='?';p.className='big unk';}
    const l=leftNow();
    const a=document.getElementById('armedBox');
    if(l && l>0){ a.style.display='block';
      document.getElementById('armedTxt').textContent='AUTO-OFF IN '+fmtDur(l)+' (was '+st.armed_min+'m)';
    } else { a.style.display='none'; }
    const w=document.getElementById('warnBox');
    if(st.plug==='ON' && !(l>0)){ w.style.display='block'; w.textContent='WARNING: plug is ON with no timer armed.'; }
    else w.style.display='none';
    document.getElementById('err').textContent = st.last_error? ('last error: '+st.last_error) : '';
  }catch(e){}
}
render(); tick(); setInterval(tick,5000);
</script></body></html>"#;

async fn serve(c: &btleplug::platform::Adapter, port: u16, skey: Option<&[u8; 8]>) {
    let sh = Arc::new(Shared {
        st: tokio::sync::Mutex::new(Status::default()),
        bus: tokio::sync::Mutex::new(()),
    });

    // Initial read + periodic refresh. The plug owns the timer, so polling is
    // only for display. Kept slow (3 min) on purpose: the humidity daemon
    // shares this radio and the H5179 already reads at a marginal -78 dBm, so
    // every extra connect is contention it does not need. The page counts the
    // remaining seconds down locally between refreshes, so the UI stays live.
    // Immediate updates come from the action handlers below, which write the
    // verified result into the cache as soon as the command returns.
    {
        let c = c.clone();
        let sh = sh.clone();
        let sk = skey.copied();
        tokio::spawn(async move {
            loop {
                refresh(&c, &sh, sk.as_ref()).await;
                sleep(Duration::from_secs(180)).await;
            }
        });
    }

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .unwrap();
    log::info!("status: http://0.0.0.0:{port}/");
    loop {
        let Ok((mut sock, _)) = listener.accept().await else {
            continue;
        };
        let c = c.clone();
        let sh = sh.clone();
        let sk = skey.copied();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let n = match sock.read(&mut buf).await {
                Ok(n) => n,
                Err(_) => return,
            };
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let mut lines = req.lines();
            let first = lines.next().unwrap_or("");
            let mut parts = first.split_whitespace();
            let method = parts.next().unwrap_or("");
            let path_q = parts.next().unwrap_or("/");
            let (path, q) = path_q.split_once('?').unwrap_or((path_q, ""));

            let resp = match (method, path) {
                ("GET", "/") => http_response("200 OK", "text/html; charset=utf-8", PAGE).await,
                ("GET", "/state.json") => {
                    let st = sh.st.lock().await;
                    http_response("200 OK", "application/json", &st.json()).await
                }
                ("POST", "/charge") => {
                    let bars: u8 = q
                        .split('&')
                        .find_map(|kv| {
                            let (k, v) = kv.split_once('=')?;
                            (k == "bars").then(|| v.parse().ok()).flatten()
                        })
                        .unwrap_or(0);
                    let mode = q
                        .split('&')
                        .find_map(|kv| {
                            let (k, v) = kv.split_once('=')?;
                            (k == "mode").then(|| v.to_string())
                        })
                        .unwrap_or_else(|| "full".into());
                    let mins = q
                        .split('&')
                        .find_map(|kv| {
                            let (k, v) = kv.split_once('=')?;
                            (k == "mins").then(|| v.parse::<u32>().ok()).flatten()
                        })
                        .or_else(|| preset(bars, &mode));
                    match mins {
                        None => http_response("400 Bad Request", "application/json",
                            r#"{"ok":false,"error":"no preset for that bar count"}"#).await,
                        Some(0) => http_response("200 OK", "application/json",
                            r#"{"ok":false,"error":"battery already at target - no charge needed"}"#).await,
                        Some(m) => {
                            let _g = sh.bus.lock().await;
                            let r = cmd_charge(&c, m, sk.as_ref()).await;
                            {
                                let mut st = sh.st.lock().await;
                                st.mode = mode.clone();
                                st.last_cmd = Some(format!("charge {m}m"));
                                st.last_error = r.as_ref().err().cloned();
                                // cmd_charge verified the arm, so update the
                                // cache now instead of letting the page show a
                                // stale OFF for up to a minute.
                                if let Ok(armed) = r {
                                    st.plug = Some(true);
                                    st.armed_mins = Some(armed);
                                    st.left_sec = Some((armed * 60) as i32);
                                    st.last_ok_ts = now_epoch();
                                }
                            }
                            log::info!("charge: {m}m -> {r:?}");
                            match r {
                                Ok(m) => http_response("200 OK", "application/json",
                                    &format!(r#"{{"ok":true,"mins":{m}}}"#)).await,
                                Err(e) => http_response("500 Internal Server Error", "application/json",
                                    &format!(r#"{{"ok":false,"error":"{}"}}"#, e.replace('"', "'"))).await,
                            }
                        }
                    }
                }
                ("POST", "/stop") => {
                    let _g = sh.bus.lock().await;
                    let r = cmd_stop(&c, sk.as_ref()).await;
                    {
                        let mut st = sh.st.lock().await;
                        st.last_cmd = Some("stop".into());
                        st.last_error = r.as_ref().err().cloned();
                        if r.is_ok() {
                            st.plug = Some(false);
                            st.armed_mins = None;
                            st.left_sec = Some(0);
                            st.last_ok_ts = now_epoch();
                        }
                    }
                    log::info!("stop -> {r:?}");
                    match r {
                        Ok(()) => http_response("200 OK", "application/json", r#"{"ok":true}"#).await,
                        Err(e) => http_response("500 Internal Server Error", "application/json",
                            &format!(r#"{{"ok":false,"error":"{}"}}"#, e.replace('"', "'"))).await,
                    }
                }
                ("POST", "/refresh") => {
                    let _g = sh.bus.lock().await;
                    drop(_g);
                    refresh(&c, &sh, sk.as_ref()).await;
                    http_response("200 OK", "application/json", r#"{"ok":true}"#).await
                }
                _ => http_response("404 Not Found", "text/plain", "not found").await,
            };
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.shutdown().await;
        });
    }
}

// ========================= CLI =========================
fn usage() -> ! {
    eprintln!(
        r#"govee-charger — safety timer for the Gotrax XR Ultra charger

USAGE:
  govee-charger scan                                  list nearby H5080 plugs
  govee-charger status                                relay state + armed timer
  govee-charger charge --bars N [--mode full|long]    charge with on-device cap
  govee-charger charge --mins N                       explicit minutes (max {cap})
  govee-charger stop                                  clear timer + switch off
  govee-charger serve [--port P]                      dashboard (default 8844)

PRESETS (charge-to-full):
  1 bar = 5h   2 bars = 4h   3 bars = 3h   4 bars = 2h
PRESETS (longevity, ~80% SoC):
  1 bar = 2.5h 2 bars = 1.5h 3 bars = 1h   4 bars = already there

Every charge arms the plug's OWN timer ({cap}m hard cap), which survives a
power cut. A brownout cannot leave the charger running unattended."#,
        cap = HARD_CAP_MINS
    );
    std::process::exit(2)
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 2 {
        usage();
    }
    let skey = Some(PLUG_SKEY);
    let c = adapter().await;

    match a[1].as_str() {
        "scan" => {
            c.start_scan(ScanFilter::default()).await.unwrap();
            log::info!("scanning 10s for H5080 plugs...");
            sleep(Duration::from_secs(10)).await;
            for p in c.peripherals().await.unwrap() {
                if let Ok(Some(props)) = p.properties().await {
                    if props.local_name.as_deref().unwrap_or("").contains("H5080") {
                        println!(
                            "{}  {:>5}  {}",
                            p.address(),
                            props.rssi.map(|r| format!("{r}dBm")).unwrap_or("?".into()),
                            props.local_name.unwrap_or_default()
                        );
                    }
                }
            }
            c.stop_scan().await.ok();
        }
        "status" => match plug_info(&c, skey).await {
            Ok((on, m, left)) => {
                println!("plug:  {}", if on { "ON" } else { "OFF" });
                if left > 0 {
                    println!("timer: {m}m armed, {left}s left -> turns off on its own");
                } else {
                    println!("timer: none armed");
                }
                if on && left <= 0 {
                    eprintln!("WARNING: plug is ON with no timer armed.");
                }
            }
            Err(e) => {
                eprintln!("failed: {e}");
                std::process::exit(1);
            }
        },
        "charge" => {
            let mins = if let Some(i) = a.iter().position(|x| x == "--mins") {
                a.get(i + 1).and_then(|v| v.parse::<u32>().ok())
            } else {
                let bars = a
                    .iter()
                    .position(|x| x == "--bars")
                    .and_then(|i| a.get(i + 1))
                    .and_then(|v| v.parse::<u8>().ok())
                    .unwrap_or(0);
                let mode = a
                    .iter()
                    .position(|x| x == "--mode")
                    .and_then(|i| a.get(i + 1))
                    .map(|s| s.as_str())
                    .unwrap_or("full");
                preset(bars, mode)
            };
            match mins {
                None => {
                    eprintln!("need --bars 1-4 (with optional --mode long) or --mins N");
                    std::process::exit(2);
                }
                Some(0) => {
                    eprintln!("battery already at target for that preset — no charge needed");
                    std::process::exit(0);
                }
                Some(m) => match cmd_charge(&c, m, skey).await {
                    Ok(m) => println!("ON, auto-off armed for {m}m (hard cap {HARD_CAP_MINS}m)"),
                    Err(e) => {
                        eprintln!("failed: {e}");
                        std::process::exit(1);
                    }
                },
            }
        }
        "stop" => match cmd_stop(&c, skey).await {
            Ok(()) => println!("OFF, timer cleared"),
            Err(e) => {
                eprintln!("failed: {e}");
                std::process::exit(1);
            }
        },
        "serve" => {
            let port = a
                .iter()
                .position(|x| x == "--port")
                .and_then(|i| a.get(i + 1))
                .and_then(|v| v.parse::<u16>().ok())
                .unwrap_or(8844);
            serve(&c, port, skey).await;
        }
        _ => usage(),
    }
}
