# govee-charger-control

Safety cut-off for charging a **Gotrax XR Ultra** e-scooter through a **Govee H5080**
smart plug.

The entire point of this project is that **it must be impossible to leave the
charger energised**. Everything below is in service of that one sentence.

## Why a timer and not a measurement

The H5080 is a bare relay. It has **no power monitoring whatsoever** — no watts,
no amps, no energy, nothing in the protocol to report a load. So "stop when the
battery is full" cannot be measured; it has to be bounded in time.

That is also why the presets are **generous ceilings, not estimates**. The
charger's own red→green CV cutoff is the primary stop. This project is the
backstop for when you forget, not a charge controller.

## Two independent stops

1. **The plug's own auto-off timer.** `0x33 0xB0` arms an on-device timer that
   lives in the plug's non-volatile memory and counts down against absolute wall
   clock. Verified live 2026-11-17: a 30-minute timer was armed, the plug was
   pulled off the wall for ~2 minutes, and on restore the deadline was
   **unchanged** (`leftSec 1546` vs `1545` expected uninterrupted; a restart
   would have shown ~1740). So a Pi crash, a brownout or a full power cut cannot
   leave the charger running — the plug kills it by itself.

2. **The relay remembers its last state across a power cut.** Verified: ON→ON,
   OFF→OFF. This is *why* (1) matters. A brownout re-energises whatever the plug
   was doing, and no code on the Pi can prevent that, because the relay decides
   before Linux is even up. Never leave this plug ON without a timer armed.

## Hardware

| | |
|---|---|
| Plug | Govee H5080, MAC `D4:AD:FC:42:E2:45` (advertises `ihoment_H5080_E245`), skey `f6e0730a5be545e3` |
| Scooter | Gotrax XR Ultra — 36 V 7 Ah (252 Wh), charger 42 V 2 A |
| Host | Raspberry Pi (`192.168.2.21`) with a TP-Link USB BT dongle; the onboard radio is disabled via `dtoverlay=disable-bt` |

Charging from empty: 7 Ah ÷ 2 A = 3.5 h constant-current, plus the CV taper —
about **4–5 h** in practice.

## Presets

Read the scooter's 4-bar display. The bars are voltage-derived and sag under
load, so they are a rough guide at best.

**Charge to full** — generous, so you never come back to a half-charged scooter:

| Bars | Timer |
|---|---|
| 1 | 5 h |
| 2 | 4 h |
| 3 | 3 h |
| 4 | 2 h |

**Longevity (~80 % SoC)** — stops before the CV taper, where Li-ion ages slowest:

| Bars | Timer |
|---|---|
| 1 | 2.5 h |
| 2 | 1.5 h |
| 3 | 1 h |
| 4 | none (already at target) |

Any single session is clamped to a **360-minute hard cap**, so a session can
never run overnight even if a preset is wrong or the CLI is misused.

## Usage

```sh
govee-charger status                              # relay state + armed timer
govee-charger charge --bars 2 --mode full         # preset
govee-charger charge --mins 90                    # explicit (clamped to 360)
govee-charger stop                                # clear timer, then switch off
govee-charger scan                                # list nearby H5080s
govee-charger serve --port 8844                   # dashboard
```

Dashboard at `http://192.168.2.21:8844/`. LAN only, no TLS, no CDN — one inline
HTML page plus `/state.json`, same approach as the sibling humidity project.

Both `charge` and the CLI verify the arm before reporting success: if the plug
turned ON but the timer did not take, the command fails loudly rather than
leaving an unprotected charger.

## Safety invariants

- **Order is ON, then arm.** Arming first and failing to switch on would leave a
  pending timer (harmless but confusing). Switching on and failing to arm is the
  dangerous case, so it is verified immediately afterwards.
- **`stop` clears the timer before cutting power**, so nothing is left pending.
- **The dashboard shows a red warning when the plug is ON with no timer armed.**
- **`govee-charger status` prints the same warning to stderr.**
- The plug is left safe by `stop`: relay off, timers cleared.

## Install on the Pi

```sh
cd ~/Github/govee-charger-control/govee-charger
export PATH=$HOME/.cargo/bin:$PATH
cargo build --release          # ~7 min from cold on a Pi 4
sudo systemctl enable --now govee-charger
```

`/etc/systemd/system/govee-charger.service` runs `serve --port 8844` as root
(BLE needs the privilege), `Restart=always`. It is paired with an
`ExecStartPre=/usr/local/sbin/govee-wait-bt.sh` drop-in — `bluetooth.service`
reports *started* before `org.bluez` answers on D-Bus, and a connect in that
window fails with `le-connection-abort-by-local`.

## Protocol

20-byte frames: AES-128-ECB over the first 16 bytes, RC4 over the last 4, XOR
checksum in byte 19. Handshake is `E7 01` (all-zero payload, common key
`MakingLifeSmarte`) → reply carries the session key in bytes 2..18 → `E7 02`.
Then `33 B2 <skey>`, `AA EF`, `33 B5 <unix ts BE4><01><tz i8><00>` (SyncTime —
**required**, or the on-device timer counts against a stale epoch).

Frames that matter here:

| Frame | Meaning |
|---|---|
| `33 01 11` / `33 01 10` | relay ON / OFF (sub-command is the same, payload differs) |
| `AA 01` → `aa 01 <st>` | read relay state (1 = ON) |
| `33 B0 [idx, type, mm/60, mm%60]` | arm on-device timer; idx 0, type 0 = auto-off, type 1 = auto-on |
| `AA B0 [idx, type]` → `aa b0 idx type hh mm left(3B BE)` | read timer; `left == 0` and an all-zero readback both mean no timer |

Writes go to characteristic `…2b11` with **write-without-response**; notify comes
on `…2b10`. `response=True` fails with `WRITE_NOT_PERMITTED`.

Derived from the decompiled Govee H5080 Android module
(`TurnOnOffDelayController`, `BleConstants`) and confirmed live against plug
E245 — including that `33 B0` accepts up to 1440 minutes.

## Sibling project

[`govee-humidity-control`](https://github.com/AutoMas0n/govee-humidity-control)
controls the dehumidifier (plug E1DD) and its H5179 sensor on the same Pi and the
same radio. Both daemons share the one BLE adapter, which is why the dashboard
polls the plug only every 3 minutes — every extra connect is contention the
marginal sensor link does not need. The dashboard counts the remaining time down
locally between refreshes so the UI stays live.
