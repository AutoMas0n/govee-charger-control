# Govee H5080 protocol notes (as used by this project)

Everything here was derived from the decompiled Govee H5080 Android module
(`TurnOnOffDelayController`, `BleConstants`, `AbsSingleController`) and then
confirmed live against plug E245 on 2026-11-17. The sibling project
`govee-humidity-control` documents the same protocol against its own plug.

## Transport

- GATT service `00010203-0405-0607-0809-0a0b0c0d1910`
- notify characteristic `…2b10` (`read,notify`)
- write characteristic `…2b11` (**write-without-response**)

Writing with an acknowledged (with-response) write fails:

```
BleakGATTProtocolError: (<BleakGATTProtocolErrorCode.WRITE_NOT_PERMITTED: 3>,
                         'GATT Protocol Error: Write Not Permitted')
```

## Frame layout

20 bytes. Bytes 0..16 are AES-128-ECB encrypted; bytes 16..20 are RC4 encrypted
with the same key; byte 19 is an XOR checksum over bytes 0..19.

```
frame[0]      command
frame[1]      sub-command
frame[2..19]  payload, zero padded
frame[19]     XOR of frame[0..19]
```

## Session

1. Write `E7 01` with a 16-byte all-zero payload, encrypted with the fixed
   common key `MakingLifeSmarte`. This key is a protocol constant, not a device
   secret.
2. The reply is `E7 01` and carries the per-session key in bytes 2..18.
3. Write `E7 02`.
4. Write `33 B2 <8-byte skey>` with the device skey (see the table below).

## Time sync — required

```
33 B5 <unix time as BE4> <01> <timezone as signed byte> <00>
```

**This is not optional.** Without it the plug counts its on-device timer against
a stale epoch, so a timer armed for 30 minutes can expire at the wrong moment
(or appear to have hours left). Sync on every session before touching `0xB0`.

## Commands used

| Frame | Direction | Meaning |
|---|---|---|
| `33 01 11` | write | relay ON — note the sub-command is `0x01` and only the payload differs |
| `33 01 10` | write | relay OFF |
| `AA 01` | read | relay state; replies `aa 01 <st>`, `1` = ON |
| `33 B0 [idx, type, mm/60, mm%60]` | write | arm the on-device timer |
| `AA B0 [idx, type]` | read | read the timer |
| `AA 12` | read | timer count |
| `AA 13` | read | timer data |

Timer reply: `aa b0 <idx> <type> <hh> <mm> <left as BE3>`.
`left == 0`, and an all-zero readback, both mean no timer is armed.

`type` is `0` for auto-**off** (this project's only mode) and `1` for
auto-**on**. `idx` is `0` here; indices `0` and `1` were both probed and answered.

## What the timer actually is (measured, not assumed)

`0xB0` writes a deadline into the plug's **non-volatile memory** that is counted
against **absolute wall clock time**. Measured 2026-11-17:

1. Armed a 30-minute auto-off at 00:05:41.
2. Wall power was pulled for roughly two minutes (a poller caught it at 00:08:11
   with `BleakDeviceNotFoundError`).
3. Power restored; readback at 00:09:56 was `aab00000001e00060a00`, i.e.
   index 0, type 0, minutes 30, `leftSec 1546`.

The uninterrupted expectation was 1545 seconds. A plug that had rebooted and
restarted its countdown would have shown roughly 1740. It did not restart, so
the deadline survived the outage intact.

This is the property the whole project rests on: once armed, the timer is
enforced by the plug itself, and no failure on the host side can leave the
relay on.

**Capacity:** `33 B0` accepted 240, 480 and 1440 minutes, with readbacks of
14399s, 28799s and 86399s respectively. This project still clamps to 360.

## Relay state survives a power cut (measured)

- Plug ON, power pulled and restored → relay comes back **ON**.
- Plug OFF, power pulled and restored → relay comes back **OFF**.

So the relay restores whatever it was doing before the outage. That is the fire
hazard: a brownout re-energises the charger, and no host-side code can prevent
it because the relay decides before the operating system boots.

## What the plug cannot do

There is **no power monitoring**. No watts, no amps, no energy, no load
detection. `SINGLE_BATTERY` exists as a constant in `BleConstants` but nothing
implements it — it is stale. The plug is a relay with a timer, nothing more.

This is why charge level in this project is a human input read off the
scooter's display, and why the presets are time ceilings rather than estimates.

## Constant reference

From `BleConstants` in the decompiled module:

| Name | Value |
|---|---|
| `SINGLE_BATTERY` | stale, unimplemented |
| `SINGLE_SYNC_TIME` | `-75` (`0xB5`) |
| `SINGLE_NEW_TIMER` | `-76` (`0xB4`) |
| `SINGLE_SPEC` | `-77` (`0xB3`) |
| `SINGLE_READ_SKEY` | `-79` (`0xB1`) |
| `SINGLE_NEW_DELAY` | `-80` (`0xB0`) |
| `SINGLE_READ` | `-86` (`0xAA`) |
| `SINGLE_WRITE` | `51` (`0x33`) |
| `SINGLE_NEW_TIMER_COUNT` | `18` |
| `SINGLE_NEW_TIMER_V2` | `19` |

Read vs write framing comes from `skc/AbsSingleController.java`: `getProType()`
returns `51` for write and `-86` for read.

## Devices on this Pi's radio

| Label | MAC | skey | Role |
|---|---|---|---|
| E245 | `D4:AD:FC:42:E2:45` | `f6e0730a5be545e3` | scooter charger plug (this project) |
| E1DD | `D4:AD:FC:41:E1:DD` | `a69f370afd964e0d` | dehumidifier plug (sibling project) |
| 40A4 | `E3:32:81:12:40:A4` | — | H5179 temperature/humidity sensor |
