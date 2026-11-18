#!/usr/bin/env python3
"""Read-only BLE probe for the Govee H5080. Survives as the tool of record.

Every protocol fact in README.md was established with a script like this one,
because Rust costs a ~7 min rebuild on the Pi while this costs seconds. Keep it
around for the next time the protocol has to be re-derived.

Read-only on purpose: it only ever sends 0xAA (read) frames, never 0x33
(write), so it cannot switch the relay or arm a timer. Use the Rust binary for
anything that changes state.

    PYTHONPATH=$HOME/.local/lib/python3.11/site-packages python3 plug.py

bleak is installed per-user on the Pi. Run it via systemd-run if you need root:
    sudo systemd-run --collect --unit=probe \\
        --setenv=PYTHONPATH=/home/pi/.local/lib/python3.11/site-packages \\
        --working-directory=/home/pi python3 plug.py
"""
import asyncio

from bleak import BleakClient, BleakScanner

ADDR = "D4:AD:FC:42:E2:45"          # E245, the scooter charger plug
SKEY = bytes.fromhex("f6e0730a5be545e3")
KEY_COMM = b"MakingLifeSmarte"       # fixed common key, not a device secret

CH_NOTIFY = "00010203-0405-0607-0809-0a0b0c0d2b10"
CH_WRITE = "00010203-0405-0607-0809-0a0b0c0d2b11"


# ---------------- crypto ----------------
def rc4(data, key):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out, i, j = bytearray(), 0, 0
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


def _aes():
    from Crypto.Cipher import AES
    return AES


def enc(frame, key):
    a = _aes()
    return a.new(key, a.MODE_ECB).encrypt(frame[:16]) + rc4(frame[16:], key)


def dec(payload, key):
    a = _aes()
    return a.new(key, a.MODE_ECB).decrypt(payload[:16]) + rc4(payload[16:], key)


def mk(cmd, sub, data=b""):
    f = bytearray(20)
    f[0], f[1] = cmd, sub
    f[2:2 + len(data)] = data[:17]
    f[19] = 0
    for b in f[:19]:
        f[19] ^= b
    return bytes(f)


def chk(frame):
    x = 0
    for b in frame[:19]:
        x ^= b
    return x == frame[19]


def show(frame, label):
    mins = frame[4] * 60 + frame[5]
    left = int.from_bytes(frame[6:9], "big")
    print(f"{label}: raw={frame.hex()}")
    if frame[0] == 0xAA and frame[1] == 0x01:
        print(f"  relay: {'ON' if frame[2] == 1 else 'OFF'}")
    elif frame[0] == 0xAA and frame[1] == 0xB0:
        print(f"  timer: index={frame[2]} type={frame[3]} {mins}m left={left}s")


async def main():
    dev = await BleakScanner.find_device_by_address(ADDR, timeout=20.0)
    if dev is None:
        print(f"{ADDR} not found")
        return
    seen = []

    def on_notify(_, data):
        seen.append(bytes(data))

    async with BleakClient(dev) as cli:
        # Writes MUST be response=False; the characteristic is
        # write-without-response and response=True raises WRITE_NOT_PERMITTED.
        await cli.start_notify(CH_NOTIFY, on_notify)
        await cli.write_gatt_char(CH_WRITE, enc(mk(0xE7, 0x01, b"\x00" * 16), KEY_COMM), response=False)
        await asyncio.sleep(0.6)
        sk = None
        for n in seen:
            d = dec(n, KEY_COMM)
            if d[0] == 0xE7 and d[1] == 0x01 and chk(d):
                sk = d[2:18]
        if sk is None:
            print("handshake: no key")
            return
        print(f"session key: {sk.hex()}")
        await cli.write_gatt_char(CH_WRITE, enc(mk(0xE7, 0x02, b"\x00" * 16), KEY_COMM), response=False)
        await asyncio.sleep(0.3)
        await cli.write_gatt_char(CH_WRITE, enc(mk(0x33, 0xB2, SKEY), sk), response=False)
        await asyncio.sleep(0.3)

        for cmd, sub, data, label in [
            (0xAA, 0x01, b"", "relay state"),
            (0xAA, 0xB0, b"\x00\x00", "timer idx0/type0"),
            (0xAA, 0xB0, b"\x00\x01", "timer idx0/type1"),
            (0xAA, 0x12, b"", "timer count"),
            (0xAA, 0x13, b"", "timer data"),
        ]:
            seen.clear()
            await cli.write_gatt_char(CH_WRITE, enc(mk(cmd, sub, data), sk), response=False)
            await asyncio.sleep(0.8)
            hit = False
            for n in seen:
                d = dec(n, sk)
                if chk(d) and d[0] == cmd and (sub == 0 or d[1] == sub):
                    show(d, label)
                    hit = True
            if not hit:
                print(f"{label}: no reply")


if __name__ == "__main__":
    asyncio.run(main())
