#!/usr/bin/env python3
"""Builds demo mode's Windows gaming PC from another demo recording.

No Windows machine with an NVIDIA card was at hand to record, so this one is
reconstructed rather than recorded: the moment-to-moment CPU load, network and
disk timing come from a real (already scrubbed) recording, and everything is
written in exactly the fields the Windows agent sends — PDH CPU and memory, the
GPU engines Windows reports, nvidia-smi's temperature, power, fan and clocks,
LibreHardwareMonitor's sensors and fans, drive letters, .exe processes, and no
load average or pressure stall, which Windows does not have.

Replace it with a real recording when you can:

    AGENT_PATH='.\\AppData\\Local\\RexBoingRemote\\rex-boing-agent.exe' Tools/demo-record.sh gaming-pc > raw.jsonl
    Tools/demo-scrub.py raw.jsonl RexBoingRemote/Demo/Recordings/windows-gaming-pc.jsonl --hostname GAMING-PC ...

Usage:
    Tools/demo-windows.py RexBoingRemote/Demo/Recordings/linux-home-server.jsonl \\
        RexBoingRemote/Demo/Recordings/windows-gaming-pc.jsonl
"""
import json
import math
import random
import sys

GPU = "NVIDIA GeForce RTX 4070 SUPER"
IGPU = "AMD Radeon(TM) Graphics"
CPU = "AMD Ryzen 7 7800X3D"
GIB = 1 << 30

# name, path, base CPU (% of one core), memory, GPU %, threads
PROCESSES = [
    ("Game-Win64-Shipping.exe", r"D:\Games\Game\Binaries\Win64\Game-Win64-Shipping.exe", 260, 9.6 * GIB, 88, 118),
    ("obs64.exe", r"C:\Program Files\obs-studio\bin\64bit\obs64.exe", 9, 0.62 * GIB, 6, 64),
    ("dwm.exe", r"C:\Windows\System32\dwm.exe", 3.5, 0.16 * GIB, 2.5, 22),
    ("msedge.exe", r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", 1.6, 0.34 * GIB, 0.4, 41),
    ("MsMpEng.exe", r"C:\Program Files\Windows Defender\MsMpEng.exe", 1.2, 0.38 * GIB, 0, 38),
    ("explorer.exe", r"C:\Windows\explorer.exe", 0.6, 0.19 * GIB, 0.2, 74),
    ("audiodg.exe", r"C:\Windows\System32\audiodg.exe", 0.9, 0.03 * GIB, 0, 7),
    ("Memory Compression", "", 0.2, 0.71 * GIB, 0, 52),
    ("System", "", 1.1, 0.002 * GIB, 0, 260),
    ("svchost.exe", r"C:\Windows\System32\svchost.exe", 0.5, 0.05 * GIB, 0, 14),
    ("nvcontainer.exe", r"C:\Program Files\NVIDIA Corporation\NvContainer\nvcontainer.exe", 0.3, 0.06 * GIB, 0, 31),
    ("csrss.exe", r"C:\Windows\System32\csrss.exe", 0.3, 0.006 * GIB, 0.1, 13),
    ("sshd.exe", r"C:\Windows\System32\OpenSSH\sshd.exe", 0.1, 0.008 * GIB, 0, 4),
    ("rex-boing-agent.exe", r"C:\Users\alex\AppData\Local\RexBoingRemote\rex-boing-agent.exe", 0.4, 0.025 * GIB, 0, 12),
]


def gpu_load(i, n, rng):
    """In a match, then a loading screen, then back in."""
    if 0.42 * n <= i < 0.5 * n:
        return 0.32 + rng.uniform(-0.04, 0.04)
    return min(0.99, 0.94 + 0.03 * math.sin(i / 3.1) + rng.uniform(-0.03, 0.02))


def main():
    source, out = sys.argv[1], sys.argv[2]
    rng = random.Random(4070)
    lines = [json.loads(line) for line in open(source, encoding="utf-8") if line.strip()]
    samples = [m for m in lines if m.get("type") == "sample"]
    n = len(samples)
    t0 = samples[0]["t"]

    hello = {
        "type": "hello", "protocol": 1,
        "agent": {"name": "rex-boing-agent", "version": "0.1.0", "os": "windows", "arch": "amd64"},
        "host": {"hostname": "GAMING-PC", "modelName": "Desktop PC", "chipName": CPU,
                 "osName": "Windows 11 Pro", "osVersion": "24H2", "kernel": "10.0.26100.4652",
                 "physicalCores": 8, "logicalCores": 16, "memoryBytes": 32 * GIB,
                 "bootTime": t0 - int(3.4 * 86400 * 1000), "virtualization": "none"},
        "capabilities": ["cpu", "memory", "gpu", "sensors", "fans", "power", "network", "disk",
                         "processes", "system"],
        "interval": 1,
    }
    out_lines = [hello]
    starts = {p[0]: t0 * 1000 - rng.randint(600, 200000) * 1_000_000 for p in PROCESSES}
    starts["Game-Win64-Shipping.exe"] = t0 * 1000 - 2_460 * 1_000_000
    rx_total = tx_total = read_total = write_total = 0.0
    gpu_c = 63.0
    cpu_c = 70.0

    for i, src in enumerate(samples):
        full = "processes" in src
        u = gpu_load(i, n, rng)
        per_core = [round(min(1, 0.35 + 0.6 * v + rng.uniform(-0.05, 0.05)), 3)
                    for v in src["cpu"]["perCore"]]
        total = sum(per_core) / len(per_core)
        system_share = 0.18 + rng.uniform(-0.02, 0.02)
        cpu = {"total": round(total, 4), "user": round(total * (1 - system_share), 4),
               "system": round(total * system_share, 4), "idle": round(1 - total, 4),
               "perCore": per_core, "clockMHz": round(4750 + 200 * total + rng.uniform(-40, 40)),
               "processes": 291 + rng.randint(-2, 2), "threads": 4180 + rng.randint(-20, 20)}

        used = int((18.4 + 0.3 * math.sin(i / 9) + (0.0 if u > 0.5 else -1.1)) * GIB)
        page_total = 9 * GIB
        memory = {"total": 32 * GIB, "used": used, "available": 32 * GIB - used,
                  "pressure": round(used / (32 * GIB), 4), "pressureLevel": "normal",
                  "cached": int(6.2 * GIB), "wired": int(0.92 * GIB),
                  "swap": {"total": page_total, "used": int(page_total * 0.06), "free": int(page_total * 0.94)}}

        # The card warms and cools behind its load, as a heatsink does.
        gpu_c += ((58 + 13 * u) - gpu_c) * 0.15
        cpu_c += ((52 + 30 * total) - cpu_c) * 0.25
        watts = round(48 + 170 * u + rng.uniform(-6, 6), 1)
        engines = {"3d": round(u, 3), "copy": round(0.05 + rng.uniform(0, 0.03), 3),
                   "videoencode": round(0.12 + rng.uniform(-0.01, 0.02), 3),
                   "videodecode": 0.0, "compute": round(rng.uniform(0, 0.02), 3)}
        gpus = [
            {"name": GPU, "vendor": "nvidia", "utilization": round(u, 3), "engines": engines,
             "memoryUsed": int((9.2 + 0.25 * u) * GIB), "memoryTotal": 12 * GIB,
             "celsius": round(gpu_c), "watts": watts, "fanPercent": round(30 + 30 * (gpu_c - 55) / 20),
             "clockMHz": round(2610 + 110 * u + rng.uniform(-15, 15)), "maxClockMHz": 3105},
            {"name": IGPU, "vendor": "amd", "utilization": round(rng.uniform(0.005, 0.02), 3),
             "engines": {"3d": round(rng.uniform(0.005, 0.02), 3), "copy": 0.0, "videodecode": 0.0},
             "memoryUsed": int(0.31 * GIB), "memoryTotal": int(16.5 * GIB)},
        ]

        thermal = {"cpuCelsius": round(cpu_c, 1), "gpuCelsius": round(gpu_c),
                   "storageCelsius": 44.0, "peakCelsius": round(max(cpu_c + 6, gpu_c + 11), 1),
                   "state": "nominal"}
        if i % 10 == 0:
            thermal["sensors"] = [
                {"key": "cpu0", "label": f"Core (Tctl/Tdie) ({CPU})", "celsius": round(cpu_c, 1), "category": "CPU"},
                {"key": "cpu1", "label": f"CCD1 (Tdie) ({CPU})", "celsius": round(cpu_c - 3.5, 1), "category": "CPU"},
                {"key": "gpu0", "label": f"GPU Core ({GPU})", "celsius": round(gpu_c), "category": "GPU"},
                {"key": "gpu1", "label": f"GPU Hot Spot ({GPU})", "celsius": round(gpu_c + 11), "category": "GPU"},
                {"key": "gpu2", "label": f"GPU Memory Junction ({GPU})", "celsius": round(gpu_c + 8), "category": "GPU"},
                {"key": "ssd0", "label": "Composite Temperature (NVMe SSD 2TB)", "celsius": 44.0, "category": "Storage"},
                {"key": "ssd1", "label": "Composite Temperature (NVMe SSD 4TB)", "celsius": 41.0, "category": "Storage"},
                {"key": "mb0", "label": "Motherboard (Nuvoton NCT6799D)", "celsius": 38.0, "category": "Other"},
            ]
        if full:
            thermal["fans"] = [
                {"index": 0, "label": "CPU Fan", "rpm": round(900 + 18 * (cpu_c - 50))},
                {"index": 1, "label": "System Fan #1", "rpm": 860 + rng.randint(-10, 10)},
                {"index": 2, "label": "System Fan #2", "rpm": 880 + rng.randint(-10, 10)},
                {"index": 3, "label": f"GPU Fan 1 ({GPU})", "rpm": round(900 + 40 * (gpu_c - 55))},
            ]

        cpu_watts = round(42 + 45 * total + rng.uniform(-3, 3), 1)
        power = {"cpuWatts": cpu_watts, "packageWatts": cpu_watts, "gpuWatts": watts}

        rx = 140_000 + src["network"]["rx"] * 2 + rng.uniform(0, 40_000)
        tx = 760_000 + rng.uniform(-30_000, 30_000)  # a 6 Mbit/s stream going out
        rx_total += rx
        tx_total += tx
        network = {"rx": round(rx), "tx": round(tx), "rxTotal": int(rx_total), "txTotal": int(tx_total),
                   "primaryInterface": "Ethernet", "localAddress": "192.168.1.40"}
        if full:
            network["interfaces"] = [{"name": "Ethernet", "rx": round(rx), "tx": round(tx), "speedMbps": 2500, "up": True}]

        loading = u < 0.5
        read = (180e6 if loading else 4e6) * rng.uniform(0.5, 1.2)
        write = src["disk"].get("write", 0) * 0.2 + rng.uniform(0, 300_000)
        read_total += read
        write_total += write
        disk = {"read": round(read), "write": round(write), "readTotal": int(read_total), "writeTotal": int(write_total)}
        if full and i % 10 == 0:
            disk["volumes"] = [
                {"name": "C:\\", "mount": "C:\\", "fs": "NTFS", "total": 2_000_381_014_016, "available": 1_204_550_000_000},
                {"name": "D:\\", "mount": "D:\\", "fs": "NTFS", "total": 4_000_768_028_672, "available": 1_398_200_000_000},
            ]

        sample = {"type": "sample", "seq": i + 1, "t": src["t"], "interval": 1, "detail": "full",
                  "resync": False, "cpu": cpu, "memory": memory, "gpus": gpus, "thermal": thermal,
                  "power": power, "network": network, "disk": disk,
                  "system": {"uptime": round((src["t"] - hello["host"]["bootTime"]) / 1000), "rebootRequired": False}}

        if full:
            rows = []
            pid = 1000
            for name, path, base, mem, gpu_pct, threads in PROCESSES:
                pid += 1700 + (len(name) * 37) % 900
                scale = (0.45 if loading else 1) if name.startswith("Game") else 1
                row = {"pid": 4 if name == "System" else pid, "name": name, "start": starts[name],
                       "cpu": round(base * scale * rng.uniform(0.85, 1.15), 2),
                       "memory": int(mem * rng.uniform(0.98, 1.02)),
                       "gpu": round(gpu_pct * (u / 0.95 if name.startswith("Game") else 1) * rng.uniform(0.9, 1.1), 2),
                       "diskRead": round(read * (0.9 if name.startswith("Game") else 0.001)),
                       "diskWrite": round(write * (0.6 if name.startswith("obs") else 0.02)),
                       "threads": threads}
                if path:
                    row["path"] = path
                rows.append(row)

            def ranked(key, value):
                ordered = sorted((r for r in rows if value(r) > 0), key=value, reverse=True)
                return [r["pid"] for r in ordered[:8]]

            sample["processes"] = {
                "count": cpu["processes"], "sampledAt": src["t"], "interval": 1, "gpuAttribution": True,
                "rows": rows,
                "rank": {"cpu": ranked("cpu", lambda r: r["cpu"]),
                         "memory": ranked("memory", lambda r: r["memory"]),
                         "gpu": ranked("gpu", lambda r: r["gpu"]),
                         "disk": ranked("disk", lambda r: r["diskRead"] + r["diskWrite"])},
            }
        out_lines.append(sample)

    text = "\n".join(json.dumps(m, separators=(",", ":")) for m in out_lines) + "\n"
    with open(out, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"wrote {out}: {n} samples, {len(text) // 1024} KB")


if __name__ == "__main__":
    main()
