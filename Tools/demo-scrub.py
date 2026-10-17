#!/usr/bin/env python3
"""Turns a recorded agent stream into a demo recording.

Every hostname, user, address, mount point, path and process command line
becomes a neutral example; the process table is thinned to what the dashboard
shows; numbers are rounded so the file stays small. Then it checks its own
work, and writes nothing if anything it removed, anything passed with --deny,
or anything that looks like a real address or home folder is still there.

    Tools/demo-record.sh myserver > raw.jsonl
    Tools/demo-scrub.py raw.jsonl RexBoingRemote/Demo/Recordings/linux-home-server.jsonl \\
        --hostname home-server --model "Mini PC" --deny myserver --deny alice

--deny takes anything else that must not appear (a NAS name, a domain, your
own name). It is checked case-insensitively and never written anywhere.
"""
import argparse
import ipaddress
import json
import re
import sys

# Processes whose names say nothing about whose machine it is.
KEEP_NAMES = {
    # Linux
    "systemd", "systemd-journald", "systemd-resolved", "systemd-udevd", "systemd-logind",
    "systemd-networkd", "systemd-timesyncd", "systemd-oomd", "init", "kthreadd", "sshd",
    "sshd-session", "cron", "rsyslogd", "dbus-daemon", "dbus-broker", "containerd",
    "containerd-shim", "containerd-shim-runc-v2", "dockerd", "docker-proxy", "tailscaled",
    "node", "python", "python3", "java", "postgres", "redis-server", "nginx", "mysqld",
    "mariadbd", "smbd", "nmbd", "gnome-shell", "Xorg", "Xwayland", "pipewire", "wireplumber",
    "snapd", "NetworkManager", "ModemManager", "polkitd", "udisksd", "upowerd", "avahi-daemon",
    "cupsd", "thermald", "irqbalance", "multipathd", "agetty", "bash", "sh", "zsh", "ffmpeg",
    "rex-boing-agent", "fwupd", "packagekitd", "unattended-upgr", "networkd-dispatcher",
    # macOS
    "kernel_task", "WindowServer", "launchd", "mds", "mds_stores", "mdworker_shared", "backupd",
    "cfprefsd", "coreaudiod", "bluetoothd", "sharingd", "logd", "opendirectoryd", "syspolicyd",
    "trustd", "distnoted", "powerd", "airportd", "configd", "hidd", "softwareupdated", "Finder",
    "Dock", "SystemUIServer", "ControlCenter", "loginwindow", "cloudd", "nsurlsessiond",
    "photoanalysisd", "mediaanalysisd", "corespotlightd", "spotlightknowledged", "Spotlight",
    "VTDecoderXPCService", "VTEncoderXPCService", "avconferenced", "coreduetd", "runningboardd",
    "UserEventAgent", "remoted", "watchdogd", "symptomsd", "rapportd", "locationd", "fseventsd",
}
KERNEL_THREAD = re.compile(r"^(kworker|ksoftirqd|migration|irq|rcu|cpuhp|idle_inject|kswapd|jbd2|"
                           r"khugepaged|kcompactd|watchdog|ext4|xfs|nfs|zfs|z_|txg|card\d|i915|xe)")
# Binaries from these places belong to the system, not to anyone in particular.
SYSTEM_DIRS = ("/usr/libexec/", "/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/", "/System/",
               "/usr/lib/", "/lib/", "/Library/Apple/")
SYSTEM_USERS = {"root", "daemon", "nobody", "messagebus", "syslog", "systemd-resolve",
                "systemd-network", "systemd-timesync", "systemd-oom", "polkitd", "avahi",
                "postgres", "www-data", "_windowserver", "colord", "rtkit", "gdm", "lp",
                "kernoops", "whoopsie", "tss", "uuidd", "dnsmasq", "redis", "mysql"}
KEEP_MOUNTS = {"/", "/boot", "/boot/efi", "/home", "/var", "/tmp", "/System/Volumes/Data"}

NAME_POOL = {
    "linux": ["python3", "java", "postgres", "redis-server", "nginx", "grafana", "prometheus",
              "influxd", "mosquitto", "syncthing", "caddy", "restic", "rsync", "deno",
              "beam.smp", "php-fpm", "node", "ffmpeg"],
    "darwin": ["node", "ffmpeg", "python3", "postgres", "redis-server", "nginx", "syncthing",
               "rsync", "caddy", "ruby", "java", "deno", "swift-frontend", "clang", "git",
               "make", "go", "dotnet"],
}
MOUNT_POOL = ["/srv/media", "/srv/backup", "/srv/photos", "/srv/archive", "/srv/scratch",
              "/srv/projects", "/srv/downloads", "/srv/music"]
SERVICE_POOL = ["backup.service", "nightly-sync.service", "media-scan.service"]


def significant(value, digits=5):
    """Rounds floats to a few significant digits; the dashboard shows fewer."""
    if isinstance(value, float):
        return float(f"{value:.{digits}g}")
    if isinstance(value, list):
        return [significant(v, digits) for v in value]
    if isinstance(value, dict):
        return {k: significant(v, digits) for k, v in value.items()}
    return value


class Scrubber:
    def __init__(self, args, hello):
        self.args = args
        self.os = (hello.get("agent") or {}).get("os", "linux")
        self.names = {}
        self.mounts = {}
        self.pool = list(NAME_POOL.get(self.os, NAME_POOL["linux"]))
        self.deny = {d.lower() for d in args.deny if d}
        host = hello.get("host") or {}
        if host.get("hostname"):
            self.deny.add(host["hostname"].lower())
        self.first_chip = host.get("chipName")

    # -- names -----------------------------------------------------------

    def is_system(self, name, binary):
        if name in KEEP_NAMES or KERNEL_THREAD.match(name or ""):
            return True
        return bool(binary) and binary.startswith(SYSTEM_DIRS) and "/Users/" not in binary \
            and "/home/" not in binary

    def name(self, name, binary=None):
        if name is None:
            return None
        if name in self.names:
            return self.names[name]
        if name in self.args.renames:
            mapped = self.args.renames[name]
        elif self.is_system(name, binary):
            mapped = name
        else:
            mapped = self.pool[len([v for k, v in self.names.items() if v != k]) % len(self.pool)]
        self.names[name] = mapped
        return mapped

    def user(self, user):
        if user is None:
            return None
        # A bare uid (a container's user, unknown to the host) names nobody.
        if user in SYSTEM_USERS or user.startswith(("_", "systemd-")) or user.isdigit():
            return user
        self.deny.add(user.lower())
        return self.args.user

    def mount(self, mount):
        if mount in KEEP_MOUNTS or re.fullmatch(r"[A-Z]:\\", mount or ""):
            return mount
        if mount not in self.mounts:
            self.deny.add(mount.lower())
            self.mounts[mount] = MOUNT_POOL[len(self.mounts) % len(MOUNT_POOL)]
        return self.mounts[mount]

    # -- sections --------------------------------------------------------

    def hello(self, hello):
        host = hello.setdefault("host", {})
        host["hostname"] = self.args.hostname
        for key, value in (("modelName", self.args.model), ("modelIdentifier", self.args.model_id),
                           ("vendor", self.args.vendor), ("chipName", self.args.chip)):
            if value == "":
                host.pop(key, None)
            elif value is not None:
                host[key] = value
        if self.args.no_battery:
            hello["capabilities"] = [c for c in hello.get("capabilities", []) if c != "battery"]
        if self.args.efficiency_cores and host.get("efficiencyCores") is not None:
            extra = self.args.efficiency_cores - host["efficiencyCores"]
            for key in ("efficiencyCores", "physicalCores", "logicalCores"):
                if host.get(key) is not None:
                    host[key] += extra
        return hello

    def processes(self, processes):
        rows = processes.get("rows") or []
        rank = processes.get("rank") or {}
        top = self.args.rank_top
        keep = set()
        for metric, pids in rank.items():
            keep.update(pids[:top])
        out_rows = []
        for row in rows:
            if row.get("pid") not in keep:
                continue
            original = row.get("name")
            binary = row.get("path") or (row.get("cmd") or "").split(" ")[0]
            name = self.name(original, binary)
            # A system binary keeps its path, but never its arguments.
            system = name == original and binary.startswith(SYSTEM_DIRS) and self.is_system(original, binary) \
                and original not in self.args.renames
            row["name"] = name
            if "user" in row:
                row["user"] = self.user(row["user"])
            if "cmd" in row:
                row["cmd"] = "" if not row.get("cmd") else binary if system else "/usr/bin/" + name
            if "path" in row:
                row["path"] = binary if system else "/usr/local/bin/" + name
            out_rows.append(row)
        processes["rows"] = out_rows
        processes["rank"] = {m: [p for p in pids[:top] if p in keep] for m, pids in rank.items()}
        return processes

    def sample(self, sample, index):
        if index % self.args.process_every != 0:
            sample.pop("processes", None)
        elif sample.get("processes"):
            sample["processes"] = self.processes(sample["processes"])
        # The app keeps the last sensor list until a new one comes, as it
        # does for agents that read slow sensors less often.
        thermal = sample.get("thermal") or {}
        if index % self.args.slow_every != 0:
            thermal.pop("sensors", None)
            (sample.get("disk") or {}).pop("volumes", None)
        elif self.args.no_battery and thermal.get("sensors"):
            thermal["sensors"] = [x for x in thermal["sensors"] if x.get("category") != "Battery"]

        network = sample.get("network")
        if network and network.get("localAddress"):
            self.deny.add(network["localAddress"])
            network["localAddress"] = self.args.address

        disk = sample.get("disk")
        for volume in (disk or {}).get("volumes") or []:
            mount = self.mount(volume.get("mount"))
            if volume.get("name") == volume.get("mount"):
                volume["name"] = mount
            volume["mount"] = mount

        system = sample.get("system")
        if system and system.get("failedServices"):
            system["failedServices"] = [SERVICE_POOL[i % len(SERVICE_POOL)]
                                        for i, _ in enumerate(system["failedServices"])]

        sleep = sample.get("sleep")
        if sleep and sleep.get("blockers"):
            for blocker in sleep["blockers"]:
                blocker["name"] = self.name(blocker.get("name"))
                blocker["assertions"] = ["PreventUserIdleSystemSleep"]

        if self.args.no_battery:
            sample.pop("battery", None)
            (sample.get("thermal") or {}).pop("batteryCelsius", None)
            for key in ("adapterWatts", "dcInWatts", "chargingWatts", "batteryWatts"):
                (sample.get("power") or {}).pop(key, None)

        if self.args.chip and self.first_chip:
            for gpu in sample.get("gpus") or []:
                if gpu.get("name"):
                    gpu["name"] = gpu["name"].replace(self.first_chip, self.args.chip)

        cpu = sample.get("cpu")
        if self.args.efficiency_cores and cpu and cpu.get("kinds") and cpu.get("perCore"):
            kinds, cores = cpu["kinds"], cpu["perCore"]
            existing = [v for k, v in zip(kinds, cores) if k == "E"]
            extra = self.args.efficiency_cores - len(existing)
            if extra > 0 and existing:
                added = [round(existing[i % len(existing)] * 0.85, 4) for i in range(extra)]
                cpu["kinds"] = "E" * extra + kinds
                cpu["perCore"] = added + cores
        return significant(sample)

    # -- the check -------------------------------------------------------

    def leaks(self, text):
        found = []
        lower = text.lower()
        for word in sorted(self.deny):
            if word and word in lower:
                found.append(f"'{word}'")
        allowed = {self.args.address, "127.0.0.1", "0.0.0.0"}
        for match in re.findall(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])", text):
            try:
                ipaddress.ip_address(match)
            except ValueError:
                continue
            if match not in allowed:
                found.append(f"address {match}")
        for marker in ("/Users/", "/home/", "C:\\\\Users\\\\"):
            if marker.lower() in lower:
                found.append(f"a path under {marker}")
        return found


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("raw")
    parser.add_argument("out")
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--model")
    parser.add_argument("--model-id")
    parser.add_argument("--vendor")
    parser.add_argument("--chip")
    parser.add_argument("--user", default="alex")
    parser.add_argument("--address", default="192.168.1.20")
    parser.add_argument("--no-battery", action="store_true", help="drop the battery (a desktop shown from a laptop's recording)")
    parser.add_argument("--efficiency-cores", type=int, help="Apple silicon: pad the efficiency cores to this many")
    parser.add_argument("--samples", type=int, help="keep at most this many samples")
    parser.add_argument("--process-every", type=int, default=3, help="keep the process table of every Nth sample")
    parser.add_argument("--slow-every", type=int, default=10, help="keep the sensor and volume lists of every Nth sample")
    parser.add_argument("--rename", action="append", default=[], metavar="OLD=NEW",
                        help="show a process under another name (say, a load generator as the work it stands for)")
    parser.add_argument("--rank-top", type=int, default=8, help="keep the top N processes of each ranking")
    parser.add_argument("--deny", action="append", default=[], help="text that must not appear in the output")
    args = parser.parse_args()
    args.renames = dict(pair.split("=", 1) for pair in args.rename)

    messages = [json.loads(line) for line in open(args.raw, encoding="utf-8") if line.strip()]
    hello = next(m for m in messages if m.get("type") == "hello")
    scrubber = Scrubber(args, hello)
    out = [scrubber.hello(hello)]
    samples = [m for m in messages if m.get("type") == "sample" and not m.get("resync")]
    if args.samples:
        samples = samples[:args.samples]
    out += [scrubber.sample(s, i) for i, s in enumerate(samples)]
    out += [m for m in messages if m.get("type") == "notice"]

    text = "\n".join(json.dumps(m, separators=(",", ":")) for m in out) + "\n"
    leaks = scrubber.leaks(text)
    if leaks:
        print("refusing to write: still contains " + ", ".join(sorted(set(leaks))), file=sys.stderr)
        sys.exit(1)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(text)
    kept = sorted({v for k, v in scrubber.names.items() if k == v})
    print(f"wrote {args.out}: {len(samples)} samples, {len(text) // 1024} KB; "
          f"{len(scrubber.names)} process names, {len(kept)} kept as they were")


if __name__ == "__main__":
    main()
