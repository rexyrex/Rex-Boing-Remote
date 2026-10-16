import SwiftUI
import RexBoingKit

/// How long work waited for CPU, memory and disk — Linux's pressure stall
/// information. Busy is not the same as struggling; this is the struggling.
struct PressureCard: View {
    var pressure: WirePressure

    var body: some View {
        Card(
            accent: Palette.swap, title: "Pressure", symbol: "gauge.with.dots.needle.33percent",
            headline: Format.percent((pressure.cpu ?? 0) / 100, decimals: 1)
        ) {
            row("CPU", pressure.cpu, full: nil)
            row("Memory", pressure.memory, full: pressure.memoryFull)
            row("Disk", pressure.io, full: pressure.ioFull)
            Text("Share of the last 10 seconds that work spent waiting.")
                .font(.system(size: 9.5))
                .foregroundStyle(.tertiary)
        }
    }

    private func row(_ label: String, _ some: Double?, full: Double?) -> some View {
        let value = (some ?? 0) / 100
        return VStack(alignment: .leading, spacing: 3) {
            HStack {
                Text(label).metricLabel()
                Spacer()
                Text(Format.percent(value, decimals: 1))
                    .metricValue(size: 10.5)
                    .foregroundStyle(Severity.load(min(1, value * 4)).swiftUIColor)
                if let full, full > 0 {
                    Text("· all \(Format.percent(full / 100, decimals: 1))")
                        .font(.system(size: 9.5))
                        .foregroundStyle(.secondary)
                }
            }
            MiniBar(fraction: min(1, value * 4), accent: Palette.swap, height: 3)
        }
    }
}

/// The things that need a person: reboots, updates, failed services.
struct SystemCard: View {
    var snapshot: Snapshot
    var hello: WireHello?

    var body: some View {
        let system = snapshot.extras.system
        Card(accent: Palette.calm, title: "System", symbol: "server.rack",
             trailing: system?.uptime.map { "up \(Format.duration($0))" }) {
            if system?.rebootRequired == true {
                StatRow(label: "Restart needed", value: Self.shortReason(system?.rebootReason),
                        tint: Palette.elevated, symbol: "arrow.clockwise")
                    .help(system?.rebootReason ?? "")
            }
            if let updates = system?.updates {
                let security = system?.securityUpdates ?? 0
                StatRow(label: "Updates",
                        value: updates == 0 ? "up to date" : "\(updates)\(security > 0 ? " · \(security) security" : "")",
                        tint: security > 0 ? Palette.high : nil, symbol: "shippingbox")
            }
            if let failed = system?.failedServices, !failed.isEmpty {
                StatRow(label: "Failed", value: failed.prefix(3).joined(separator: ", ") + (failed.count > 3 ? " +\(failed.count - 3)" : ""),
                        tint: Palette.high, symbol: "xmark.octagon")
            } else if system != nil {
                StatRow(label: "Services", value: "none failed", symbol: "checkmark.circle")
            }
            if let containers = system?.containers {
                StatRow(label: "Containers", value: "\(containers) running", symbol: "shippingbox.circle")
            }
            if let zombies = snapshot.extras.zombies, zombies > 0 {
                StatRow(label: "Zombies", value: "\(zombies)", symbol: "exclamationmark.circle")
            }
            if let virtualization = hello?.host?.virtualization, virtualization != "none" {
                StatRow(label: "Runs in", value: virtualization, symbol: "square.stack.3d.down.right")
            }
            if let kernel = hello?.host?.kernel {
                Text(kernel)
                    .font(.system(size: 9.5, design: .monospaced))
                    .foregroundStyle(.tertiary)
                    .lineLimit(1)
            }
            if let agent = hello?.agent?.version {
                Text("agent \(agent)")
                    .font(.system(size: 9.5))
                    .foregroundStyle(.tertiary)
            }
        }
    }
}

extension SystemCard {
    /// "linux-image-6.8.0-147-generic, linux-base, gnome-shell" → "kernel 6.8.0-147 +2".
    static func shortReason(_ reason: String?) -> String {
        guard let reason, !reason.isEmpty else { return "yes" }
        let parts = reason.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        var first = parts.first ?? reason
        if first.hasPrefix("linux-image-") {
            first = "kernel " + first.dropFirst("linux-image-".count)
                .replacingOccurrences(of: "-generic", with: "")
        } else if first.hasPrefix("kernel ") {
            first = first.replacingOccurrences(of: " installed", with: "")
        }
        if first.count > 26 { first = String(first.prefix(25)) + "…" }
        return parts.count > 1 ? "\(first) +\(parts.count - 1)" : first
    }
}

/// Every GPU, with its engines, clocks, temperature, power and fan.
struct GPUDetailCard: View {
    var gpus: [WireGPU]
    var unit: TemperatureUnit

    var body: some View {
        Card(accent: Palette.gpu, title: gpus.count > 1 ? "GPUs" : "GPU detail", symbol: "cpu") {
            ForEach(Array(gpus.enumerated()), id: \.offset) { _, gpu in
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Text(gpu.name ?? "GPU").font(.system(size: 11, weight: .medium))
                        Spacer()
                        Text(Format.percent(gpu.utilization ?? 0)).metricValue(size: 11, weight: .semibold)
                            .foregroundStyle(Palette.gpu)
                    }
                    if let engines = gpu.engines, !engines.isEmpty {
                        ForEach(engines.sorted(by: { $0.key < $1.key }), id: \.key) { name, value in
                            HStack(spacing: 8) {
                                Text(name.capitalized).metricLabel().frame(width: 80, alignment: .leading)
                                MiniBar(fraction: value, accent: Palette.gpu, height: 3)
                                Text(Format.percent(value)).metricValue(size: 10).frame(width: 38, alignment: .trailing)
                            }
                        }
                    }
                    HStack(spacing: 0) {
                        if let celsius = gpu.celsius {
                            StatTile(label: "Temp", value: Format.temperature(celsius, unit: unit),
                                     tint: Severity.temperature(celsius).swiftUIColor)
                        }
                        if let watts = gpu.watts { StatTile(label: "Power", value: Format.watts(watts)) }
                        if let fan = gpu.fanPercent { StatTile(label: "Fan", value: Format.percent(fan / 100)) }
                        if let clock = gpu.clockMHz { StatTile(label: "Clock", value: Format.frequency(clock)) }
                        if let used = gpu.memoryUsed, let total = gpu.memoryTotal, total > 0 {
                            StatTile(label: "Memory", value: "\(Format.bytes(used)) / \(Format.bytes(total))")
                        }
                    }
                }
            }
        }
    }
}

/// Every mounted filesystem, fullest first.
struct VolumesCard: View {
    var volumes: [WireVolume]

    var body: some View {
        Card(accent: Palette.disk, title: "Filesystems", symbol: "externaldrive", trailing: "\(volumes.count)") {
            ForEach(volumes.sorted(by: { fraction($0) > fraction($1) })) { volume in
                VStack(alignment: .leading, spacing: 3) {
                    HStack {
                        Text(volume.name ?? volume.mount ?? "?")
                            .font(.system(size: 10.5, design: .monospaced))
                            .lineLimit(1)
                            .truncationMode(.middle)
                        if let fs = volume.fs {
                            Text(fs).font(.system(size: 9)).foregroundStyle(.tertiary)
                        }
                        Spacer()
                        Text("\(Format.diskBytes(volume.available ?? 0)) free of \(Format.diskBytes(volume.total ?? 0))")
                            .metricValue(size: 10)
                            .foregroundStyle(.secondary)
                    }
                    MiniBar(fraction: fraction(volume),
                            accent: fraction(volume) > 0.9 ? Palette.critical : Palette.disk, height: 4)
                }
            }
        }
    }

    private func fraction(_ volume: WireVolume) -> Double {
        guard let total = volume.total, total > 0 else { return 0 }
        return 1 - Double(volume.available ?? 0) / Double(total)
    }
}

/// One-off hints from the agent, such as a permission that unlocks CPU power.
struct NoticesCard: View {
    var notices: [String: String]

    var body: some View {
        Card(accent: .secondary, title: "Tips from the agent", symbol: "lightbulb") {
            ForEach(notices.sorted(by: { $0.key < $1.key }), id: \.key) { _, message in
                Text(message)
                    .font(.system(size: 10.5))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}
