import SwiftUI
import RexBoingKit

/// One row per server: five vitals and whatever needs attention.
struct FleetList: View {
    @ObservedObject var fleet: Fleet
    @ObservedObject var store: ServerStore
    @ObservedObject var settings: AppSettings
    var open: (Server.ID) -> Void

    var body: some View {
        ScrollView {
            VStack(spacing: 0) {
                HStack(spacing: 8) {
                    Text("Server").frame(maxWidth: .infinity, alignment: .leading)
                    ForEach(["CPU", "Memory", "GPU", "Temp", "Power"], id: \.self) { label in
                        Text(label).frame(width: 58, alignment: .leading)
                    }
                }
                .font(.system(size: 9, weight: .semibold))
                .foregroundStyle(.tertiary)
                .textCase(.uppercase)
                .padding(.horizontal, 14)
                .padding(.top, 10)
                .padding(.bottom, 4)

                ForEach(store.servers) { server in
                    if let connection = fleet.connection(server.id) {
                        FleetRow(server: server, connection: connection, unit: settings.temperatureUnit)
                            .contentShape(Rectangle())
                            .onTapGesture { open(server.id) }
                        Divider().opacity(0.35).padding(.leading, 14)
                    }
                }
            }
            .padding(.bottom, 8)
        }
    }
}

private struct FleetRow: View {
    var server: Server
    @ObservedObject var connection: ServerConnection
    var unit: TemperatureUnit

    @State private var hovering = false

    var body: some View {
        HStack(spacing: 8) {
            HStack(spacing: 8) {
                Image(nsImage: CharacterIcon.image(for: server.character))
                    .renderingMode(.template)
                    .resizable()
                    .interpolation(.high)
                    .frame(width: 27, height: 16.5)
                    .foregroundStyle(isLive ? Palette.cpu : Color.secondary.opacity(0.5))
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 5) {
                        Text(server.name)
                            .font(.system(size: 12, weight: .semibold))
                            .lineLimit(1)
                        if let flag { FlagChip(text: flag.text, color: flag.color) }
                    }
                    Text(subtitle)
                        .font(.system(size: 10))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            if isLive, let snapshot = connection.snapshot {
                Vital(value: Format.percent(snapshot.cpu.total), fraction: snapshot.cpu.total, color: Palette.cpu)
                Vital(value: Format.percent(snapshot.memory.fractionUsed), fraction: snapshot.memory.fractionUsed, color: Palette.memory)
                if snapshot.gpu.available {
                    Vital(value: Format.percent(snapshot.gpu.utilization), fraction: snapshot.gpu.utilization, color: Palette.gpu)
                } else {
                    Vital(value: "—", fraction: 0, color: Palette.gpu)
                }
                let temperature = snapshot.thermal.cpuCelsius ?? snapshot.thermal.peakCelsius
                Vital(
                    value: temperature.map { String(format: "%.0f°", Format.temperatureValue($0, unit: unit)) } ?? "—",
                    fraction: (temperature ?? 0) / 100, color: Palette.thermal)
                let watts = snapshot.power.totalWatts ?? snapshot.power.gpuWatts
                Vital(value: watts.map { Format.watts($0) } ?? "—", fraction: min(1, (watts ?? 0) / 150), color: Palette.power)
            } else {
                Text(statusLine)
                    .font(.system(size: 10.5))
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .frame(width: 58 * 5 + 32, alignment: .leading)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .background(Color.primary.opacity(hovering ? 0.05 : 0))
        .onHover { hovering = $0 }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isButton)
    }

    private var isLive: Bool { connection.state == .live }

    private var subtitle: String {
        var parts: [String] = []
        if let host = connection.hello?.host {
            if let os = [host.osName, host.osVersion].compactMap({ $0 }).joined(separator: " ").nilIfEmpty { parts.append(os) }
        } else {
            parts.append(server.destinationLabel)
        }
        if isLive, let uptime = connection.snapshot?.extras.system?.uptime {
            parts.append("up \(Format.duration(uptime))")
        } else if isLive, let boot = connection.snapshot?.host.bootTime, boot > .distantPast {
            parts.append("up \(Format.duration(Date().timeIntervalSince(boot)))")
        }
        return parts.joined(separator: " · ")
    }

    private var flag: (text: String, color: Color)? {
        if case .attention = connection.state { return ("Needs you", Palette.critical) }
        guard isLive, let snapshot = connection.snapshot else { return nil }
        if snapshot.extras.system?.rebootRequired == true { return ("Reboot", Palette.elevated) }
        if let failed = snapshot.extras.system?.failedServices, !failed.isEmpty {
            return ("\(failed.count) failed", Palette.high)
        }
        if snapshot.memory.pressureLevel == .critical { return ("Memory", Palette.critical) }
        if let fraction = Optional(snapshot.disk.fractionUsed), fraction > 0.92 { return ("Disk full", Palette.high) }
        return nil
    }

    private var statusLine: String {
        switch connection.state {
        case .idle: return "Paused"
        case .connecting: return "Connecting…"
        case .live: return ""
        case .waiting(_, let reason):
            let since = connection.downSince.map { " Offline \(Format.duration(Date().timeIntervalSince($0)))." } ?? ""
            return reason + since
        case .attention(let issue): return issue.title
        }
    }
}

private struct Vital: View {
    var value: String
    var fraction: Double
    var color: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(value)
                .font(.system(size: 11.5, weight: .medium))
                .monospacedDigit()
                .lineLimit(1)
                .minimumScaleFactor(0.8)
            MiniBar(fraction: max(0, min(1, fraction)), accent: color, height: 3)
        }
        .frame(width: 58, alignment: .leading)
    }
}

struct FlagChip: View {
    var text: String
    var color: Color

    var body: some View {
        Text(text)
            .font(.system(size: 9, weight: .semibold))
            .foregroundStyle(color)
            .padding(.horizontal, 5)
            .padding(.vertical, 1)
            .background(Capsule(style: .continuous).fill(color.opacity(0.14)))
    }
}

extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
}
