import SwiftUI
import RexBoingKit

/// One server, in Rex Boing's cards, plus the cards only a server has.
struct ServerDashboard: View {
    var server: Server
    @ObservedObject var connection: ServerConnection
    @ObservedObject var settings: AppSettings
    var back: () -> Void
    var openSettings: () -> Void
    /// Full detail from the server for as long as this dashboard exists.
    @StateObject private var viewer: ViewerLease

    init(server: Server, connection: ServerConnection, settings: AppSettings,
         back: @escaping () -> Void, openSettings: @escaping () -> Void) {
        self.server = server
        self.connection = connection
        self.settings = settings
        self.back = back
        self.openSettings = openSettings
        _viewer = StateObject(wrappedValue: connection.addViewer())
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider().opacity(0.5)
            if let issue = issue {
                ConnectionBanner(connection: connection, issue: issue)
            }
            if let snapshot = connection.snapshot {
                content(snapshot)
            } else {
                VStack(spacing: 10) {
                    ProgressView().controlSize(.small)
                    Text(waitingText)
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
                .padding()
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .onAppear { connection.refreshHistory() }
        .environment(\.machineNoun, server.os == "darwin" ? "Mac" : "machine")
        .environment(\.processControl, ProcessControl(isLocal: false))
    }

    private func content(_ snapshot: Snapshot) -> some View {
        let history = connection.history
        let unit = settings.temperatureUnit
        return ScrollView {
            VStack(spacing: Metrics.sectionSpacing) {
                HStack(alignment: .top, spacing: Metrics.sectionSpacing) {
                    CPUCard(snapshot: snapshot, history: history, unit: unit)
                    GPUCard(snapshot: snapshot, history: history, unit: unit)
                }
                .fixedSize(horizontal: false, vertical: true)

                HStack(alignment: .top, spacing: Metrics.sectionSpacing) {
                    MemoryCard(snapshot: snapshot, history: history)
                    ThermalCard(snapshot: snapshot, history: history, unit: unit)
                }
                .fixedSize(horizontal: false, vertical: true)

                HistoryCard(connection: connection, unit: unit, keepsHistory: server.keepHistory ?? false,
                            isWindows: server.isWindows, openSettings: openSettings)

                if snapshot.extras.pressure != nil || snapshot.extras.system != nil {
                    HStack(alignment: .top, spacing: Metrics.sectionSpacing) {
                        if let pressure = snapshot.extras.pressure {
                            PressureCard(pressure: pressure)
                        }
                        SystemCard(snapshot: snapshot, hello: connection.hello)
                    }
                    .fixedSize(horizontal: false, vertical: true)
                }

                if snapshot.extras.gpus.count > 1 || snapshot.extras.gpus.contains(where: { ($0.engines?.count ?? 0) > 2 || $0.celsius != nil || $0.fanPercent != nil }) {
                    GPUDetailCard(gpus: snapshot.extras.gpus, unit: unit)
                }

                ProcessesCard(usage: nil, snapshot: snapshot, rowCount: 8)
                PowerCard(snapshot: snapshot, history: history, unit: unit)

                HStack(alignment: .top, spacing: Metrics.sectionSpacing) {
                    NetworkCard(snapshot: snapshot, history: history)
                    StorageCard(snapshot: snapshot, history: history)
                }
                .fixedSize(horizontal: false, vertical: true)

                if snapshot.extras.volumes.count > 1 {
                    VolumesCard(volumes: snapshot.extras.volumes)
                }

                if !connection.notices.isEmpty {
                    NoticesCard(notices: connection.notices)
                }
            }
            .padding(11)
        }
    }

    private var header: some View {
        HStack(spacing: 10) {
            Button(action: back) {
                Image(systemName: "chevron.left")
                    .font(.system(size: 12, weight: .semibold))
            }
            .buttonStyle(.plain)
            .foregroundStyle(.secondary)
            .help("All servers")
            .accessibilityLabel("All servers")

            Image(nsImage: CharacterIcon.image(for: server.character))
                .renderingMode(.template)
                .resizable()
                .interpolation(.high)
                .frame(width: Visualizer.canvasSize.width, height: Visualizer.canvasSize.height)
                .foregroundStyle(connection.state == .live ? Palette.cpu : .secondary)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 6) {
                    Text(server.name)
                        .font(.system(size: 16, weight: .bold, design: .rounded))
                        .lineLimit(1)
                    StateDot(state: connection.state)
                }
                Text(subtitle)
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .help(subtitle)
            }
            Spacer(minLength: 4)
            Button(action: openSettings) {
                Image(systemName: "gearshape")
                    .font(.system(size: 12.5))
            }
            .buttonStyle(.plain)
            .foregroundStyle(.secondary)
            .help("Settings")
            .accessibilityLabel("Settings")
        }
        .padding(.horizontal, 13)
        .padding(.vertical, 10)
    }

    private var subtitle: String {
        guard let host = connection.hello?.host else { return server.destinationLabel }
        var parts: [String] = []
        if let model = host.modelName ?? host.hostname { parts.append(model) }
        if let chip = host.chipName, !chip.isEmpty { parts.append(chip) }
        if let cores = host.logicalCores { parts.append("\(cores) threads") }
        if let memory = host.memoryBytes { parts.append(Format.bytes(memory)) }
        if let os = [host.osName, host.osVersion].compactMap({ $0 }).joined(separator: " ").nilIfEmpty { parts.append(os) }
        if let uptime = connection.snapshot?.extras.system?.uptime {
            parts.append("up \(Format.duration(uptime))")
        }
        return parts.joined(separator: " · ")
    }

    private var issue: String? {
        switch connection.state {
        case .live, .idle: return nil
        case .connecting: return connection.snapshot == nil ? nil : "Reconnecting…"
        case .waiting(_, let reason): return reason
        case .attention(let issue): return issue.title
        }
    }

    private var waitingText: String {
        switch connection.state {
        case .connecting: return "Connecting to \(server.name)…"
        case .waiting(_, let reason): return reason
        case .attention(let issue): return issue.explanation(for: server)
        case .idle: return "Paused."
        case .live: return "Taking the first sample…"
        }
    }
}

struct StateDot: View {
    var state: ServerConnection.State

    var body: some View {
        Circle()
            .fill(color)
            .frame(width: 7, height: 7)
            .accessibilityLabel(label)
    }

    private var color: Color {
        switch state {
        case .live: return Palette.calm
        case .connecting, .waiting: return Palette.elevated
        case .attention: return Palette.critical
        case .idle: return .secondary
        }
    }

    private var label: String {
        switch state {
        case .live: return "Live"
        case .connecting: return "Connecting"
        case .waiting: return "Reconnecting"
        case .attention: return "Needs attention"
        case .idle: return "Paused"
        }
    }
}

/// Shown above the cards while the stream is down: what happened, when the
/// next try is, and the one button that helps.
struct ConnectionBanner: View {
    @ObservedObject var connection: ServerConnection
    var issue: String

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            HStack(alignment: .top, spacing: 8) {
                Image(systemName: icon)
                    .foregroundStyle(tint)
                VStack(alignment: .leading, spacing: 2) {
                    Text(issue).font(.system(size: 11, weight: .semibold))
                    Text(detail(now: context.date))
                        .font(.system(size: 10.5))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 6)
                Button("Retry Now") { connection.retryNow() }
                    .controlSize(.small)
            }
            .padding(10)
            .background(tint.opacity(0.08))
        }
    }

    private var tint: Color {
        if case .attention = connection.state { return Palette.critical }
        return Palette.elevated
    }

    private var icon: String {
        if case .attention = connection.state { return "exclamationmark.triangle.fill" }
        return "arrow.triangle.2.circlepath"
    }

    private func detail(now: Date) -> String {
        var text = ""
        switch connection.state {
        case .waiting(let until, _):
            text = "Retrying in \(max(0, Int(until.timeIntervalSince(now).rounded()))) s."
        case .attention(let issue):
            text = issue.explanation(for: connection.server)
        case .connecting:
            text = "Connecting…"
        default:
            break
        }
        if let last = connection.lastSampleAt {
            text += " Last reading \(Format.duration(now.timeIntervalSince(last))) ago."
        }
        return text
    }
}
