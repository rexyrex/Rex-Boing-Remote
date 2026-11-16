import SwiftUI
import RexBoingKit

// The window: the fleet down the side, one server — or all of them — beside it.
//
// The popover is for a glance at one machine. This is for keeping an eye on
// several, or on one for an afternoon: an ordinary window that can be resized,
// put on another display and left there, with the servers always in reach in
// a sidebar and the selected one's cards laid out in as many columns as the
// width allows, their detail open, under a strip of headline readings.

/// What the window's sidebar has selected.
enum FleetSelection: Hashable {
    case overview
    case server(Server.ID)
}

@MainActor
final class FleetWindowModel: ObservableObject {
    @Published var selection: FleetSelection? = .overview
}

struct FleetWindowView: View {
    @ObservedObject var fleet: Fleet
    @ObservedObject var store: ServerStore
    @ObservedObject var settings: AppSettings
    @ObservedObject var model: FleetWindowModel
    var actions: PopoverActions

    var body: some View {
        NavigationSplitView {
            sidebar
                .navigationSplitViewColumnWidth(min: 210, ideal: 240, max: 320)
        } detail: {
            detail
        }
        .navigationSplitViewStyle(.balanced)
        .frame(minWidth: 860, minHeight: 520)
        .toolbar { toolbar }
        // A server removed in Settings while it was on screen leaves the
        // overview, not a blank pane.
        .onChange(of: store.servers.map(\.id)) { _, ids in
            if case .server(let id) = model.selection, !ids.contains(id) {
                model.selection = .overview
            }
        }
    }

    private var selectedServer: (server: Server, connection: ServerConnection)? {
        guard case .server(let id) = model.selection,
              let server = store.server(id), let connection = fleet.connection(id) else { return nil }
        return (server, connection)
    }

    // MARK: Sidebar

    private var sidebar: some View {
        List(selection: $model.selection) {
            Section {
                Label {
                    HStack {
                        Text("All Servers")
                        Spacer()
                        Text(liveSummary)
                            .font(.system(size: 11))
                            .monospacedDigit()
                            .foregroundStyle(.secondary)
                    }
                } icon: {
                    Image(systemName: "square.grid.2x2")
                        .foregroundStyle(Brand.violet)
                }
                .tag(FleetSelection.overview)
            }

            Section("Servers") {
                ForEach(store.servers) { server in
                    if let connection = fleet.connection(server.id) {
                        SidebarServerRow(server: server, connection: connection)
                            .tag(FleetSelection.server(server.id))
                    }
                }
            }
        }
        .listStyle(.sidebar)
        .safeAreaInset(edge: .bottom, spacing: 0) {
            VStack(spacing: 0) {
                Divider().opacity(0.5)
                Button(action: actions.addServer) {
                    Label("Add Server…", systemImage: "plus.circle.fill")
                        .font(.system(size: 12, weight: .medium))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .foregroundStyle(Brand.violet)
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
            }
        }
    }

    private var liveSummary: String {
        let total = store.servers.count
        return total == 0 ? "" : "\(fleet.liveCount)/\(total)"
    }

    // MARK: Detail

    @ViewBuilder
    private var detail: some View {
        if let selected = selectedServer {
            ServerBoard(
                server: selected.server, connection: selected.connection,
                settings: settings, openSettings: actions.openSettings)
                .id(selected.server.id)
                .navigationTitle(selected.server.name)
                .navigationSubtitle(selected.connection.hostLine(for: selected.server))
        } else {
            Group {
                if store.servers.isEmpty {
                    EmptyFleet(addServer: actions.addServer)
                } else {
                    FleetBoard(fleet: fleet, store: store, settings: settings) { id in
                        model.selection = .server(id)
                    }
                }
            }
            .background(WindowBackdrop())
            .navigationTitle("Rex Boing Remote")
            .navigationSubtitle(fleetSubtitle)
        }
    }

    private var fleetSubtitle: String {
        let total = store.servers.count
        guard total > 0 else { return "No servers yet" }
        let live = fleet.liveCount
        return live == total
            ? "\(total) server\(total == 1 ? "" : "s"), all live"
            : "\(live) of \(total) servers live"
    }

    // MARK: Toolbar

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        ToolbarItem(placement: .navigation) {
            // The selected server's own character at its own pace, or the
            // fleet's at the busiest server's — what the menu bar shows.
            RexMascot(
                visualizer: selectedServer?.server.character ?? settings.fleetCharacter,
                load: mascotLoad,
                animated: settings.animate && mascotIsLive,
                color: mascotIsLive ? Brand.violet : Color.secondary)
                .padding(.horizontal, 4)
        }

        ToolbarItem(placement: .primaryAction) {
            Button {
                if let selected = selectedServer {
                    selected.connection.retryNow()
                } else {
                    fleet.retryAll()
                }
            } label: {
                Label(selectedServer == nil ? "Reconnect All" : "Reconnect", systemImage: "arrow.clockwise")
            }
            .help(selectedServer == nil ? "Reconnect every server" : "Reconnect this server")
        }

        ToolbarItem(placement: .primaryAction) {
            Button(action: actions.addServer) {
                Label("Add Server", systemImage: "plus")
            }
            .help("Add Server")
        }

        ToolbarItem(placement: .primaryAction) {
            Button(action: actions.openSettings) {
                Label("Settings", systemImage: "gearshape")
            }
            .help("Settings")
        }
    }

    private var mascotIsLive: Bool {
        if let selected = selectedServer { return selected.connection.state == .live }
        return fleet.liveCount > 0
    }

    private var mascotLoad: Double {
        if let selected = selectedServer { return selected.connection.snapshot?.cpu.total ?? 0 }
        return fleet.busiestLoad
    }
}

/// The window's ground: the system's, with Remote's violet let into the top.
struct WindowBackdrop: View {
    var body: some View {
        ZStack(alignment: .top) {
            Color(nsColor: .windowBackgroundColor)
            LinearGradient(
                colors: [Brand.violet.opacity(0.13), Brand.violet.opacity(0)],
                startPoint: .top, endPoint: .bottom)
                .frame(height: 280)
        }
        .ignoresSafeArea()
    }
}

// MARK: - Sidebar row

private struct SidebarServerRow: View {
    var server: Server
    @ObservedObject var connection: ServerConnection

    var body: some View {
        HStack(spacing: 8) {
            RemoteCharacter(character: server.character, isLive: isLive, width: 26)

            VStack(alignment: .leading, spacing: 1) {
                Text(server.name)
                    .font(.system(size: 12.5, weight: .medium))
                    .lineLimit(1)
                Text(caption)
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }

            Spacer(minLength: 4)

            if isLive, let snapshot = connection.snapshot {
                Text(Format.percent(snapshot.cpu.total))
                    .font(.system(size: 11, weight: .medium, design: .rounded))
                    .monospacedDigit()
                    .foregroundStyle(.secondary)
            }
            StateDot(state: connection.state)
        }
        .padding(.vertical, 3)
        .accessibilityElement(children: .combine)
    }

    private var isLive: Bool { connection.state == .live }

    private var caption: String {
        switch connection.state {
        case .live:
            if let host = connection.hello?.host,
               let os = [host.osName, host.osVersion].compactMap({ $0 }).joined(separator: " ").nilIfEmpty {
                return os
            }
            return server.destinationLabel
        case .connecting: return "Connecting…"
        case .waiting: return "Reconnecting…"
        case .attention(let issue): return issue.title
        case .idle: return "Paused"
        }
    }
}

// MARK: - Fleet overview

/// Every server at once: a tile each, with its vitals and whatever needs
/// attention. The fleet list of the popover, given a window's room.
struct FleetBoard: View {
    @ObservedObject var fleet: Fleet
    @ObservedObject var store: ServerStore
    @ObservedObject var settings: AppSettings
    var open: (Server.ID) -> Void

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                HStack(alignment: .firstTextBaseline) {
                    RemoteWordmark(size: 22)
                    Spacer()
                    Text(summary)
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }

                LazyVGrid(
                    columns: [GridItem(.adaptive(minimum: 300, maximum: 520), spacing: 12, alignment: .top)],
                    alignment: .leading, spacing: 12
                ) {
                    ForEach(store.servers) { server in
                        if let connection = fleet.connection(server.id) {
                            ServerTile(server: server, connection: connection, unit: settings.temperatureUnit)
                                .onTapGesture { open(server.id) }
                                .accessibilityAddTraits(.isButton)
                                .accessibilityHint("Opens this server's dashboard")
                                .accessibilityAction { open(server.id) }
                        }
                    }
                }
            }
            .padding(18)
        }
    }

    private var summary: String {
        let total = store.servers.count
        let live = fleet.liveCount
        var text = live == total ? "All \(total) live" : "\(live) of \(total) live"
        if total == 1 { text = live == 1 ? "1 server, live" : "1 server, not live" }
        if fleet.needsAttention { text += " · one needs you" }
        return text
    }
}

private struct ServerTile: View {
    var server: Server
    @ObservedObject var connection: ServerConnection
    var unit: TemperatureUnit

    @State private var isHovering = false

    var body: some View {
        VStack(alignment: .leading, spacing: 11) {
            HStack(spacing: 9) {
                RemoteCharacter(character: server.character, isLive: isLive)
                VStack(alignment: .leading, spacing: 1) {
                    HStack(spacing: 6) {
                        Text(server.name)
                            .font(.system(size: 15, weight: .bold, design: .rounded))
                            .lineLimit(1)
                        StateDot(state: connection.state)
                    }
                    Text(connection.hello?.host == nil ? server.destinationLabel : subtitle)
                        .font(.system(size: 10.5))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                Spacer(minLength: 4)
                PlatformChip(os: server.os, arch: nil)
            }

            if isLive, let snapshot = connection.snapshot {
                Sparkline(
                    values: connection.history.cpu.values, accent: Palette.cpu,
                    timestamps: connection.history.cpu.timestamps)
                    .frame(height: 38)
                    .allowsHitTesting(false)

                HStack(spacing: 0) {
                    StatTile(label: "CPU", value: Format.percent(snapshot.cpu.total),
                             tint: tint(.load(snapshot.cpu.total)))
                    StatTile(label: "Memory", value: Format.percent(snapshot.memory.fractionUsed),
                             tint: tint(.memory(snapshot.memory.pressureLevel)))
                    StatTile(label: "GPU",
                             value: snapshot.gpu.available ? Format.percent(snapshot.gpu.utilization) : "—")
                    StatTile(label: "Temp", value: temperature(snapshot),
                             tint: (snapshot.thermal.cpuCelsius ?? snapshot.thermal.peakCelsius)
                                .flatMap { tint(.temperature($0)) })
                    StatTile(label: "Power",
                             value: (snapshot.power.totalWatts ?? snapshot.power.gpuWatts)
                                .map { Format.watts($0) } ?? "—")
                }

                if let flag = flag(snapshot) {
                    FlagChip(text: flag.text, color: flag.color)
                }
            } else {
                Text(connection.waitingText(for: server))
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, minHeight: 60, alignment: .leading)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .background(
            RoundedRectangle(cornerRadius: 13, style: .continuous)
                .fill(Palette.cardBackground))
        .overlay(
            RoundedRectangle(cornerRadius: 13, style: .continuous)
                .strokeBorder(isHovering ? Brand.violet.opacity(0.6) : Palette.cardStroke, lineWidth: 1))
        .contentShape(Rectangle())
        .onHover { isHovering = $0 }
        .accessibilityElement(children: .combine)
    }

    private var isLive: Bool { connection.state == .live }

    private var subtitle: String {
        var parts: [String] = []
        if let host = connection.hello?.host,
           let os = [host.osName, host.osVersion].compactMap({ $0 }).joined(separator: " ").nilIfEmpty {
            parts.append(os)
        }
        if isLive, let uptime = connection.snapshot?.extras.system?.uptime {
            parts.append("up \(Format.duration(uptime))")
        }
        return parts.isEmpty ? server.destinationLabel : parts.joined(separator: " · ")
    }

    private func tint(_ severity: Severity) -> Color? {
        severity == .calm ? nil : severity.swiftUIColor
    }

    private func temperature(_ snapshot: Snapshot) -> String {
        (snapshot.thermal.cpuCelsius ?? snapshot.thermal.peakCelsius)
            .map { Format.temperature($0, unit: unit) } ?? "—"
    }

    private func flag(_ snapshot: Snapshot) -> (text: String, color: Color)? {
        if snapshot.extras.system?.rebootRequired == true { return ("Restart needed", Palette.elevated) }
        if let failed = snapshot.extras.system?.failedServices, !failed.isEmpty {
            return ("\(failed.count) failed service\(failed.count == 1 ? "" : "s")", Palette.high)
        }
        if snapshot.memory.pressureLevel == .critical { return ("Memory pressure", Palette.critical) }
        if snapshot.disk.fractionUsed > 0.92 { return ("Disk nearly full", Palette.high) }
        return nil
    }
}

// MARK: - One server

/// One server in the window: its banner, a strip of headline readings, and
/// every card with its detail open, in as many columns as fit.
struct ServerBoard: View {
    var server: Server
    @ObservedObject var connection: ServerConnection
    @ObservedObject var settings: AppSettings
    var openSettings: () -> Void
    /// Full detail from the server for as long as this board exists.
    @StateObject private var viewer: ViewerLease

    /// About five minutes at the one-second cadence an open dashboard asks
    /// the agent for.
    private static let span = 300

    init(server: Server, connection: ServerConnection, settings: AppSettings,
         openSettings: @escaping () -> Void) {
        self.server = server
        self.connection = connection
        self.settings = settings
        self.openSettings = openSettings
        _viewer = StateObject(wrappedValue: connection.addViewer())
    }

    private var unit: TemperatureUnit { settings.temperatureUnit }
    private var history: MetricsHistory { connection.history }

    var body: some View {
        VStack(spacing: 0) {
            if let issue = connection.issueTitle {
                ConnectionBanner(connection: connection, issue: issue)
            }
            if let snapshot = connection.snapshot {
                board(snapshot)
                Divider().opacity(0.5)
                footer(snapshot)
            } else {
                VStack(spacing: 14) {
                    ServerBanner(server: server, connection: connection)
                        .frame(maxWidth: 560)
                    ProgressView().controlSize(.small)
                    Text(connection.waitingText(for: server))
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 420)
                }
                .padding(24)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .background(WindowBackdrop())
        .onAppear { connection.refreshHistory() }
        .environment(\.dashboardStyle, .window)
        .environment(\.graphSpan, Self.span)
        .environment(\.machineNoun, server.os == "darwin" ? "Mac" : "machine")
        .environment(\.processControl, ProcessControl(isLocal: false))
    }

    private func board(_ snapshot: Snapshot) -> some View {
        GeometryReader { proxy in
            ScrollView {
                VStack(spacing: 14) {
                    ServerBanner(server: server, connection: connection)

                    VitalsStrip(snapshot: snapshot, history: history, unit: unit, span: Self.span)

                    columns(MonitorColumns.count(for: proxy.size.width), snapshot)
                }
                .padding(.horizontal, 16)
                .padding(.top, 14)
                .padding(.bottom, 16)
            }
        }
    }

    /// Dealt by hand, like Rex Boing's Monitor window, so that no card
    /// changes column when another changes height.
    @ViewBuilder
    private func columns(_ count: Int, _ snapshot: Snapshot) -> some View {
        let spacing = DashboardStyle.window.sectionSpacing
        switch count {
        case 3:
            HStack(alignment: .top, spacing: spacing) {
                column {
                    processor(snapshot); memory(snapshot)
                    pressure(snapshot); system(snapshot)
                }
                column {
                    graphics(snapshot); gpuDetail(snapshot)
                    thermals(snapshot); power(snapshot); network(snapshot)
                }
                column {
                    historyCard; processes(snapshot)
                    storage(snapshot); volumes(snapshot); notices
                }
            }
        case 2:
            HStack(alignment: .top, spacing: spacing) {
                column {
                    processor(snapshot); memory(snapshot); thermals(snapshot)
                    power(snapshot); pressure(snapshot); system(snapshot)
                }
                column {
                    graphics(snapshot); gpuDetail(snapshot); historyCard
                    processes(snapshot); network(snapshot)
                    storage(snapshot); volumes(snapshot); notices
                }
            }
        default:
            column {
                processor(snapshot); graphics(snapshot); memory(snapshot); thermals(snapshot)
                historyCard; pressure(snapshot); system(snapshot); gpuDetail(snapshot)
                processes(snapshot); power(snapshot); network(snapshot)
                storage(snapshot); volumes(snapshot); notices
            }
        }
    }

    private func column<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        VStack(spacing: DashboardStyle.window.sectionSpacing) { content() }
            .frame(maxWidth: .infinity, alignment: .top)
    }

    // Each card at its own height: a row of columns offers every column the
    // tallest one's, and an unpinned card stretches to take it.

    private func processor(_ snapshot: Snapshot) -> some View {
        CPUCard(snapshot: snapshot, history: history, unit: unit)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func graphics(_ snapshot: Snapshot) -> some View {
        GPUCard(snapshot: snapshot, history: history, unit: unit)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func memory(_ snapshot: Snapshot) -> some View {
        MemoryCard(snapshot: snapshot, history: history)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func thermals(_ snapshot: Snapshot) -> some View {
        ThermalCard(snapshot: snapshot, history: history, unit: unit)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func power(_ snapshot: Snapshot) -> some View {
        PowerCard(snapshot: snapshot, history: history, unit: unit)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func network(_ snapshot: Snapshot) -> some View {
        NetworkCard(snapshot: snapshot, history: history)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func storage(_ snapshot: Snapshot) -> some View {
        StorageCard(snapshot: snapshot, history: history)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func processes(_ snapshot: Snapshot) -> some View {
        ProcessesCard(usage: nil, snapshot: snapshot, rowCount: 12)
            .fixedSize(horizontal: false, vertical: true)
    }

    private var historyCard: some View {
        HistoryCard(connection: connection, unit: unit, keepsHistory: server.keepHistory ?? false,
                    isWindows: server.isWindows, openSettings: openSettings)
            .fixedSize(horizontal: false, vertical: true)
    }

    @ViewBuilder
    private func pressure(_ snapshot: Snapshot) -> some View {
        if let pressure = snapshot.extras.pressure {
            PressureCard(pressure: pressure)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    @ViewBuilder
    private func system(_ snapshot: Snapshot) -> some View {
        if snapshot.extras.pressure != nil || snapshot.extras.system != nil {
            SystemCard(snapshot: snapshot, hello: connection.hello)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    @ViewBuilder
    private func gpuDetail(_ snapshot: Snapshot) -> some View {
        let gpus = snapshot.extras.gpus
        if gpus.count > 1 || gpus.contains(where: {
            ($0.engines?.count ?? 0) > 2 || $0.celsius != nil || $0.fanPercent != nil
        }) {
            GPUDetailCard(gpus: gpus, unit: unit)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    @ViewBuilder
    private func volumes(_ snapshot: Snapshot) -> some View {
        if snapshot.extras.volumes.count > 1 {
            VolumesCard(volumes: snapshot.extras.volumes)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    @ViewBuilder
    private var notices: some View {
        if !connection.notices.isEmpty {
            NoticesCard(notices: connection.notices)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    /// What the cards take for granted: that the numbers are arriving, from
    /// which agent, and how long the machine has been up.
    private func footer(_ snapshot: Snapshot) -> some View {
        HStack(spacing: 14) {
            HStack(spacing: 6) {
                StateDot(state: connection.state)
                Text(connection.state == .live ? "Live · every second" : StatusController.stateText(connection.state))
            }
            if snapshot.cpu.processCount > 0 {
                Text("\(snapshot.cpu.processCount) processes")
            }
            if let version = connection.hello?.agent?.version {
                Text("agent \(version)")
            }
            Spacer(minLength: 8)
            Text(server.destinationLabel)
                .font(.system(size: 11, design: .monospaced))
        }
        .font(.system(size: 11))
        .monospacedDigit()
        .foregroundStyle(.secondary)
        .lineLimit(1)
        .padding(.horizontal, 16)
        .padding(.vertical, 7)
        .background(.bar)
    }
}
