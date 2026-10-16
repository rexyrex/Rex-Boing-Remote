import SwiftUI
import RexBoingKit

/// The popover: the fleet list, or one server's dashboard.
struct PopoverView: View {
    @ObservedObject var fleet: Fleet
    @ObservedObject var store: ServerStore
    @ObservedObject var settings: AppSettings
    @ObservedObject var navigation: Navigation
    var actions: PopoverActions
    /// The tallest the content may be: the dashboard uses all of it, the
    /// fleet list only what its rows need.
    var maxHeight: CGFloat = 760

    private var height: CGFloat {
        if navigation.selected != nil { return maxHeight }
        if store.servers.isEmpty { return min(maxHeight, 380) }
        return min(maxHeight, 64 + 30 + CGFloat(store.servers.count) * 53 + 16)
    }

    var body: some View {
        content
            .frame(width: Metrics.dashboardWidth, height: height)
            .animation(.easeInOut(duration: 0.2), value: height)
    }

    private var content: some View {
        VStack(spacing: 0) {
            if let id = navigation.selected, let server = store.server(id), let connection = fleet.connection(id) {
                ServerDashboard(
                    server: server, connection: connection, settings: settings,
                    back: { navigation.selected = nil },
                    openSettings: actions.openSettings)
                    .id(id)
            } else {
                header
                Divider().opacity(0.5)
                if store.servers.isEmpty {
                    EmptyFleet(addServer: actions.addServer)
                } else {
                    FleetList(fleet: fleet, store: store, settings: settings) { id in
                        navigation.selected = id
                    }
                }
            }
        }
    }

    private var header: some View {
        HStack(spacing: 10) {
            Image(nsImage: CharacterIcon.image(for: settings.fleetCharacter))
                .renderingMode(.template)
                .resizable()
                .interpolation(.high)
                .frame(width: Visualizer.canvasSize.width, height: Visualizer.canvasSize.height)
                .foregroundStyle(Palette.cpu)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text("Rex \(Text("Boing").foregroundStyle(Palette.cpu)) Remote")
                    .font(.system(size: 17, weight: .bold, design: .rounded))
                    .tracking(-0.3)
                Text(summary)
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 4)
            Button(action: actions.addServer) {
                Image(systemName: "plus.circle")
                    .font(.system(size: 13))
            }
            .buttonStyle(.plain)
            .foregroundStyle(.secondary)
            .help("Add Server")
            .accessibilityLabel("Add Server")
            Button(action: actions.openSettings) {
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

    private var summary: String {
        let total = store.servers.count
        guard total > 0 else { return "No servers yet" }
        let live = fleet.liveCount
        return live == total ? "\(total) server\(total == 1 ? "" : "s"), all live"
            : "\(live) of \(total) servers live"
    }
}

/// The first thing a new user sees: what the app does and the one button
/// that starts it.
struct EmptyFleet: View {
    var addServer: () -> Void

    var body: some View {
        VStack(spacing: 14) {
            Spacer()
            Image(nsImage: CharacterIcon.image(for: .rex))
                .renderingMode(.template)
                .resizable()
                .interpolation(.high)
                .frame(width: Visualizer.canvasSize.width * 2.5, height: Visualizer.canvasSize.height * 2.5)
                .foregroundStyle(Palette.cpu)
            Text("Watch your servers from the menu bar")
                .font(.system(size: 15, weight: .semibold))
            Text("Linux, macOS and Windows machines, over the SSH you already use. Nothing to open on your router, nothing running as root.")
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 360)
            Button("Add a Server…", action: addServer)
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
            Spacer()
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// A still frame of a character, drawn by the menu bar's own code.
@MainActor
enum CharacterIcon {
    private static var cache: [Visualizer: NSImage] = [:]

    static func image(for visual: Visualizer) -> NSImage {
        if let cached = cache[visual] { return cached }
        let size = Visualizer.canvasSize
        let image = NSImage(size: size, flipped: false) { rect in
            guard let context = NSGraphicsContext.current?.cgContext else { return false }
            visual.draw(in: context, rect: rect, time: Visualizer.restingTime, load: 0.45, color: .black)
            return true
        }
        image.isTemplate = true
        cache[visual] = image
        return image
    }
}
