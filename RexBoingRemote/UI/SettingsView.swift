import SwiftUI
import RexBoingKit

struct SettingsView: View {
    @ObservedObject var store: ServerStore
    @ObservedObject var fleet: Fleet
    @ObservedObject var settings: AppSettings
    var addServer: () -> Void

    var body: some View {
        TabView {
            ServersSettings(store: store, fleet: fleet, addServer: addServer)
                .tabItem { Label("Servers", systemImage: "server.rack") }
            GeneralSettings(settings: settings)
                .tabItem { Label("General", systemImage: "gearshape") }
        }
        .frame(width: 600, height: 460)
    }
}

private struct ServersSettings: View {
    @ObservedObject var store: ServerStore
    @ObservedObject var fleet: Fleet
    var addServer: () -> Void
    @State private var selection: Server.ID?
    @StateObject private var setup = Setup()
    @State private var message: String?
    @State private var confirmRemove: Server?
    @State private var removeAgent = true

    var body: some View {
        HStack(spacing: 0) {
            VStack(spacing: 0) {
                List(selection: $selection) {
                    ForEach(store.servers) { server in
                        HStack {
                            if let connection = fleet.connection(server.id) {
                                StateIndicator(connection: connection)
                            }
                            Text(server.name)
                            Spacer()
                            if server.pinned { Image(systemName: "pin.fill").foregroundStyle(.tertiary) }
                        }
                        .tag(server.id)
                    }
                    .onMove { store.move(from: $0, to: $1) }
                }
                HStack {
                    Button(action: addServer) { Image(systemName: "plus") }
                        .help("Add Server")
                    Button {
                        if let id = selection, let server = store.server(id) { confirmRemove = server }
                    } label: { Image(systemName: "minus") }
                        .disabled(selection == nil)
                        .help("Remove Server")
                    Spacer()
                }
                .buttonStyle(.borderless)
                .padding(6)
            }
            .frame(width: 200)
            Divider()
            if let id = selection, let server = store.server(id) {
                ServerDetail(server: server, store: store, fleet: fleet, setup: setup, message: $message)
                    .id(id)
                    .padding()
            } else {
                Text(store.servers.isEmpty ? "No servers yet." : "Select a server.")
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .onAppear { if selection == nil { selection = store.servers.first?.id } }
        .sheet(item: $confirmRemove) { server in
            VStack(alignment: .leading, spacing: 12) {
                Text("Remove \(server.name)?").font(.headline)
                Toggle("Also remove the agent and Rex Boing Remote's key from the server", isOn: $removeAgent)
                Text("The server's other SSH keys and settings are not touched.")
                    .font(.caption).foregroundStyle(.secondary)
                HStack {
                    Spacer()
                    Button("Cancel") { confirmRemove = nil }.keyboardShortcut(.cancelAction)
                    Button("Remove", role: .destructive) {
                        let target = server
                        let uninstall = removeAgent
                        confirmRemove = nil
                        selection = nil
                        fleet.connection(target.id)?.stop()
                        Task {
                            if uninstall { _ = await setup.uninstall(target) }
                            else if let alias = target.hostKeyAlias { KnownHosts.forget(alias: alias) }
                            store.remove(target.id)
                        }
                    }
                    .keyboardShortcut(.defaultAction)
                }
            }
            .padding(20)
            .frame(width: 380)
        }
    }
}

private struct StateIndicator: View {
    @ObservedObject var connection: ServerConnection
    var body: some View { StateDot(state: connection.state) }
}

private struct ServerDetail: View {
    var server: Server
    @ObservedObject var store: ServerStore
    @ObservedObject var fleet: Fleet
    @ObservedObject var setup: Setup
    @Binding var message: String?
    @State private var name = ""

    var body: some View {
        Form {
            TextField("Name", text: $name)
                .onSubmit { store.update(server.id) { $0.name = name } }
            LabeledContent("Address", value: server.destinationLabel)
            if let connection = fleet.connection(server.id) {
                StatusRow(connection: connection)
            }
            Toggle("Own rex in the menu bar", isOn: Binding(
                get: { server.pinned },
                set: { value in store.update(server.id) { $0.pinned = value } }))
            Picker("Character", selection: Binding(
                get: { server.character },
                set: { value in store.update(server.id) { $0.character = value } })) {
                ForEach(Visualizer.allCases) { visual in Text(visual.name).tag(visual) }
            }
            Picker("Beside the rex", selection: Binding(
                get: { server.readout },
                set: { value in store.update(server.id) { $0.readout = value } })) {
                ForEach(Server.Readout.allCases) { readout in Text(readout.label).tag(readout) }
            }
            if let connection = fleet.connection(server.id) {
                BackgroundToggle(server: server, connection: connection, enabled: !setup.isRunning) { setBackground($0) }
            }
            LabeledContent("Agent", value: agentLine)
            HStack {
                Button("Reconnect") { fleet.connection(server.id)?.restart() }
                if server.hostKeyAlias == nil {
                    Button("Repair…") { repair() }
                        .help("Copies the agent and the key again, using your SSH access.")
                }
                if server.auth == .appKey, let version = fleet.connection(server.id)?.hello?.agent?.version,
                   version != BundledAgent.version {
                    Button("Update Agent") { update() }
                }
                if setup.isRunning { ProgressView().controlSize(.small) }
            }
            if let message {
                Text(message).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
        .formStyle(.grouped)
        .onAppear { name = server.name }
        .onChange(of: name) { store.update(server.id) { $0.name = name.isEmpty ? $0.name : name } }
    }

    private var agentLine: String {
        let version = fleet.connection(server.id)?.hello?.agent?.version ?? server.agentVersion ?? "unknown"
        let os = [server.os, server.arch].compactMap { $0 }.joined(separator: " ")
        let auth = server.auth == .appKey ? "restricted key" : "your SSH setup"
        return "\(version) · \(os) · \(auth)"
    }

    private func repair() {
        message = nil
        Task {
            do {
                let repaired = try await setup.add(destination: server.host, name: server.name, port: server.port, existing: server)
                store.applySetup(repaired)
                fleet.connection(server.id)?.restart()
                message = "Repaired."
            } catch {
                message = (error as? Setup.Failure).map { [$0.message, $0.detail].compactMap { $0 }.joined(separator: "\n") }
                    ?? error.localizedDescription
            }
        }
    }

    /// Installs or removes the agent's background service on the server,
    /// then reconnects so the stream picks up (or stops expecting) history.
    private func setBackground(_ enabled: Bool) {
        message = nil
        Task {
            do {
                let (text, upgraded) = try await setup.setBackgroundHistory(server, enabled: enabled)
                store.update(server.id) {
                    $0.keepHistory = enabled
                    if upgraded { $0.agentVersion = BundledAgent.version }
                }
                fleet.connection(server.id)?.restart()
                message = text
            } catch {
                message = (error as? Setup.Failure).map { [$0.message, $0.detail].compactMap { $0 }.joined(separator: "\n") }
                    ?? error.localizedDescription
            }
        }
    }

    private func update() {
        message = nil
        Task {
            do {
                try await setup.upgrade(server)
                store.update(server.id) { $0.agentVersion = BundledAgent.version }
                fleet.connection(server.id)?.restart()
                message = "Updated to \(BundledAgent.version)."
            } catch {
                message = (error as? Setup.Failure)?.message ?? error.localizedDescription
            }
        }
    }
}

/// "Keep history while this Mac is away", with what the server says about it.
private struct BackgroundToggle: View {
    var server: Server
    @ObservedObject var connection: ServerConnection
    var enabled: Bool
    var set: (Bool) -> Void

    var body: some View {
        Toggle(isOn: Binding(get: { isOn }, set: set)) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Keep history while this Mac is away")
                Text(caption)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .disabled(!enabled)
    }

    /// The user's choice, or, for a server whose agent was set up to keep
    /// history some other way, what the server says.
    private var isOn: Bool {
        if let choice = server.keepHistory { return choice }
        if case .running = connection.background { return true }
        return false
    }

    private var caption: String {
        var text = "The agent keeps sampling on the server, 48 hours deep, as a service of your user there "
            + "(\(manager)). It opens no port. Turning it off deletes what it kept."
        switch connection.background {
        case .running(let since):
            text += " Running, with history since \(HistoryCard.moment(since))."
        case .absent where server.keepHistory == true:
            text += server.isWindows
                ? " Not running now: Windows runs it while someone is signed in to the PC."
                : " Not running on the server right now."
        default:
            break
        }
        return text
    }

    private var manager: String {
        switch server.os {
        case "darwin": return "a LaunchAgent"
        case "windows": return "a scheduled task at sign-in"
        default: return "a systemd user service"
        }
    }
}

private struct StatusRow: View {
    @ObservedObject var connection: ServerConnection

    var body: some View {
        LabeledContent("Status") {
            HStack(spacing: 6) {
                StateDot(state: connection.state)
                Text(StatusController.stateText(connection.state))
                    .lineLimit(2)
            }
        }
    }
}

private struct GeneralSettings: View {
    @ObservedObject var settings: AppSettings

    var body: some View {
        Form {
            Picker("Update the menu bar every", selection: $settings.vitalsInterval) {
                ForEach(AppSettings.intervals, id: \.self) { value in
                    Text(value == 1 ? "second" : "\(Int(value)) seconds").tag(value)
                }
            }
            Text("An open dashboard always updates every second.")
                .font(.caption).foregroundStyle(.secondary)
            Picker("Temperature", selection: $settings.temperatureUnit) {
                ForEach(TemperatureUnit.allCases) { unit in Text(unit.label).tag(unit) }
            }
            Picker("Fleet character", selection: $settings.fleetCharacter) {
                ForEach(Visualizer.allCases) { visual in Text(visual.name).tag(visual) }
            }
            Toggle("Show the busiest server's CPU beside the fleet rex", isOn: $settings.showFleetReadout)
            Toggle("Animate characters", isOn: $settings.animate)
            Toggle("Open at login", isOn: Binding(
                get: { settings.launchAtLogin },
                set: { settings.setLaunchAtLogin($0) }))
            LabeledContent("Data") {
                Button("Show in Finder") { NSWorkspace.shared.activateFileViewerSelecting([Paths.support]) }
            }
            LabeledContent("Version", value: BundledAgent.version)
        }
        .formStyle(.grouped)
    }
}
