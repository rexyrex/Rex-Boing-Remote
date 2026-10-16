import SwiftUI
import Network
import SystemConfiguration
import RexBoingKit

/// Adding a server, two ways: from this Mac over SSH you already have, or
/// from the server's own end with one command and one pasted code.
struct AddServerView: View {
    @ObservedObject var store: ServerStore
    @ObservedObject var settings: AppSettings
    @StateObject private var setup = Setup()
    @StateObject private var browser = SSHBrowser()
    var close: () -> Void

    enum Method: Hashable { case ssh, fromServer }
    @State private var method: Method = .ssh
    @State private var configHosts: [String] = []
    @State private var selection: String?
    @State private var manual = ""
    @State private var portText = ""
    @State private var name = ""
    @State private var serverOS: ServerOS = .unix
    @State private var code = ""
    @State private var failure: Setup.Failure?
    @State private var added: Server?
    @State private var launchAtLogin = true
    @State private var copied = false

    enum ServerOS: Hashable { case unix, windows }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Picker("", selection: $method) {
                Text("I can SSH to it").tag(Method.ssh)
                Text("Set it up from the server").tag(Method.fromServer)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .disabled(setup.isRunning)

            Group {
                switch method {
                case .ssh: sshForm
                case .fromServer: fromServerForm
                }
            }
            .disabled(setup.isRunning)

            if setup.isRunning || setup.step == .done { progress }
            if let failure { FailureView(failure: failure) }

            Divider()
            footer
        }
        .padding(20)
        .frame(width: 560)
        .onAppear {
            configHosts = SSHConfigHosts.load()
            browser.start()
        }
        .onDisappear { browser.stop() }
    }

    // MARK: - Over SSH

    private var sshForm: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Pick a host you can already reach with ssh. Rex Boing Remote uses your SSH setup once — to copy its agent and add a key that can only start that agent — and its own key from then on.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            List(selection: $selection) {
                if !configHosts.isEmpty {
                    Section("From ~/.ssh/config") {
                        ForEach(configHosts, id: \.self) { host in
                            hostRow(host, detail: alreadyAdded(host) ? "added" : nil).tag(host)
                        }
                    }
                }
                if !browser.found.isEmpty {
                    Section("On this network") {
                        ForEach(browser.found, id: \.self) { host in
                            hostRow(host, detail: "Remote Login").tag(host)
                        }
                    }
                }
                if configHosts.isEmpty && browser.found.isEmpty {
                    Text("No hosts in ~/.ssh/config yet. Type one below.")
                        .foregroundStyle(.secondary)
                }
            }
            .frame(height: 170)
            .onChange(of: selection) { manual = selection ?? manual }

            HStack(spacing: 8) {
                TextField("user@host or an alias", text: $manual)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit(addOverSSH)
                TextField("Port", text: $portText)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 60)
            }
            TextField("Name (optional)", text: $name)
                .textFieldStyle(.roundedBorder)
            HStack {
                Spacer()
                Button("Add Server", action: addOverSSH)
                    .keyboardShortcut(.defaultAction)
                    .disabled(manual.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
    }

    private func hostRow(_ host: String, detail: String?) -> some View {
        HStack {
            Image(systemName: "server.rack").foregroundStyle(.secondary)
            Text(host)
            Spacer()
            if let detail { Text(detail).font(.caption).foregroundStyle(.tertiary) }
        }
    }

    private func alreadyAdded(_ host: String) -> Bool {
        store.servers.contains { $0.host == host }
    }

    private func addOverSSH() {
        let destination = manual.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !destination.isEmpty else { return }
        let port = Int(portText.trimmingCharacters(in: .whitespaces))
        failure = nil
        added = nil
        let existing = store.servers.first { $0.host == destination && $0.port == port }
        Task {
            do {
                let server = try await setup.add(
                    destination: destination, name: name.isEmpty ? nil : name, port: port, existing: existing)
                finish(server)
            } catch let error as Setup.Failure {
                failure = error
            } catch {
                failure = Setup.Failure(message: error.localizedDescription)
            }
        }
    }

    // MARK: - From the server

    private var fromServerForm: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("For a server you can open a terminal on, but can't reach with ssh keys from this Mac yet. The command installs the agent for the user who runs it and authorises this Mac — nothing runs as root.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Picker("The server runs", selection: $serverOS) {
                Text("Linux or macOS").tag(ServerOS.unix)
                Text("Windows (PowerShell)").tag(ServerOS.windows)
            }
            .pickerStyle(.radioGroup)
            .horizontalRadioGroupLayout()

            Text("1. Run this on the server:").font(.system(size: 12, weight: .semibold))
            let command = Setup.installCommand(windows: serverOS == .windows)
            HStack(alignment: .top) {
                Text(command)
                    .font(.system(size: 10.5, design: .monospaced))
                    .textSelection(.enabled)
                    .lineLimit(5)
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(RoundedRectangle(cornerRadius: 6).fill(Color.primary.opacity(0.06)))
                Button(copied ? "Copied" : "Copy") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(command, forType: .string)
                    copied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 2) { copied = false }
                }
            }
            Text(serverOS == .windows
                 ? "Needs OpenSSH Server: Settings › System › Optional features. Run PowerShell as the user Rex Boing Remote should log in as."
                 : "Needs SSH turned on. On a Mac: System Settings › General › Sharing › Remote Login.")
                .font(.caption)
                .foregroundStyle(.secondary)

            Text("2. Paste the code it prints:").font(.system(size: 12, weight: .semibold))
            HStack {
                TextField("rbr1:…", text: $code)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 11, design: .monospaced))
                    .onSubmit(addFromCode)
                Button("Add Server", action: addFromCode)
                    .keyboardShortcut(.defaultAction)
                    .disabled(!code.contains("rbr1:"))
            }
        }
    }

    private func addFromCode() {
        failure = nil
        added = nil
        let parsed: PairingCode
        do { parsed = try PairingCode.parse(code) } catch {
            failure = Setup.Failure(message: error.localizedDescription)
            return
        }
        let existing = store.servers.first { $0.user == parsed.user && parsed.addresses.contains($0.addresses.first ?? $0.host) }
        Task {
            do {
                let server = try await setup.add(code: parsed, existing: existing)
                finish(server)
            } catch let error as Setup.Failure {
                failure = error
            } catch {
                failure = Setup.Failure(message: error.localizedDescription)
            }
        }
    }

    // MARK: - Progress and result

    private var progress: some View {
        VStack(alignment: .leading, spacing: 5) {
            ForEach(Setup.Step.allCases.filter { $0 != .done }, id: \.self) { step in
                HStack(spacing: 8) {
                    Group {
                        if let current = setup.step, step < current || current == .done {
                            Image(systemName: "checkmark.circle.fill").foregroundStyle(Palette.calm)
                        } else if setup.step == step {
                            ProgressView().controlSize(.mini)
                        } else {
                            Image(systemName: "circle").foregroundStyle(.tertiary)
                        }
                    }
                    .frame(width: 16)
                    Text(step.label).foregroundStyle(setup.step == step ? .primary : .secondary)
                }
                .font(.system(size: 12))
            }
            if let added {
                Label("\(added.name) is added. Its rex is in the menu bar.", systemImage: "checkmark.seal.fill")
                    .foregroundStyle(Palette.calm)
                    .font(.system(size: 12, weight: .semibold))
                    .padding(.top, 4)
            }
        }
    }

    private func finish(_ server: Server) {
        var server = server
        if !store.servers.contains(where: { $0.id == server.id }), store.servers.isEmpty {
            // The first server gets its own rex, so the menu bar shows the
            // app working the moment setup ends.
            server.pinned = true
        }
        store.add(server)
        settings.applyFirstRunLoginChoice(launchAtLogin)
        added = server
        manual = ""
        name = ""
        code = ""
        selection = nil
    }

    private var footer: some View {
        HStack {
            if !settings.hasAskedAboutLogin {
                Toggle("Open Rex Boing Remote at login", isOn: $launchAtLogin)
                    .toggleStyle(.checkbox)
            }
            Spacer()
            Button(added == nil ? "Cancel" : "Done", action: close)
                .keyboardShortcut(.cancelAction)
        }
    }
}

struct FailureView: View {
    var failure: Setup.Failure
    @State private var showDetail = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Label(failure.message, systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(Palette.critical)
                .font(.system(size: 12, weight: .medium))
                .fixedSize(horizontal: false, vertical: true)
            if let detail = failure.detail, !detail.isEmpty {
                DisclosureGroup("Details", isExpanded: $showDetail) {
                    Text(detail)
                        .font(.system(size: 10.5, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .font(.caption)
            }
        }
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 8).fill(Palette.critical.opacity(0.08)))
    }
}

/// Computers on this network that accept SSH: Macs with Remote Login and
/// Linux machines running Avahi. Only names are shown; whether a machine is
/// really the one it claims to be is settled by its host key at setup.
@MainActor
final class SSHBrowser: ObservableObject {
    @Published private(set) var found: [String] = []
    private var browser: NWBrowser?

    func start() {
        guard browser == nil else { return }
        let browser = NWBrowser(for: .bonjour(type: "_ssh._tcp", domain: nil), using: .tcp)
        let reference = WeakReference(self)
        browser.browseResultsChangedHandler = { results, _ in
            let names = results.compactMap { result -> String? in
                if case .service(let name, _, _, _) = result.endpoint { return name }
                return nil
            }
            let local = Set([SCDynamicStoreCopyComputerName(nil, nil) as String?].compactMap { $0 })
            let hosts = Array(Set(names.filter { !local.contains($0) }.map { Self.hostName(for: $0) })).sorted()
            DispatchQueue.main.async {
                MainActor.assumeIsolated { reference.value?.found = hosts }
            }
        }
        browser.start(queue: .main)
        self.browser = browser
    }

    func stop() {
        browser?.cancel()
        browser = nil
    }

    /// A Bonjour service name ("Alex's Mac mini") as an mDNS host name
    /// ("Alexs-Mac-mini.local"), which is what ssh connects to.
    nonisolated static func hostName(for service: String) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-"))
        let hyphenated = service.replacingOccurrences(of: " ", with: "-")
        let cleaned = String(hyphenated.unicodeScalars.filter { allowed.contains($0) })
        return cleaned + ".local"
    }
}
