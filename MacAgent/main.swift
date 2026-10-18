import Foundation
import CryptoKit
import SystemConfiguration
import RexBoingKit

// rex-boing-agent for macOS: Rex Boing's own samplers, headless, speaking
// the Rex Boing Remote protocol on stdin and stdout. See PROTOCOL.md.

signal(SIGPIPE, SIG_IGN)
setvbuf(stdout, nil, _IOFBF, 1 << 16)

let arguments = Array(CommandLine.arguments.dropFirst())

func usage() -> Never {
    FileHandle.standardError.write(Data("""
        rex-boing-agent \(agentVersion) — the Rex Boing Remote agent for macOS

        Usage:
          rex-boing-agent stream [--interval S] [--detail vitals|full] [--count N]
          rex-boing-agent version | doctor [--json] | pair-code
          rex-boing-agent install [--key KEY] [--label NAME]
          rex-boing-agent upgrade --sha256 HEX --size N
          rex-boing-agent uninstall
          rex-boing-agent serve [--interval S]    keep history in the background (optional)
          rex-boing-agent install-service         run serve as a LaunchAgent, now and at every login
          rex-boing-agent uninstall-service       stop it and delete the history it kept

        """.utf8))
    exit(2)
}

func option(_ name: String, in args: [String]) -> String? {
    guard let index = args.firstIndex(of: name), index + 1 < args.count else { return nil }
    return args[index + 1]
}

func printJSON<T: Encodable>(_ value: T) {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    if let data = try? encoder.encode(value) {
        FileHandle.standardOutput.write(data + Data([0x0A]))
    }
}

func run(_ args: [String]) -> Never {
    guard let command = args.first else { usage() }
    let rest = Array(args.dropFirst())
    switch command {
    case "stream":
        Stream.run(
            interval: option("--interval", in: rest).flatMap(Double.init) ?? 1,
            detail: option("--detail", in: rest) == "full" ? .full : .vitals,
            count: option("--count", in: rest).flatMap(Int.init))
    case "version":
        printJSON(VersionInfo())
        exit(0)
    case "doctor":
        Doctor.run(json: rest.contains("--json"))
    case "install":
        let key = option("--key", in: rest) ?? readLine(strippingNewline: true) ?? ""
        let result = Manage.install(key: key, label: option("--label", in: rest))
        printJSON(result)
        exit(result.ok ? 0 : 1)
    case "pair-code":
        print(Manage.pairCode())
        exit(0)
    case "upgrade":
        guard let sha = option("--sha256", in: rest), let size = option("--size", in: rest).flatMap(Int.init) else { usage() }
        var result = Manage.upgrade(sha256: sha, size: size)
        // The background agent still runs the old binary: restart it on the
        // new one. Its history is saved and reloaded on the way.
        if result.ok, LaunchAgent.restart() {
            result.details = (result.details ?? [:]).merging(["service": "restarted"]) { $1 }
        }
        printJSON(result)
        exit(result.ok ? 0 : 1)
    case "uninstall":
        // The service first, while the agent it runs still exists.
        let background = LaunchAgent.uninstall()
        var result = Manage.uninstall()
        if !background.ok {
            result.message = (result.message ?? "") + " The background service was not removed: " + (background.message ?? "")
        }
        printJSON(result)
        exit(result.ok ? 0 : 1)
    case "serve":
        BackgroundServer.run(interval: option("--interval", in: rest).flatMap(Double.init) ?? Background.defaultInterval)
    case "install-service":
        let result = LaunchAgent.install()
        printJSON(result)
        exit(result.ok ? 0 : 1)
    case "uninstall-service":
        let result = LaunchAgent.uninstall()
        printJSON(result)
        exit(result.ok ? 0 : 1)
    case "ssh":
        // The restricted key's forced command: only these, in exactly these
        // forms, whatever the client asked for.
        let original = ProcessInfo.processInfo.environment["SSH_ORIGINAL_COMMAND"] ?? ""
        let words = original.split(whereSeparator: \.isWhitespace).map(String.init)
        guard allowedOverSSH(words) else {
            FileHandle.standardError.write(Data(("This key can only run the Rex Boing Remote agent (allowed: stream, version, doctor, "
                + "doctor --json, upgrade, uninstall, pair-code, install-service, uninstall-service).\n").utf8))
            exit(1)
        }
        run(words)
    default:
        usage()
    }
}

/// Whether the restricted key may run this command line: the same list,
/// and the same exact forms, as the Go agent's.
func allowedOverSSH(_ words: [String]) -> Bool {
    guard let first = words.first else { return false }
    switch first {
    case "stream", "version", "uninstall", "pair-code", "install-service", "uninstall-service":
        return words.count == 1
    case "doctor":
        return words.count == 1 || words == ["doctor", "--json"]
    case "upgrade":
        guard words.count == 5 else { return false }
        let flags = Dictionary([(words[1], words[2]), (words[3], words[4])], uniquingKeysWith: { first, _ in first })
        guard flags.count == 2, let sha = flags["--sha256"], let size = flags["--size"].flatMap(Int.init) else { return false }
        return sha.count == 64 && sha.allSatisfy(\.isHexDigit) && size > 0
    default:
        return false
    }
}

struct VersionInfo: Encodable {
    var name = WireProtocol.agentName
    var version = agentVersion
    var `protocol` = WireProtocol.version
    var os = "darwin"
    var arch = Machine.arch
}

enum Machine {
    static var arch: String {
        var info = utsname()
        uname(&info)
        let machine = withUnsafeBytes(of: &info.machine) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
        return machine == "x86_64" ? "amd64" : "arm64"
    }

    static var kernel: String {
        var info = utsname()
        uname(&info)
        return withUnsafeBytes(of: &info.release) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
    }

    static var hostname: String {
        if let local = SCDynamicStoreCopyLocalHostName(nil) as String? { return local }
        var buffer = [CChar](repeating: 0, count: 256)
        gethostname(&buffer, buffer.count)
        return String(cString: buffer)
    }
}

// MARK: - Stream

enum Stream {
    enum Detail { case vitals, full }

    final class State: @unchecked Sendable {
        var detail: Detail
        var interval: Double
        var seq: UInt64 = 0
        var fullSamples = 0
        var count: Int?
        let sampler = SnapshotSampler()
        var timer: DispatchSourceTimer?

        init(detail: Detail, interval: Double, count: Int?) {
            self.detail = detail
            self.interval = interval
            self.count = count
        }
    }

    static let queue = DispatchQueue(label: "rex-boing-agent.sampler")
    static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes]
        return encoder
    }()

    static func run(interval: Double, detail: Detail, count: Int?) -> Never {
        let state = State(detail: detail, interval: clamp(interval), count: count)

        // Requests from the app; end of file means the session is over.
        Thread.detachNewThread {
            while let line = readLine(strippingNewline: true) {
                guard let data = line.data(using: .utf8),
                      let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }
                let want = object["want"] as? String
                let interval = object["interval"] as? Double ?? (object["interval"] as? Int).map(Double.init)
                queue.async {
                    switch want {
                    case "full": state.detail = .full
                    case "vitals": state.detail = .vitals
                    case "history": sendHistory()
                    default: break
                    }
                    if let value = interval {
                        let clamped = clamp(value)
                        if clamped != state.interval {
                            state.interval = clamped
                            schedule(state)
                        }
                    }
                }
            }
            exit(0)
        }

        queue.async {
            apply(state)
            let (snapshot, _) = state.sampler.tick(refreshInterval: state.interval)
            var hello = WireHello()
            hello.protocol = WireProtocol.version
            hello.agent = WireAgent(name: WireProtocol.agentName, version: agentVersion, os: "darwin", arch: Machine.arch)
            hello.host = snapshot.host.wire(hostname: Machine.hostname, kernel: Machine.kernel)
            hello.capabilities = ["cpu", "memory", "gpu", "sensors", "fans", "power", "battery", "processes", "sleep"]
            hello.interval = state.interval
            write(hello)
            // What a background agent kept while the app was away, if one runs.
            sendHistory()
            schedule(state)
        }
        dispatchMain()
    }

    static func sendHistory() {
        guard let history = Background.history(), history.count < Background.maxLine else { return }
        writeRaw(history)
    }

    static func clamp(_ value: Double) -> Double { min(10, max(0.5, value)) }

    static func apply(_ state: State) {
        state.sampler.detailedMetricsVisible = state.detail == .full
        state.sampler.liveProcessSampling = state.detail == .full
    }

    static func schedule(_ state: State) {
        state.timer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + state.interval, repeating: state.interval, leeway: .milliseconds(50))
        timer.setEventHandler { tick(state) }
        timer.resume()
        state.timer = timer
    }

    static func tick(_ state: State) {
        apply(state)
        let (snapshot, resync) = state.sampler.tick(refreshInterval: state.interval)
        var sample = snapshot.wireSample(full: state.detail == .full)
        // The full sensor list runs to a couple of hundred entries on Apple
        // silicon and changes slowly; the headline temperatures go every
        // sample, the list every third. The app keeps the last list it got.
        if state.detail == .full {
            state.fullSamples += 1
            if state.fullSamples % 3 != 1 { sample.thermal?.sensors = nil }
        }
        state.seq += 1
        sample.seq = state.seq
        sample.resync = resync
        if !write(sample) {
            // A reading that is not a number can't be put in JSON. Without
            // the process table and the sensor list, where such readings
            // most likely are, then with nothing but its place in the
            // stream: a sample that never comes would look like a dead
            // link to the app, which would reconnect again and again.
            sample.processes = nil
            sample.thermal?.sensors = nil
            if !write(sample) {
                var bare = WireSample()
                bare.seq = sample.seq
                bare.t = sample.t
                bare.interval = state.interval
                bare.detail = sample.detail
                bare.resync = true
                write(bare)
            }
        }
        if let count = state.count {
            state.count = count - 1
            if count - 1 <= 0 { exit(0) }
        }
    }

    /// False if the value could not be encoded, and nothing was written.
    @discardableResult
    static func write<T: Encodable>(_ value: T) -> Bool {
        guard let data = try? encoder.encode(value) else { return false }
        writeRaw(data)
        return true
    }

    static func writeRaw(_ data: Data) {
        do {
            try FileHandle.standardOutput.write(contentsOf: data + Data([0x0A]))
        } catch {
            exit(0)
        }
    }
}

// MARK: - Doctor

enum Doctor {
    struct Check: Encodable {
        var name: String
        var ok: Bool
        var detail: String
        var fix: String?
    }

    static func run(json: Bool) -> Never {
        let sampler = SnapshotSampler()
        sampler.detailedMetricsVisible = true
        sampler.liveProcessSampling = true
        _ = sampler.tick(refreshInterval: 1)
        Thread.sleep(forTimeInterval: 1)
        let (snapshot, _) = sampler.tick(refreshInterval: 1)

        var checks: [Check] = []
        checks.append(Check(name: "CPU", ok: !snapshot.cpu.perCore.isEmpty,
                            detail: "\(snapshot.cpu.perCore.count) cores, \(Int(snapshot.cpu.total * 100))% busy"))
        checks.append(Check(name: "Memory", ok: snapshot.memory.total > 0,
                            detail: "\(snapshot.memory.total >> 30) GiB"))
        checks.append(Check(name: "GPU", ok: snapshot.gpu.available, detail: snapshot.gpu.name))
        checks.append(Check(name: "Temperatures", ok: !snapshot.thermal.sensors.isEmpty,
                            detail: "\(snapshot.thermal.sensors.count) sensors",
                            fix: snapshot.thermal.sensors.isEmpty ? "No readable sensors on this Mac." : nil))
        checks.append(Check(name: "Fans", ok: true, detail: snapshot.thermal.fans.isEmpty ? "none (fanless or not exposed)" : "\(snapshot.thermal.fans.count)"))
        checks.append(Check(name: "Power", ok: snapshot.power.hasAny,
                            detail: snapshot.power.totalWatts.map { String(format: "%.1f W", $0) } ?? "not available"))
        checks.append(Check(name: "Battery", ok: true, detail: snapshot.battery.present ? "present" : "none"))
        checks.append(Check(name: "Processes", ok: snapshot.processes.count > 0,
                            detail: "\(snapshot.processes.count) running"))
        let viaSSH = ProcessInfo.processInfo.environment["SSH_CONNECTION"] != nil
        checks.append(Check(name: "Session", ok: true, detail: viaSSH ? "over SSH" : "local"))
        checks.append(backgroundCheck())

        if json {
            printJSON(checks)
        } else {
            print("rex-boing-agent \(agentVersion) on \(snapshot.host.modelName), macOS \(snapshot.host.osVersion)")
            for check in checks {
                print("\(check.ok ? "ok  " : "--  ") \(check.name): \(check.detail)")
                if let fix = check.fix { print("      \(fix)") }
            }
        }
        exit(0)
    }
}

extension Doctor {
    static func backgroundCheck() -> Check {
        let formatter = DateFormatter()
        formatter.dateFormat = "MMM d HH:mm"
        if let status = Background.status() {
            var detail = "running (pid \(status.pid), since \(formatter.string(from: Date(timeIntervalSince1970: Double(status.started) / 1000))), "
                + "sampling every \(String(format: "%g", status.interval)) s)"
            if let oldest = status.oldest {
                detail += "; history back to \(formatter.string(from: Date(timeIntervalSince1970: Double(oldest) / 1000)))"
            }
            return Check(name: "Background history", ok: true, detail: detail)
        }
        if LaunchAgent.installed {
            return Check(name: "Background history", ok: false, detail: "installed as a LaunchAgent, but not running",
                         fix: "launchctl print gui/\(getuid())/\(LaunchAgent.label)")
        }
        return Check(name: "Background history", ok: true,
                     detail: "off (optional: Rex Boing Remote › Settings › Servers › Keep history while this Mac is away)")
    }
}

// MARK: - Install, upgrade, uninstall, pairing

struct ManageResult: Encodable {
    var ok: Bool
    var error: String?
    var message: String?
    var details: [String: String]?
}

enum Manage {
    static let commentPrefix = "rex-boing-remote:"
    static let home = NSHomeDirectory()
    static var installDir: String { home + "/.local/share/rex-boing-remote" }
    static var installedPath: String { installDir + "/rex-boing-agent" }
    static var keyFile: String { home + "/.ssh/authorized_keys" }

    static func install(key rawKey: String, label: String?) -> ManageResult {
        let parts = rawKey.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: " ", maxSplits: 2).map(String.init)
        let types: Set<String> = ["ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa"]
        guard parts.count >= 2, types.contains(parts[0]), Data(base64Encoded: parts[1]) != nil else {
            return ManageResult(ok: false, error: "bad-key", message: "That isn't an OpenSSH public key.")
        }
        let name = sanitise(label ?? (parts.count > 2 ? parts[2].replacingOccurrences(of: commentPrefix, with: "") : "mac"))

        let fileManager = FileManager.default
        do {
            try fileManager.createDirectory(atPath: installDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o755])
            let me = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath().path
            let self_ = (Bundle.main.executablePath.map { URL(fileURLWithPath: $0).resolvingSymlinksInPath().path }) ?? me
            if self_ != installedPath {
                let temp = installDir + "/.rex-boing-agent.\(getpid())"
                try? fileManager.removeItem(atPath: temp)
                try fileManager.copyItem(atPath: self_, toPath: temp)
                chmod(temp, 0o755)
                guard rename(temp, installedPath) == 0 else {
                    throw NSError(domain: "install", code: Int(errno), userInfo: [NSLocalizedDescriptionKey: String(cString: strerror(errno))])
                }
            }

            let sshDir = home + "/.ssh"
            if !fileManager.fileExists(atPath: sshDir) {
                try fileManager.createDirectory(atPath: sshDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            }
            // Through a symlink if it is one, keeping every other line as
            // it is, and refusing rather than starting from an empty file
            // when the one there can't be read.
            let path = AuthorizedKeys.resolve(keyFile)
            let existing = try AuthorizedKeys.read(path)
            let quotedPath = "'" + installedPath.replacingOccurrences(of: "'", with: "'\\''") + "'"
            let line = "restrict,command=\"\(quotedPath.replacingOccurrences(of: "\"", with: "\\\"")) ssh\" \(parts[0]) \(parts[1]) \(commentPrefix)\(name)"
            let updated = AuthorizedKeys.upsert(existing?.bytes ?? [], line: Array(line.utf8), blob: parts[1]).content
            if updated != existing?.bytes {
                try AuthorizedKeys.write(updated, to: path, mode: existing?.mode ?? 0o600)
            }
            return ManageResult(ok: true, message: "Installed. This key can now only start the agent.",
                                details: ["agentPath": installedPath, "keyFile": path])
        } catch {
            return ManageResult(ok: false, error: "install-failed", message: error.localizedDescription)
        }
    }

    static func uninstall() -> ManageResult {
        var removed = 0
        let path = AuthorizedKeys.resolve(keyFile)
        do {
            if let existing = try AuthorizedKeys.read(path) {
                let edited = AuthorizedKeys.removeKeys(existing.bytes, commentPrefix: commentPrefix)
                removed = edited.removed
                if removed > 0 { try AuthorizedKeys.write(edited.content, to: path, mode: existing.mode) }
            }
        } catch {
            // The agent stays, so uninstall can be run again once the file
            // can be read: without it, the key would be left behind.
            return ManageResult(ok: false, error: "uninstall-failed", message: error.localizedDescription)
        }
        try? FileManager.default.removeItem(atPath: installDir)
        return ManageResult(ok: true, message: "Removed \(removed) key\(removed == 1 ? "" : "s") and the agent.")
    }

    static func upgrade(sha256 expected: String, size: Int) -> ManageResult {
        guard size > 0, size < 256 << 20 else { return ManageResult(ok: false, error: "bad-size", message: "Implausible size.") }
        var data = Data()
        data.reserveCapacity(size)
        let input = FileHandle.standardInput
        while data.count < size {
            let chunk = (try? input.read(upToCount: min(1 << 16, size - data.count))) ?? nil
            guard let chunk, !chunk.isEmpty else { break }
            data.append(chunk)
        }
        guard data.count == size else {
            return ManageResult(ok: false, error: "short-read", message: "Received \(data.count) of \(size) bytes.")
        }
        let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        guard digest == expected.lowercased() else {
            return ManageResult(ok: false, error: "bad-hash", message: "The new agent's checksum doesn't match.")
        }
        let temp = installDir + "/.rex-boing-agent.new"
        do {
            try FileManager.default.createDirectory(atPath: installDir, withIntermediateDirectories: true)
            try data.write(to: URL(fileURLWithPath: temp))
            chmod(temp, 0o755)
            // Before it runs even once: see CodeSignature.
            if let team = CodeSignature.ownTeamID(), let problem = CodeSignature.problem(path: temp, teamID: team) {
                try? FileManager.default.removeItem(atPath: temp)
                return ManageResult(ok: false, error: "bad-signature", message: problem)
            }
            let check = Process()
            check.executableURL = URL(fileURLWithPath: temp)
            check.arguments = ["version"]
            let pipe = Pipe()
            check.standardOutput = pipe
            try check.run()
            check.waitUntilExit()
            let output = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            guard check.terminationStatus == 0, output.contains("\"protocol\":1") else {
                try? FileManager.default.removeItem(atPath: temp)
                return ManageResult(ok: false, error: "bad-binary", message: "The new agent didn't start.")
            }
            guard rename(temp, installedPath) == 0 else {
                return ManageResult(ok: false, error: "rename", message: String(cString: strerror(errno)))
            }
            struct V: Decodable { var version: String }
            let version = (try? JSONDecoder().decode(V.self, from: Data(output.utf8)))?.version ?? "?"
            return ManageResult(ok: true, message: "Updated.", details: ["version": version])
        } catch {
            return ManageResult(ok: false, error: "upgrade-failed", message: error.localizedDescription)
        }
    }

    static func pairCode() -> String {
        struct Code: Encodable {
            var v = 1
            var n: String
            var u: String
            var p: Int
            var o = "darwin"
            var a: [String]
            var k: [String]
        }
        let keys = ["ed25519", "ecdsa", "rsa"].compactMap { kind -> String? in
            guard let text = try? String(contentsOfFile: "/etc/ssh/ssh_host_\(kind)_key.pub", encoding: .utf8) else { return nil }
            let parts = text.split(separator: " ")
            return parts.count >= 2 ? "\(parts[0]) \(parts[1])" : nil
        }
        let code = Code(n: Machine.hostname, u: NSUserName(), p: sshPort(), a: addresses() + [Machine.hostname + ".local"], k: keys)
        let data = (try? JSONEncoder().encode(code)) ?? Data()
        let base64 = data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return "rbr1:" + base64
    }

    static func sshPort() -> Int {
        var files = ["/etc/ssh/sshd_config"]
        if let extra = try? FileManager.default.contentsOfDirectory(atPath: "/etc/ssh/sshd_config.d") {
            files += extra.filter { $0.hasSuffix(".conf") }.sorted().map { "/etc/ssh/sshd_config.d/" + $0 }
        }
        for file in files {
            guard let text = try? String(contentsOfFile: file, encoding: .utf8) else { continue }
            for line in text.split(separator: "\n") {
                let words = line.trimmingCharacters(in: .whitespaces).split(whereSeparator: \.isWhitespace)
                if words.count >= 2, words[0].lowercased() == "port", let port = Int(words[1]) { return port }
            }
        }
        return 22
    }

    static func addresses() -> [String] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }
        var found: [String] = []
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            defer { cursor = entry.pointee.ifa_next }
            let flags = Int32(entry.pointee.ifa_flags)
            guard flags & IFF_UP != 0, flags & IFF_LOOPBACK == 0,
                  let address = entry.pointee.ifa_addr, address.pointee.sa_family == UInt8(AF_INET) else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(address, socklen_t(address.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 {
                found.append(String(cString: host))
            }
        }
        func rank(_ ip: String) -> Int {
            let octets = ip.split(separator: ".").compactMap { Int($0) }
            guard octets.count == 4 else { return 3 }
            if octets[0] == 10 || (octets[0] == 192 && octets[1] == 168) || (octets[0] == 172 && (16...31).contains(octets[1])) { return 0 }
            if octets[0] == 100 && (64...127).contains(octets[1]) { return 1 }
            if octets[0] == 169 && octets[1] == 254 { return 4 }
            return 2
        }
        return Array(Set(found)).sorted { (rank($0), $0) < (rank($1), $1) }.filter { rank($0) < 4 }
    }

    static func sanitise(_ label: String) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "._-"))
        let cleaned = String(label.unicodeScalars.map { allowed.contains($0) ? Character($0) : "-" })
        return cleaned.isEmpty ? "mac" : String(cleaned.prefix(64))
    }
}

run(arguments)
