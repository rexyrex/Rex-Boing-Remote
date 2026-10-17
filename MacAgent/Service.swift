import Foundation

// install-service and uninstall-service on macOS: a LaunchAgent,
// ~/Library/LaunchAgents/com.rexyrex.rex-boing-remote.agent.plist, that
// runs `serve` as this user. Loaded into the GUI session when the user is
// logged in at the Mac, otherwise into their background session; launchd
// loads it again at every login.

enum LaunchAgent {
    static let label = "com.rexyrex.rex-boing-remote.agent"
    static var plistPath: String { NSHomeDirectory() + "/Library/LaunchAgents/\(label).plist" }
    static var installed: Bool { FileManager.default.fileExists(atPath: plistPath) }

    static var domains: [String] { ["gui/\(getuid())", "user/\(getuid())"] }

    @discardableResult
    static func launchctl(_ arguments: [String]) -> (status: Int32, output: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do { try process.run() } catch { return (-1, error.localizedDescription) }
        let deadline = Date().addingTimeInterval(30)
        while process.isRunning, Date() < deadline { usleep(20_000) }
        if process.isRunning { process.terminate() }
        process.waitUntilExit()
        let output = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        return (process.terminationStatus, output.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    static func install() -> ManageResult {
        let agent = Manage.installedPath
        guard FileManager.default.isExecutableFile(atPath: agent) else {
            return ManageResult(ok: false, error: "not-installed",
                                message: "The agent is not installed at \(agent) yet. Add this Mac in Rex Boing Remote first.")
        }
        let plist: [String: Any] = [
            "Label": label,
            "ProgramArguments": [agent, "serve"],
            "RunAtLoad": true,
            // Restarted if it fails; left stopped when it exits on purpose
            // (asked to stop, or another serve already runs).
            "KeepAlive": ["SuccessfulExit": false],
            "ThrottleInterval": 30,
            "ProcessType": "Background",
            "LowPriorityIO": true,
            "Nice": 10,
        ]
        do {
            try FileManager.default.createDirectory(
                atPath: (plistPath as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
            let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
            try data.write(to: URL(fileURLWithPath: plistPath), options: .atomic)
        } catch {
            return ManageResult(ok: false, error: "install-failed", message: "Cannot write \(plistPath): \(error.localizedDescription)")
        }
        // Replace whatever runs now: an older definition, or a serve
        // started by hand.
        for domain in domains { launchctl(["bootout", "\(domain)/\(label)"]) }
        Background.stop()
        var loaded: String?
        var errors: [String] = []
        for domain in domains {
            let result = launchctl(["bootstrap", domain, plistPath])
            if result.status == 0 {
                loaded = domain
                break
            }
            errors.append("\(domain): \(result.output)")
        }
        guard let domain = loaded else {
            return ManageResult(ok: false, error: "install-failed",
                                message: "launchd did not load the agent: \(errors.joined(separator: "; "))")
        }
        let deadline = Date().addingTimeInterval(8)
        var status = Background.status(timeout: 1)
        while status == nil, Date() < deadline {
            usleep(200_000)
            status = Background.status(timeout: 1)
        }
        guard let status else {
            return ManageResult(ok: false, error: "not-running",
                                message: "The LaunchAgent is installed but did not start. See: launchctl print \(domain)/\(label)")
        }
        let interval = String(format: "%g", status.interval)
        return ManageResult(
            ok: true,
            message: "Keeping history: the agent samples every \(interval) s in the background and keeps 48 hours, "
                + "as the LaunchAgent \(label). macOS starts it again whenever \(NSUserName()) logs in.",
            details: ["manager": "launchd", "plist": plistPath, "domain": domain, "interval": interval])
    }

    static func uninstall() -> ManageResult {
        let hadPlist = installed
        for domain in domains { launchctl(["bootout", "\(domain)/\(label)"]) }
        if hadPlist {
            do { try FileManager.default.removeItem(atPath: plistPath) } catch {
                return ManageResult(ok: false, error: "uninstall-failed",
                                    message: "Cannot remove \(plistPath): \(error.localizedDescription)")
            }
        }
        let stopped = Background.stop()
        try? FileManager.default.removeItem(atPath: Background.historyFile)
        if hadPlist {
            return ManageResult(ok: true, message: "History is off: the LaunchAgent and the history it kept were removed.",
                                details: ["removed": plistPath])
        }
        if stopped {
            return ManageResult(ok: true, message: "History is off: the background agent was stopped and its history removed.")
        }
        return ManageResult(ok: true, message: "History was already off.")
    }

    /// Starts the background agent again on a freshly upgraded binary, and
    /// waits for it to answer.
    @discardableResult
    static func restart() -> Bool {
        guard installed else { return false }
        Background.stop()
        var started = domains.contains { launchctl(["kickstart", "\($0)/\(label)"]).status == 0 }
        if !started {
            // Not loaded anywhere (the Mac restarted and no one has logged
            // in since): load it.
            started = domains.contains { launchctl(["bootstrap", $0, plistPath]).status == 0 }
        }
        guard started else { return false }
        let deadline = Date().addingTimeInterval(5)
        while Background.status(timeout: 0.5) == nil, Date() < deadline { usleep(100_000) }
        return true
    }
}
