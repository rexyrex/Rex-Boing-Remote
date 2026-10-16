import AppKit

/// The app's own `SSH_ASKPASS` helper.
///
/// During setup, ssh runs this same executable with the environment variable
/// below set and the prompt as its argument, and reads the answer from its
/// standard output. So passwords, one-time codes, passphrases and new host
/// keys are all answered in native dialogs instead of a terminal — and the
/// answer goes straight to ssh, never through the app or onto disk.
enum Askpass {
    static let environmentKey = "REX_BOING_REMOTE_ASKPASS"

    static var isRequested: Bool {
        ProcessInfo.processInfo.environment[environmentKey] == "1"
    }

    /// Runs the dialog and exits the process. Never returns.
    @MainActor
    static func run() -> Never {
        let prompt = CommandLine.arguments.dropFirst().joined(separator: " ")
        let kind = ProcessInfo.processInfo.environment["SSH_ASKPASS_PROMPT"] ?? ""

        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        app.activate(ignoringOtherApps: true)

        // A notification-style prompt ("Confirm user presence for key…"):
        // shown until ssh kills this process when the touch is done.
        if kind == "none" {
            let alert = NSAlert()
            alert.messageText = "Touch your security key"
            alert.informativeText = prompt
            alert.addButton(withTitle: "Cancel")
            alert.runModal()
            exit(1)
        }

        let lower = prompt.lowercased()
        let isHostKey = lower.contains("(yes/no")
        if isHostKey || kind == "confirm" {
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = isHostKey ? "Trust this server?" : "Confirm"
            alert.informativeText = isHostKey
                ? Self.hostKeyExplanation(prompt)
                : prompt
            alert.addButton(withTitle: isHostKey ? "Trust and Connect" : "Allow")
            alert.addButton(withTitle: "Cancel")
            let answer = alert.runModal()
            guard answer == .alertFirstButtonReturn else { exit(1) }
            if isHostKey { print("yes") }
            exit(0)
        }

        let alert = NSAlert()
        alert.messageText = Self.title(for: lower)
        alert.informativeText = prompt
        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 260, height: 24))
        // One-time codes are not secret enough to hide, and hiding them makes
        // a mistyped digit impossible to see.
        let isCode = lower.contains("verification code") || lower.contains("one-time")
            || lower.contains("otp") || lower.contains("token")
        let input: NSTextField = isCode
            ? NSTextField(frame: NSRect(x: 0, y: 0, width: 260, height: 24)) : field
        alert.accessoryView = input
        alert.addButton(withTitle: "Continue")
        alert.addButton(withTitle: "Cancel")
        alert.window.initialFirstResponder = input
        let answer = alert.runModal()
        guard answer == .alertFirstButtonReturn else { exit(1) }
        print(input.stringValue)
        exit(0)
    }

    private static func title(for prompt: String) -> String {
        if prompt.contains("passphrase") { return "Unlock your SSH key" }
        if prompt.contains("password") { return "Server password" }
        if prompt.contains("code") || prompt.contains("otp") { return "Verification code" }
        return "SSH needs an answer"
    }

    /// ssh's host-key question, reworded around what the user is deciding.
    private static func hostKeyExplanation(_ prompt: String) -> String {
        var lines = prompt.split(separator: "\n").map(String.init)
        lines.removeAll { $0.lowercased().contains("are you sure you want to continue connecting") }
        let detail = lines.joined(separator: "\n")
        return """
            This is the first connection to this server. Check that the fingerprint matches the \
            server's own (on the server: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub).

            \(detail)
            """
    }
}
