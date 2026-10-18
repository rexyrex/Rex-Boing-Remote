import Foundation

/// Where the app keeps its own files. Everything lives in one folder so that
/// removing the app's data is one `rm -r`. The app never edits `~/.ssh`; the
/// only thing that can land there is a host key the user accepts during
/// setup, which ssh saves exactly as it would from Terminal.
enum Paths {
    /// `~/Library/Application Support/Rex Boing Remote`
    static let support: URL = {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let url = base.appendingPathComponent("Rex Boing Remote", isDirectory: true)
        try? FileManager.default.createDirectory(
            at: url, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        return url
    }()

    /// The app's own SSH key. The public half is what servers authorise,
    /// restricted to running the agent.
    static var privateKey: URL { support.appendingPathComponent("id_ed25519") }
    static var publicKey: URL { support.appendingPathComponent("id_ed25519.pub") }

    /// Host keys pinned from pairing codes, under each server's own alias.
    static var knownHosts: URL { support.appendingPathComponent("known_hosts") }

    static var hosts: URL { support.appendingPathComponent("servers.json") }

    /// Control sockets for the short-lived setup sessions. Kept under /tmp:
    /// a Unix socket path must stay under 104 bytes, and Application
    /// Support's path plus ssh's 40-character hash does not fit.
    static let controlDirectory = URL(
        fileURLWithPath: controlDirectory(
            preferred: "/tmp/rbr-\(getuid())",
            fallback: (NSTemporaryDirectory() as NSString).appendingPathComponent("rbr")),
        isDirectory: true)

    /// `preferred` if it is, or can be made, a directory of this user's that
    /// nobody else can enter. Anyone can create /tmp/rbr-501 first, as a
    /// directory they own or a symlink to one, and read or plant sockets
    /// there; then `fallback`, in the per-user temporary directory macOS
    /// keeps for this user alone (short enough for a socket path too).
    static func controlDirectory(preferred: String, fallback: String) -> String {
        if privateDirectory(preferred) { return preferred }
        _ = privateDirectory(fallback)
        return fallback
    }

    /// Makes `path` a directory owned by this user with no access for
    /// anyone else, creating it if it is missing. False if it is anything
    /// else — a symlink, a file, someone else's — or can't be made so.
    static func privateDirectory(_ path: String) -> Bool {
        mkdir(path, 0o700)
        var info = stat()
        guard lstat(path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR, info.st_uid == getuid() else { return false }
        if info.st_mode & 0o077 != 0 {
            guard chmod(path, 0o700) == 0 else { return false }
        }
        return true
    }

    /// The agents shipped inside the app, one folder per platform.
    static var bundledAgents: URL {
        Bundle.main.resourceURL!.appendingPathComponent("Agents", isDirectory: true)
    }

    /// The user's own known_hosts, which the app reads alongside its own.
    static var userKnownHosts: String {
        (NSHomeDirectory() as NSString).appendingPathComponent(".ssh/known_hosts")
    }
}
