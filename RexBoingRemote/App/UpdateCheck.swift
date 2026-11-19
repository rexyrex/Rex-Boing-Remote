import AppKit
import Combine
import Foundation

/// Whether a newer Rex Boing Remote has been released, asked of GitHub about
/// once a day while "Check for new versions" is on (Settings › General, on by
/// default). When one is out, the fleet popover, the window, the rexes'
/// right-click menu and Settings say so, with a link to its release page.
///
/// The app's only connection that is not to a server the user added. It asks
/// for the repository's latest release — drafts and pre-releases never count —
/// over an ephemeral session, with no cookies and no cache, and a User-Agent
/// that names the app's version and nothing about the Mac or its servers. It
/// installs nothing: the release page is where the download is. Demo mode
/// never starts it.
///
/// What it heard is kept in the preferences domain, so a notice survives a
/// relaunch and a relaunch within the day asks nothing. Switched off, it
/// stops asking and forgets what it last heard.
@MainActor
final class UpdateCheck: ObservableObject {
    static let shared = UpdateCheck()

    enum Status: Equatable {
        /// Switched off: no requests at all.
        case off
        /// On, and nothing heard yet.
        case idle
        case checking
        /// The last check answered; `available` says what it found.
        case checked
        /// The last attempt failed, with a few words on why. The next hourly
        /// look tries again, since a failure does not count as a check.
        case failed(String)
    }

    /// A release newer than this copy, or nil.
    @Published private(set) var available: AppRelease?
    @Published private(set) var status: Status = .off
    /// When GitHub last answered.
    @Published private(set) var lastChecked: Date?

    /// This copy's version, as Info.plist gives it.
    let currentVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0"

    private nonisolated static let endpoint = URL(string: "https://api.github.com/repos/rexyrex/Rex-Boing-Remote/releases/latest")!
    nonisolated static let releasesPage = URL(string: "https://github.com/rexyrex/Rex-Boing-Remote/releases/latest")!

    /// How often to ask, and how often to look whether it is time to. The
    /// look is hourly rather than one day-long timer, because a timer's clock
    /// stops while the Mac sleeps and a laptop that sleeps every night would
    /// otherwise put the check off indefinitely.
    private static let interval: TimeInterval = 24 * 60 * 60
    private static let lookInterval: TimeInterval = 60 * 60

    private enum Key {
        static let lastChecked = "updateCheckLastChecked"
        static let latestVersion = "updateCheckLatestVersion"
        static let latestPage = "updateCheckLatestPage"
    }

    private let defaults = UserDefaults.standard
    private var enabled = false
    private var timer: Timer?
    private var inFlight: Task<Void, Never>?
    /// Bumped whenever the setting changes, so an answer to a request made
    /// before the change — off and on again while it was out — is dropped
    /// rather than taken for the current one's.
    private var generation = 0
    private var subscription: AnyCancellable?

    private init() {}

    /// Follows the setting from now on, starting with its current value. The
    /// first look waits a few seconds, so it is not part of launch.
    func start<P: Publisher>(enabled setting: P) where P.Output == Bool, P.Failure == Never {
        subscription = setting
            .removeDuplicates()
            .sink { [weak self] isOn in self?.setEnabled(isOn) }
    }

    /// Asks now, whatever the time since the last check. Does nothing while
    /// switched off or while a check is already under way.
    func checkNow() {
        guard enabled, inFlight == nil else { return }
        status = .checking
        let userAgent = "Rex Boing Remote/\(currentVersion)"
        let token = generation
        inFlight = Task { [weak self] in
            let result = await Self.fetchLatest(userAgent: userAgent)
            self?.finish(result, token: token)
        }
    }

    func openReleasePage() {
        NSWorkspace.shared.open(available?.page ?? Self.releasesPage)
    }

    // MARK: - Private

    private func setEnabled(_ isOn: Bool) {
        enabled = isOn
        generation += 1
        timer?.invalidate()
        timer = nil
        inFlight?.cancel()
        inFlight = nil

        guard isOn else {
            // Off means off: nothing kept that a later "on" would show stale.
            for key in [Key.lastChecked, Key.latestVersion, Key.latestPage] {
                defaults.removeObject(forKey: key)
            }
            available = nil
            lastChecked = nil
            status = .off
            return
        }

        restore()
        let timer = Timer(timeInterval: Self.lookInterval, repeats: true) { _ in
            MainActor.assumeIsolated { UpdateCheck.shared.checkIfDue() }
        }
        timer.tolerance = 5 * 60
        RunLoop.main.add(timer, forMode: .common)
        self.timer = timer
        Task { [weak self] in
            try? await Task.sleep(for: .seconds(10))
            self?.checkIfDue()
        }
    }

    private func checkIfDue() {
        guard enabled else { return }
        if let lastChecked, Date().timeIntervalSince(lastChecked) < Self.interval,
           lastChecked <= Date() {
            return
        }
        checkNow()
    }

    /// What the last successful check heard, so a notice is up from launch
    /// rather than from the next check. A release this copy has caught up
    /// with — the user updated — is no longer news.
    private func restore() {
        lastChecked = defaults.object(forKey: Key.lastChecked) as? Date
        if let version = defaults.string(forKey: Key.latestVersion),
           AppVersion.isNewer(version, than: currentVersion) {
            let page = defaults.string(forKey: Key.latestPage).flatMap(AppRelease.trustedPage) ?? Self.releasesPage
            available = AppRelease(version: version, page: page)
        } else {
            available = nil
        }
        status = lastChecked == nil ? .idle : .checked
    }

    private func finish(_ result: Result<AppRelease, UpdateCheckError>, token: Int) {
        // Switched off (and perhaps on again) while the request was out: what
        // it brought back belongs to a setting that no longer holds.
        guard token == generation else { return }
        inFlight = nil
        switch result {
        case .success(let latest):
            let now = Date()
            lastChecked = now
            defaults.set(now, forKey: Key.lastChecked)
            defaults.set(latest.version, forKey: Key.latestVersion)
            defaults.set(latest.page.absoluteString, forKey: Key.latestPage)
            available = AppVersion.isNewer(latest.version, than: currentVersion) ? latest : nil
            status = .checked
        case .failure(.cancelled):
            status = lastChecked == nil ? .idle : .checked
        case .failure(let error):
            status = .failed(error.summary)
        }
    }

    private nonisolated static func fetchLatest(userAgent: String) async -> Result<AppRelease, UpdateCheckError> {
        var request = URLRequest(url: endpoint, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 20)
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        let session = URLSession(configuration: .ephemeral)
        defer { session.finishTasksAndInvalidate() }
        do {
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse else { return .failure(.unreadable) }
            guard http.statusCode == 200 else { return .failure(.status(http.statusCode)) }
            guard let release = AppRelease.decode(data, fallbackPage: releasesPage) else {
                return .failure(.unreadable)
            }
            return .success(release)
        } catch is CancellationError {
            return .failure(.cancelled)
        } catch let error as URLError where error.code == .cancelled {
            return .failure(.cancelled)
        } catch {
            return .failure(.offline)
        }
    }
}

enum UpdateCheckError: Error, Equatable {
    case offline
    case status(Int)
    case unreadable
    case cancelled

    var summary: String {
        switch self {
        case .offline: return "GitHub could not be reached"
        case .status(let code): return "GitHub answered \(code)"
        case .unreadable: return "GitHub's answer could not be read"
        case .cancelled: return "cancelled"
        }
    }
}

/// A release, reduced to what the notice needs.
struct AppRelease: Equatable, Sendable {
    /// Normalised: "1.4.0", never "v1.4.0".
    var version: String
    var page: URL

    private struct Payload: Decodable {
        var tag: String
        var page: String?
        var draft: Bool?
        var prerelease: Bool?

        enum CodingKeys: String, CodingKey {
            case tag = "tag_name"
            case page = "html_url"
            case draft, prerelease
        }
    }

    /// From the body of GitHub's `GET /repos/{owner}/{repo}/releases/latest`.
    /// Nil for a draft, a pre-release, a tag that is not a version, or a body
    /// that is not a release at all.
    static func decode(_ data: Data, fallbackPage: URL) -> AppRelease? {
        guard let payload = try? JSONDecoder().decode(Payload.self, from: data),
              payload.draft != true, payload.prerelease != true,
              let version = AppVersion.normalized(payload.tag) else { return nil }
        let page = payload.page.flatMap(trustedPage) ?? fallbackPage
        return AppRelease(version: version, page: page)
    }

    /// The page to open, if it is GitHub's over HTTPS. Anything else in the
    /// answer is ignored in favour of the releases page, so a click can only
    /// ever open github.com.
    static func trustedPage(_ string: String) -> URL? {
        guard let url = URL(string: string), url.scheme == "https", url.host == "github.com" else { return nil }
        return url
    }
}

/// Release versions: dotted numbers, as tags carry them ("v1.4.0").
enum AppVersion {
    /// "v1.4.0" → "1.4.0". Nil unless it starts with a number.
    static func normalized(_ tag: String) -> String? {
        var text = tag.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.first == "v" || text.first == "V" { text.removeFirst() }
        guard let first = text.first, first.isNumber else { return nil }
        return text
    }

    /// Component by component, as numbers, a missing component counting as
    /// zero: 1.4 is 1.4.0, 1.10 is newer than 1.9. Anything after a
    /// component's digits ("1.4.0-beta") is ignored.
    static func isNewer(_ candidate: String, than current: String) -> Bool {
        guard let a = normalized(candidate).map(components), let b = normalized(current).map(components) else {
            return false
        }
        for index in 0..<max(a.count, b.count) {
            let x = index < a.count ? a[index] : 0
            let y = index < b.count ? b[index] : 0
            if x != y { return x > y }
        }
        return false
    }

    private static func components(_ version: String) -> [Int] {
        version.split(separator: ".").map { part in
            Int(part.prefix { $0.isNumber }) ?? 0
        }
    }
}
