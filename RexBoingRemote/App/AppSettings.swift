import Foundation
import Combine
import RexBoingKit
import ServiceManagement

/// App-wide preferences, in `UserDefaults`. Per-server choices (pinning, the
/// character, the readout) live with the server in `ServerStore`.
@MainActor
final class AppSettings: ObservableObject {
    static let shared = AppSettings()

    /// Demo mode keeps its own preferences, so trying it changes none of yours.
    private let defaults = Demo.isActive
        ? UserDefaults(suiteName: Demo.defaultsSuite) ?? .standard
        : .standard

    /// Seconds between samples while a server is only in the menu bar or the
    /// fleet list. An open dashboard always samples every second.
    @Published var vitalsInterval: Double {
        didSet { defaults.set(vitalsInterval, forKey: Keys.vitalsInterval) }
    }

    @Published var temperatureUnit: TemperatureUnit {
        didSet { defaults.set(temperatureUnit.rawValue, forKey: Keys.temperatureUnit) }
    }

    /// The character standing for the whole fleet.
    @Published var fleetCharacter: Visualizer {
        didSet { defaults.set(fleetCharacter.rawValue, forKey: Keys.fleetCharacter) }
    }

    @Published var animate: Bool {
        didSet { defaults.set(animate, forKey: Keys.animate) }
    }

    /// Whether the fleet item shows the busiest server's CPU beside its rex.
    @Published var showFleetReadout: Bool {
        didSet { defaults.set(showFleetReadout, forKey: Keys.showFleetReadout) }
    }

    @Published private(set) var launchAtLogin: Bool

    private enum Keys {
        static let vitalsInterval = "vitalsInterval"
        static let temperatureUnit = "temperatureUnit"
        static let fleetCharacter = "fleetCharacter"
        static let animate = "animate"
        static let showFleetReadout = "showFleetReadout"
        static let askedAboutLogin = "askedAboutLogin"
    }

    static let intervals: [Double] = [1, 2, 5, 10]

    private init() {
        let stored = defaults.double(forKey: Keys.vitalsInterval)
        vitalsInterval = Self.intervals.contains(stored) ? stored : 2
        temperatureUnit = TemperatureUnit(rawValue: defaults.string(forKey: Keys.temperatureUnit) ?? "") ?? .celsius
        fleetCharacter = Visualizer(rawValue: defaults.string(forKey: Keys.fleetCharacter) ?? "") ?? .rex
        animate = defaults.object(forKey: Keys.animate) as? Bool ?? true
        showFleetReadout = defaults.object(forKey: Keys.showFleetReadout) as? Bool ?? true
        launchAtLogin = SMAppService.mainApp.status == .enabled
    }

    func setLaunchAtLogin(_ enabled: Bool) {
        guard !Demo.isActive else { return }
        do {
            if enabled {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
        } catch {
            // Reported by the status below; the toggle snaps back.
        }
        launchAtLogin = SMAppService.mainApp.status == .enabled
    }

    /// The first time a server is added, the app starts at login unless the
    /// user turned that off in the setup window: a monitor that stops
    /// watching after a reboot is not doing its job.
    func applyFirstRunLoginChoice(_ enabled: Bool) {
        guard !defaults.bool(forKey: Keys.askedAboutLogin) else { return }
        defaults.set(true, forKey: Keys.askedAboutLogin)
        if enabled != launchAtLogin { setLaunchAtLogin(enabled) }
    }

    var hasAskedAboutLogin: Bool { defaults.bool(forKey: Keys.askedAboutLogin) }
}
