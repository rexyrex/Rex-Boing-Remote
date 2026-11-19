import Foundation

/// Times as the MCP tools write and read them. Out: ISO 8601 with this Mac's
/// UTC offset, so an agent reading "03:00" sees the user's 3 a.m. In: the
/// simple forms people and agents type, the same family `rex-boing-agent
/// history` takes on the server.
enum MCPTime {
    nonisolated(unsafe) private static let writer: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter
    }()
    private static let lock = NSLock()

    static func format(_ date: Date) -> String {
        lock.lock()
        defer { lock.unlock() }
        // Set every time rather than once: the Mac may have moved time zone
        // since the formatter was made.
        writer.timeZone = TimeZone.current
        return writer.string(from: date)
    }

    static func format(ms: Int64) -> String {
        format(Date(timeIntervalSince1970: Double(ms) / 1000))
    }

    /// What `parseMoment` accepts, for error messages and tool descriptions.
    static let acceptedForms = "\"now\"; how long ago, such as 90s, 15m, 6h, 2d or 1h30m; "
        + "a time of day such as 03:00 (today's, or yesterday's if it is still to come); "
        + "or ISO 8601 such as 2026-11-17T03:00:00+09:00 (without an offset, this Mac's time zone)"

    /// A moment: `now`, a duration ago, a time of day, or ISO 8601. Nil for
    /// anything else.
    static func parseMoment(_ text: String, now: Date = Date()) -> Date? {
        var text = text.trimmingCharacters(in: .whitespaces).lowercased()
        if text == "now" { return now }
        if text.hasSuffix(" ago") { text = String(text.dropLast(4)).trimmingCharacters(in: .whitespaces) }
        if let seconds = parseDuration(text) { return now.addingTimeInterval(-seconds) }
        if let date = parseTimeOfDay(text, now: now) { return date }
        return parseISO(text)
    }

    /// `90s`, `15m`, `6h`, `2d`, `1w`, `1h30m`: seconds. Nil otherwise.
    static func parseDuration(_ text: String) -> TimeInterval? {
        let units: [Character: Double] = ["s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604_800]
        var total = 0.0
        var digits = ""
        var sawUnit = false
        for character in text {
            if character.isASCII, character.isNumber {
                digits.append(character)
            } else if let unit = units[character], let value = Double(digits) {
                total += value * unit
                digits = ""
                sawUnit = true
            } else {
                return nil
            }
        }
        guard sawUnit, digits.isEmpty, total.isFinite, total <= 400 * 86400 else { return nil }
        return total
    }

    /// `03:00`, `3:00`, `03:00:30`: the latest such moment that isn't in
    /// the future.
    private static func parseTimeOfDay(_ text: String, now: Date) -> Date? {
        let parts = text.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 2 || parts.count == 3,
              parts.allSatisfy({ !$0.isEmpty && $0.count <= 2 && $0.allSatisfy(\.isNumber) }),
              let hour = Int(parts[0]), let minute = Int(parts[1]), hour < 24, minute < 60 else { return nil }
        let second = parts.count == 3 ? Int(parts[2]) ?? 60 : 0
        guard second < 60 else { return nil }
        let calendar = Calendar.current
        guard let today = calendar.date(bySettingHour: hour, minute: minute, second: second, of: now) else { return nil }
        return today <= now ? today : calendar.date(byAdding: .day, value: -1, to: today)
    }

    private static func parseISO(_ text: String) -> Date? {
        let upper = text.uppercased()
        let withOffset = ISO8601DateFormatter()
        withOffset.formatOptions = [.withInternetDateTime]
        if let date = withOffset.date(from: upper) { return date }
        withOffset.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = withOffset.date(from: upper) { return date }
        // Without an offset: this Mac's time zone, as a person means it.
        let local = DateFormatter()
        local.locale = Locale(identifier: "en_US_POSIX")
        local.timeZone = TimeZone.current
        for format in ["yyyy-MM-dd'T'HH:mm:ss", "yyyy-MM-dd'T'HH:mm", "yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd HH:mm", "yyyy-MM-dd"] {
            local.dateFormat = format
            if let date = local.date(from: upper) { return date }
        }
        return nil
    }
}
