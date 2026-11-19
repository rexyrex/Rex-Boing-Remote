import Foundation

/// A JSON document as a value: what the MCP layer passes between stdio, the
/// app's message port, tool arguments, schemas and results.
///
/// `[String: Any]` can't cross threads under strict concurrency and loses
/// the difference between `1` and `true` (both are `NSNumber`). An enum
/// keeps both, and its literals keep the tool schemas readable.
enum JSONValue: Sendable, Hashable {
    case null
    case bool(Bool)
    case int(Int)
    case double(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])

    subscript(key: String) -> JSONValue? {
        if case .object(let object) = self { return object[key] }
        return nil
    }

    var stringValue: String? {
        if case .string(let value) = self { return value }
        return nil
    }

    var boolValue: Bool? {
        if case .bool(let value) = self { return value }
        return nil
    }

    /// Integers, and doubles with no fractional part: a client may send
    /// `5.0` for an integer argument.
    var intValue: Int? {
        switch self {
        case .int(let value): return value
        case .double(let value) where value.rounded() == value && abs(value) < 1e15: return Int(value)
        default: return nil
        }
    }

    var doubleValue: Double? {
        switch self {
        case .int(let value): return Double(value)
        case .double(let value): return value
        default: return nil
        }
    }

    var arrayValue: [JSONValue]? {
        if case .array(let value) = self { return value }
        return nil
    }

    var objectValue: [String: JSONValue]? {
        if case .object(let value) = self { return value }
        return nil
    }
}

extension JSONValue: ExpressibleByNilLiteral, ExpressibleByBooleanLiteral, ExpressibleByIntegerLiteral,
    ExpressibleByFloatLiteral, ExpressibleByStringLiteral, ExpressibleByArrayLiteral,
    ExpressibleByDictionaryLiteral {
    init(nilLiteral: ()) { self = .null }
    init(booleanLiteral value: Bool) { self = .bool(value) }
    init(integerLiteral value: Int) { self = .int(value) }
    init(floatLiteral value: Double) { self = .double(value) }
    init(stringLiteral value: String) { self = .string(value) }
    init(arrayLiteral elements: JSONValue...) { self = .array(elements) }
    init(dictionaryLiteral elements: (String, JSONValue)...) {
        self = .object(Dictionary(elements, uniquingKeysWith: { _, last in last }))
    }
}

// MARK: - Parsing and serialization

extension JSONValue {
    struct ParseError: Error {}

    static func parse(_ data: Data) throws -> JSONValue {
        guard let object = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) else {
            throw ParseError()
        }
        return JSONValue(foundation: object)
    }

    static func parse(_ text: String) throws -> JSONValue {
        try parse(Data(text.utf8))
    }

    private init(foundation object: Any) {
        switch object {
        case is NSNull:
            self = .null
        case let number as NSNumber:
            // CFBoolean is the only NSNumber whose type is the boolean's;
            // `as? Bool` would also accept 0 and 1.
            if CFGetTypeID(number) == CFBooleanGetTypeID() {
                self = .bool(number.boolValue)
            } else if CFNumberIsFloatType(number) {
                self = .double(number.doubleValue)
            } else {
                self = .int(number.intValue)
            }
        case let string as String:
            self = .string(string)
        case let array as [Any]:
            self = .array(array.map(JSONValue.init(foundation:)))
        case let dictionary as [String: Any]:
            self = .object(dictionary.mapValues(JSONValue.init(foundation:)))
        default:
            self = .string(String(describing: object))
        }
    }

    /// Compact, single-line UTF-8, keys sorted so output is stable for checks
    /// and diffs. Newlines inside strings are escaped, so a message is always
    /// one line, as stdio framing needs. A number that is not finite is
    /// written as null; the payload builders leave such readings out before
    /// they get here.
    func serialized() -> Data { Data(serializedString().utf8) }

    func serializedString(pretty: Bool = false) -> String {
        var output = ""
        write(into: &output, pretty: pretty, indent: 0)
        return output
    }

    private func write(into output: inout String, pretty: Bool, indent: Int) {
        switch self {
        case .null:
            output += "null"
        case .bool(let value):
            output += value ? "true" : "false"
        case .int(let value):
            output += String(value)
        case .double(let value):
            if !value.isFinite {
                output += "null"
            } else if value.rounded() == value, abs(value) < 1e15 {
                output += String(Int(value))
            } else {
                output += String(value)
            }
        case .string(let value):
            Self.writeString(value, into: &output)
        case .array(let values):
            guard !values.isEmpty else { output += "[]"; return }
            output += "["
            for (index, value) in values.enumerated() {
                if index > 0 { output += "," }
                if pretty { output += "\n" + String(repeating: "  ", count: indent + 1) }
                value.write(into: &output, pretty: pretty, indent: indent + 1)
            }
            if pretty { output += "\n" + String(repeating: "  ", count: indent) }
            output += "]"
        case .object(let object):
            guard !object.isEmpty else { output += "{}"; return }
            output += "{"
            for (index, key) in object.keys.sorted().enumerated() {
                if index > 0 { output += "," }
                if pretty { output += "\n" + String(repeating: "  ", count: indent + 1) }
                Self.writeString(key, into: &output)
                output += pretty ? ": " : ":"
                object[key]!.write(into: &output, pretty: pretty, indent: indent + 1)
            }
            if pretty { output += "\n" + String(repeating: "  ", count: indent) }
            output += "}"
        }
    }

    private static func writeString(_ value: String, into output: inout String) {
        output += "\""
        // Most strings need no escaping and are appended whole.
        guard value.utf8.contains(where: { $0 < 0x20 || $0 == 0x22 || $0 == 0x5C || $0 == 0xE2 }) else {
            output += value
            output += "\""
            return
        }
        for scalar in value.unicodeScalars {
            switch scalar {
            case "\"": output += "\\\""
            case "\\": output += "\\\\"
            case "\n": output += "\\n"
            case "\r": output += "\\r"
            case "\t": output += "\\t"
            case _ where scalar.value < 0x20 || scalar.value == 0x2028 || scalar.value == 0x2029:
                output += String(format: "\\u%04x", scalar.value)
            default:
                output.unicodeScalars.append(scalar)
            }
        }
        output += "\""
    }
}

/// Builds a JSON object from readings that may be missing. Every `put` leaves
/// the key out when the value is nil or not a finite number: a reading a
/// server cannot report is left out, never sent as 0 (CONTRIBUTING.md,
/// "Missing is not zero").
struct JSONObject {
    private(set) var fields: [String: JSONValue] = [:]

    init() {}

    var isEmpty: Bool { fields.isEmpty }
    var value: JSONValue { .object(fields) }

    subscript(key: String) -> JSONValue? {
        get { fields[key] }
        set { fields[key] = newValue }
    }

    /// An empty string says nothing, and is left out like a missing one.
    mutating func put(_ key: String, _ value: String?) {
        guard let value, !value.isEmpty else { return }
        fields[key] = .string(value)
    }

    mutating func put(_ key: String, _ value: Bool?) {
        guard let value else { return }
        fields[key] = .bool(value)
    }

    mutating func put(_ key: String, _ value: Int?) {
        guard let value else { return }
        fields[key] = .int(value)
    }

    mutating func put(_ key: String, _ value: Int32?) {
        guard let value else { return }
        fields[key] = .int(Int(value))
    }

    mutating func put(_ key: String, _ value: UInt64?) {
        guard let value else { return }
        fields[key] = .int(Int(clamping: value))
    }

    /// A double, rounded to `decimals` places.
    mutating func put(_ key: String, _ value: Double?, decimals: Int) {
        guard let value, value.isFinite else { return }
        fields[key] = .double(JSONObject.round(value, decimals))
    }

    /// A fraction (0 to 1) as a percent (0 to 100), to a tenth.
    mutating func putPercent(_ key: String, fraction: Double?) {
        guard let fraction, fraction.isFinite else { return }
        fields[key] = .double(JSONObject.round(fraction * 100, 1))
    }

    mutating func put(_ key: String, _ date: Date?) {
        guard let date else { return }
        fields[key] = .string(MCPTime.format(date))
    }

    mutating func put(_ key: String, object: JSONObject) {
        guard !object.isEmpty else { return }
        fields[key] = object.value
    }

    mutating func put(_ key: String, array: [JSONValue]) {
        fields[key] = .array(array)
    }

    static func round(_ value: Double, _ decimals: Int) -> Double {
        let scale = pow(10, Double(decimals))
        return (value * scale).rounded() / scale
    }
}
