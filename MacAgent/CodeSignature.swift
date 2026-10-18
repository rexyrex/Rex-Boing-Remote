import Foundation
import Security

/// Who signed a program, for `upgrade`.
///
/// The restricted key can ask for an upgrade, and the SHA-256 that comes
/// with it only proves the bytes arrived as sent: whoever holds the app's
/// key chooses them. So an agent signed by a team takes only a new binary
/// signed by that same team, and a stolen key can't put a program of its
/// own in its place. An agent built from source (ad-hoc signed, no team)
/// has nothing to compare with and takes any binary, as before.
enum CodeSignature {
    /// The Team ID the running program was signed with, or nil for an
    /// ad-hoc or unsigned build.
    static func ownTeamID() -> String? {
        var code: SecCode?
        guard SecCodeCopySelf(SecCSFlags(), &code) == errSecSuccess, let code else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, SecCSFlags(), &staticCode) == errSecSuccess, let staticCode else { return nil }
        return teamID(of: staticCode)
    }

    /// The Team ID a program on disk was signed with, or nil.
    static func teamID(path: String) -> String? {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, SecCSFlags(), &code) == errSecSuccess,
              let code else { return nil }
        return teamID(of: code)
    }

    private static func teamID(of code: SecStaticCode) -> String? {
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let information = information as? [String: Any] else { return nil }
        return information[kSecCodeInfoTeamIdentifier as String] as? String
    }

    /// Nil when the program at `path` carries a valid signature, in every
    /// architecture it has, from a certificate Apple issued to `teamID`;
    /// otherwise why not, in a sentence.
    static func problem(path: String, teamID: String) -> String? {
        // A Team ID is ten letters and digits; anything else can't be put
        // into a requirement safely, and can't be one.
        guard !teamID.isEmpty, teamID.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber) }) else {
            return "This agent's own signature can't be read."
        }
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, SecCSFlags(), &code) == errSecSuccess,
              let code else {
            return "The new agent isn't a program macOS can check."
        }
        var requirement: SecRequirement?
        let text = "anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\""
        guard SecRequirementCreateWithString(text as CFString, SecCSFlags(), &requirement) == errSecSuccess,
              let requirement else {
            return "This agent's own signature can't be read."
        }
        let status = SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSCheckAllArchitectures), requirement)
        guard status == errSecSuccess else {
            return "The new agent isn't signed by the same developer as this one (team \(teamID)), so it was not installed. "
                + "To change to another build, install it with your own SSH access: Repair in Rex Boing Remote, "
                + "or the install command on this Mac."
        }
        return nil
    }
}
