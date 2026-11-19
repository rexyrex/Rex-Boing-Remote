import AppKit

// Checks how the update check reads GitHub's answer and compares versions,
// without asking GitHub anything.
//
//   swiftc -O -o /tmp/update-check Tools/update-check.swift RexBoingRemote/App/UpdateCheck.swift
//   /tmp/update-check
//
// The notice is only as good as two small pieces of logic: deciding that
// 1.10.0 is newer than 1.9.2 (a string comparison says otherwise) and reading
// a release out of the API's JSON while refusing drafts, pre-releases, tags
// that are not versions, and release pages anywhere but github.com.
@main
enum UpdateCheckCheck {
    static func main() {
        var failures = 0
        func expect(_ condition: Bool, _ message: String) {
            if !condition {
                failures += 1
                print("FAIL: \(message)")
            }
        }

        // Versions.
        let newer: [(String, String)] = [
            ("1.3.1", "1.3.0"), ("1.4", "1.3.9"), ("v1.4.0", "1.3.0"), ("1.10.0", "1.9.2"),
            ("2", "1.99.99"), ("1.3.0.1", "1.3.0"), ("V1.4.0", "v1.3.0"),
        ]
        for (a, b) in newer {
            expect(AppVersion.isNewer(a, than: b), "\(a) should be newer than \(b)")
            expect(!AppVersion.isNewer(b, than: a), "\(b) should not be newer than \(a)")
        }
        let same: [(String, String)] = [("1.3.0", "1.3.0"), ("v1.3.0", "1.3.0"), ("1.3", "1.3.0"), ("1.4.0-beta", "1.4.0")]
        for (a, b) in same {
            expect(!AppVersion.isNewer(a, than: b) && !AppVersion.isNewer(b, than: a), "\(a) and \(b) should be equal")
        }
        for junk in ["", "latest", "release-1", "vv1.4"] {
            expect(AppVersion.normalized(junk) == nil, "\"\(junk)\" is not a version")
            expect(!AppVersion.isNewer(junk, than: "1.0"), "\"\(junk)\" must never count as newer")
        }
        expect(AppVersion.normalized(" v1.4.0\n") == "1.4.0", "tags are trimmed and lose their v")

        // GitHub's answer.
        let fallback = URL(string: "https://github.com/rexyrex/Rex-Boing-Remote/releases/latest")!
        func release(_ json: String) -> AppRelease? {
            AppRelease.decode(Data(json.utf8), fallbackPage: fallback)
        }
        let page = "https://github.com/rexyrex/Rex-Boing-Remote/releases/tag/v1.4.0"
        let full = release("""
            {"tag_name": "v1.4.0", "name": "Rex Boing 1.4.0", "html_url": "\(page)",
             "draft": false, "prerelease": false, "assets": [{"name": "Rex.Boing.zip"}]}
            """)
        expect(full == AppRelease(version: "1.4.0", page: URL(string: page)!), "a published release reads: \(String(describing: full))")
        expect(release(#"{"tag_name": "1.4.0"}"#)?.page == fallback, "a missing page falls back to the releases page")
        expect(release(#"{"tag_name": "v1.4.0", "html_url": "https://evil.example/r"}"#)?.page == fallback,
               "a page off github.com is never opened")
        expect(release(#"{"tag_name": "v1.4.0", "html_url": "http://github.com/r"}"#)?.page == fallback,
               "a page over plain HTTP is never opened")
        expect(release(#"{"tag_name": "v1.5.0", "draft": true}"#) == nil, "a draft is not a release")
        expect(release(#"{"tag_name": "v1.5.0", "prerelease": true}"#) == nil, "a pre-release is not a release")
        expect(release(#"{"tag_name": "nightly"}"#) == nil, "a tag that is not a version is ignored")
        expect(release(#"{"message": "Not Found"}"#) == nil, "an error body is not a release")
        expect(release(#"{"message": "API rate limit exceeded"}"#) == nil, "a rate-limit body is not a release")
        expect(release("not json") == nil, "garbage is not a release")
        expect(AppRelease.trustedPage("https://github.com/rexyrex/Rex-Boing-Remote/releases") != nil, "github.com over HTTPS is trusted")
        expect(AppRelease.trustedPage("https://github.com.evil.example/") == nil, "a look-alike host is not trusted")

        if failures == 0 {
            print("PASS")
        } else {
            print("\(failures) failure(s)")
            exit(1)
        }
    }
}
