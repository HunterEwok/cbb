// SPDX-License-Identifier: AGPL-3.0-only

import Foundation

/// Runs cbb as the administrator: what changes the group goes only through
/// the service's admin socket, which only root may reach, so macOS asks for
/// the password first, as sudo cbb does in Terminal.
enum Admin {
    enum Failure: Error, Equatable {
        /// cbb is not where the installer or Homebrew puts it.
        case noCommand
        /// The user closed the password prompt.
        case cancelled
        /// cbb failed: what it said, and the prompt's own words.
        case failed(String, detail: String)
    }

    /// Where the installer (packaging/macos) or Homebrew put cbb.
    static var command: String? {
        ["/usr/local/bin/cbb", "/opt/homebrew/bin/cbb"].first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    /// Runs cbb with the arguments, typing yes when a question follows
    /// (cbb global on), and returns what it printed.
    static func run(_ arguments: [String], answer yes: Bool = false, details: Bool) async throws -> String {
        guard let cbb = command else { throw Failure.noCommand }
        let script = appleScript(shell: shellCommand(cbb, arguments, answer: yes, details: details))
        return try await withCheckedThrowingContinuation { done in
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            p.arguments = ["-e", script]
            let out = Pipe(), err = Pipe()
            p.standardOutput = out
            p.standardError = err
            p.terminationHandler = { p in
                let printed = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
                let failed = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
                if p.terminationStatus == 0 {
                    done.resume(returning: printed.trimmingCharacters(in: .whitespacesAndNewlines))
                } else {
                    done.resume(throwing: failure(failed))
                }
            }
            do {
                try p.run()
            } catch {
                done.resume(throwing: Failure.failed("osascript did not start", detail: String(describing: error)))
            }
        }
    }

    /// The shell command line, every argument quoted; CBB_DEBUG makes cbb
    /// name the error underneath, as the app does with error details on.
    static func shellCommand(_ cbb: String, _ arguments: [String], answer yes: Bool, details: Bool) -> String {
        let line = ([cbb] + arguments).map(quoted).joined(separator: " ")
        let env = details ? "CBB_DEBUG=1 " : ""
        return (yes ? "echo yes | " : "") + env + line
    }

    /// The shell's single quotes around a word.
    static func quoted(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    static func appleScript(shell: String) -> String {
        let literal = shell.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        return "do shell script \"\(literal)\" with administrator privileges"
    }

    /// osascript's error, as "0:44: execution error: cbb: … (1)": cbb's own
    /// words for the user, or a cancelled prompt (-128).
    static func failure(_ stderr: String) -> Failure {
        let text = stderr.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.hasSuffix("(-128)") { return .cancelled }
        var message = text
        if let r = message.range(of: "execution error: ") { message = String(message[r.upperBound...]) }
        if let r = message.range(of: #" \(-?\d+\)$"#, options: .regularExpression) { message.removeSubrange(r) }
        if message.hasPrefix("cbb: ") { message.removeFirst(5) }
        return .failed(message, detail: text)
    }
}
