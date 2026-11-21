// SPDX-License-Identifier: AGPL-3.0-only

import Foundation

/// Runs cbb for what changes the group. cbb runs as the user, and the
/// service has macOS confirm the action with its own prompt, Touch ID or
/// the password, once for five minutes or each time for what cannot be
/// undone (docs/design.md, "Confirming admin actions"). What needs root
/// itself (installing an update, joining a group, whose files cbb writes),
/// and anything the service cannot confirm, runs cbb as the administrator,
/// with macOS's password prompt, as sudo cbb does in Terminal.
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

    /// cbb's exit codes: the user cancelled the prompt; nothing here
    /// confirms the action for this user, so it takes the administrator
    /// (member/src/confirm.rs).
    static let cancelledExit: Int32 = 75
    static let needsAdminExit: Int32 = 77

    /// Whether cbb itself must run as root for the arguments: installing an
    /// update, and joining a group, where cbb writes the service's files.
    static func needsRoot(_ arguments: [String]) -> Bool {
        arguments.first == "update" || (arguments.first == "pair" && arguments.contains("-app"))
    }

    /// Runs cbb with the arguments, typing yes when a question follows
    /// (cbb global on), or with input as its standard input, and returns
    /// what it printed: as the user, with macOS's confirmation, or as the
    /// administrator where it needs root or the service cannot confirm.
    static func run(_ arguments: [String], answer yes: Bool = false, input: String? = nil, details: Bool) async throws -> String {
        guard let cbb = command else { throw Failure.noCommand }
        if !needsRoot(arguments) {
            let stdin = input ?? (yes ? "yes\n" : nil)
            switch try await runAsUser(cbb, arguments, input: stdin, details: details) {
            case .done(let printed): return printed
            case .needsAdmin: break
            }
        }
        return try await runAsAdmin(cbb, arguments, answer: yes, input: input, details: details)
    }

    enum UserRun: Equatable {
        case done(String)
        case needsAdmin
    }

    /// Runs cbb as the user, which reaches the service's control socket;
    /// the service asks macOS to confirm the action.
    static func runAsUser(_ cbb: String, _ arguments: [String], input: String?, details: Bool) async throws -> UserRun {
        try await withCheckedThrowingContinuation { done in
            let p = Process()
            p.executableURL = URL(fileURLWithPath: cbb)
            p.arguments = arguments
            var env = ProcessInfo.processInfo.environment
            env["CBB_DEBUG"] = details ? "1" : "0"
            p.environment = env
            let out = Pipe(), err = Pipe(), inp = Pipe()
            p.standardOutput = out
            p.standardError = err
            p.standardInput = inp
            p.terminationHandler = { p in
                let printed = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
                let failed = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
                done.resume(with: Result { try userResult(p.terminationStatus, printed: printed, stderr: failed) })
            }
            do {
                try p.run()
                if let input { inp.fileHandleForWriting.write(Data(input.utf8)) }
                try? inp.fileHandleForWriting.close()
            } catch {
                done.resume(throwing: Failure.failed("cbb did not start", detail: String(describing: error)))
            }
        }
    }

    /// What a run of cbb as the user ended with.
    static func userResult(_ status: Int32, printed: String, stderr: String) throws -> UserRun {
        switch status {
        case 0: return .done(printed.trimmingCharacters(in: .whitespacesAndNewlines))
        case cancelledExit: throw Failure.cancelled
        case needsAdminExit: return .needsAdmin
        default:
            let text = stderr.trimmingCharacters(in: .whitespacesAndNewlines)
            var message = text.components(separatedBy: "\n").first ?? text
            if message.hasPrefix("cbb: ") { message.removeFirst(5) }
            throw Failure.failed(message, detail: text.isEmpty ? "cbb exited with \(status)" : text)
        }
    }

    /// Runs cbb as the administrator, through macOS's password prompt. The
    /// input goes through a file only the user reads, never on a command
    /// line, which every program may see.
    static func runAsAdmin(_ cbb: String, _ arguments: [String], answer yes: Bool, input: String?, details: Bool) async throws -> String {
        var inputFile: URL?
        if let input {
            let file = FileManager.default.temporaryDirectory.appendingPathComponent("cbb-input-\(UUID().uuidString).txt")
            guard FileManager.default.createFile(atPath: file.path, contents: Data(input.utf8), attributes: [.posixPermissions: 0o600]) else {
                throw Failure.failed(String(localized: "The app could not make the file for cbb."), detail: file.path)
            }
            inputFile = file
        }
        defer { if let inputFile { try? FileManager.default.removeItem(at: inputFile) } }
        let script = appleScript(shell: shellCommand(cbb, arguments, answer: yes, input: inputFile?.path, details: details))
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
    static func shellCommand(_ cbb: String, _ arguments: [String], answer yes: Bool, input: String? = nil, details: Bool) -> String {
        let line = ([cbb] + arguments).map(quoted).joined(separator: " ")
        let env = details ? "CBB_DEBUG=1 " : ""
        return (yes ? "echo yes | " : "") + env + line + (input.map { " < " + quoted($0) } ?? "")
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
