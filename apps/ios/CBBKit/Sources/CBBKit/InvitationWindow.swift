// SPDX-License-Identifier: AGPL-3.0-only

#if canImport(Network)
import Foundation
import Network
import Security

/// The pairing window of a remote invitation on the phone that is the
/// group's hub (docs/protocol.md, section 12): it listens on the loopback
/// address, where cbbtun's hub joins the connections of the invitation's
/// guest tunnel, and runs each attempt with admit, one at a time. It admits
/// one device once, until expires, and ends after three failed attempts;
/// onEnd gets the admitted device, or why it ended without one.
public final class InvitationWindow: @unchecked Sendable {
    /// Why the window ended without a device.
    public enum Ended: Error, Equatable {
        case expired, tooManyAttempts, cancelled
    }

    /// Failed attempts after which the window ends.
    public static let maxFailures = 3

    public typealias Admit = @Sendable (TLSTransport, Data, [UInt8]) async throws -> PairingMember.Admitted

    private let listener: TLSListener
    private let expires: Date
    private let admit: Admit
    private let onEnd: @Sendable (Result<PairingMember.Admitted, Error>) -> Void
    private let onError: @Sendable (Error) -> Void
    private let lock = NSLock()
    private var busy = false
    private var failures = 0
    private var ended = false
    private var current: TLSTransport?
    private var tasks: [Task<Void, Never>] = []

    /// identity is the phone's member identity; admit runs the exchange
    /// (PhoneGroup.admit with the invitation) over the connection, with
    /// the joiner's certificate and the session ID; onError gets why an
    /// attempt failed, for the log.
    public init(identity: SecIdentity, expires: Date, admit: @escaping Admit,
                onEnd: @escaping @Sendable (Result<PairingMember.Admitted, Error>) -> Void,
                onError: @escaping @Sendable (Error) -> Void = { _ in }) throws {
        (self.expires, self.admit, self.onEnd, self.onError) = (expires, admit, onEnd, onError)
        listener = try TLSListener(alpn: Pairing.alpn, identity: identity, loopback: true) { !$0.isEmpty }
    }

    /// Starts listening and returns the port, which cbbtun's Hub.Invite
    /// takes.
    public func start() async throws -> UInt16 {
        let port = try await listener.start()
        let wait = expires.timeIntervalSinceNow
        let expiry = Task { [weak self] in
            if wait > 0 { try? await Task.sleep(for: .seconds(wait)) }
            guard !Task.isCancelled else { return }
            self?.end(.failure(Ended.expired))
        }
        let accepting = Task { [weak self, listener] in
            while let t = await listener.next() {
                Task { await self?.attempt(t) }
            }
        }
        lock.withLock { tasks = [expiry, accepting] }
        return port
    }

    private func attempt(_ t: TLSTransport) async {
        do {
            try await t.start()
        } catch {
            t.close()
            return onError(error)
        }
        guard let joiner = t.peerCertificate, let sid = t.exportKeyingMaterial(label: Pairing.exporterLabel, length: 32) else {
            return t.close()
        }
        let free = lock.withLock {
            guard !ended, !busy else { return false }
            (busy, current) = (true, t)
            return true
        }
        guard free else {
            // Read the device's first message before answering, as a
            // computer's window does.
            _ = try? await t.readFrame()
            try? await t.writeFrame(Pairing.Frame(error: Pairing.ErrorCode.busy.rawValue))
            return t.close()
        }
        do {
            let admitted = try await admit(t, joiner, sid)
            t.close()
            end(.success(admitted))
        } catch {
            t.close()
            onError(error)
            let tooMany = lock.withLock {
                (busy, current) = (false, nil)
                failures += 1
                return failures >= Self.maxFailures
            }
            if tooMany { end(.failure(Ended.tooManyAttempts)) }
        }
    }

    private func end(_ result: Result<PairingMember.Admitted, Error>) {
        let ending: (TLSTransport?, [Task<Void, Never>])? = lock.withLock {
            guard !ended else { return nil }
            ended = true
            defer { (current, self.tasks) = (nil, []) }
            return (current, self.tasks)
        }
        guard let (t, tasks) = ending else { return }
        listener.stop()
        tasks.forEach { $0.cancel() }
        // An attempt still waiting for the admin ends with the window.
        if case .failure = result { t?.close() }
        onEnd(result)
    }

    /// Closes the window, as the admin cancelling the invitation.
    public func close() { end(.failure(Ended.cancelled)) }
}
#endif
