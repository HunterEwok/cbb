// SPDX-License-Identifier: AGPL-3.0-only

import ClipboardBridgeKit
import CoreNFC
import Foundation

/// A YubiKey held to the iPhone, over Core NFC: withCard shows the system's
/// NFC sheet with prompt, and runs the kit's PIV commands (Piv) on the card
/// once it is there. The card's NFC tap is the touch its key asks for.
/// Core NFC needs its entitlement, which the Apple developer account gives:
/// a build signed ad hoc has no NFC.
final class YubiKeyNfc: NSObject, NFCTagReaderSessionDelegate, @unchecked Sendable {
    enum Failure: Error {
        /// The phone has no NFC reader, or the build lacks its entitlement.
        case unavailable
        /// No YubiKey came to the phone before the sheet timed out.
        case noCard
    }

    /// The PIV commands run here, not on the session's queue, whose
    /// callbacks answer them.
    private let work = DispatchQueue(label: "tools.cbb.yubikey")
    private let queue = DispatchQueue(label: "tools.cbb.nfc")
    private let lock = NSLock()
    private var finish: ((Result<Any, Error>) -> Void)?
    private let block: (SmartCard) throws -> Any
    private let done: String
    private var session: NFCTagReaderSession?

    private init(done: String, block: @escaping (SmartCard) throws -> Any) {
        (self.done, self.block) = (done, block)
    }

    static var available: Bool { NFCTagReaderSession.readingAvailable }

    /// Waits for a YubiKey with the system's sheet saying prompt, runs
    /// block on it while it stays, and closes the sheet with done.
    static func withCard<T>(prompt: String, done: String, _ block: @escaping (SmartCard) throws -> T) async throws -> T {
        guard available else { throw Failure.unavailable }
        try Task.checkCancellation()
        let reader = YubiKeyNfc(done: done) { try block($0) }
        let any: Any = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (c: CheckedContinuation<Any, Error>) in
                reader.lock.withLock { reader.finish = { c.resume(with: $0) } }
                guard let s = NFCTagReaderSession(pollingOption: [.iso14443], delegate: reader, queue: reader.queue) else {
                    reader.end(.failure(Failure.unavailable))
                    return
                }
                reader.session = s
                s.alertMessage = prompt
                s.begin()
            }
        } onCancel: {
            reader.session?.invalidate()
        }
        guard let t = any as? T else { throw Piv.Failure(kind: .card, message: "the YubiKey's answer has the wrong type") }
        return t
    }

    private func end(_ r: Result<Any, Error>) {
        let f: ((Result<Any, Error>) -> Void)? = lock.withLock {
            defer { finish = nil }
            return finish
        }
        f?(r)
    }

    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {}

    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        // The user closed the sheet, or it timed out: unless the work ended first.
        if let e = error as? NFCReaderError, e.code == .readerSessionInvalidationErrorUserCanceled {
            end(.failure(CancellationError()))
        } else if let e = error as? NFCReaderError, e.code == .readerSessionInvalidationErrorSessionTimeout {
            end(.failure(Failure.noCard))
        } else {
            end(.failure(error))
        }
    }

    func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard let first = tags.first, case let .iso7816(tag) = first else {
            session.alertMessage = String(localized: "This is not a YubiKey. Hold the YubiKey to the phone.", bundle: .app)
            session.restartPolling()
            return
        }
        session.connect(to: first) { [self] error in
            if let error {
                session.invalidate(errorMessage: String(localized: "The YubiKey left too soon.", bundle: .app))
                end(.failure(Piv.Failure(kind: .card, message: String(describing: error))))
                return
            }
            work.async { [self] in
                do {
                    let out = try block(Card(tag: tag))
                    session.alertMessage = done
                    session.invalidate()
                    end(.success(out))
                } catch {
                    session.invalidate(errorMessage: String(localized: "Stopped. The app says why.", bundle: .app))
                    end(.failure(error))
                }
            }
        }
    }

    /// The tag as the kit's SmartCard: each command waits for its answer.
    private final class Card: SmartCard {
        let tag: NFCISO7816Tag
        init(tag: NFCISO7816Tag) { self.tag = tag }

        func transmit(_ apdu: Data) throws -> Data {
            guard let command = NFCISO7816APDU(data: apdu) else { throw Piv.Failure(kind: .card, message: "a command the reader does not take") }
            let wait = DispatchSemaphore(value: 0)
            var out: Result<Data, Error> = .failure(Piv.Failure(kind: .card, message: "the YubiKey did not answer"))
            tag.sendCommand(apdu: command) { data, sw1, sw2, error in
                if let error {
                    // The card left, most often: Piv's .card says to hold it still.
                    out = .failure(Piv.Failure(kind: .card, message: String(describing: error)))
                } else {
                    out = .success(data + Data([sw1, sw2]))
                }
                wait.signal()
            }
            guard wait.wait(timeout: .now() + 10) == .success else { throw Piv.Failure(kind: .card, message: "the YubiKey did not answer in time") }
            return try out.get()
        }
    }
}
