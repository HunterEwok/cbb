// SPDX-License-Identifier: AGPL-3.0-only

import ServiceManagement
import SwiftUI

/// The Mac app: a menu bar item and a window over the cbb service, which
/// syncs the clipboard by itself (docs/apps.md, The Mac app). Like the tray
/// app on Windows and Linux it lives in the menu bar: no Dock icon
/// (LSUIElement), no window at launch, and it starts at login.
@main
struct ClipboardBridgeMacApp: App {
    @NSApplicationDelegateAdaptor(LaunchDelegate.self) private var launch
    @StateObject private var model = MacModel()

    var body: some Scene {
        Window(Text("Clipboard Bridge"), id: "main") {
            MainView().environmentObject(model).modifier(Themed())
        }
        .defaultSize(width: 920, height: 620)

        MenuBarExtra {
            MenuContent().environmentObject(model)
        } label: {
            // The label is drawn at launch, the menu only when it opens.
            Image(model.trayImage).onAppear { model.start() }
        }

        Settings {
            SettingsView().environmentObject(model).modifier(Themed())
        }
    }
}

/// Keeps the window closed at launch, which SwiftUI opens for the first
/// scene, and makes the app a login item the first time it runs.
final class LaunchDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        DispatchQueue.main.async {
            for w in NSApp.windows where w.identifier?.rawValue.hasPrefix("main") == true {
                w.close()
            }
        }
        LoginItem.registerOnce()
    }
}

/// The app as a login item (SMAppService), on by default; Settings turns
/// it off and on.
enum LoginItem {
    static let askedKey = "LoginItemSet"

    static var isOn: Bool { SMAppService.mainApp.status == .enabled }

    /// Registers the app once, on its first run; later the user's choice
    /// in Settings, or in System Settings, Login Items, stands.
    static func registerOnce() {
        guard !UserDefaults.standard.bool(forKey: askedKey) else { return }
        UserDefaults.standard.set(true, forKey: askedKey)
        set(true)
    }

    /// Turns the login item on or off; nil when it worked, else why not.
    @discardableResult
    static func set(_ on: Bool) -> String? {
        do {
            if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
            return nil
        } catch {
            return error.localizedDescription
        }
    }
}
