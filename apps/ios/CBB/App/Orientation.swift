// SPDX-License-Identifier: AGPL-3.0-only

import UIKit

/// Keeps a phone's screen upright and lets a big one turn: an iPad, and the
/// inner screen of a foldable iPhone, where the system moves the toolbar to
/// the strip at the right edge in landscape.
final class AppDelegate: NSObject, UIApplicationDelegate {
    func application(_ application: UIApplication, supportedInterfaceOrientationsFor window: UIWindow?) -> UIInterfaceOrientationMask {
        guard let window else { return .portrait }
        return Self.mask(idiom: UIDevice.current.userInterfaceIdiom, regular: window.traitCollection.horizontalSizeClass == .regular)
    }

    /// Upright on a small screen, every way but upside down on a big one;
    /// an iPad turns every way.
    static func mask(idiom: UIUserInterfaceIdiom, regular: Bool) -> UIInterfaceOrientationMask {
        if idiom == .pad { return .all }
        return regular ? .allButUpsideDown : .portrait
    }
}
