import Foundation
import ServiceManagement
import os.log

/// Manages the "Open at Login" functionality using SMAppService (macOS 13+)
enum LaunchAtLogin {
    private static let logger = Logger(subsystem: "com.witnessd.app", category: "launch-at-login")

    static var isEnabled: Bool {
        get {
            if #available(macOS 13.0, *) {
                return SMAppService.mainApp.status == .enabled
            } else {
                // Fallback for older macOS - stored preference only
                return UserDefaults.standard.bool(forKey: "LaunchAtLogin")
            }
        }
        set {
            if #available(macOS 13.0, *) {
                do {
                    if newValue {
                        try SMAppService.mainApp.register()
                        logger.info("Launch at login enabled")
                    } else {
                        try SMAppService.mainApp.unregister()
                        logger.info("Launch at login disabled")
                    }
                } catch {
                    logger.error("Failed to \(newValue ? "enable" : "disable") launch at login: \(error.localizedDescription)")
                }
            } else {
                // Fallback for older macOS - note: this only stores the preference,
                // actual login item would require deprecated LSSharedFileList APIs
                UserDefaults.standard.set(newValue, forKey: "LaunchAtLogin")
                logger.info("Launch at login preference saved (legacy mode)")
            }
        }
    }
}
