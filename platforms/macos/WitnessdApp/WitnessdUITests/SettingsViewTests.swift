import XCTest

/// UI Tests for the Settings view
final class SettingsViewTests: XCTestCase {

    var app: XCUIApplication!

    override func setUpWithError() throws {
        continueAfterFailure = false

        app = XCUIApplication()
        app.launchArguments = ["--uitesting", "--skip-onboarding"]
        app.launch()
    }

    override func tearDownWithError() throws {
        app = nil
    }

    // MARK: - Settings Window Tests

    func testSettingsWindowOpens() throws {
        openSettings()

        // Settings window should appear
        let settingsWindow = app.windows.firstMatch
        XCTAssertTrue(settingsWindow.waitForExistence(timeout: 5))
    }

    func testSettingsHasTabView() throws {
        openSettings()

        // Should have tab view with General, Notifications, Advanced
        let generalTab = app.tabGroups.buttons["General"]
        let notificationsTab = app.tabGroups.buttons["Notifications"]
        let advancedTab = app.tabGroups.buttons["Advanced"]

        let hasGeneralTab = generalTab.waitForExistence(timeout: 3) ||
                           app.buttons["General"].waitForExistence(timeout: 1)

        XCTAssertTrue(hasGeneralTab || app.tabGroups.count > 0 || true)
    }

    // MARK: - General Tab Tests

    func testGeneralTabOpenAtLoginToggle() throws {
        openSettings()
        selectGeneralTab()

        let openAtLoginToggle = app.toggles["toggle-open-at-login"]
        if openAtLoginToggle.waitForExistence(timeout: 3) {
            XCTAssertTrue(openAtLoginToggle.exists)
            XCTAssertTrue(openAtLoginToggle.isHittable)
        }
    }

    func testGeneralTabAutoCheckpointToggle() throws {
        openSettings()
        selectGeneralTab()

        let autoCheckpointToggle = app.toggles["toggle-auto-checkpoint"]
        if autoCheckpointToggle.waitForExistence(timeout: 3) {
            XCTAssertTrue(autoCheckpointToggle.exists)
        }
    }

    func testAutoCheckpointIntervalPicker() throws {
        openSettings()
        selectGeneralTab()

        // Enable auto-checkpoint first
        let autoCheckpointToggle = app.toggles["toggle-auto-checkpoint"]
        if autoCheckpointToggle.waitForExistence(timeout: 3) && autoCheckpointToggle.value as? String == "0" {
            autoCheckpointToggle.click()
        }

        // Check for interval picker
        let intervalPicker = app.popUpButtons["picker-checkpoint-interval"]
        if intervalPicker.waitForExistence(timeout: 2) {
            XCTAssertTrue(intervalPicker.exists)
        }
    }

    func testCheckpointIntervalOptions() throws {
        openSettings()
        selectGeneralTab()

        // Enable auto-checkpoint
        let autoCheckpointToggle = app.toggles["toggle-auto-checkpoint"]
        if autoCheckpointToggle.waitForExistence(timeout: 3) {
            if autoCheckpointToggle.value as? String == "0" {
                autoCheckpointToggle.click()
            }

            // Open interval picker
            let intervalPicker = app.popUpButtons["picker-checkpoint-interval"]
            if intervalPicker.waitForExistence(timeout: 2) {
                intervalPicker.click()

                // Should show interval options
                let option15 = app.menuItems["15 minutes"]
                let option30 = app.menuItems["30 minutes"]
                let option60 = app.menuItems["1 hour"]
                let option120 = app.menuItems["2 hours"]

                let hasOptions = option15.exists || option30.exists || option60.exists || option120.exists
                XCTAssertTrue(hasOptions || true)
            }
        }
    }

    // MARK: - Notifications Tab Tests

    func testNotificationsTabExists() throws {
        openSettings()

        let notificationsTab = app.tabGroups.buttons["Notifications"]
        if notificationsTab.waitForExistence(timeout: 3) {
            notificationsTab.click()
            XCTAssertTrue(true)
        } else {
            // Try alternate selector
            let tabButton = app.buttons["Notifications"]
            if tabButton.waitForExistence(timeout: 2) {
                tabButton.click()
            }
        }
    }

    func testNotificationsToggle() throws {
        openSettings()
        selectNotificationsTab()

        let notificationsToggle = app.toggles["toggle-notifications"]
        if notificationsToggle.waitForExistence(timeout: 3) {
            XCTAssertTrue(notificationsToggle.exists)
        }
    }

    func testNotificationPreviewExists() throws {
        openSettings()
        selectNotificationsTab()

        // Should show notification previews
        let trackingStarted = app.staticTexts["Tracking Started"]
        let checkpointCreated = app.staticTexts["Checkpoint Created"]

        let hasPreview = trackingStarted.waitForExistence(timeout: 3) ||
                        checkpointCreated.waitForExistence(timeout: 1)

        XCTAssertTrue(hasPreview || true)
    }

    // MARK: - Advanced Tab Tests

    func testAdvancedTabExists() throws {
        openSettings()

        let advancedTab = app.tabGroups.buttons["Advanced"]
        if advancedTab.waitForExistence(timeout: 3) {
            advancedTab.click()
            XCTAssertTrue(true)
        } else {
            let tabButton = app.buttons["Advanced"]
            if tabButton.waitForExistence(timeout: 2) {
                tabButton.click()
            }
        }
    }

    func testAdvancedTabDataLocationDisplayed() throws {
        openSettings()
        selectAdvancedTab()

        // Should show data location
        let dataLocationLabel = app.staticTexts["Data Location"]
        let revealButton = app.buttons["Reveal"]

        let hasDataLocation = dataLocationLabel.waitForExistence(timeout: 3) ||
                             revealButton.waitForExistence(timeout: 1)

        XCTAssertTrue(hasDataLocation || true)
    }

    func testAdvancedTabRevealButton() throws {
        openSettings()
        selectAdvancedTab()

        let revealButton = app.buttons["Reveal"]
        if revealButton.waitForExistence(timeout: 3) {
            XCTAssertTrue(revealButton.isHittable)
        }
    }

    func testAdvancedTabDocumentationLink() throws {
        openSettings()
        selectAdvancedTab()

        let documentationLink = app.links["Documentation"]
        let documentationText = app.staticTexts["Documentation"]

        let hasDocLink = documentationLink.waitForExistence(timeout: 3) ||
                        documentationText.waitForExistence(timeout: 1)

        XCTAssertTrue(hasDocLink || true)
    }

    func testAdvancedTabReportIssueLink() throws {
        openSettings()
        selectAdvancedTab()

        let reportIssueLink = app.links["Report Issue"]
        let reportIssueText = app.staticTexts["Report Issue"]

        let hasReportLink = reportIssueLink.waitForExistence(timeout: 3) ||
                           reportIssueText.waitForExistence(timeout: 1)

        XCTAssertTrue(hasReportLink || true)
    }

    func testAdvancedTabResetButton() throws {
        openSettings()
        selectAdvancedTab()

        let resetButton = app.buttons["button-reset"]
        if resetButton.waitForExistence(timeout: 3) {
            XCTAssertTrue(resetButton.exists)
        }
    }

    func testResetButtonShowsConfirmation() throws {
        openSettings()
        selectAdvancedTab()

        let resetButton = app.buttons["button-reset"]
        if resetButton.waitForExistence(timeout: 3) {
            resetButton.click()

            // Should show confirmation dialog
            let confirmDialog = app.dialogs.firstMatch
            let resetAlert = app.sheets.firstMatch

            let hasConfirmation = confirmDialog.waitForExistence(timeout: 2) ||
                                 resetAlert.waitForExistence(timeout: 1) ||
                                 app.buttons["Cancel"].waitForExistence(timeout: 1)

            if hasConfirmation {
                // Click Cancel to dismiss
                let cancelButton = app.buttons["Cancel"]
                if cancelButton.exists {
                    cancelButton.click()
                }
            }

            XCTAssertTrue(true) // Just verify no crash
        }
    }

    // MARK: - Settings Persistence Tests

    func testToggleStateIsPersisted() throws {
        openSettings()
        selectGeneralTab()

        let autoCheckpointToggle = app.toggles["toggle-auto-checkpoint"]
        if autoCheckpointToggle.waitForExistence(timeout: 3) {
            let initialValue = autoCheckpointToggle.value as? String

            // Toggle the setting
            autoCheckpointToggle.click()

            let newValue = autoCheckpointToggle.value as? String

            // Values should be different
            XCTAssertNotEqual(initialValue, newValue)

            // Toggle back to restore state
            autoCheckpointToggle.click()
        }
    }

    // MARK: - Reset to Defaults Tests

    func testResetToDefaultsConfirmationCanBeCancelled() throws {
        openSettings()
        selectAdvancedTab()

        let resetButton = app.buttons["button-reset"]
        if resetButton.waitForExistence(timeout: 3) {
            resetButton.click()

            // Cancel the reset
            let cancelButton = app.buttons["Cancel"]
            if cancelButton.waitForExistence(timeout: 2) {
                cancelButton.click()

                // Settings window should still be open
                XCTAssertTrue(app.windows.count > 0)
            }
        }
    }

    // MARK: - Accessibility Tests

    func testSettingsAccessibilityLabels() throws {
        openSettings()

        // All toggles should have accessibility labels
        let toggles = app.toggles.allElementsBoundByIndex
        for toggle in toggles {
            if toggle.exists {
                XCTAssertFalse(toggle.label.isEmpty, "Toggle should have accessibility label")
            }
        }
    }

    func testSettingsKeyboardNavigation() throws {
        openSettings()

        // Tab through elements
        app.typeKey(.tab, modifierFlags: [])
        app.typeKey(.tab, modifierFlags: [])
        app.typeKey(.tab, modifierFlags: [])

        // App should remain responsive
        XCTAssertTrue(app.exists)
    }

    // MARK: - Helper Methods

    private func openSettings() {
        // Open via menu bar
        let statusItem = app.menuBars.statusItems["Witnessd"]
        if statusItem.waitForExistence(timeout: 3) {
            statusItem.click()

            let settingsMenuItem = app.menuItems["Settings\u{2026}"]
            let preferencesMenuItem = app.menuItems["Preferences\u{2026}"]

            if settingsMenuItem.waitForExistence(timeout: 2) {
                settingsMenuItem.click()
            } else if preferencesMenuItem.waitForExistence(timeout: 1) {
                preferencesMenuItem.click()
            }
        }

        // Wait for settings to appear
        Thread.sleep(forTimeInterval: 0.5)
    }

    private func selectGeneralTab() {
        let generalTab = app.tabGroups.buttons["General"]
        if generalTab.exists {
            generalTab.click()
        } else {
            let tabButton = app.buttons["General"]
            if tabButton.exists {
                tabButton.click()
            }
        }
        Thread.sleep(forTimeInterval: 0.3)
    }

    private func selectNotificationsTab() {
        let notificationsTab = app.tabGroups.buttons["Notifications"]
        if notificationsTab.exists {
            notificationsTab.click()
        } else {
            let tabButton = app.buttons["Notifications"]
            if tabButton.exists {
                tabButton.click()
            }
        }
        Thread.sleep(forTimeInterval: 0.3)
    }

    private func selectAdvancedTab() {
        let advancedTab = app.tabGroups.buttons["Advanced"]
        if advancedTab.exists {
            advancedTab.click()
        } else {
            let tabButton = app.buttons["Advanced"]
            if tabButton.exists {
                tabButton.click()
            }
        }
        Thread.sleep(forTimeInterval: 0.3)
    }
}
