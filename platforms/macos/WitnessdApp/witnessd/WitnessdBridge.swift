import Foundation

/// Result from a witnessd command
struct CommandResult: Sendable {
    let success: Bool
    let message: String
    let exitCode: Int32
}

/// Status information from witnessd
struct WitnessStatus: Sendable {
    var isInitialized: Bool = false
    var isTracking: Bool = false
    var trackingDocument: String? = nil
    var keystrokeCount: Int = 0
    var trackingDuration: String = ""
    var vdfCalibrated: Bool = false
    var vdfIterPerSec: String = ""
    var tpmAvailable: Bool = false
    var tpmInfo: String = ""
    var databaseEvents: Int = 0
    var databaseFiles: Int = 0
}

/// Strip ANSI escape codes from a string (free function for Sendable compatibility)
private func stripANSICodes(_ string: String) -> String {
    let pattern = #"\x1B\[[0-9;]*[a-zA-Z]"#
    return string.replacingOccurrences(of: pattern, with: "", options: .regularExpression)
}

/// Bridge to communicate with the bundled witnessd CLI
final class WitnessdBridge: @unchecked Sendable {
    private let witnessdPath: String
    private let dataDirectory: String

    init() {
        // Find witnessd in the app bundle
        if let bundlePath = Bundle.main.path(forResource: "witnessd", ofType: nil) {
            self.witnessdPath = bundlePath
        } else {
            // Fallback: look for witnessd in PATH (for development)
            self.witnessdPath = "/usr/local/bin/witnessd"
        }

        // Determine data directory for sandboxed container
        // In a sandboxed app, Application Support is within the container
        if let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first {
            self.dataDirectory = appSupport.appendingPathComponent("Witnessd").path
        } else {
            // Fallback to traditional location
            let home = FileManager.default.homeDirectoryForCurrentUser.path
            self.dataDirectory = "\(home)/.witnessd"
        }

        // Ensure directory exists
        try? FileManager.default.createDirectory(
            atPath: dataDirectory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
    }

    /// Returns the data directory path for display in UI
    var dataDirectoryPath: String {
        return dataDirectory
    }

    // MARK: - Commands

    func initialize() async -> CommandResult {
        return await runCommand(["init"])
    }

    func calibrate() async -> CommandResult {
        return await runCommand(["calibrate"])
    }

    func commit(filePath: String, message: String) async -> CommandResult {
        var args = ["commit", filePath]
        if !message.isEmpty {
            args.append(contentsOf: ["-m", message])
        }
        return await runCommand(args)
    }

    func log(filePath: String) async -> CommandResult {
        return await runCommand(["log", filePath])
    }

    func export(filePath: String, tier: String, outputPath: String) async -> CommandResult {
        return await runCommand(["export", filePath, "-tier", tier, "-o", outputPath])
    }

    func verify(filePath: String) async -> CommandResult {
        return await runCommand(["verify", filePath])
    }

    func list() async -> CommandResult {
        return await runCommand(["list"])
    }

    func startTracking(documentPath: String) async -> CommandResult {
        return await runCommand(["track", "start", documentPath])
    }

    func stopTracking() async -> CommandResult {
        return await runCommand(["track", "stop"])
    }

    func getStatus() async -> WitnessStatus {
        var status = WitnessStatus()

        // Check if initialized by running status command
        let result = await runCommand(["status"])

        if result.success {
            let output = result.message

            // Parse the output to extract status information
            status.isInitialized = output.contains("Data directory:")

            // Check VDF calibration
            if let match = output.range(of: #"VDF iterations/sec: (\d+)"#, options: .regularExpression) {
                let value = output[match].components(separatedBy: ": ").last ?? ""
                status.vdfIterPerSec = value
                status.vdfCalibrated = true
            }

            // Check TPM
            if output.contains("TPM: available") {
                status.tpmAvailable = true
                if let match = output.range(of: #"TPM: available \(([^)]+)\)"#, options: .regularExpression) {
                    status.tpmInfo = String(output[match])
                        .replacingOccurrences(of: "TPM: available (", with: "")
                        .replacingOccurrences(of: ")", with: "")
                }
            }

            // Check database stats
            if let match = output.range(of: #"Events: (\d+)"#, options: .regularExpression) {
                let value = output[match].components(separatedBy: ": ").last ?? "0"
                status.databaseEvents = Int(value) ?? 0
            }

            if let match = output.range(of: #"Files tracked: (\d+)"#, options: .regularExpression) {
                let value = output[match].components(separatedBy: ": ").last ?? "0"
                status.databaseFiles = Int(value) ?? 0
            }
        }

        // Check tracking status separately
        let trackResult = await runCommand(["track", "status"])
        if trackResult.success && trackResult.message.contains("Active Tracking Session") {
            status.isTracking = true

            // Parse tracking info
            if let match = trackResult.message.range(of: #"Document: (.+)"#, options: .regularExpression) {
                let line = String(trackResult.message[match])
                status.trackingDocument = line.components(separatedBy: ": ").last?.trimmingCharacters(in: .whitespaces)
            }

            if let match = trackResult.message.range(of: #"Keystrokes: (\d+)"#, options: .regularExpression) {
                let value = trackResult.message[match].components(separatedBy: ": ").last ?? "0"
                status.keystrokeCount = Int(value) ?? 0
            }

            if let match = trackResult.message.range(of: #"Duration: (.+)"#, options: .regularExpression) {
                let line = String(trackResult.message[match])
                status.trackingDuration = line.components(separatedBy: ": ").last?.trimmingCharacters(in: .whitespaces) ?? ""
            }
        }

        return status
    }

    // MARK: - Private

    private func runCommand(_ arguments: [String]) async -> CommandResult {
        let path = self.witnessdPath
        let dataDir = self.dataDirectory
        return await Task.detached {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: path)
            process.arguments = arguments

            // Set environment variable for sandboxed data directory
            var environment = ProcessInfo.processInfo.environment
            environment["WITNESSD_DATA_DIR"] = dataDir
            process.environment = environment

            // Capture output
            let outputPipe = Pipe()
            let errorPipe = Pipe()
            process.standardOutput = outputPipe
            process.standardError = errorPipe

            // Hide from user - no terminal window
            process.standardInput = FileHandle.nullDevice

            do {
                try process.run()
                process.waitUntilExit()

                let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
                let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()

                let output = String(data: outputData, encoding: .utf8) ?? ""
                let errorOutput = String(data: errorData, encoding: .utf8) ?? ""

                let exitCode = process.terminationStatus
                let success = exitCode == 0

                // Combine output, strip ANSI codes for cleaner display
                var message = output
                if !success && !errorOutput.isEmpty {
                    message = errorOutput
                }
                message = stripANSICodes(message)

                return CommandResult(
                    success: success,
                    message: message.trimmingCharacters(in: .whitespacesAndNewlines),
                    exitCode: exitCode
                )
            } catch {
                return CommandResult(
                    success: false,
                    message: "Failed to run witnessd: \(error.localizedDescription)",
                    exitCode: -1
                )
            }
        }.value
    }
}
