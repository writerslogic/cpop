# Age Rating Questionnaire Responses

This document provides guidance for completing the Microsoft Store age rating questionnaire for Witnessd.

## IARC Age Rating

Witnessd is expected to receive a rating of **PEGI 3** / **ESRB Everyone** based on the following questionnaire responses.

## Questionnaire Responses

### Violence and Gore

**Q: Does your app depict violence?**
A: No

**Q: Does your app contain blood or gore?**
A: No

### Sexual Content

**Q: Does your app contain sexual content or nudity?**
A: No

**Q: Does your app contain suggestive themes?**
A: No

### Language

**Q: Does your app contain profanity or crude humor?**
A: No

**Q: Does your app use discriminatory language?**
A: No

### Controlled Substances

**Q: Does your app reference or depict alcohol?**
A: No

**Q: Does your app reference or depict tobacco?**
A: No

**Q: Does your app reference or depict drugs or controlled substances?**
A: No

### Gambling

**Q: Does your app contain gambling or simulated gambling?**
A: No

**Q: Does your app allow users to gamble with real currency?**
A: No

### User Interaction

**Q: Does your app enable user-to-user communication?**
A: No

**Q: Does your app enable users to share personal information?**
A: No

**Q: Does your app enable sharing of user location?**
A: No

### Data Collection

**Q: Does your app collect personal data?**
A: The app collects keystroke timing data locally. This data never leaves the device and is not transmitted to any server.

**Q: Does your app share data with third parties?**
A: No

### In-App Purchases

**Q: Does your app offer in-app purchases?**
A: No

**Q: Does your app offer subscriptions?**
A: No

## Privacy Considerations

Witnessd processes keystroke timing data for biometric authentication purposes:

1. **What is collected**: Only inter-keystroke timing intervals (milliseconds between key presses)
2. **What is NOT collected**: Actual key values, passwords, or typed content
3. **Where is it stored**: Locally on the user's device only
4. **Is it transmitted**: No, all data stays on-device
5. **Can it be deleted**: Yes, users can delete all data at any time

This approach ensures user privacy while providing the biometric authentication needed for authorship verification.

## Restricted Capabilities Justification

Witnessd requests the following restricted capabilities:

### broadFileSystemAccess
**Justification**: Required to create checkpoint evidence files for any document the user is working on, regardless of location.

### inputForegroundObservation
**Justification**: Required to observe keystroke timing for biometric authentication. Only timing data is collected, not key values.

### inputObservation
**Justification**: Required for background keystroke timing collection during active tracking sessions. Privacy-preserving implementation collects only timing, not content.

### runFullTrust
**Justification**: Required for desktop application functionality including file system access and system integration.

## Notes for Submission

1. Witnessd is a developer/productivity tool with no content concerns
2. All data collection is local and privacy-preserving
3. No network communication is required for core functionality
4. No user accounts or authentication services are used
5. The application is fully functional offline
