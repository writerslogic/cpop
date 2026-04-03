# WritersProof macOS App -- Demo Script

**Duration:** ~4 minutes
**Format:** Screen recording with voiceover
**Setup before recording:**
- WritersProof.app running, dashboard visible
- A text editor open (TextEdit, Pages, or Word) with a blank document
- No other apps in the dock/foreground that distract

---

## INTRO (0:00 -- 0:20)

**[Screen: WritersProof dashboard, idle state]**

> WritersProof solves a problem that didn't exist five years ago: proving that a human actually wrote something. With generative AI producing text indistinguishable from human writing, institutions need evidence, not just assertions. WritersProof captures cryptographic proof of the writing process itself.

---

## START WITNESSING (0:20 -- 0:50)

**[Action: Open TextEdit or Pages. Click "Start Witnessing" in WritersProof, or show it auto-detecting the document.]**

> When you open a document, WritersProof begins capturing behavioral telemetry in real time. It records keystroke timing, pause patterns, revision sequences, and focus events. None of the actual text leaves your machine. What gets recorded is the process, not the content.

**[Action: Point to the status indicator showing active witnessing.]**

> You can see it's now actively monitoring. The green indicator means the proof daemon is running and checkpoints are being created.

---

## LIVE WRITING (0:50 -- 2:00)

**[Action: Type naturally for about 60 seconds. Write 2-3 sentences. Make some typos and correct them. Pause to think. Delete a phrase and rewrite it. This is the most important part: write like a real person.]**

> I'm going to write a few sentences now. Notice I'm typing naturally. I'm pausing to think, making corrections, deleting a phrase I didn't like. Every one of these micro-behaviors is being captured: the timing between keystrokes, the pattern of deletions, the rhythm of composition. These are things that are extraordinarily difficult to fake, because they emerge from human cognition, not from an algorithm.

**[Action: Pause typing for 3-4 seconds mid-sentence, then continue.]**

> That pause right there: that's a thinking pause. The system measures its duration and position in the sentence. Human writers pause at semantically meaningful boundaries. Machines don't.

---

## CHECKPOINTS (2:00 -- 2:30)

**[Action: Show the WritersProof window with checkpoint count incrementing, or the session details panel.]**

> Behind the scenes, WritersProof is creating cryptographic checkpoints. Each checkpoint hashes the document state and chains it to the previous one, similar to a blockchain. It also runs a Verifiable Delay Function: a computation that takes real wall-clock time to complete. This means you can't backdate the evidence. Producing 30 minutes of writing proof requires at least 30 minutes of sequential computation.

---

## EXPORT EVIDENCE (2:30 -- 3:15)

**[Action: Click Export or Generate Report. Select HTML format. Open the generated report in a browser.]**

> Now let's export the evidence. WritersProof generates a forensic examination report.

**[Action: Scroll through the HTML report slowly, pausing at key sections.]**

> This is structured as a formal forensic document. At the top, the Declaration of Findings shows the assessment score and likelihood ratio, classified on the ENFSI verbal equivalence scale -- the standard used in European forensic laboratories.

**[Action: Scroll to Chain of Evidence section.]**

> The Chain of Evidence section shows the SHA-256 document hash, the signing key fingerprint, and the device attestation. This establishes provenance.

**[Action: Scroll to Process Evidence exhibits.]**

> Process Evidence presents the behavioral data as labeled exhibits. Revision intensity, pause distribution, keystroke dynamics, deletion patterns. Each is independently verifiable.

**[Action: Scroll to the checkpoint chain table.]**

> Here's the checkpoint chain. Each entry is hash-linked to the previous one. The VDF iterations column proves elapsed time. This is a tamper-evident log of the entire writing process.

---

## VERIFICATION (3:15 -- 3:45)

**[Action: Show the verification section of the report, or demonstrate uploading the .cpop file to writerslogic.com/verify if available.]**

> The critical point is that none of this requires trusting us. The evidence file is cryptographically signed and can be verified by anyone. Upload it to the web verifier, or run the open-source command-line tool. Verification checks the signatures, the checkpoint chain, the VDF timing proofs, and the behavioral plausibility -- all independently.

---

## CLOSE (3:45 -- 4:10)

**[Screen: Back to the report, showing the Scope and Limitations section.]**

> WritersProof doesn't claim to prove identity, and it doesn't guarantee that AI was never consulted. What it proves is that a human being sat at a keyboard and composed this text through a natural cognitive process, backed by cryptographic evidence that holds up to forensic scrutiny. For universities, publishers, legal proceedings, and anywhere authorship integrity matters -- that's the evidence that's been missing.

**[Screen: WritersProof logo or dashboard.]**

> WritersProof. Cryptographic proof of human authorship.

---

## RECORDING TIPS

- **Resolution:** 2560x1440 or 1920x1080, 60fps
- **Audio:** Record voiceover separately for cleaner audio; sync in post
- **Typing:** Your normal speed. Corrections and pauses make the demo more convincing, not less
- **Font size:** Increase editor font to 16-18pt so text is readable in the recording
- **Browser zoom:** 125-150% on the HTML report so viewers can read section headings
- **Cursor:** Consider a cursor highlighter so viewers can follow the mouse
- **Pacing:** Let the viewer read each report section for 2-3 seconds before scrolling
- **Cuts:** If you stumble, pause and restart the section; edit in post
