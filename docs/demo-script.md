# WritersLogic CLI Video Demo Script

## Overview

**Duration:** ~5–7 minutes
**Goal:** Show WritersLogic capturing authorship proof across Scrivener, VS Code, and Notepad — then exporting verifiable evidence.

**Setup before recording:**
- Terminal visible alongside each editor
- `~/.writerslogic/` directory removed (fresh install)
- Have a short paragraph ready to type in each app (don't paste — type live to show keystroke capture)
- Terminal font large enough to read on video (16pt+)

---

## Scene 1 — Install & Init (~60s)

**[Terminal full-screen]**

> "WritersLogic is a cryptographic authorship witnessing tool. It captures behavioral evidence while you write — keystroke timing, editing cadence, focus events — and packages it into cryptographically signed proof that you authored your work. Let me show you how to get started."

> "Installation is a single command."

```bash
curl -fsSL https://writerslogic.com/install.sh | sh
```

> "The install script detects your platform, downloads the right binary, and adds it to your path."

```bash
wld init
```

> "Now we initialize. This generates an Ed25519 signing key, creates a tamper-evident database, and detects hardware security features on this machine."

```bash
wld calibrate
```

> "Calibration measures CPU speed so we can create verifiable delay function proofs — time-locked puzzles that prove minimum elapsed time between checkpoints."

```bash
wld status
```

> "We're set up. You can see the public key, device ID, and calibration results."

---

## Scene 2 — Writing in Scrivener (~90s)

**[Split screen: Scrivener on left, Terminal on right]**

> "Let's start with Scrivener. I'll begin a tracking session on my manuscript file."

```bash
wld track start ~/Documents/novel-chapter.txt
```

> "WritersLogic is now capturing keystroke timing in the background. It records *when* you type, not *what* you type — timing intervals only, never key values."

**[Switch focus to Scrivener. Type 2–3 sentences naturally, ~30 seconds of real typing.]**

> *(Type something like: "The morning light filtered through the curtains as she reached for her notebook. Every story begins somewhere, and this one began with a question she couldn't answer.")*

**[Switch back to Terminal]**

```bash
wld track status
```

> "You can see the session duration, keystroke count, and typing rate. Let's create our first checkpoint."

```bash
wld commit ~/Documents/novel-chapter.txt -m "Opening paragraph"
```

> "That created a cryptographic checkpoint — a SHA-256 content hash, an event chain hash, and a VDF proof that at least one second of real wall-clock time elapsed."

**[Go back to Scrivener. Type another sentence or two.]**

```bash
wld commit ~/Documents/novel-chapter.txt -m "Added second paragraph"
```

```bash
wld track stop
```

> "Two checkpoints captured with keystroke evidence from Scrivener. Let's move to a different application."

---

## Scene 3 — Writing in VS Code (~60s)

**[Split screen: VS Code on left, Terminal on right]**

> "Now let's switch to VS Code — maybe I'm writing documentation or a blog post."

**[Open a markdown file in VS Code]**

```bash
wld track start ~/Documents/blog-post.md
```

**[Type in VS Code for ~20 seconds]**

> *(Type something like: "## Why Authorship Matters\n\nIn an age of AI-generated content, proving that a human actually wrote something is becoming essential.")*

```bash
wld commit ~/Documents/blog-post.md -m "Draft intro section"
```

**[Type a few more lines]**

```bash
wld commit ~/Documents/blog-post.md -m "Added motivation section"
```

```bash
wld track stop
```

> "Same workflow, different editor. WritersLogic captures evidence regardless of which application you're writing in — it monitors at the OS level."

---

## Scene 4 — Writing in Notepad (~45s)

**[Split screen: Notepad (or TextEdit on macOS) on left, Terminal on right]**

> "And it works with any text editor — even something as simple as Notepad."

```bash
wld track start ~/Documents/quick-note.txt
```

**[Type a few sentences in Notepad/TextEdit, ~15 seconds]**

```bash
wld commit ~/Documents/quick-note.txt -m "Meeting notes"
```

```bash
wld commit ~/Documents/quick-note.txt -m "Action items added"
```

```bash
wld track stop
```

> "Three documents across three applications, all with cryptographic authorship evidence."

---

## Scene 5 — Review & History (~30s)

**[Terminal full-screen]**

> "Let's review what we've captured."

```bash
wld log
```

> "All three documents are tracked. Let's look at the checkpoint history for our novel chapter."

```bash
wld log ~/Documents/novel-chapter.txt
```

> "Each checkpoint has a timestamp, content hash, and VDF elapsed time — an unforgeable timeline of the writing process."

---

## Scene 6 — Export Evidence (~60s)

**[Terminal full-screen]**

> "Now let's export a proper evidence packet. I'll use the standard tier, which includes VDF proofs and a signed authorship declaration."

```bash
wld export ~/Documents/novel-chapter.txt -t standard
```

> *(When prompted for AI declaration):* "No, I did not use AI tools."
> *(When prompted for statement):* "I authored this document."

> "The evidence packet includes the full checkpoint chain, VDF time proofs, and my cryptographically signed declaration."

> "Let's also generate an HTML report for the blog post."

```bash
wld export ~/Documents/blog-post.md -t enhanced -f html
```

> "The HTML report provides a visual summary with an authorship verdict, likelihood ratio, and ENFSI-scale forensic tier."

**[Open the HTML report in a browser briefly to show the visual output]**

---

## Scene 7 — Verify (~30s)

**[Terminal full-screen]**

> "Anyone can verify an evidence packet — they don't need my private key, just the evidence file."

```bash
wld verify ~/Documents/novel-chapter.txt.evidence.json
```

> "Verification checks every VDF proof in the chain, validates the declaration signature, and confirms spec conformance against the draft-condrey-rats-pop IETF protocol."

> "We can also verify the integrity of the entire local database."

```bash
wld verify ~/.writerslogic/events.db
```

---

## Scene 8 — Closing (~15s)

**[Terminal full-screen]**

> "That's WritersLogic — cryptographic proof of authorship that works across any application. Your keystroke timing, editing cadence, and checkpoint history create an evidence trail that's computationally infeasible to forge. It captures how you write, not what you write."

```bash
wld status
```

> "Get started with `wld init`."

---

## Recording Tips

- **Type naturally** — don't rush. The demo is more convincing when typing looks organic.
- **Pause briefly** after each command to let output render on screen.
- **Use a dark terminal theme** with high contrast for readability.
- **Keep the editor font large** (14pt+ for editors, 16pt+ for terminal).
- **Consider a keystroke visualizer** overlay (like KeyCastr on macOS) to show that you're genuinely typing.
- **Cut or speed up** long typing segments in post-production if needed — just ensure the real-time typing is visible for at least a few seconds in each app.
- **Terminal prompt suggestion:** Keep it short, e.g. `$ ` — avoid long path prompts that clutter the screen.
