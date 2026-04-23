// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Registry of known writing applications with storage metadata.
//!
//! Centralises knowledge about how different apps store their documents so the
//! sentinel can:
//!
//! 1. Identify documents by window title for apps that do not expose
//!    `AXDocument` (container-based, cloud-library, or database-backed apps).
//! 2. Emit a list of container directories to watch so file-change events
//!    arrive even when the app uses a non-standard storage location.
//! 3. Drive the `TITLE_INFERRED_APPS` constant in `types.rs` — any app in
//!    this registry with `needs_title_inference: true` should also be listed
//!    there.
//!
//! # Adding a new app
//!
//! Add a `WritingApp` entry to `KNOWN_WRITING_APPS`. Specify:
//! - `bundle_id`: the macOS CFBundleIdentifier (use `mdls -name kMDItemCFBundleIdentifier <app>`)
//! - `display_name`: human-readable name shown in logs / status
//! - `storage`: one of the `StoragePattern` variants
//! - `container_paths`: slice of paths relative to `$HOME` that should be
//!   added to the file-watch list. Use empty `&[]` for file-based apps.
//! - `needs_title_inference`: `true` when the app does not expose a real
//!   file path via `AXDocument` (must also appear in `TITLE_INFERRED_APPS`).

use std::path::PathBuf;

/// How a writing application stores its content on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoragePattern {
    /// Documents are saved as ordinary files; the sentinel discovers them
    /// through the Accessibility `AXDocument` attribute or FSEvents.
    FileBased,
    /// Content lives inside an app group container (`~/Library/Group Containers/…`).
    /// The container path is provided so it can be watched directly.
    ContainerBased,
    /// Content is managed in an iCloud drive library
    /// (`~/Library/Mobile Documents/…`). The library path is watched.
    CloudLibrary,
    /// Content is stored in a private SQLite database or proprietary format
    /// inside the app's sandbox. The sentinel watches the container for any
    /// change activity; document identity comes from the window title.
    DatabaseBacked,
}

/// Metadata about a writing application known to WritersProof.
#[derive(Debug, Clone)]
pub struct WritingApp {
    /// macOS `CFBundleIdentifier` (case-insensitive matching).
    pub bundle_id: &'static str,
    /// Human-readable application name.
    pub display_name: &'static str,
    /// How the app stores its documents.
    pub storage: StoragePattern,
    /// Paths relative to `$HOME` that the file watcher should observe.
    /// These supplement (or replace) ordinary `AXDocument`-derived paths.
    pub container_paths: &'static [&'static str],
    /// When `true`, the sentinel will accept bare document names from the
    /// window title even without a recognised file extension. The bundle ID
    /// must also appear in `TITLE_INFERRED_APPS` in `sentinel/types.rs`.
    pub needs_title_inference: bool,
}

/// All writing applications known to WritersProof.
///
/// Order does not matter; searched by `bundle_id` (case-insensitive).
pub static KNOWN_WRITING_APPS: &[WritingApp] = &[
    // ── Microsoft ──────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.microsoft.Word",
        display_name: "Microsoft Word",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
    },
    WritingApp {
        bundle_id: "com.microsoft.onenote.mac",
        display_name: "Microsoft OneNote",
        storage: StoragePattern::ContainerBased,
        container_paths: &[
            "Library/Containers/com.microsoft.onenote.mac/Data/Library/Application Support",
        ],
        needs_title_inference: true,
    },
    // ── Apple iWork ────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.apple.iWork.Pages",
        display_name: "Pages",
        storage: StoragePattern::CloudLibrary,
        container_paths: &["Library/Mobile Documents/com~apple~Pages/Documents"],
        needs_title_inference: false,
    },
    // ── Ulysses ────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.ulyssesapp.mac",
        display_name: "Ulysses",
        storage: StoragePattern::CloudLibrary,
        container_paths: &[
            "Library/Mobile Documents/X5AZV975AG~com~soulmen~ulysses3/Documents",
            "Library/Containers/com.ulyssesapp.mac/Data/Library/Application Support/Ulysses",
        ],
        needs_title_inference: true,
    },
    // ── Bear ────────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "net.shinyfrog.bear",
        display_name: "Bear",
        storage: StoragePattern::DatabaseBacked,
        container_paths: &[
            "Library/Group Containers/9K33E3U3T4.com.shinyfrog.bear/Application Data",
        ],
        needs_title_inference: true,
    },
    // ── iA Writer ──────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "pro.writer.mac",
        display_name: "iA Writer",
        storage: StoragePattern::FileBased,
        container_paths: &["Library/Mobile Documents/pro~writer~mac/Documents"],
        needs_title_inference: false,
    },
    // ── Scrivener ──────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.literatureandlatte.scrivener3",
        display_name: "Scrivener",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
    },
    // ── Affinity Publisher ─────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.seriflabs.affinitypublisher",
        display_name: "Affinity Publisher",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
    },
    WritingApp {
        bundle_id: "com.seriflabs.affinitypublisher2",
        display_name: "Affinity Publisher 2",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
    },
    // ── Drafts ─────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.agiletortoise.Drafts-OSX",
        display_name: "Drafts",
        storage: StoragePattern::ContainerBased,
        container_paths: &[
            "Library/Group Containers/com.agiletortoise.Drafts-Shared",
        ],
        needs_title_inference: true,
    },
    // ── Day One ────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.bloombuilt.dayone-mac",
        display_name: "Day One",
        storage: StoragePattern::DatabaseBacked,
        container_paths: &[
            "Library/Group Containers/5U8NS4GX82.com.dayoneapp.dayone",
        ],
        needs_title_inference: true,
    },
    // ── Craft ──────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.luki.paper.mac",
        display_name: "Craft",
        storage: StoragePattern::ContainerBased,
        container_paths: &[
            "Library/Containers/com.luki.paper.mac/Data/Library/Application Support/Craft",
        ],
        needs_title_inference: true,
    },
    // ── Highland 2 ─────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.quoteunquoteapps.highland2",
        display_name: "Highland 2",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
    },
    // ── Final Draft ────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.finaldraft.mac.finaldraft10",
        display_name: "Final Draft",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
    },
    WritingApp {
        bundle_id: "com.finaldraft.mac.fd11",
        display_name: "Final Draft 11",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
    },
    // ── Fade In ────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.moviemagic.fadein",
        display_name: "Fade In",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
    },
    // ── Hemingway Editor ───────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.hemingwayapp.hemingway",
        display_name: "Hemingway Editor",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true, // Electron; exposes limited AX info
    },
    // ── Obsidian (already in TITLE_INFERRED_APPS; listed here for container) ─
    WritingApp {
        bundle_id: "md.obsidian",
        display_name: "Obsidian",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
    },
    // ── Typora ─────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "abnerworks.Typora",
        display_name: "Typora",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
    },
    // ── Zettlr ─────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.zettlr.app",
        display_name: "Zettlr",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
    },
    // ── Logseq ─────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.logseq.logseq",
        display_name: "Logseq",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
    },
    // ── Notion ─────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.notion.id",
        display_name: "Notion",
        storage: StoragePattern::ContainerBased,
        container_paths: &[],
        needs_title_inference: true,
    },
    // ── Cursor ─────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.todesktop.230313mzl4w4u92",
        display_name: "Cursor",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
    },
    // ── VS Code ────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.microsoft.VSCode",
        display_name: "Visual Studio Code",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
    },
    WritingApp {
        bundle_id: "com.microsoft.VSCodeInsiders",
        display_name: "VS Code Insiders",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
    },
    // ── Noteship ───────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.red-sweater.noteship",
        display_name: "Noteship",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
    },
    // ── Notebooks ──────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.alfonsschmid.Notebooks",
        display_name: "Notebooks",
        storage: StoragePattern::FileBased,
        container_paths: &["Library/Mobile Documents/com~alfonsschmid~Notebooks/Documents"],
        needs_title_inference: false,
    },
    // ── Mellel ─────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.redlers.mellel",
        display_name: "Mellel",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
    },
    // ── Nisus Writer ───────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.nisus.NisusWriter",
        display_name: "Nisus Writer Pro",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
    },
    // ── TextEdit (built-in) ────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.apple.TextEdit",
        display_name: "TextEdit",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
    },
    // ── BBEdit ─────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.barebones.bbedit",
        display_name: "BBEdit",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
    },
    // ── Ghostwriter ────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "io.github.wereturtle.ghostwriter",
        display_name: "Ghostwriter",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
    },
    // ── Manuskript ─────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.olivierkes.manuskript",
        display_name: "Manuskript",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
    },
    // ── LibreOffice Writer ─────────────────────────────────────────────────
    WritingApp {
        bundle_id: "org.libreoffice.script",
        display_name: "LibreOffice",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
    },
    // ── Marked 2 (preview app; writers use it with other editors) ──────────
    WritingApp {
        bundle_id: "com.brettterpstra.marked2",
        display_name: "Marked 2",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
    },
    // ── Taskpaper ──────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.hogbaysoftware.TaskPaper3",
        display_name: "TaskPaper",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
    },
    // ── FoldingText ────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.foldingtext.FoldingText",
        display_name: "FoldingText",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
    },
    // ── Byword ─────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.metaclassy.byword",
        display_name: "Byword",
        storage: StoragePattern::FileBased,
        container_paths: &["Library/Mobile Documents/com~metaclassy~byword/Documents"],
        needs_title_inference: false,
    },
    // ── Markdown Editor ────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.markdowneditor.mac",
        display_name: "Markdown Editor",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
    },
    // ── Coppice ────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.mekentosj.coppice",
        display_name: "Coppice",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
    },
    // ── Bike Outliner ──────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.hogbaysoftware.Bike",
        display_name: "Bike Outliner",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
    },
    // ── OmniOutliner ───────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.omnigroup.OmniOutliner5",
        display_name: "OmniOutliner",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
    },
    // ── Celtx (web, but has a desktop wrapper) ─────────────────────────────
    WritingApp {
        bundle_id: "com.celtx.mac",
        display_name: "Celtx",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
    },
];

/// Look up a `WritingApp` by bundle ID (case-insensitive).
pub fn lookup(bundle_id: &str) -> Option<&'static WritingApp> {
    KNOWN_WRITING_APPS
        .iter()
        .find(|a| a.bundle_id.eq_ignore_ascii_case(bundle_id))
}

/// Return paths (relative to `$HOME`) of all writing-app containers that
/// exist on the current system.
///
/// Used at sentinel startup to extend the file-watch list so that apps like
/// Ulysses and Bear produce file-change events even when their storage is not
/// in an ordinary `~/Documents` folder.
pub fn auto_watch_paths() -> Vec<PathBuf> {
    let Some(home) = dirs::home_dir() else {
        return Vec::new();
    };

    let mut paths = Vec::new();
    for app in KNOWN_WRITING_APPS {
        for rel in app.container_paths {
            let abs = home.join(rel);
            if abs.exists() {
                paths.push(abs);
            }
        }
    }

    // Deduplicate (multiple apps may share a prefix).
    paths.sort();
    paths.dedup();
    paths
}

/// Return whether `bundle_id` belongs to a known writing app that requires
/// title-based document identity (i.e., does not expose `AXDocument`).
pub fn needs_title_inference(bundle_id: &str) -> bool {
    lookup(bundle_id).is_some_and(|a| a.needs_title_inference)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_known_apps() {
        assert!(lookup("com.ulyssesapp.mac").is_some());
        assert!(lookup("net.shinyfrog.bear").is_some());
        assert!(lookup("com.microsoft.Word").is_some());
        assert!(lookup("com.seriflabs.affinitypublisher").is_some());
        // Case-insensitive
        assert!(lookup("COM.ULYSSESAPP.MAC").is_some());
    }

    #[test]
    fn test_lookup_unknown_app_returns_none() {
        assert!(lookup("com.nonexistent.App").is_none());
    }

    #[test]
    fn test_needs_title_inference() {
        assert!(needs_title_inference("net.shinyfrog.bear"));
        assert!(needs_title_inference("com.ulyssesapp.mac"));
        assert!(!needs_title_inference("com.microsoft.Word"));
        assert!(!needs_title_inference("com.apple.iWork.Pages"));
    }

    #[test]
    fn test_auto_watch_paths_no_panic() {
        // Should not panic even when none of the paths exist.
        let _ = auto_watch_paths();
    }

    #[test]
    fn test_all_container_apps_have_paths() {
        for app in KNOWN_WRITING_APPS {
            if matches!(
                app.storage,
                StoragePattern::ContainerBased
                    | StoragePattern::CloudLibrary
                    | StoragePattern::DatabaseBacked
            ) {
                assert!(
                    !app.container_paths.is_empty() || app.storage == StoragePattern::ContainerBased,
                    "App '{}' has non-FileBased storage but no container_paths",
                    app.display_name
                );
            }
        }
    }
}
