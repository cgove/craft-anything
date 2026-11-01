//! Study: look at the target before the first build (capture a website, triage a program, start
//! Ghidra's analysis in Deep mode) and write the notes the builder reads.

use super::*;

/// Build a replacement beside the project's evidence. The live reference stays available until
/// the complete study succeeds; failed captures never become the project's current reference.
fn replace_capture(root: &Path, capture: impl FnOnce(&Path) -> Result<(), ToolError>) -> Result<(), ToolError> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let staging = root.join("investigation.cany").join(format!(
        "capture-staging-{}-{}-{}",
        std::process::id(),
        craft_anything_engine::inbox::now_ms(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    if let Some(parent) = staging.parent() {
        std::fs::create_dir_all(parent).map_err(|e| ToolError::io(parent.display(), e))?;
    }
    std::fs::create_dir(&staging).map_err(|e| ToolError::io(staging.display(), e))?;
    let next = staging.join("capture");
    let previous = staging.join("previous");
    let result = capture(&next).and_then(|()| {
        if !next.join("capture.json").is_file() {
            return Err(ToolError::invalid("The replacement capture is incomplete; the previous capture was kept."));
        }
        let current = root.join("capture");
        let had_previous = current.exists();
        if had_previous {
            std::fs::rename(&current, &previous).map_err(|e| ToolError::io(current.display(), e))?;
        }
        if let Err(e) = std::fs::rename(&next, &current) {
            if had_previous && let Err(restore) = std::fs::rename(&previous, &current) {
                return Err(ToolError::io(current.display(), restore).with_remediation(format!(
                    "The previous capture is safe in {}. Restore it to {} before trying again.",
                    previous.display(),
                    current.display()
                )));
            }
            return Err(ToolError::io(current.display(), e));
        }
        Ok(())
    });
    // A failed rollback keeps its backup for recovery. Otherwise only temporary output remains.
    if result.is_ok() || !previous.exists() {
        let _ = std::fs::remove_dir_all(&staging);
    }
    result
}

impl Worker {
    pub(super) fn study(&mut self, ws: &mut Workspace, kind: &dyn TargetKind) -> Result<(), ToolError> {
        match ws.manifest.target.clone() {
            TargetRef::Website { url } => {
                let root = ws.root.clone();
                replace_capture(&root, |capture| {
                    self.step(ws, Step::Study, Status::Inspecting, &format!("Opening {url} in a private browser…"))?;
                    self.call("web_site_open", json!({"url": url, "headless": !ws.manifest.website_sign_in}))?;
                    if ws.manifest.website_sign_in {
                        self.wait_for_website_sign_in(ws, Duration::from_secs(10 * 60))?;
                        self.call("web_site_open", json!({"url": url, "require_existing": true}))?;
                    }
                    self.step(ws, Step::Study, Status::Inspecting, "Photographing the page and reading its layout…")?;
                    // The widths the check compares at, so every picture has its pair.
                    let widths = self.engine.session().settings.build.widths();
                    self.call("web_site_capture", json!({"output_directory": capture.display().to_string(), "widths": widths, "noise_pass": true, "export_images": ws.manifest.website_export_images}))?;
                    // Menus, pop-ups and tabs, one at a time, on a computer and on a phone (where a menu
                    // button often replaces the navigation); a page without them (or a failure) is fine.
                    self.step(ws, Step::Study, Status::Inspecting, "Opening its menus, pop-ups and tabs…")?;
                    let mut views = vec![(kinds::website::STATES_DIR.to_string(), widths.first().copied().unwrap_or(1440))];
                    views.extend(kinds::website::phone_width(&widths).map(|w| (kinds::website::phone_states_dir(w), w)));
                    for (dir, width) in views {
                        let states = capture.join(dir);
                        if let Err(e) = self.call("web_page_states_capture", json!({"output_directory": states.display().to_string(), "width": width})) {
                            self.step(ws, Step::Study, Status::Inspecting, &format!("Couldn't open its menus and pop-ups at {width} px: {}", e.message))?;
                        }
                    }
                    self.capture_routes(ws, &url, &widths, capture)?;
                    if !self.engine.session().clean_room() {
                        self.how_it_works(ws, &url, capture)?;
                    }
                    self.stop.check()?;
                    Ok(())
                })?;
            }
            TargetRef::Local { path } if self.engine.session().clean_room() => self.study_from_outside(ws, &path)?,
            TargetRef::Local { path } => {
                self.step(ws, Step::Study, Status::Inspecting, "Looking inside it (nothing is run)…")?;
                let (program, folder) = locate(&path, kind.studies_folder());
                let mut notes = format!("# What we found in {}\n\n", path.display());
                if program != path {
                    notes.push_str(&format!("{} starts {}, so that's what we looked at.\n\n", path.display(), program.display()));
                }
                match self.call("core_target_triage", json!({"path": program.display().to_string()})) {
                    Ok(out) => notes.push_str(&describe(&out)),
                    Err(e) => notes.push_str(&format!("A first look failed: {}\n", e.message)),
                }
                if !program.is_file() && !self.engine.session().clean_room() {
                    self.step(
                        ws,
                        Step::Study,
                        Status::Inspecting,
                        "Couldn't find the program to decompile, so Ghidra can't be used. Pick the game's or app's main folder or its program.",
                    )?;
                    notes.push_str(&format!("\n## Ghidra\n\nNo program was found in {}, so Ghidra couldn't be used.\n", path.display()));
                }
                if let Some(done) = self.prepare_ghidra(&program) {
                    // Deep mode always waits for Ghidra: the builder then decompiles with it straight away.
                    let started = std::time::Instant::now();
                    // One line: the app's progress card shows how long it has been going.
                    self.step(ws, Step::Study, Status::Inspecting, "Ghidra is analysing the program (only the first time; a big game takes a while)…")?;
                    let result = loop {
                        match done.recv_timeout(Duration::from_secs(30)) {
                            Ok(r) => break r,
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => self.stop.check()?,
                            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break Err("the analysis stopped unexpectedly".into()),
                        }
                    };
                    notes.push_str(&match result {
                        Ok(()) => format!(
                            "\n## Ghidra\n\nDeep mode: Ghidra has analysed {} ({} min), so decompiling it is quick.\n",
                            program.display(),
                            started.elapsed().as_secs() / 60
                        ),
                        Err(e) => format!("\n## Ghidra\n\nGhidra couldn't analyse {} ({e}), so decompiling uses the built-in decompiler.\n", program.display()),
                    });
                }
                if let Some(f) = folder {
                    self.step(ws, Step::Study, Status::Inspecting, "Listing its maps, pictures, models and sounds…")?;
                    if let Some(found) = game::detect(&f) {
                        notes.push_str(&format!("\n## Made with {}\n\nThe giveaway: {}.", found.label(), found.clue));
                        if let Some(n) = &found.note {
                            notes.push_str(&format!(" {n}"));
                        }
                        notes.push('\n');
                    }
                    notes.push_str(&inventory(&f));
                }
                let is_js = path.extension().is_some_and(|e| e == "asar") || path.join("resources/app.asar").exists() || path.join("package.json").exists();
                if is_js && let Ok(out) = self.call("js_app_map", json!({"input_path": path.display().to_string(), "limit": 50})) {
                    notes.push_str("\n## JavaScript application\n\n");
                    notes.push_str(&describe(&out));
                }
                let capture = ws.capture_dir();
                std::fs::create_dir_all(&capture).map_err(|e| ToolError::io(capture.display(), e))?;
                let runtime = self.engine.session().settings.runtime_study;
                let mut console = false;
                if runtime && program.is_file() && kinds::runs::is_console(&program) {
                    // A console program draws no window: run it with each input instead.
                    self.step(ws, Step::Study, Status::Inspecting, "Running it with a few inputs to see what it prints…")?;
                    if let Some(section) = self.capture_runs(&program, &capture)? {
                        notes.push_str(&section);
                        console = true;
                    }
                }
                if !console && runtime && program.is_file() && is_program(&program) {
                    notes.push_str(&self.picture_window(ws, &program, &capture)?);
                }
                craft_anything_engine::project::write_atomic(&capture.join("README.md"), notes.as_bytes())?;
            }
            TargetRef::None => {
                let capture = ws.capture_dir();
                std::fs::create_dir_all(&capture).map_err(|e| ToolError::io(capture.display(), e))?;
                craft_anything_engine::project::write_atomic(&capture.join("README.md"), b"# No target\n\nBuild from the request alone.\n")?;
            }
        }
        Ok(())
    }

    pub(super) fn wait_for_website_sign_in(&mut self, ws: &mut Workspace, timeout: Duration) -> Result<(), ToolError> {
        use craft_anything_engine::inbox::RequestKind;
        const CONTINUE: &str = "I'm signed in, continue";
        self.step(ws, Step::Study, Status::NeedsYou, "Sign in in the private browser, then continue here.")?;
        let id = self.inbox.post(
            RequestKind::Question,
            "Sign in before capture",
            "Sign in in the private browser, including any verification steps. Leave it open. Your password and login session stay in that browser. Continue only when the page you want is accessible.",
            vec!["Cancel".into(), CONTINUE.into()],
            false,
            None,
        )?;
        self.relay_inbox();
        let answer = self.inbox.wait(&id, timeout, &|| self.stop.is_cancelled());
        self.stop.check()?;
        match answer {
            Some(a) if a.choice.as_deref() == Some(CONTINUE) => Ok(()),
            Some(_) => Err(ToolError::new(ErrorCode::Cancelled, "Website sign-in was cancelled; nothing was captured.")),
            None => Err(ToolError::new(ErrorCode::TimedOut, "Website sign-in timed out; nothing was captured.")
                .with_remediation("Try again and sign in in the private browser within ten minutes.")),
        }
    }

    /// Deep mode: how the site works, not only how it looks, into capture/how-it-works.md: what its
    /// JavaScript is made of (with readable sources where its maps allow) and ten seconds of what the
    /// start page does (requests, console, WebSocket messages). A part that fails is said, not fatal.
    fn how_it_works(&mut self, ws: &mut Workspace, url: &str, capture: &Path) -> Result<(), ToolError> {
        self.step(ws, Step::Study, Status::Inspecting, "Reading its JavaScript and watching what it does…")?;
        // The routes left the browser on another page; these look at the start page.
        let _ = self.call("web_site_open", json!({"url": url}));
        let mut notes = String::from("# How it works\n\nDeep mode: what the site's JavaScript is made of and what its start page did while we watched.\n");
        let looks = [
            ("Its JavaScript", "web_page_js_analyze", json!({"load_source_maps": true})),
            ("Ten seconds of it", "web_page_watch", json!({"watch_ms": 10_000, "with_websocket_outlines": true})),
        ];
        for (title, tool, params) in looks {
            notes.push_str(&format!("\n## {title}\n\n"));
            notes.push_str(&match self.call(tool, params) {
                Ok(out) => describe(&out),
                Err(e) => format!("{tool} didn't work: {}\n", e.message),
            });
        }
        craft_anything_engine::project::write_atomic(&capture.join(HOW_IT_WORKS), notes.as_bytes())
    }

    /// Clean room: nothing inside the original is read (no files, folder or code). When Settings
    /// allows running it and the person picked the program itself, it is started once and its
    /// window pictured, as anyone could see it.
    fn study_from_outside(&mut self, ws: &mut Workspace, path: &Path) -> Result<(), ToolError> {
        self.step(ws, Step::Study, Status::Inspecting, "Clean room: nothing inside it is read…")?;
        let capture = ws.capture_dir();
        std::fs::create_dir_all(&capture).map_err(|e| ToolError::io(capture.display(), e))?;
        let mut notes = format!(
            "# Clean room\n\nNothing inside {} was read: its files, its folder and its code stay closed, and the tools that look inside are off. Build from the person's request and description and the pictures in reference/, and ask them with core_person_ask when something isn't clear.\n",
            path.display()
        );
        let runtime = self.engine.session().settings.runtime_study;
        if runtime && path.is_file() && is_program(path) {
            notes.push_str(&self.picture_window(ws, path, &capture)?);
        }
        craft_anything_engine::project::write_atomic(&capture.join("README.md"), notes.as_bytes())
    }

    /// Runtime study (Settings): start the program once and picture its window into capture/, for
    /// the notes.
    fn picture_window(&mut self, ws: &mut Workspace, program: &Path, capture: &Path) -> Result<String, ToolError> {
        self.step(ws, Step::Study, Status::Inspecting, "Starting it for a moment to picture its window…")?;
        let shot = capture.join("window.png");
        let tree = capture.join("ui-tree.json");
        let params =
            json!({"program": program.display().to_string(), "wait_secs": 15, "output": shot.display().to_string(), "ui_tree": tree.display().to_string()});
        let picture = "capture/window.png is a picture of its window 15 seconds after it started. Open it with the Read tool: match its layout, colours and proportions.\n";
        let mut notes = String::from("\n## How it looks running\n\n");
        notes.push_str(&match self.call("native_window_capture", params) {
            Ok(_) if tree.is_file() => format!(
                "{picture}capture/ui-tree.json lists the controls in its windows at that moment, in order (role, title, identifier, value, position and size in pixels): use it for the names, order and placement of its menus, buttons and fields.\n"
            ),
            Ok(_) => picture.to_string(),
            Err(e) => format!("Starting it for a picture didn't work ({}), so there's no picture of it running.\n", e.message),
        });
        Ok(notes)
    }

    /// The site's other pages (up to `build.max_pages` same-site pages: links from the start
    /// page, then links from those pages while there's room), each captured into
    /// capture/routes/<name>/ and listed in capture/routes.json. A page that can't be captured is
    /// left out; it never stops the study.
    fn capture_routes(&mut self, ws: &mut Workspace, start: &str, widths: &[u32], capture: &Path) -> Result<(), ToolError> {
        let read = |dir: &Path| std::fs::read(dir.join("capture.json")).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok());
        let found = read(capture).unwrap_or(Value::Null);
        let max = self.engine.session().settings.build.max_pages.min(kinds::website::MAX_ROUTES);
        let picked = kinds::website::pick_routes(&found, start, max);
        let mut kept = self.capture_pages(ws, &picked, widths, capture)?;
        // One level deeper: pages linked from the ones just captured, while there's room.
        if kept.len() < max && !kept.is_empty() {
            let captures: Vec<Value> = kept.iter().filter_map(|r| read(&capture.join("routes").join(&r.slug))).collect();
            let deeper = kinds::website::pick_deeper_routes(&captures, start, &kept, max - kept.len());
            kept.extend(self.capture_pages(ws, &deeper, widths, capture)?);
        }
        if !kept.is_empty() {
            let json = serde_json::to_vec_pretty(&kept).map_err(|e| ToolError::internal(e.to_string()))?;
            craft_anything_engine::project::write_atomic(&capture.join(kinds::website::ROUTES_FILE), &json)?;
        }
        Ok(())
    }

    /// Capture each page into capture/routes/<slug>/; returns the ones that worked.
    fn capture_pages(
        &mut self,
        ws: &mut Workspace,
        picked: &[kinds::website::Route],
        widths: &[u32],
        capture: &Path,
    ) -> Result<Vec<kinds::website::Route>, ToolError> {
        let mut kept = Vec::new();
        if !picked.is_empty() {
            // web_site_capture creates its own folder, inside one that exists.
            std::fs::create_dir_all(capture.join("routes")).map_err(|e| ToolError::io(capture.display(), e))?;
        }
        for (i, r) in picked.iter().enumerate() {
            self.step(ws, Step::Study, Status::Inspecting, &format!("Photographing more pages ({} of {}): {}…", i + 1, picked.len(), r.path))?;
            let dir = capture.join("routes").join(&r.slug);
            let got = self.call("web_site_open", json!({"url": r.url, "require_existing": ws.manifest.website_sign_in})).and_then(|_| {
                self.call(
                    "web_site_capture",
                    json!({"output_directory": dir.display().to_string(), "include_html": false, "widths": widths, "noise_pass": true, "export_images": ws.manifest.website_export_images}),
                )
            });
            match got {
                Ok(_) => kept.push(r.clone()),
                // Said in the feed, not hidden: the page is left out and the study goes on.
                Err(e) => self.step(ws, Step::Study, Status::Inspecting, &format!("Couldn't photograph {}: {}", r.path, e.message))?,
            }
        }
        Ok(kept)
    }

    /// Deep mode with Ghidra installed: run Ghidra's one-time analysis of `program` on its own
    /// thread; the receiver gets its result. The builder's tools share the analysis (waiting for it
    /// rather than starting another), and it carries on if the person pauses, so nothing is lost.
    pub(super) fn prepare_ghidra(&self, program: &Path) -> Option<Receiver<Result<(), String>>> {
        // A folder (nothing in it recognised as the program) isn't something Ghidra can open.
        if !program.is_file() {
            return None;
        }
        let settings = {
            let s = self.engine.session();
            if s.clean_room() || s.settings.ghidra_launcher().is_none() {
                return None;
            }
            s.settings.clone()
        };
        let program = program.to_path_buf();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("ghidra-prepare".into())
            .spawn(move || {
                let result = std::fs::read(&program).map_err(|e| e.to_string()).and_then(|bytes| {
                    let sha = craft_anything_evidence::sha256_hex(&bytes);
                    craft_anything_engine::tools::deep::prepare(&settings, &bytes, &sha, &|_| {})
                });
                if let Err(e) = &result {
                    log::warn!("Ghidra's analysis of {} failed: {e}", program.display());
                }
                let _ = tx.send(result);
            })
            .ok()?;
        Some(rx)
    }
}

/// Deep mode's notes on how a website works, in capture/.
pub(super) const HOW_IT_WORKS: &str = "how-it-works.md";

/// A short text view of a tool result for the study notes.
pub(super) fn describe(out: &ToolOutput) -> String {
    match out {
        ToolOutput::Evidence(e) => {
            let body = serde_json::to_string_pretty(&e.result).unwrap_or_default();
            format!("{}\n\nEvidence {}.\n\n```json\n{}\n```\n", e.summary, e.id, body.chars().take(20_000).collect::<String>())
        }
        ToolOutput::Value(v) => format!("```json\n{}\n```\n", serde_json::to_string_pretty(v).unwrap_or_default().chars().take(20_000).collect::<String>()),
    }
}

#[cfg(test)]
mod capture_tests {
    use super::*;

    #[test]
    fn replacement_preserves_existing_work_and_commits_only_after_success() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("capture")).unwrap();
        std::fs::write(root.path().join("capture/capture.json"), b"old reference").unwrap();
        std::fs::create_dir(root.path().join("app")).unwrap();
        std::fs::write(root.path().join("app/index.html"), b"partially built app").unwrap();
        std::fs::write(root.path().join("transcript.json"), b"builder history").unwrap();
        for outcome in [ErrorCode::Cancelled, ErrorCode::ProgramFailed] {
            let error = replace_capture(root.path(), |next| {
                std::fs::create_dir(next).unwrap();
                std::fs::write(next.join("partial.png"), b"partial output").unwrap();
                Err(ToolError::new(outcome, "fixture stopped"))
            })
            .unwrap_err();
            assert_eq!(error.code, outcome);
            assert_eq!(std::fs::read(root.path().join("capture/capture.json")).unwrap(), b"old reference");
        }
        replace_capture(root.path(), |next| {
            assert_eq!(std::fs::read(root.path().join("capture/capture.json")).unwrap(), b"old reference");
            std::fs::create_dir(next).unwrap();
            std::fs::write(next.join("capture.json"), b"new authenticated reference").unwrap();
            Ok(())
        })
        .unwrap();
        assert_eq!(std::fs::read(root.path().join("capture/capture.json")).unwrap(), b"new authenticated reference");
        assert_eq!(std::fs::read(root.path().join("app/index.html")).unwrap(), b"partially built app");
        assert_eq!(std::fs::read(root.path().join("transcript.json")).unwrap(), b"builder history");
        assert!(std::fs::read_dir(root.path().join("investigation.cany")).unwrap().next().is_none());
    }
}
