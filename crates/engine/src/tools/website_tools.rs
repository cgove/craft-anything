//! Websites as targets: `web_site_open` starts a private browser owned by the session and loads a
//! page; every other browser tool then looks at that page by default (see
//! [`super::web_common::Browser::resolve`]). `web_site_capture` records what a rebuild needs —
//! full-page screenshots at several widths, the rendered HTML, design tokens, a layout outline,
//! assets, links and form outlines — into a folder. `web_site_close` ends the browser.
//!
//! Data minimisation: form field values, cookies and storage are never read; the capture holds
//! what any visitor sees on the page.

use super::artifact_tools::{create_absent_dir, write_new_file};
use super::browser_tools::{browser_env, cleanup, deadline};
use super::native_common::spec;
use super::web_common::{self, Browser, LaunchOptions};
use crate::tool::{Ctx, Effects, Requires, ToolOutput, ToolSpec, Toolset, parse_params, schema_of};
use craft_anything_engines::cdp::{self, CdpClient, CdpEvent, Deadline, Endpoint, PAGE_MAX_MESSAGE};
use craft_anything_evidence::{Authority, Confidence, Coverage, ErrorCode, EvidenceBuilder, Limitation, Location, Subject, ToolError, sha256_hex};
use craft_anything_platform::sync::Mutex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

pub fn specs() -> Vec<ToolSpec> {
    vec![
        spec(
            "web_site_open",
            "Open a website",
            "Load a web page (http/https) in a private browser owned by this session (fresh profile, no history or logins) at a chosen window size, wait for it to finish loading, and report its final address, title and size. Every browser tool then inspects this page unless given another endpoint. Runs the site's scripts, so it needs your approval.",
            "Open a website in a private, hidden browser so it can be studied.",
            Toolset::Browser,
            Effects::EVIDENCE.union(Effects::EXECUTES_FOREIGN_CODE).union(Effects::ACCESSES_NETWORK).union(Effects::LAUNCHES_PROCESS),
            Requires::Engine("chromium"),
            schema_of::<OpenParams>,
            web_site_open,
        ),
        spec(
            "web_site_capture",
            "Capture a website for rebuilding",
            "Record the open website into a new folder: full-page PNG screenshots at each requested width, the rendered HTML, design tokens (fonts, sizes, weights, text and background colours as hex, radii, shadows, spacing, content widths, CSS custom properties), the widths its CSS switches layout at, the layout at each width (page width, heading and text sizes, each section's padding, gap, content column and items per row), a layout outline of visible landmarks, headings, controls and images with positions, asset lists (images, stylesheets, scripts, font files, the requests it made), links and form outlines (never values). Writes capture.json and a README.md summary. With export_images in Deep mode, also save permitted original image files from this browser's cache (100 images, 10 MiB each, 50 MiB total); capture.json lists saved and skipped images. Credentials stay in the browser.",
            "Save pictures and a blueprint of a web page so it can be rebuilt.",
            Toolset::Browser,
            Effects::EVIDENCE.union(Effects::WRITES_FILESYSTEM).union(Effects::ACCESSES_NETWORK),
            Requires::Engine("chromium"),
            schema_of::<CaptureParams>,
            web_site_capture,
        ),
        spec(
            "web_page_states_capture",
            "Capture menus, dialogs and tabs",
            "On the open website, open up to max_states of its visible menus, pop-ups, tabs and collapsed sections (aria-expanded, aria-haspopup, unselected tabs, <summary>; never form controls or submit buttons) one at a time: click it, take a screenshot, record what changed (expanded, a dialog appeared, the tab or the address changed), then put the page back. Writes state-<n>.png and states.json into a new folder. Clicking runs the site's own code, so it needs your approval.",
            "Open the site's menus, pop-ups and tabs and photograph each, so a rebuild can match them too.",
            Toolset::Browser,
            Effects::EVIDENCE.union(Effects::WRITES_FILESYSTEM).union(Effects::EXECUTES_FOREIGN_CODE).union(Effects::ACCESSES_NETWORK),
            Requires::Engine("chromium"),
            schema_of::<StatesParams>,
            web_page_states_capture,
        ),
        spec(
            "web_site_close",
            "Close the website",
            "Close the private browser started by web_site_open and delete its temporary profile.",
            "Close the hidden browser.",
            Toolset::Browser,
            Effects::MUTATES_SESSION.union(Effects::IDEMPOTENT),
            Requires::Engine("chromium"),
            schema_of::<CloseParams>,
            web_site_close,
        ),
    ]
}

/// The session's website browser. The process lives as long as this slot (it is killed and its
/// profile removed when the last handle drops).
pub struct SiteBrowser {
    pub endpoint: Endpoint,
    pub product: String,
    pub version: String,
    pub url: Mutex<String>,
    /// What went wrong while the last page opened ([`page_health`]); web_site_capture records it.
    pub health: Mutex<Value>,
    _owner: Mutex<Browser>,
    handoff: BrowserHandoff,
}

impl SiteBrowser {
    /// Only the path crosses the agent's command line. The connection capability stays in a
    /// private temporary file, outside the workspace and evidence, until the owning run ends.
    pub fn handoff_path(&self) -> PathBuf {
        self.handoff.path.clone()
    }

    /// Join the capture browser from a local MCP process without taking ownership of it.
    pub fn attach(session: &mut crate::Session, path: &Path) -> Result<(), ToolError> {
        if session.clean_room() {
            return Err(ToolError::invalid("Sharing the capture browser requires Deep mode."));
        }
        let file = std::fs::File::open(path).map_err(|_| browser_handoff_error())?;
        let metadata = file.metadata().map_err(|_| browser_handoff_error())?;
        if !metadata.is_file() || metadata.len() > 16_384 {
            return Err(browser_handoff_error());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(browser_handoff_error());
            }
        }
        let mut bytes = Vec::new();
        file.take(16_385).read_to_end(&mut bytes).map_err(|_| browser_handoff_error())?;
        let connection: BrowserConnection = serde_json::from_slice(&bytes).map_err(|_| browser_handoff_error())?;
        if bytes.len() > 16_384 || connection.version != 1 || connection.identity.is_empty() {
            return Err(browser_handoff_error());
        }
        let endpoint = cdp::parse_endpoint(&connection.endpoint).map_err(|_| browser_handoff_error())?;
        let dl = Deadline::new(Duration::from_secs(5), Default::default());
        let info = cdp::json_version(&endpoint, &dl).map_err(|_| browser_handoff_error())?;
        if info["webSocketDebuggerUrl"].as_str() != Some(connection.identity.as_str()) {
            return Err(browser_handoff_error());
        }
        let product = info["Browser"].as_str().unwrap_or("unknown").to_string();
        let version = info["Protocol-Version"].as_str().unwrap_or_default().to_string();
        session.ext.insert(Arc::new(Self {
            _owner: Mutex::new(Browser::attached(&endpoint, &product, &version)),
            endpoint,
            product,
            version,
            url: Mutex::new(String::new()),
            health: Mutex::new(Value::Null),
            handoff: BrowserHandoff { path: path.into(), owned_directory: None, identity: connection.identity },
        }));
        Ok(())
    }

    pub(crate) fn is_live(&self, dl: &Deadline) -> bool {
        self.handoff.path.is_file()
            && cdp::json_version(&self.endpoint, dl).is_ok_and(|info| info["webSocketDebuggerUrl"].as_str() == Some(self.handoff.identity.as_str()))
    }

    /// A non-owning handle for the shared browser helpers.
    fn handle(&self) -> Browser {
        Browser::attached(&self.endpoint, &self.product, &self.version)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserConnection {
    version: u32,
    endpoint: String,
    identity: String,
}

struct BrowserHandoff {
    path: PathBuf,
    owned_directory: Option<PathBuf>,
    identity: String,
}

impl BrowserHandoff {
    fn create(browser: &Browser, dl: &Deadline) -> Result<Self, ToolError> {
        let info = cdp::json_version(&browser.endpoint, dl)?;
        let identity = info["webSocketDebuggerUrl"].as_str().filter(|s| !s.is_empty()).ok_or_else(browser_handoff_error)?.to_string();
        let directory = super::artifact_tools::fresh_temp_dir("craft-browser-handoff")?;
        let handoff = Self { path: directory.join("connection.json"), owned_directory: Some(directory), identity };
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let connection = BrowserConnection { version: 1, endpoint: browser.endpoint.origin.clone(), identity: handoff.identity.clone() };
        let bytes = serde_json::to_vec(&connection).map_err(|_| browser_handoff_error())?;
        options.open(&handoff.path).and_then(|mut f| f.write_all(&bytes)).map_err(|_| browser_handoff_error())?;
        Ok(handoff)
    }
}

impl Drop for BrowserHandoff {
    fn drop(&mut self) {
        if let Some(directory) = &self.owned_directory {
            let _ = std::fs::remove_dir_all(directory);
        }
    }
}

fn browser_handoff_error() -> ToolError {
    ToolError::new(ErrorCode::NotFound, "The signed-in capture browser is no longer available.")
        .with_remediation("Recapture the website and sign in again. Leave its private browser open while building.")
}

// ---------------------------------------------------------------------------------------------
// web_site_open

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OpenParams {
    /// The page to open (http or https).
    pub url: String,
    /// Window width in CSS pixels (320..=3840, default 1440).
    #[serde(default = "d_width")]
    pub width: u32,
    /// Window height in CSS pixels (320..=4000, default 900).
    #[serde(default = "d_height")]
    pub height: u32,
    /// Extra time to let late content settle after the load event, in milliseconds (default 2000).
    #[serde(default = "d_settle")]
    pub settle_ms: u64,
    /// Run the browser without a window (default true).
    #[serde(default = "yes")]
    pub headless: bool,
    /// Require the existing browser to still be open, rather than starting a signed-out replacement.
    #[serde(default)]
    pub require_existing: bool,
    #[serde(default = "d_timeout")]
    pub timeout_secs: u64,
}

fn d_width() -> u32 {
    1440
}
fn d_height() -> u32 {
    900
}
fn d_settle() -> u64 {
    2000
}
fn d_timeout() -> u64 {
    90
}
fn yes() -> bool {
    true
}

/// Only http(s) pages; never local files or browser-internal schemes.
pub fn check_url(url: &str) -> Result<&str, ToolError> {
    let u = url.trim();
    let rest = u.strip_prefix("https://").or_else(|| u.strip_prefix("http://"));
    match rest {
        Some(r) if !r.is_empty() && !r.starts_with('/') && !u.chars().any(char::is_whitespace) => Ok(u),
        _ => Err(ToolError::invalid(format!("{url:?} is not a web address")).with_remediation("Give a full address such as https://example.com.")),
    }
}

/// A URL as shown in evidence and summaries: no credentials, query or fragment.
fn shown_url(url: &str) -> String {
    web_common::sanitize_url(url).split(['?', '#']).next().unwrap_or_default().to_string()
}

fn web_site_open(ctx: &mut Ctx<'_>, params: Value) -> Result<ToolOutput, ToolError> {
    let p: OpenParams = parse_params(params)?;
    let url = check_url(&p.url)?.to_string();
    if !(320..=3840).contains(&p.width) || !(320..=4000).contains(&p.height) {
        return Err(ToolError::invalid("width must be 320..=3840 and height 320..=4000"));
    }
    let dl = deadline(ctx, p.timeout_secs)?;
    let site = match live_site(ctx, &dl)? {
        Some(s) => s,
        None => {
            if p.require_existing {
                return Err(ToolError::new(ErrorCode::NotFound, "The private browser was closed; sign in again before capture.")
                    .with_remediation("Try again and leave the private browser open after signing in."));
            }
            ctx.report(None, "Starting a private browser…");
            let opts = LaunchOptions { allow_launch: true, headless: p.headless, no_sandbox: false, startup_secs: 30 };
            let b = Browser::launch(ctx, &opts, &dl)?;
            let handoff = BrowserHandoff::create(&b, &dl)?;
            let site = Arc::new(SiteBrowser {
                endpoint: b.endpoint.clone(),
                product: b.product.clone(),
                version: b.version.clone(),
                url: Mutex::new(String::new()),
                health: Mutex::new(Value::Null),
                _owner: Mutex::new(b),
                handoff,
            });
            ctx.session.ext.insert(site.clone());
            site
        }
    };
    ctx.report(None, format!("Loading {url}…"));
    let mut client = page_client(&site, &dl)?;
    let r = navigate(&mut client, &url, p.width, p.height, p.settle_ms, &dl).and_then(|health| Ok((health, page_facts(&mut client, &dl)?)));
    cleanup(&mut client, &dl);
    let (health, facts) = r?;
    let final_url = facts.get("url").and_then(Value::as_str).unwrap_or(&url).to_string();
    if let Ok(mut u) = site.url.lock() {
        u.clone_from(&final_url);
    }
    if let Ok(mut h) = site.health.lock() {
        h.clone_from(&health);
    }
    // Clean room keeps what a visitor sees: not the page's load errors, failed requests or size in elements.
    let (visitor, mut facts) = (ctx.session.clean_room(), facts);
    let health = if visitor {
        if let Some(f) = facts.as_object_mut() {
            f.remove("elements");
        }
        Value::Null
    } else {
        health
    };
    let title = facts.get("title").and_then(Value::as_str).unwrap_or_default().to_string();
    let shown = shown_url(&final_url);
    let opened = if title.is_empty() { format!("Opened {shown}.") } else { format!("Opened {shown}: \"{title}\".") };
    let count = |k: &str| health.get(k).and_then(Value::as_array).map_or(0, Vec::len);
    let summary = match (count("errors"), count("failed_requests")) {
        (0, 0) => opened,
        (e, f) => format!("{opened} While loading: {e} error(s), {f} failed request(s)."),
    };
    let browser = site.handle();
    let ev = EvidenceBuilder::new("web_site_open", Subject { kind: "website".into(), sha256: None, name: Some(shown.clone()) }, browser_env(&browser))
        .params(json!({"url": shown, "width": p.width, "height": p.height}))
        .result(json!({"url": final_url, "title": title, "facts": facts, "health": health, "browser": site.product}))
        .summary(summary)
        .confidence(Confidence::Observed)
        .authority(Authority::OurRun)
        .limitation(Limitation::new(
            "private_profile",
            "A private browser profile: existing browser logins are not imported; manual logins last only for this session.",
        ))
        .coverage(Coverage::complete(1))
        .location(Location::new("url", shown))
        .build()?;
    Ok(ToolOutput::evidence(ev))
}

/// The session's website browser when it is still answering; a dead one is dropped.
fn live_site(ctx: &Ctx<'_>, dl: &Deadline) -> Result<Option<Arc<SiteBrowser>>, ToolError> {
    let Some(site) = ctx.session.ext.get::<SiteBrowser>() else { return Ok(None) };
    if site.is_live(dl) {
        return Ok(Some(site));
    }
    Err(browser_handoff_error())
}

fn page_client(site: &SiteBrowser, dl: &Deadline) -> Result<CdpClient, ToolError> {
    let b = site.handle();
    let targets = cdp::json_list(&site.endpoint, dl)?;
    let target = web_common::pick_target(&targets, None, Some("page"))?;
    web_common::connect_target(&b, target, PAGE_MAX_MESSAGE, dl)
}

/// Size the page and pin light mode, so captures don't depend on this computer's theme.
fn set_viewport(client: &mut CdpClient, width: u32, height: u32, dl: &Deadline) -> Result<(), ToolError> {
    client.call("Emulation.setDeviceMetricsOverride", json!({"width": width, "height": height, "deviceScaleFactor": 1, "mobile": width < 600}), None, dl)?;
    let _ = client.call("Emulation.setEmulatedMedia", json!({"features": [{"name": "prefers-color-scheme", "value": "light"}]}), None, dl);
    Ok(())
}

/// Open `url` and wait for it to settle; returns what went wrong while it loaded ([`page_health`]).
fn navigate(client: &mut CdpClient, url: &str, width: u32, height: u32, settle_ms: u64, dl: &Deadline) -> Result<Value, ToolError> {
    client.call("Page.enable", json!({}), None, dl)?;
    // Errors and failed requests are read from the browser's own events; a browser that refuses
    // one of these still loads the page.
    for domain in ["Runtime.enable", "Log.enable", "Network.enable"] {
        let _ = client.call(domain, json!({}), None, dl);
    }
    set_viewport(client, width, height, dl)?;
    let r = client.call("Page.navigate", json!({"url": url}), None, dl)?;
    if let Some(err) = r.get("errorText").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        return Err(ToolError::new(ErrorCode::ProgramFailed, format!("the page didn't load: {err}"))
            .with_remediation("Check the address and your internet connection, then try again."));
    }
    // Wait for the load event (bounded by the overall deadline), then let late content settle.
    let loaded = Deadline::new(Duration::from_secs(45), crate::tool::CancelToken::default());
    let mut done = false;
    let mut seen: Vec<CdpEvent> = Vec::new();
    let mut keep = |events: Vec<CdpEvent>| {
        let wanted = events.into_iter().filter(|e| e.method.starts_with("Runtime.") || e.method.starts_with("Log.") || e.method.starts_with("Network."));
        seen.extend(wanted.take(MAX_HEALTH_EVENTS.saturating_sub(seen.len())));
    };
    while !done && !loaded.expired() && !dl.expired() {
        let slice = Deadline::new(Duration::from_millis(250), crate::tool::CancelToken::default());
        client.pump_until(&slice)?;
        let events = client.take_events();
        done = events.iter().any(|e| e.method == "Page.loadEventFired");
        keep(events);
    }
    let settle = Deadline::new(Duration::from_millis(settle_ms.min(30_000)), crate::tool::CancelToken::default());
    client.pump_until(&settle)?;
    keep(client.take_events());
    for domain in ["Network.disable", "Log.disable"] {
        let _ = client.call(domain, json!({}), None, dl);
    }
    Ok(page_health(&seen))
}

/// Most browser events read for a page's health (a busy page sends thousands of network events).
const MAX_HEALTH_EVENTS: usize = 20_000;

/// What went wrong while a page loaded, from the browser's events: `errors` (uncaught script
/// errors, console errors and error log entries, each text once) and `failed_requests` (answers
/// of 400 or more, and loads that failed). Texts are cut to one line of 300 characters and
/// addresses lose their query strings, so ids in them aren't kept.
pub fn page_health(events: &[CdpEvent]) -> Value {
    let line = |s: &str| s.lines().next().unwrap_or_default().chars().take(300).collect::<String>();
    let str_at = |v: &Value, p: &str| v.pointer(p).and_then(Value::as_str).unwrap_or_default().to_string();
    let mut urls: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut errors: Vec<Value> = Vec::new();
    let mut failed: Vec<Value> = Vec::new();
    let mut add_error = |kind: &str, text: String, url: String| {
        if !text.is_empty() && errors.len() < 30 && !errors.iter().any(|e| e["text"] == text.as_str()) {
            errors.push(json!({"kind": kind, "text": text, "url": shown_url(&url)}));
        }
    };
    for e in events {
        let p = &e.params;
        match e.method.as_str() {
            "Network.requestWillBeSent" => {
                urls.insert(str_at(p, "/requestId"), str_at(p, "/request/url"));
            }
            "Runtime.exceptionThrown" => {
                let d = &p["exceptionDetails"];
                let text = Some(str_at(d, "/exception/description")).filter(|t| !t.is_empty()).unwrap_or_else(|| str_at(d, "/text"));
                add_error("script", line(&text), str_at(d, "/url"));
            }
            "Runtime.consoleAPICalled" if matches!(p["type"].as_str(), Some("error" | "assert")) => {
                let parts: Vec<String> = p["args"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|a| a.get("value").and_then(Value::as_str).or_else(|| a.get("description").and_then(Value::as_str)).map(String::from))
                    .collect();
                add_error("console", line(&parts.join(" ")), String::new());
            }
            // A failed load is also logged by the browser; the network events say it better.
            "Log.entryAdded" if p.pointer("/entry/level") == Some(&json!("error")) && p.pointer("/entry/source") != Some(&json!("network")) => {
                add_error("log", line(&str_at(p, "/entry/text")), str_at(p, "/entry/url"));
            }
            "Network.responseReceived" => {
                let status = p.pointer("/response/status").and_then(Value::as_u64).unwrap_or(0);
                if status >= 400 && failed.len() < 50 {
                    failed.push(json!({"url": shown_url(&str_at(p, "/response/url")), "status": status, "type": p["type"]}));
                }
            }
            "Network.loadingFailed" if p["canceled"] != true && failed.len() < 50 => {
                let url = urls.get(&str_at(p, "/requestId")).cloned().unwrap_or_default();
                failed.push(json!({"url": shown_url(&url), "error": p["errorText"], "type": p["type"]}));
            }
            _ => {}
        }
    }
    json!({"errors": errors, "failed_requests": failed})
}

/// Evaluate one of our own read-only scripts in the page and return its JSON value.
fn eval(client: &mut CdpClient, script: &str, dl: &Deadline) -> Result<Value, ToolError> {
    let r = client.call("Runtime.evaluate", json!({"expression": script, "returnByValue": true, "awaitPromise": true}), None, dl)?;
    if let Some(ex) = r.get("exceptionDetails") {
        let m = ex.pointer("/exception/description").or_else(|| ex.get("text")).and_then(Value::as_str).unwrap_or("script error");
        return Err(ToolError::new(ErrorCode::ProgramFailed, format!("reading the page failed: {}", m.lines().next().unwrap_or(m))));
    }
    Ok(r.pointer("/result/value").cloned().unwrap_or(Value::Null))
}

fn page_facts(client: &mut CdpClient, dl: &Deadline) -> Result<Value, ToolError> {
    eval(
        client,
        "({url: location.href, title: document.title, ready: document.readyState, lang: document.documentElement.lang || '', \
          width: document.documentElement.scrollWidth, height: document.documentElement.scrollHeight, \
          elements: document.getElementsByTagName('*').length, images: document.images.length, links: document.links.length, \
          forms: document.forms.length})",
        dl,
    )
}

// ---------------------------------------------------------------------------------------------
// web_page_states_capture

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StatesParams {
    /// Absolute path of a folder that does not exist yet; the states are written there.
    pub output_directory: String,
    /// Most controls to open (1..=8, default 4).
    #[serde(default = "d_states")]
    pub max_states: usize,
    /// Page width in CSS pixels (320..=3840, default 1440).
    #[serde(default = "d_state_width")]
    pub width: u32,
    #[serde(default = "d_timeout")]
    pub timeout_secs: u64,
}

fn d_states() -> usize {
    4
}
fn d_state_width() -> u32 {
    1440
}

/// Marks the visible toggles (`data-craft-state="<n>"`) and lists them. `__MAX__` is replaced.
const FIND_STATES_JS: &str = r#"(() => {
  const cap = (s, n) => String(s || '').replace(/\s+/g, ' ').trim().slice(0, n);
  const shown = el => { const r = el.getBoundingClientRect(); if (r.width < 1 || r.height < 1) return false; const s = getComputedStyle(el); return s.visibility !== 'hidden' && s.display !== 'none'; };
  const sel = '[aria-expanded="false"], [aria-haspopup]:not([aria-haspopup="false"]), [role="tab"][aria-selected="false"], details:not([open]) > summary';
  const out = [];
  for (const el of document.querySelectorAll(sel)) {
    if (out.length >= __MAX__) break;
    if (!shown(el) || el.closest('form') || el.matches('[type="submit"]')) continue;
    const pop = el.getAttribute('aria-haspopup');
    const kind = el.matches('summary') ? 'section' : el.getAttribute('role') === 'tab' ? 'tab' : pop === 'dialog' ? 'dialog' : 'menu';
    el.setAttribute('data-craft-state', String(out.length));
    out.push({index: out.length, kind, label: cap(el.innerText || el.getAttribute('aria-label') || el.getAttribute('title'), 80)});
  }
  return out;
})()"#;

/// What the page looks like around control `__I__` now.
const STATE_JS: &str = r#"(() => {
  const el = document.querySelector('[data-craft-state="__I__"]');
  const seen = d => { const r = d.getBoundingClientRect(); return r.width > 0 && r.height > 0; };
  const dialogs = Array.from(document.querySelectorAll('[role="dialog"], [role="alertdialog"], dialog[open], [aria-modal="true"]')).filter(seen).length;
  const details = el && el.parentElement && el.parentElement.tagName === 'DETAILS' ? el.parentElement.open : null;
  return {present: !!el, expanded: el ? el.getAttribute('aria-expanded') : null, selected: el ? el.getAttribute('aria-selected') : null, open: details, dialogs, url: location.href};
})()"#;

const CLICK_STATE_JS: &str = r#"(() => { const el = document.querySelector('[data-craft-state="__I__"]'); if (!el) return false; el.scrollIntoView({block: 'center'}); el.click(); return true; })()"#;

fn press_escape(client: &mut CdpClient, dl: &Deadline) {
    for kind in ["keyDown", "keyUp"] {
        let _ = client.call("Input.dispatchKeyEvent", json!({"type": kind, "key": "Escape", "code": "Escape", "windowsVirtualKeyCode": 27}), None, dl);
    }
}

fn settle(client: &mut CdpClient, ms: u64) -> Result<(), ToolError> {
    let d = Deadline::new(Duration::from_millis(ms), crate::tool::CancelToken::default());
    client.pump_until(&d)?;
    let _ = client.take_events();
    Ok(())
}

/// What a click changed, in plain words, from the state before and after.
fn state_change(before: &Value, after: &Value) -> Vec<&'static str> {
    let mut out = Vec::new();
    if after["expanded"] == "true" && before["expanded"] != "true" {
        out.push("expanded");
    }
    if after["selected"] == "true" && before["selected"] != "true" {
        out.push("tab selected");
    }
    if after["open"] == true && before["open"] != true {
        out.push("section opened");
    }
    if after["dialogs"].as_u64().unwrap_or(0) > before["dialogs"].as_u64().unwrap_or(0) {
        out.push("dialog appeared");
    }
    if after["url"] != before["url"] {
        out.push("address changed");
    }
    out
}

fn web_page_states_capture(ctx: &mut Ctx<'_>, params: Value) -> Result<ToolOutput, ToolError> {
    let p: StatesParams = parse_params(params)?;
    if !(1..=8).contains(&p.max_states) {
        return Err(ToolError::invalid("max_states must be 1..=8"));
    }
    if !(320..=3840).contains(&p.width) {
        return Err(ToolError::invalid("width must be 320..=3840"));
    }
    let dl = deadline(ctx, p.timeout_secs.max(30))?;
    let site =
        live_site(ctx, &dl)?.ok_or_else(|| ToolError::new(ErrorCode::NotFound, "no website is open").with_remediation("Open one first with web_site_open."))?;
    let out = create_absent_dir(&p.output_directory)?;
    let mut client = page_client(&site, &dl)?;
    let r = (|| -> Result<(String, Vec<Value>, usize), ToolError> {
        client.call("Page.enable", json!({}), None, &dl)?;
        set_viewport(&mut client, p.width, 900, &dl)?;
        settle(&mut client, 500)?;
        let start = eval(&mut client, "location.href", &dl)?.as_str().unwrap_or_default().to_string();
        let found = eval(&mut client, &FIND_STATES_JS.replace("__MAX__", &p.max_states.to_string()), &dl)?;
        let found = found.as_array().cloned().unwrap_or_default();
        let mut states = Vec::new();
        for (n, c) in found.iter().enumerate() {
            if dl.expired() {
                break;
            }
            let i = c.get("index").and_then(Value::as_u64).unwrap_or(n as u64).to_string();
            ctx.report(Some(n as f32 / found.len().max(1) as f32), format!("Opening {}…", c.get("label").and_then(Value::as_str).unwrap_or("a control")));
            let before = eval(&mut client, &STATE_JS.replace("__I__", &i), &dl)?;
            if eval(&mut client, &CLICK_STATE_JS.replace("__I__", &i), &dl)? != true {
                continue;
            }
            settle(&mut client, 700)?;
            let after = eval(&mut client, &STATE_JS.replace("__I__", &i), &dl).unwrap_or(Value::Null);
            let changed = state_change(&before, &after);
            let mut row = json!({"index": n, "kind": c.get("kind"), "label": c.get("label"), "changed": changed});
            if !changed.contains(&"address changed") {
                let shot = client.call("Page.captureScreenshot", json!({"format": "png"}), None, &dl)?;
                if let Some(data) = shot.get("data").and_then(Value::as_str) {
                    let bytes = web_common::b64_decode(data)?;
                    let name = format!("state-{}.png", n + 1);
                    write_new_file(&out, std::slice::from_ref(&name), &bytes).map_err(ToolError::invalid)?;
                    row["file"] = json!(name);
                    row["sha256"] = json!(sha256_hex(&bytes));
                }
            }
            // Put the page back for the next one: close what opened, or go back to where it was.
            press_escape(&mut client, &dl);
            if after["url"].as_str().is_some_and(|u| u != start) {
                let _ = navigate(&mut client, &start, p.width, 900, 800, &dl)?;
                // The page reloaded: its marks are gone, so mark the toggles again.
                let _ = eval(&mut client, &FIND_STATES_JS.replace("__MAX__", &p.max_states.to_string()), &dl);
            } else if after["expanded"] == "true" || after["open"] == true {
                let _ = eval(&mut client, &CLICK_STATE_JS.replace("__I__", &i), &dl);
            }
            settle(&mut client, 300)?;
            states.push(row);
        }
        Ok((start, states, found.len()))
    })();
    cleanup(&mut client, &dl);
    let (start, states, found) = r?;
    let json_bytes = serde_json::to_vec_pretty(&json!({"url": start, "width": p.width, "states": states})).map_err(|e| ToolError::internal(e.to_string()))?;
    write_new_file(&out, &["states.json".into()], &json_bytes).map_err(ToolError::invalid)?;
    let shown = shown_url(&start);
    let pictured = states.iter().filter(|s| s.get("file").is_some()).count();
    let summary = if found == 0 {
        format!("{shown} has no menus, pop-ups, tabs or collapsed sections to open.")
    } else {
        format!("Opened {} of {found} control(s) on {shown}; {pictured} pictured in {}.", states.len(), out.display())
    };
    let browser = site.handle();
    let ev =
        EvidenceBuilder::new("web_page_states_capture", Subject { kind: "website".into(), sha256: None, name: Some(shown.clone()) }, browser_env(&browser))
            .params(json!({"max_states": p.max_states, "width": p.width}))
            .result(json!({"url": start, "found": found, "states": states, "folder": out.display().to_string()}))
            .summary(summary)
            .confidence(Confidence::Observed)
            .authority(Authority::OurRun)
            .limitation(Limitation::new(
                "first_controls",
                "Only the first controls found are opened, one at a time; menus inside menus and hover-only menus are not.",
            ))
            .coverage(Coverage::complete(states.len() as u64))
            .location(Location::new("url", start))
            .build()?;
    Ok(ToolOutput::evidence(ev))
}

// ---------------------------------------------------------------------------------------------
// web_site_capture

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureParams {
    /// Absolute path of a folder that does not exist yet; the capture is written there.
    pub output_directory: String,
    /// Page widths to screenshot, in CSS pixels (1..=4 widths, each 320..=3840). Default: desktop and phone.
    #[serde(default = "d_widths")]
    pub widths: Vec<u32>,
    /// Tallest screenshot in CSS pixels; longer pages are cut here (600..=20000, default 12000).
    #[serde(default = "d_max_height")]
    pub max_height: u32,
    /// Keep the rendered HTML (default true).
    #[serde(default = "yes")]
    pub include_html: bool,
    /// Photograph each width a second time a moment later and save the parts that changed by
    /// themselves (carousels, videos, animations) as noise-<width>.png, white where it changed,
    /// so comparisons can leave them out (default false).
    #[serde(default)]
    pub noise_pass: bool,
    /// Save loaded original image files through this browser session. Deep mode only; setting
    /// this confirms you own the images or have permission to reuse them. Default false.
    #[serde(default)]
    pub export_images: bool,
    #[serde(default = "d_timeout")]
    pub timeout_secs: u64,
}

fn d_widths() -> Vec<u32> {
    vec![1440, 390]
}
fn d_max_height() -> u32 {
    12_000
}

const MAX_HTML_BYTES: usize = 4 << 20;

/// Our read-only blueprint script. Counts styles, outlines visible structure and lists assets;
/// form fields contribute only their type, name, label and placeholder.
const BLUEPRINT_JS: &str = r#"(() => {
  const cap = (s, n) => String(s || '').replace(/\s+/g, ' ').trim().slice(0, n);
  const box = el => { const r = el.getBoundingClientRect(); return {x: Math.round(r.x + scrollX), y: Math.round(r.y + scrollY), w: Math.round(r.width), h: Math.round(r.height)}; };
  const shown = el => { const r = el.getBoundingClientRect(); if (r.width < 1 || r.height < 1) return false; const s = getComputedStyle(el); return s.visibility !== 'hidden' && s.display !== 'none' && s.opacity !== '0'; };
  const tally = (m, k) => { if (k) m[k] = (m[k] || 0) + 1; };
  const top = (m, n) => Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, n).map(([value, count]) => ({value, count}));
  const fonts = {}, sizes = {}, weights = {}, colors = {}, backgrounds = {}, radii = {}, shadows = {}, bgImages = {}, spacing = {}, maxWidths = {};
  // Colours as #rrggbb(aa), whatever notation the CSS used (oklch, hsl, named…): painted on a 1×1 canvas and read back.
  const cv = document.createElement('canvas'); cv.width = cv.height = 1; const g = cv.getContext('2d', {willReadFrequently: true}); const seenHex = {};
  const hex = c => { if (!c || !g) return c; if (c in seenHex) return seenHex[c]; g.clearRect(0, 0, 1, 1); g.fillStyle = '#000'; g.fillStyle = c; g.fillRect(0, 0, 1, 1); const d = g.getImageData(0, 0, 1, 1).data; const h2 = x => x.toString(16).padStart(2, '0'); return seenHex[c] = '#' + h2(d[0]) + h2(d[1]) + h2(d[2]) + (d[3] < 255 ? h2(d[3]) : ''); };
  const els = [document.documentElement, document.body, ...Array.from(document.querySelectorAll('body *')).slice(0, 12000)].filter(Boolean);
  for (const el of els) {
    if (!shown(el)) continue;
    const s = getComputedStyle(el);
    const text = Array.from(el.childNodes).some(n => n.nodeType === 3 && n.textContent.trim());
    if (text) { tally(fonts, s.fontFamily); tally(sizes, s.fontSize); tally(weights, s.fontWeight); tally(colors, hex(s.color)); }
    if (s.backgroundColor && s.backgroundColor !== 'rgba(0, 0, 0, 0)' && s.backgroundColor !== 'transparent') tally(backgrounds, hex(s.backgroundColor));
    for (const k of ['paddingTop', 'paddingRight', 'paddingBottom', 'paddingLeft', 'rowGap', 'columnGap', 'marginTop', 'marginBottom']) { const v = s[k]; if (v && v.endsWith('px') && v !== '0px') tally(spacing, v); }
    if (s.maxWidth.endsWith('px')) tally(maxWidths, s.maxWidth);
    if (s.borderRadius && s.borderRadius !== '0px') tally(radii, s.borderRadius);
    if (s.boxShadow && s.boxShadow !== 'none') tally(shadows, s.boxShadow);
    const bi = s.backgroundImage; if (bi && bi !== 'none') for (const m of bi.matchAll(/url\(["']?([^"')]+)["']?\)/g)) tally(bgImages, m[1]);
  }
  const vars = {}, bps = {}; let ruleCount = 0, unreadable = 0;
  const bp = (side, n, unit) => tally(bps, side + '-width ' + Math.round(parseFloat(n) * (unit === 'px' ? 1 : 16)) + 'px');
  const walk = (rules, depth) => {
    if (!rules || depth > 6) return;
    for (const r of Array.from(rules)) {
      if (++ruleCount > 40000) return;
      if (r.selectorText && r.selectorText.includes(':root') && r.style) for (const name of Array.from(r.style)) if (name.startsWith('--') && Object.keys(vars).length < 300) vars[name] = cap(r.style.getPropertyValue(name), 120);
      const media = r.media && r.media.mediaText ? r.media.mediaText : (r.conditionText || '');
      for (const m of media.matchAll(/(min|max)-width\s*:\s*([\d.]+)(px|r?em)/g)) bp(m[1], m[2], m[3]);
      for (const m of media.matchAll(/width\s*(>=?|<=?)\s*([\d.]+)(px|r?em)/g)) bp(m[1][0] === '>' ? 'min' : 'max', m[2], m[3]);
      if (r.cssRules) walk(r.cssRules, depth + 1);
    }
  };
  for (const sheet of Array.from(document.styleSheets)) { let rules; try { rules = sheet.cssRules; } catch (e) { unreadable++; continue; } walk(rules, 0); }
  const breakpoints = Object.entries(bps).map(([query, count]) => ({query, px: parseInt(query.split(' ')[1], 10), count})).sort((a, b) => a.px - b.px).slice(0, 24);
  const PICK = 'header,nav,main,footer,section,article,aside,form,h1,h2,h3,h4,p,ul,ol,button,a,img,picture,video,svg,input,select,textarea,[role]';
  const outline = [];
  for (const el of document.querySelectorAll(PICK)) {
    if (outline.length >= 900) break;
    if (!shown(el)) continue;
    let depth = 0; for (let p = el.parentElement; p; p = p.parentElement) depth++;
    const tag = el.tagName.toLowerCase();
    const item = {tag, depth, box: box(el)};
    const role = el.getAttribute('role'); if (role) item.role = role;
    if (el.id) item.id = cap(el.id, 60);
    const cls = typeof el.className === 'string' ? cap(el.className, 120) : ''; if (cls) item.class = cls;
    if (!['main', 'section', 'article', 'header', 'footer', 'nav', 'aside', 'form', 'ul', 'ol', 'svg', 'picture', 'video'].includes(tag)) { const t = cap(el.innerText, 200); if (t) item.text = t; }
    if (tag === 'a') item.href = el.href || '';
    if (tag === 'img') { item.src = el.currentSrc || el.src || ''; item.alt = cap(el.alt, 120); }
    if (['input', 'select', 'textarea'].includes(tag)) { item.type = el.type || tag; item.name = cap(el.name, 60); item.placeholder = cap(el.placeholder, 80); }
    const s = getComputedStyle(el);
    if (['header', 'nav', 'main', 'footer', 'section', 'article', 'aside', 'form', 'ul', 'ol'].includes(tag)) { item.display = s.display; if (s.display.includes('flex')) item.flex = s.flexDirection; if (s.display.includes('grid')) item.grid = cap(s.gridTemplateColumns, 120); }
    item.font = s.fontSize + ' ' + s.fontWeight; item.color = hex(s.color); if (s.backgroundColor !== 'rgba(0, 0, 0, 0)') item.background = hex(s.backgroundColor);
    outline.push(item);
  }
  const labelFor = el => { if (el.labels && el.labels[0]) return cap(el.labels[0].innerText, 80); return cap(el.getAttribute('aria-label'), 80); };
  const forms = Array.from(document.forms).slice(0, 30).map(f => ({action: f.getAttribute('action') || '', method: (f.method || 'get').toLowerCase(),
    fields: Array.from(f.elements).slice(0, 60).map(e => ({tag: e.tagName.toLowerCase(), type: e.type || '', name: cap(e.name, 60), label: labelFor(e), placeholder: cap(e.placeholder, 80), required: !!e.required}))}));
  const links = Array.from(document.links).slice(0, 400).map(a => ({text: cap(a.innerText || a.getAttribute('aria-label'), 100), href: a.href}));
  const meta = n => { const m = document.querySelector(`meta[name="${n}"],meta[property="${n}"]`); return m ? cap(m.content, 300) : ''; };
  const icons = Array.from(document.querySelectorAll('link[rel~="icon"],link[rel="apple-touch-icon"]')).map(l => l.href).slice(0, 10);
  // What the page loaded, without query strings (they can carry ids).
  const resources = (performance.getEntriesByType ? performance.getEntriesByType('resource') : []).map(e => ({url: String(e.name).split(/[?#]/)[0], type: e.initiatorType, bytes: e.transferSize || 0}));
  // Accessibility at a glance: controls a screen reader can't name, pictures without alt text,
  // the landmarks and the page language.
  const CONTROLS = 'a[href],button,input:not([type="hidden"]),select,textarea,[role="button"],[role="link"],[role="tab"],[role="menuitem"]';
  const named = el => !!(cap(el.innerText, 80) || el.getAttribute('aria-label') || el.getAttribute('aria-labelledby') || el.getAttribute('title')
    || (el.labels && el.labels.length) || el.getAttribute('placeholder') || (['submit', 'button', 'reset'].includes(el.type) && el.value)
    || el.querySelector('img[alt]:not([alt=""]),svg title,[aria-label]'));
  const unnamed = Array.from(document.querySelectorAll(CONTROLS)).slice(0, 3000).filter(el => shown(el) && !named(el));
  const landmarks = {};
  for (const el of document.querySelectorAll('header,nav,main,footer,aside,form[aria-label],[role="banner"],[role="navigation"],[role="main"],[role="contentinfo"],[role="complementary"],[role="search"]')) {
    if (!shown(el)) continue;
    const role = el.getAttribute('role') || {header: 'banner', nav: 'navigation', main: 'main', footer: 'contentinfo', aside: 'complementary', form: 'form'}[el.tagName.toLowerCase()];
    tally(landmarks, role);
  }
  const a11y = {lang: document.documentElement.lang || '', landmarks, unnamed_controls: unnamed.length,
    unnamed_examples: unnamed.slice(0, 5).map(el => el.tagName.toLowerCase() + (el.className && typeof el.className === 'string' ? '.' + cap(el.className, 40).split(' ')[0] : '')),
    images_without_alt: Array.from(document.images).filter(i => shown(i) && !i.hasAttribute('alt')).length};
  const fontFaces = []; try { document.fonts.forEach(f => { if (fontFaces.length < 80) fontFaces.push({family: f.family, weight: f.weight, style: f.style, status: f.status}); }); } catch (e) {}
  return {
    url: location.href, title: document.title, lang: document.documentElement.lang || '',
    viewport: {w: innerWidth, h: innerHeight}, page: {w: document.documentElement.scrollWidth, h: document.documentElement.scrollHeight},
    meta: {description: meta('description'), theme_color: meta('theme-color'), og_title: meta('og:title'), og_image: meta('og:image'), icons},
    design: {fonts: top(fonts, 12), font_sizes: top(sizes, 16), font_weights: top(weights, 8), text_colors: top(colors, 16), backgrounds: top(backgrounds, 16), radii: top(radii, 10), shadows: top(shadows, 8), spacing: top(spacing, 24), max_widths: top(maxWidths, 8), css_variables: vars, font_faces: fontFaces},
    breakpoints, unreadable_stylesheets: unreadable, a11y,
    outline, forms, links,
    assets: {
      images: Array.from(document.images).slice(0, 300).map(i => ({src: i.currentSrc || i.src, w: i.naturalWidth, h: i.naturalHeight, alt: cap(i.alt, 120)})),
      background_images: top(bgImages, 60).map(x => x.value),
      stylesheets: Array.from(document.styleSheets).map(s => s.href).filter(Boolean).slice(0, 80),
      scripts: Array.from(document.scripts).map(s => s.src).filter(Boolean).slice(0, 120),
      inline_scripts: Array.from(document.scripts).filter(s => !s.src).length,
      fonts: resources.filter(r => /\.(woff2?|ttf|otf|eot)$/i.test(r.url) || r.url.includes('fonts.googleapis.com')).map(r => r.url).slice(0, 40),
      requests: resources.slice(0, 300)
    },
    headings: Array.from(document.querySelectorAll('h1,h2,h3')).slice(0, 120).map(h => ({level: Number(h.tagName[1]), text: cap(h.innerText, 160)})),
    text: cap(document.body ? document.body.innerText : '', 30000)
  };
})()"#;

/// Our read-only layout script, run at every width: the page's width (wider than the window means
/// it scrolls sideways), heading and text sizes, and each landmark and section's padding, gap,
/// background, content column and how many items sit side by side.
const LAYOUT_JS: &str = r#"(() => {
  const cap = (s, n) => String(s || '').replace(/\s+/g, ' ').trim().slice(0, n);
  const px = v => Math.round(parseFloat(v) || 0);
  const shown = el => { const r = el.getBoundingClientRect(); if (r.width < 1 || r.height < 1) return false; const s = getComputedStyle(el); return s.visibility !== 'hidden' && s.display !== 'none' && s.opacity !== '0'; };
  const size = sel => { const el = Array.from(document.querySelectorAll(sel)).slice(0, 50).find(shown); return el ? px(getComputedStyle(el).fontSize) : 0; };
  const cv = document.createElement('canvas'); cv.width = cv.height = 1; const g = cv.getContext('2d', {willReadFrequently: true});
  const hex = c => { if (!g) return c; g.clearRect(0, 0, 1, 1); g.fillStyle = '#000'; g.fillStyle = c; g.fillRect(0, 0, 1, 1); const d = g.getImageData(0, 0, 1, 1).data; const h2 = x => x.toString(16).padStart(2, '0'); return '#' + h2(d[0]) + h2(d[1]) + h2(d[2]) + (d[3] < 255 ? h2(d[3]) : ''); };
  // Items side by side: the most children of one box sharing a top edge, counting only children at
  // least 15% of the block's width (cards and columns, not inline links or logo strips).
  const perRow = (root, width) => {
    let best = 1, seen = 0;
    for (const c of [root, ...root.querySelectorAll('*')]) {
      if (++seen > 400) break;
      if (c.children.length < 2) continue;
      const kids = Array.from(c.children).filter(k => shown(k) && k.getBoundingClientRect().width >= Math.max(40, width * 0.15));
      if (kids.length < 2) continue;
      const top = kids[0].getBoundingClientRect().top;
      best = Math.max(best, kids.filter(k => Math.abs(k.getBoundingClientRect().top - top) <= 2).length);
    }
    return best;
  };
  const blocks = [];
  for (const el of document.querySelectorAll('header,nav,main,footer,section,article,aside')) {
    if (blocks.length >= 60) break;
    if (!shown(el)) continue;
    const r = el.getBoundingClientRect(); if (r.height < 24) continue;
    const s = getComputedStyle(el);
    const b = {tag: el.tagName.toLowerCase(), y: Math.round(r.top + scrollY), w: Math.round(r.width), h: Math.round(r.height),
      pad: [px(s.paddingTop), px(s.paddingRight), px(s.paddingBottom), px(s.paddingLeft)], per_row: perRow(el, r.width)};
    const head = Array.from(el.querySelectorAll('h1,h2,h3')).slice(0, 20).find(shown); if (head) b.heading = cap(head.innerText, 80);
    const gap = px(s.columnGap) || px(s.rowGap); if (gap) b.gap = gap;
    if (s.backgroundColor !== 'rgba(0, 0, 0, 0)') b.background = hex(s.backgroundColor);
    // The content column: the first box (itself or inside) held to a maximum width in px.
    let n = 0;
    for (const c of [el, ...el.querySelectorAll('*')]) {
      if (++n > 80) break;
      const cs = getComputedStyle(c);
      if (cs.maxWidth.endsWith('px') && !['IMG', 'SVG', 'VIDEO', 'PICTURE'].includes(c.tagName.toUpperCase()) && shown(c)) {
        const cr = c.getBoundingClientRect();
        b.column = {max_w: px(cs.maxWidth), x: Math.round(cr.left), w: Math.round(cr.width), pad: [px(cs.paddingLeft), px(cs.paddingRight)]};
        break;
      }
    }
    blocks.push(b);
  }
  return {page_w: document.documentElement.scrollWidth, page_h: document.documentElement.scrollHeight,
    type: {h1: size('h1'), h2: size('h2'), h3: size('h3'), body: size('p')}, blocks};
})()"#;

fn web_site_capture(ctx: &mut Ctx<'_>, params: Value) -> Result<ToolOutput, ToolError> {
    let p: CaptureParams = parse_params(params)?;
    if p.widths.is_empty() || p.widths.len() > 4 || p.widths.iter().any(|w| !(320..=3840).contains(w)) {
        return Err(ToolError::invalid("widths must hold 1..=4 values, each 320..=3840"));
    }
    if !(600..=20_000).contains(&p.max_height) {
        return Err(ToolError::invalid("max_height must be 600..=20000"));
    }
    let mut p = p;
    // Clean room keeps what a visitor sees: never the page's own code.
    let visitor = ctx.session.clean_room();
    if p.export_images && visitor {
        return Err(ToolError::invalid("Original image export requires Deep mode and permission to reuse the images."));
    }
    p.include_html &= !visitor;
    let dl = deadline(ctx, p.timeout_secs.max(30))?;
    let site =
        live_site(ctx, &dl)?.ok_or_else(|| ToolError::new(ErrorCode::NotFound, "no website is open").with_remediation("Open one first with web_site_open."))?;
    let out = create_absent_dir(&p.output_directory)?;
    let mut client = page_client(&site, &dl)?;
    let r = capture_into(ctx, &mut client, &out, &p, &dl);
    // Leave the page at the first (usually desktop) width for the tools that follow.
    if let Some(w) = p.widths.first() {
        let _ = set_viewport(&mut client, *w, 900, &dl);
    }
    cleanup(&mut client, &dl);
    let (mut blueprint, shots, html_bytes) = r?;
    if visitor {
        visitor_view(&mut blueprint);
    } else if let (Value::Object(b), Ok(h)) = (&mut blueprint, site.health.lock()) {
        b.insert("health".into(), h.clone());
    }

    let url = blueprint.get("url").and_then(Value::as_str).unwrap_or_default().to_string();
    let shown = shown_url(&url);
    let n = |k: &str| blueprint.get(k).and_then(Value::as_array).map_or(0, Vec::len);
    let images = blueprint.pointer("/assets/images").and_then(Value::as_array).map_or(0, Vec::len);
    let readme = readme(&blueprint, &shots, html_bytes, visitor);
    write_new_file(&out, &["README.md".into()], readme.as_bytes()).map_err(ToolError::invalid)?;
    let capture_json = serde_json::to_vec_pretty(&blueprint).map_err(|e| ToolError::internal(e.to_string()))?;
    write_new_file(&out, &["capture.json".into()], &capture_json).map_err(ToolError::invalid)?;

    let summary = format!(
        "Captured {shown}: {} screenshot(s), {} outline items, {} headings, {images} images, {} links, {} forms → {}.",
        shots.len(),
        n("outline"),
        n("headings"),
        n("links"),
        n("forms"),
        out.display()
    );
    let browser = site.handle();
    let ev = EvidenceBuilder::new("web_site_capture", Subject { kind: "website".into(), sha256: None, name: Some(shown.clone()) }, browser_env(&browser))
        .params(json!({"widths": p.widths, "max_height": p.max_height, "include_html": p.include_html, "noise_pass": p.noise_pass, "visitor_view": visitor}))
        .result(json!({
            "output_directory": out.display().to_string(),
            "url": url,
            "title": blueprint.get("title"),
            "screenshots": shots,
            "html_bytes": html_bytes,
            "exported_images": blueprint.get("exported_images"),
            "counts": {"outline": n("outline"), "headings": n("headings"), "links": n("links"), "forms": n("forms"), "images": images},
            "design": blueprint.get("design"),
            "files": ["README.md", "capture.json"],
        }))
        .summary(summary)
        .confidence(Confidence::Observed)
        .authority(Authority::OurRun)
        .limitation(Limitation::new("one_state", "One state of the page: menus, dialogs and content behind interactions are not opened."))
        .limitation(if visitor {
            Limitation::new("visitor_view", "Clean room: only what a visitor sees was kept (screenshots, visible text, measured layout and styles); not the page's HTML, CSS rules, scripts, requests or errors.")
        } else {
            Limitation::new("cross_origin_css", "CSS custom properties and breakpoints from cross-origin stylesheets can't be read.")
        })
        .coverage(Coverage::complete(p.widths.len() as u64))
        .location(Location::new("url", shown))
        .location(Location::new("path", out.display().to_string()))
        .build()?;
    Ok(ToolOutput::evidence(ev))
}

type Captured = (Value, Vec<Value>, usize);

fn capture_into(ctx: &Ctx<'_>, client: &mut CdpClient, out: &Path, p: &CaptureParams, dl: &Deadline) -> Result<Captured, ToolError> {
    client.call("Page.enable", json!({}), None, dl)?;
    let mut shots = Vec::new();
    let mut blueprint = Value::Null;
    let mut layouts = Vec::new();
    for (i, &w) in p.widths.iter().enumerate() {
        ctx.report(Some(i as f32 / p.widths.len() as f32), format!("Photographing the page at {w} px…"));
        set_viewport(client, w, 900, dl)?;
        settle(client, 900)?;
        if i == 0 {
            // The blueprint is read at the first width, where the layout is the reference one.
            blueprint = eval(client, BLUEPRINT_JS, dl)?;
        }
        // A page whose layout can't be read is still photographed.
        if let Ok(Value::Object(mut layout)) = eval(client, LAYOUT_JS, dl) {
            layout.insert("width".into(), json!(w));
            layouts.push(Value::Object(layout));
        }
        let height = eval(client, "Math.max(document.documentElement.scrollHeight, document.body ? document.body.scrollHeight : 0)", dl)?
            .as_u64()
            .unwrap_or(900)
            .clamp(320, u64::from(p.max_height));
        let clip = json!({"format": "png", "captureBeyondViewport": true, "clip": {"x": 0, "y": 0, "width": w, "height": height, "scale": 1}});
        let photograph = |client: &mut CdpClient| -> Result<Vec<u8>, ToolError> {
            let shot = client.call("Page.captureScreenshot", clip.clone(), None, dl)?;
            let data =
                shot.get("data").and_then(Value::as_str).ok_or_else(|| ToolError::new(ErrorCode::GarbledOutput, "the browser returned no screenshot"))?;
            web_common::b64_decode(data)
        };
        let bytes = photograph(client)?;
        let (pw, ph) = web_common::png_dimensions(&bytes)?;
        let name = format!("screenshot-{w}.png");
        write_new_file(out, std::slice::from_ref(&name), &bytes).map_err(ToolError::invalid)?;
        let mut row = json!({"file": name, "width": pw, "height": ph, "css_width": w, "sha256": sha256_hex(&bytes), "cut": height >= u64::from(p.max_height)});
        if p.noise_pass {
            // The same page twice more, at uneven gaps so something repeating every so often
            // can't look still in both: what changed by itself moves, not the build's fault.
            settle(client, 900)?;
            let second = photograph(client)?;
            settle(client, 1300)?;
            let third = photograph(client)?;
            if let (Ok(a), Ok(b), Ok(c)) = (web_common::decode_png(&bytes), web_common::decode_png(&second), web_common::decode_png(&third)) {
                let mask = web_common::NoiseMask::between(&a, &b, 24).union(&web_common::NoiseMask::between(&a, &c, 24));
                row["noise_tiles"] = json!(mask.count());
                if mask.count() > 0 {
                    let file = format!("noise-{w}.png");
                    write_new_file(out, std::slice::from_ref(&file), &mask.to_png()?).map_err(ToolError::invalid)?;
                    row["noise_file"] = json!(file);
                }
            }
        }
        shots.push(row);
    }
    if let Value::Object(b) = &mut blueprint {
        b.insert("layouts".into(), Value::Array(layouts));
        if p.export_images {
            b.insert("exported_images".into(), export_images(client, out, dl)?);
        }
    }
    let mut html_bytes = 0;
    if p.include_html {
        let html = eval(client, "document.documentElement.outerHTML", dl)?;
        let html = html.as_str().unwrap_or_default();
        let kept = truncate_utf8(html, MAX_HTML_BYTES);
        html_bytes = kept.len();
        write_new_file(out, &["page.html".into()], kept.as_bytes()).map_err(ToolError::invalid)?;
    }
    Ok((blueprint, shots, html_bytes))
}

const MAX_EXPORT_IMAGES: usize = 100;
const MAX_IMAGE_BYTES: usize = 10 * 1024 * 1024;
const MAX_IMAGES_BYTES: usize = 50 * 1024 * 1024;

/// Read only images already loaded by this page, through its browser cache. No credentials are
/// read or replayed by an HTTP client, and filenames never come from the remote site.
fn export_images(client: &mut CdpClient, out: &Path, dl: &Deadline) -> Result<Value, ToolError> {
    let tree = client.call("Page.getResourceTree", json!({}), None, dl)?;
    let frame = tree.get("frameTree").unwrap_or(&Value::Null);
    let frame_id = frame.pointer("/frame/id").and_then(Value::as_str).unwrap_or_default();
    let resources = frame.get("resources").and_then(Value::as_array);
    let mut saved = Vec::new();
    let mut skipped = Vec::new();
    let mut total = 0usize;
    let mut seen = std::collections::HashSet::new();
    let mut candidates = 0usize;
    for r in resources.into_iter().flatten().filter(|r| r.get("type").and_then(Value::as_str) == Some("Image")) {
        let Some(url) = r.get("url").and_then(Value::as_str) else { continue };
        if !seen.insert(url) {
            continue;
        }
        candidates += 1;
        if candidates > MAX_EXPORT_IMAGES {
            continue;
        }
        let source = if url.starts_with("http://") || url.starts_with("https://") { shown_url(url) } else { "inline image".into() };
        let mime = r.get("mimeType").and_then(Value::as_str).unwrap_or_default();
        let ext = match mime.split(';').next().unwrap_or_default().trim() {
            "image/png" => "png",
            "image/jpeg" => "jpg",
            "image/gif" => "gif",
            "image/webp" => "webp",
            "image/avif" => "avif",
            "image/svg+xml" => "svg",
            "image/x-icon" | "image/vnd.microsoft.icon" => "ico",
            _ => {
                skipped.push(json!({"source": source, "reason": "unsupported image type"}));
                continue;
            }
        };
        if total >= MAX_IMAGES_BYTES || r.get("contentSize").and_then(Value::as_u64).is_some_and(|n| n > MAX_IMAGE_BYTES as u64) {
            skipped.push(json!({"source": source, "reason": "image export size limit"}));
            continue;
        }
        let body = client.call("Page.getResourceContent", json!({"frameId": frame_id, "url": url}), None, dl);
        let bytes = body.and_then(|body| image_body(&body));
        let bytes = match bytes {
            Ok(bytes) if !bytes.is_empty() && total.saturating_add(bytes.len()) <= MAX_IMAGES_BYTES => bytes,
            _ => {
                skipped.push(json!({"source": source, "reason": "image unavailable or exceeds export size limit"}));
                continue;
            }
        };
        if ext != "svg" && image::guess_format(&bytes).is_err() {
            skipped.push(json!({"source": source, "reason": "not a recognized image file"}));
            continue;
        }
        let hash = sha256_hex(&bytes);
        let file = format!("image-{}.{ext}", saved.len() + 1);
        write_new_file(out, &["images".into(), file.clone()], &bytes).map_err(ToolError::invalid)?;
        total += bytes.len();
        saved.push(json!({"source": source, "file": format!("images/{file}"), "mime_type": mime, "bytes": bytes.len(), "sha256": hash}));
    }
    Ok(json!({"files": saved, "skipped": skipped, "over_count_limit": candidates.saturating_sub(MAX_EXPORT_IMAGES), "total_bytes": total,
        "limitation": "Only images already loaded in the main page and available in its browser cache are exported; lazy images, iframe images and unsupported formats may be absent."}))
}

fn image_body(body: &Value) -> Result<Vec<u8>, ToolError> {
    let content = body.get("content").and_then(Value::as_str).ok_or_else(|| ToolError::invalid("No image body in browser cache."))?;
    let encoded = body.get("base64Encoded").and_then(Value::as_bool).unwrap_or(false);
    if content.len() > if encoded { MAX_IMAGE_BYTES.div_ceil(3) * 4 } else { MAX_IMAGE_BYTES } {
        return Err(ToolError::invalid("Image exceeds export size limit."));
    }
    let bytes = if encoded { web_common::b64_decode(content)? } else { content.as_bytes().to_vec() };
    if bytes.len() > MAX_IMAGE_BYTES {
        return Err(ToolError::invalid("Image exceeds export size limit."));
    }
    Ok(bytes)
}

fn truncate_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s.get(..end).unwrap_or_default()
}

/// Drop everything a visitor can't see: the page's metadata, CSS variables and breakpoints, the
/// stylesheets, scripts, fonts and requests it loaded, and where its pictures come from (their sizes
/// stay). Screenshots, visible text, the measured layout and styles, links and forms are kept.
fn visitor_view(blueprint: &mut Value) {
    let Value::Object(b) = blueprint else { return };
    for k in ["meta", "breakpoints", "unreadable_stylesheets", "health"] {
        b.remove(k);
    }
    if let Some(Value::Object(d)) = b.get_mut("design") {
        d.remove("css_variables");
        d.remove("font_faces");
    }
    let images: Vec<Value> = b
        .get("assets")
        .and_then(|a| a.get("images"))
        .and_then(Value::as_array)
        .map(|a| a.iter().map(|i| json!({"w": i.get("w"), "h": i.get("h")})).collect())
        .unwrap_or_default();
    b.insert("assets".into(), json!({"images": images}));
}

/// A short human/agent-readable summary of the capture folder.
fn readme(b: &Value, shots: &[Value], html_bytes: usize, visitor: bool) -> String {
    let s = |p: &str| b.pointer(p).and_then(Value::as_str).unwrap_or_default().to_string();
    let top = |p: &str, n: usize| {
        b.pointer(p)
            .and_then(Value::as_array)
            .map(|a| a.iter().take(n).filter_map(|x| x.get("value").and_then(Value::as_str)).map(|v| format!("`{v}`")).collect::<Vec<_>>().join(", "))
            .unwrap_or_default()
    };
    let mut md = format!("# Capture of {}\n\n", shown_url(&s("/url")));
    if let Some(exported) = b.get("exported_images") {
        let count = |key: &str| exported.get(key).and_then(Value::as_array).map_or(0, Vec::len);
        md.push_str(&format!("Original image export: {} files saved under `images/`, {} skipped, {} beyond the count limit. See `exported_images` in `capture.json` for files, hashes and reasons. Only images already loaded in the main page and available in its browser cache can be saved.\n\n", count("files"), count("skipped"), exported.get("over_count_limit").and_then(Value::as_u64).unwrap_or(0)));
    }
    md.push_str(&format!("- Title: {}\n", s("/title")));
    if !s("/meta/description").is_empty() {
        md.push_str(&format!("- Description: {}\n", s("/meta/description")));
    }
    md.push_str(&format!(
        "- Page size at the first width: {}×{} CSS px\n\n",
        b.pointer("/page/w").and_then(Value::as_u64).unwrap_or(0),
        b.pointer("/page/h").and_then(Value::as_u64).unwrap_or(0)
    ));
    md.push_str("## Files\n\n");
    for sh in shots {
        md.push_str(&format!(
            "- `{}` — {}×{} px screenshot{}\n",
            sh["file"].as_str().unwrap_or_default(),
            sh["width"],
            sh["height"],
            if sh["cut"].as_bool().unwrap_or(false) { " (cut at the height limit)" } else { "" }
        ));
        if let Some(noise) = sh["noise_file"].as_str() {
            md.push_str(&format!(
                "- `{noise}` — the parts that changed by themselves between two photos a moment apart (white, one pixel per 16 px square): carousels, videos, animations. They aren't compared.\n"
            ));
        }
    }
    if html_bytes > 0 {
        md.push_str(&format!("- `page.html` — rendered HTML ({html_bytes} bytes)\n"));
    }
    if visitor {
        md.push_str("- `capture.json` — design tokens, the layout at each width (`layouts`), layout outline (positions in CSS px), headings, links, forms, picture sizes and visible text\n\n");
        md.push_str("Clean room: only what a visitor sees was kept. The page's HTML, CSS rules, scripts, requests and errors weren't read.\n\n");
    } else {
        md.push_str("- `capture.json` — design tokens, breakpoints, the layout at each width (`layouts`), layout outline (positions in CSS px), headings, links, forms, assets and visible text\n\n");
    }
    md.push_str("## Design at a glance\n\n");
    md.push_str(&format!("- Fonts: {}\n", top("/design/fonts", 4)));
    md.push_str(&format!("- Text sizes: {}\n", top("/design/font_sizes", 8)));
    md.push_str(&format!("- Text colours: {}\n", top("/design/text_colors", 6)));
    md.push_str(&format!("- Backgrounds: {}\n", top("/design/backgrounds", 6)));
    md.push_str(&format!("- Corner radii: {}\n", top("/design/radii", 5)));
    md.push_str(&format!("- Spacing (padding, gaps, margins): {}\n", top("/design/spacing", 10)));
    md.push_str(&format!("- Content widths: {}\n", top("/design/max_widths", 4)));
    if visitor {
        md.push('\n');
    } else {
        md.push_str(&format!("- Font files: {}\n\n", b.pointer("/assets/fonts").and_then(Value::as_array).map_or(0, Vec::len)));
    }
    md.push_str(&layout_section(b, visitor));
    if !visitor {
        md.push_str(&health_section(b));
    }
    md.push_str("## Headings\n\n");
    for h in b.pointer("/headings").and_then(Value::as_array).into_iter().flatten().take(40) {
        let level = h.get("level").and_then(Value::as_u64).unwrap_or(1) as usize;
        md.push_str(&format!("{}- {}\n", "  ".repeat(level.saturating_sub(1)), h.get("text").and_then(Value::as_str).unwrap_or_default()));
    }
    md
}

/// What went wrong while the page loaded and how it reads to a screen reader, for the README.
fn health_section(b: &Value) -> String {
    let list = |p: &str| b.pointer(p).and_then(Value::as_array).cloned().unwrap_or_default();
    let (errors, failed) = (list("/health/errors"), list("/health/failed_requests"));
    let mut md = String::from("## Page health\n\n");
    if errors.is_empty() && failed.is_empty() {
        md.push_str("It loaded without script errors or failed requests.\n\n");
    } else {
        for e in errors.iter().take(10) {
            md.push_str(&format!("- {} error: {}\n", e["kind"].as_str().unwrap_or("script"), e["text"].as_str().unwrap_or_default()));
        }
        for f in failed.iter().take(10) {
            let why = f["status"].as_u64().map(|s| s.to_string()).or_else(|| f["error"].as_str().map(String::from)).unwrap_or_default();
            md.push_str(&format!("- failed request ({why}): {}\n", f["url"].as_str().unwrap_or_default()));
        }
        md.push('\n');
    }
    if let Some(a) = b.get("a11y") {
        let n = |k: &str| a.get(k).and_then(Value::as_u64).unwrap_or(0);
        let lang = a.get("lang").and_then(Value::as_str).filter(|l| !l.is_empty()).unwrap_or("not set");
        md.push_str(&format!(
            "## Accessibility\n\nLanguage: {lang}. Controls without a name: {}. Pictures without alt text: {}.\n\n",
            n("unnamed_controls"),
            n("images_without_alt")
        ));
    }
    md
}

/// The widths the page's CSS switches layout at, for the README.
fn breakpoints_section(b: &Value) -> String {
    let bps: Vec<String> = b
        .pointer("/breakpoints")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|q| q.get("query").and_then(Value::as_str))
        .map(String::from)
        .collect();
    let unreadable = b.get("unreadable_stylesheets").and_then(Value::as_u64).unwrap_or(0);
    let body = match (bps.is_empty(), unreadable) {
        (true, 0) => "Its CSS has no width breakpoints.\n\n".to_string(),
        (true, u) => format!("None readable: {u} stylesheet(s) from other sites can't be read; compare the screenshots at each width.\n\n"),
        (false, _) => format!("Its CSS switches layout at: {}\n\n", bps.join(", ")),
    };
    format!("## Breakpoints\n\n{body}")
}

/// Breakpoints (not in a visitor's view) and the layout at each width, for the README.
fn layout_section(b: &Value, visitor: bool) -> String {
    let n = |v: &Value, k: &str| v.get(k).and_then(Value::as_u64).unwrap_or(0);
    let mut md = String::new();
    if !visitor {
        md.push_str(&breakpoints_section(b));
    }
    md.push_str("## Layout at each width\n\n");
    for l in b.pointer("/layouts").and_then(Value::as_array).into_iter().flatten() {
        let (w, pw) = (n(l, "width"), n(l, "page_w"));
        let ty = |k: &str| l.pointer(&format!("/type/{k}")).and_then(Value::as_u64).unwrap_or(0);
        let scroll = if pw > w + 1 { format!("page {pw} px wide, so it scrolls sideways") } else { "no sideways scroll".into() };
        md.push_str(&format!("### {w} px ({scroll})\n\nHeadings {}/{}/{} px, text {} px.\n\n", ty("h1"), ty("h2"), ty("h3"), ty("body")));
        for blk in l.get("blocks").and_then(Value::as_array).into_iter().flatten().take(16) {
            md.push_str(&format!("- {}\n", block_line(blk)));
        }
        md.push('\n');
    }
    md
}

/// One section at one width: `section "Pricing": padding 96 32 96 32, gap 24, 3 per row, column 1280 px at x 80`.
fn block_line(blk: &Value) -> String {
    let n = |v: &Value, k: &str| v.get(k).and_then(Value::as_u64).unwrap_or(0);
    let mut s = blk.get("tag").and_then(Value::as_str).unwrap_or("block").to_string();
    if let Some(h) = blk.get("heading").and_then(Value::as_str) {
        s.push_str(&format!(" \"{h}\""));
    }
    let pad: Vec<String> = blk.get("pad").and_then(Value::as_array).into_iter().flatten().map(|p| p.as_u64().unwrap_or(0).to_string()).collect();
    s.push_str(&format!(": padding {}", pad.join(" ")));
    if n(blk, "gap") > 0 {
        s.push_str(&format!(", gap {}", n(blk, "gap")));
    }
    if n(blk, "per_row") > 1 {
        s.push_str(&format!(", {} per row", n(blk, "per_row")));
    }
    if let Some(c) = blk.get("column") {
        s.push_str(&format!(", column {} px at x {}", n(c, "max_w"), n(c, "x")));
    }
    if let Some(bg) = blk.get("background").and_then(Value::as_str) {
        s.push_str(&format!(", background {bg}"));
    }
    s
}

// ---------------------------------------------------------------------------------------------
// web_site_close

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CloseParams {}

fn web_site_close(ctx: &mut Ctx<'_>, params: Value) -> Result<ToolOutput, ToolError> {
    let _: CloseParams = parse_params(params)?;
    let closed = ctx.session.ext.remove::<SiteBrowser>().is_some();
    Ok(ToolOutput::Value(json!({"closed": closed})))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Explicit local-browser integration check; never runs as part of the normal test suite.
    #[test]
    #[ignore = "requires installed Chromium; starts only a private headless browser and loopback fixture"]
    fn authenticated_images_are_exported_through_the_private_browser() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, Ordering};
        let fixture = web_common::encode_png(&web_common::Image { width: 2, height: 2, rgba: [30, 100, 200, 255].repeat(4) }).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        struct FixtureServer(Arc<AtomicBool>, Option<std::thread::JoinHandle<()>>);
        impl Drop for FixtureServer {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
                if let Some(handle) = self.1.take() {
                    let _ = handle.join();
                }
            }
        }
        let stopping = stop.clone();
        let png = fixture.clone();
        let server = std::thread::spawn(move || {
            while !stopping.load(Ordering::SeqCst) {
                let Ok((mut stream, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                };
                stream.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
                let mut request = [0u8; 16_384];
                let Ok(n) = stream.read(&mut request) else { continue };
                let request = String::from_utf8_lossy(&request[..n]);
                let path = request.split_whitespace().nth(1).unwrap_or("/");
                let signed_in = request.lines().any(|line| line.to_ascii_lowercase().starts_with("cookie:") && line.contains("craft-fixture=allowed"));
                let (mime, extra, body): (&str, &str, Vec<u8>) = if path == "/sign-in" {
                    ("text/html", "Set-Cookie: craft-fixture=allowed; HttpOnly; SameSite=Lax; Path=/\r\n", b"<h1>Signed in</h1>".to_vec())
                } else if path.starts_with("/original.png") && signed_in {
                    ("image/png", "", png.clone())
                } else if signed_in {
                    ("text/html", "", b"<!doctype html><h1>Private fixture</h1><img src='/original.png?version=fixture' width='32' height='32'>".to_vec())
                } else {
                    ("text/html", "", b"<!doctype html><h1>Sign in required</h1>".to_vec())
                };
                let header = format!("HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n", body.len());
                let _ = stream.write_all(header.as_bytes());
                let _ = stream.write_all(&body);
            }
        });
        let _server = FixtureServer(stop, Some(server));
        let root = tempfile::tempdir().unwrap();
        let engine = crate::Engine::new(crate::testing::session());
        let call =
            |tool: &str, params: Value| engine.call(tool, params, crate::CallOptions::new(crate::Caller::Cli).with_consent(crate::Consent::Granted)).unwrap();
        call("web_site_open", json!({"url": address, "headless": true, "settle_ms": 100}));
        call("web_site_capture", json!({"output_directory": root.path().join("before"), "widths": [800], "include_html": false}));
        let before: Value = serde_json::from_slice(&std::fs::read(root.path().join("before/capture.json")).unwrap()).unwrap();
        assert!(before["text"].as_str().unwrap().contains("Sign in required"));
        call("web_site_open", json!({"url": format!("{address}/sign-in"), "require_existing": true, "settle_ms": 100}));
        call("web_site_open", json!({"url": address, "require_existing": true, "settle_ms": 100}));
        call("web_site_capture", json!({"output_directory": root.path().join("after"), "widths": [800], "include_html": false, "export_images": true}));
        let after: Value = serde_json::from_slice(&std::fs::read(root.path().join("after/capture.json")).unwrap()).unwrap();
        assert!(after["text"].as_str().unwrap().contains("Private fixture"));
        let files = after.pointer("/exported_images/files").unwrap().as_array().unwrap();
        assert_eq!(files.len(), 1, "{}", after["exported_images"]);
        let exported = std::fs::read(root.path().join("after").join(files[0]["file"].as_str().unwrap())).unwrap();
        assert_eq!(exported, fixture, "original protected image bytes, not a screenshot");
        assert!(!after["exported_images"].to_string().contains("?version="));
        assert!(!after.to_string().contains("craft-fixture"));
        // A CLI builder has its own engine, just like `craft-anything-cli mcp`.
        let builder = crate::Engine::new(crate::testing::session());
        let handoff = engine.session().ext.get::<SiteBrowser>().unwrap().handoff_path();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(std::fs::metadata(&handoff).unwrap().permissions().mode() & 0o777, 0o600);
        }
        SiteBrowser::attach(&mut builder.session(), &handoff).unwrap();
        builder
            .call(
                "web_site_open",
                json!({"url": address, "require_existing": true, "settle_ms": 100}),
                crate::CallOptions::new(crate::Caller::Cli).with_consent(crate::Consent::Granted),
            )
            .expect("the builder must keep the signed-in capture browser");
        builder
            .call(
                "web_site_capture",
                json!({"output_directory": root.path().join("builder"), "widths": [800], "include_html": false, "export_images": true}),
                crate::CallOptions::new(crate::Caller::Cli).with_consent(crate::Consent::Granted),
            )
            .unwrap();
        let result: Value = serde_json::from_slice(&std::fs::read(root.path().join("builder/capture.json")).unwrap()).unwrap();
        assert!(result["text"].as_str().unwrap().contains("Private fixture"));
        let file = result["exported_images"]["files"][0]["file"].as_str().unwrap();
        assert_eq!(std::fs::read(root.path().join("builder").join(file)).unwrap(), fixture);
        let mut clean_room = crate::testing::session();
        clean_room.deep_for_run = Some(false);
        assert!(SiteBrowser::attach(&mut clean_room, &handoff).is_err());
        call("web_site_close", json!({}));
        assert!(!handoff.exists(), "the run's connection capability must be deleted");
        assert!(SiteBrowser::attach(&mut crate::testing::session(), &handoff).is_err());
        let closed = builder.call(
            "web_site_open",
            json!({"url": address, "settle_ms": 100}),
            crate::CallOptions::new(crate::Caller::Cli).with_consent(crate::Consent::Granted),
        );
        assert!(closed.is_err(), "a closed parent browser must not silently become a new signed-out browser");
    }

    #[test]
    fn image_export_bounds_decoding_and_refuses_clean_room_before_writing() {
        assert_eq!(image_body(&json!({"content": "aGVsbG8=", "base64Encoded": true})).unwrap(), b"hello");
        assert!(image_body(&json!({"content": "x".repeat(MAX_IMAGE_BYTES + 1)})).is_err());
        assert!(image_body(&json!({"content": "!", "base64Encoded": true})).is_err());
        let dir = tempfile::tempdir().unwrap();
        let mut session = crate::testing::session();
        session.settings.deep_mode = false;
        session.settings.engines.tools.chromium = Some(std::env::current_exe().unwrap());
        let engine = crate::Engine::new(session);
        let output = dir.path().join("capture");
        let error = engine
            .call("web_site_capture", json!({"output_directory": output, "export_images": true}), crate::CallOptions::new(crate::Caller::Cli))
            .unwrap_err();
        assert!(error.message.contains("Deep mode"));
        assert!(!output.exists());
        let error = engine
            .call(
                "web_site_open",
                json!({"url": "https://example.test/", "require_existing": true}),
                crate::CallOptions::new(crate::Caller::Cli).with_consent(crate::Consent::Granted),
            )
            .unwrap_err();
        assert!(error.message.contains("private browser was closed"));
    }

    #[test]
    fn a_click_is_described_by_what_changed() {
        let before = json!({"expanded": "false", "selected": null, "open": null, "dialogs": 0, "url": "https://a.test/"});
        let menu = json!({"expanded": "true", "selected": null, "open": null, "dialogs": 0, "url": "https://a.test/"});
        assert_eq!(state_change(&before, &menu), vec!["expanded"]);
        let dialog = json!({"expanded": "false", "selected": null, "open": null, "dialogs": 1, "url": "https://a.test/"});
        assert_eq!(state_change(&before, &dialog), vec!["dialog appeared"]);
        let away = json!({"expanded": "false", "selected": null, "open": null, "dialogs": 0, "url": "https://a.test/other"});
        assert_eq!(state_change(&before, &away), vec!["address changed"]);
        let tab = json!({"selected": "true", "url": "https://a.test/"});
        assert_eq!(state_change(&json!({"selected": "false", "url": "https://a.test/"}), &tab), vec!["tab selected"]);
        assert!(state_change(&before, &before).is_empty());
        // The page scripts carry their placeholders.
        assert!(FIND_STATES_JS.contains("__MAX__") && STATE_JS.contains("__I__") && CLICK_STATE_JS.contains("__I__"));
    }

    #[test]
    fn urls_are_checked() {
        assert!(check_url("https://example.com").is_ok());
        assert!(check_url(" http://a.b/c?d ").is_ok());
        for bad in ["example.com", "file:///etc/passwd", "javascript:alert(1)", "https://", "https:///x", "https://a b.com", "chrome://settings"] {
            assert!(check_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn truncation_keeps_char_boundaries() {
        assert_eq!(truncate_utf8("héllo", 2), "h");
        assert_eq!(truncate_utf8("abc", 10), "abc");
    }

    #[test]
    fn readme_lists_files_and_tokens() {
        let b = json!({"url": "https://ex.com/a?secret=1", "title": "Ex", "page": {"w": 1440, "h": 3000},
            "design": {"fonts": [{"value": "Inter", "count": 9}], "font_sizes": [], "text_colors": [], "backgrounds": [], "radii": []},
            "headings": [{"level": 1, "text": "Hello"}, {"level": 2, "text": "World"}]});
        let md = readme(&b, &[json!({"file": "screenshot-1440.png", "width": 1440, "height": 3000, "cut": false})], 10, false);
        assert!(md.contains("screenshot-1440.png") && md.contains("`Inter`") && md.contains("  - World") && md.contains("page.html"));
        assert!(!md.contains("secret=1"), "query strings are not echoed");
        assert!(md.contains("no width breakpoints"), "{md}");
    }

    #[test]
    fn page_health_keeps_errors_and_failed_requests_without_query_strings() {
        let ev = |method: &str, params: Value| CdpEvent { method: method.into(), params, session_id: None };
        let events = vec![
            ev("Network.requestWillBeSent", json!({"requestId": "7", "request": {"url": "https://ex.com/font.woff2?token=abc"}})),
            ev(
                "Runtime.exceptionThrown",
                json!({"exceptionDetails": {"text": "Uncaught", "url": "https://ex.com/app.js?v=2", "exception": {"description": "TypeError: x is undefined\n    at app.js:1"}}}),
            ),
            ev(
                "Runtime.exceptionThrown",
                json!({"exceptionDetails": {"text": "Uncaught", "exception": {"description": "TypeError: x is undefined\n    at app.js:9"}}}),
            ),
            ev(
                "Runtime.consoleAPICalled",
                json!({"type": "error", "args": [{"type": "string", "value": "Hydration failed"}, {"type": "object", "description": "Error"}]}),
            ),
            ev("Runtime.consoleAPICalled", json!({"type": "log", "args": [{"type": "string", "value": "hello"}]})),
            ev("Log.entryAdded", json!({"entry": {"level": "error", "source": "network", "text": "Failed to load resource: 404"}})),
            ev("Log.entryAdded", json!({"entry": {"level": "error", "source": "security", "text": "Mixed content blocked", "url": "https://ex.com/"}})),
            ev("Network.responseReceived", json!({"type": "Image", "response": {"url": "https://ex.com/logo.png?sig=1", "status": 404}})),
            ev("Network.responseReceived", json!({"type": "Document", "response": {"url": "https://ex.com/", "status": 200}})),
            ev("Network.loadingFailed", json!({"requestId": "7", "type": "Font", "errorText": "net::ERR_NAME_NOT_RESOLVED"})),
            ev("Network.loadingFailed", json!({"requestId": "8", "type": "Media", "errorText": "net::ERR_ABORTED", "canceled": true})),
        ];
        let h = page_health(&events);
        let texts: Vec<&str> = h["errors"].as_array().unwrap().iter().map(|e| e["text"].as_str().unwrap()).collect();
        assert_eq!(texts, ["TypeError: x is undefined", "Hydration failed Error", "Mixed content blocked"], "one line each, once, no network log noise");
        assert_eq!(h["errors"][0]["url"], "https://ex.com/app.js");
        let failed = h["failed_requests"].as_array().unwrap();
        assert_eq!(failed.len(), 2, "a 404 and a failed font; the cancelled load and the 200 aren't failures");
        assert_eq!(failed[0], json!({"url": "https://ex.com/logo.png", "status": 404, "type": "Image"}));
        assert_eq!(failed[1]["url"], "https://ex.com/font.woff2");
        assert!(!h.to_string().contains("token") && !h.to_string().contains("sig="), "no query strings");
        assert_eq!(page_health(&[]), json!({"errors": [], "failed_requests": []}));
        let md = readme(&json!({"health": h, "a11y": {"lang": "en", "unnamed_controls": 2, "images_without_alt": 1}}), &[], 0, false);
        assert!(md.contains("- script error: TypeError: x is undefined") && md.contains("- failed request (404): https://ex.com/logo.png"), "{md}");
        assert!(md.contains("Language: en. Controls without a name: 2. Pictures without alt text: 1."), "{md}");
        assert!(readme(&json!({"health": page_health(&[])}), &[], 0, false).contains("loaded without script errors"));
    }

    #[test]
    fn readme_shows_breakpoints_and_the_layout_at_each_width() {
        let b = json!({"url": "https://ex.com/", "breakpoints": [{"query": "min-width 768px", "px": 768, "count": 3}],
        "design": {"spacing": [{"value": "96px", "count": 20}], "max_widths": [{"value": "1280px", "count": 4}]},
        "assets": {"fonts": ["https://ex.com/f.woff2"]},
        "layouts": [
            {"width": 1440, "page_w": 1440, "type": {"h1": 64, "h2": 40, "h3": 24, "body": 16},
             "blocks": [{"tag": "section", "heading": "Plans", "pad": [96, 32, 96, 32], "gap": 24, "per_row": 3, "column": {"max_w": 1280, "x": 80}, "background": "#12181f"}]},
            {"width": 390, "page_w": 512, "type": {"h1": 40}, "blocks": [{"tag": "header", "pad": [16, 16, 16, 16], "per_row": 1}]}
        ]});
        let md = readme(&b, &[], 0, false);
        assert!(md.contains("switches layout at: min-width 768px") && md.contains("`96px`") && md.contains("`1280px`") && md.contains("Font files: 1"), "{md}");
        assert!(md.contains("### 1440 px (no sideways scroll)") && md.contains("Headings 64/40/24 px, text 16 px"), "{md}");
        assert!(md.contains("- section \"Plans\": padding 96 32 96 32, gap 24, 3 per row, column 1280 px at x 80, background #12181f"), "{md}");
        assert!(md.contains("### 390 px (page 512 px wide, so it scrolls sideways)") && md.contains("- header: padding 16 16 16 16\n"), "{md}");
        let cross = readme(&json!({"unreadable_stylesheets": 2}), &[], 0, false);
        assert!(cross.contains("2 stylesheet(s) from other sites"), "{cross}");
    }

    #[test]
    fn a_visitors_view_keeps_what_shows_and_drops_the_pages_code() {
        let mut b = json!({
            "title": "Plans", "meta": {"description": "hidden"}, "breakpoints": [{"query": "min-width 768px"}], "unreadable_stylesheets": 1,
            "health": {"errors": [{"text": "boom"}]}, "design": {"fonts": [{"value": "Inter", "count": 9}], "css_variables": {"--brand": "#123"}, "font_faces": [{"family": "Inter"}]},
            "assets": {"images": [{"src": "https://cdn.test/a.png", "w": 40, "h": 30, "alt": "logo"}], "scripts": ["https://cdn.test/app.js"], "requests": [{"url": "https://api.test/x"}]},
            "headings": [{"level": 1, "text": "Plans"}], "text": "Plans Pricing", "layouts": [{"width": 1440, "page_w": 1440}]
        });
        visitor_view(&mut b);
        for gone in [
            "/meta",
            "/breakpoints",
            "/unreadable_stylesheets",
            "/health",
            "/design/css_variables",
            "/design/font_faces",
            "/assets/scripts",
            "/assets/requests",
            "/assets/images/0/src",
        ] {
            assert!(b.pointer(gone).is_none(), "{gone} isn't something a visitor sees");
        }
        assert_eq!((b["assets"]["images"][0]["w"].as_u64(), b["text"].as_str()), (Some(40), Some("Plans Pricing")));
        let md = readme(&b, &[], 0, true);
        assert!(
            md.contains("Clean room: only what a visitor sees") && !md.contains("Breakpoints") && !md.contains("Page health") && !md.contains("page.html"),
            "{md}"
        );
        assert!(md.contains("### 1440 px"), "{md}");
    }

    #[test]
    fn capture_without_open_site_is_a_clear_error() {
        let e = crate::Engine::new(crate::testing::session());
        let r = e.call(
            "web_site_capture",
            json!({"output_directory": std::env::temp_dir().join("ca-never-created").display().to_string()}),
            crate::CallOptions::new(crate::Caller::Cli),
        );
        let err = r.err().map(|e| e.message).unwrap_or_default();
        assert!(err.contains("no website is open") || err.contains("Chromium") || err.contains("chromium"), "{err}");
    }

    /// A browser that exits as soon as it starts is reported at once, not after the whole wait,
    /// with what it said. The "browser" is a system program that rejects Chrome's arguments and
    /// exits, so no browser or window starts.
    #[test]
    fn a_browser_that_exits_at_once_is_reported_at_once() {
        let stand_in = if cfg!(windows) {
            std::path::PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into())).join("System32").join("where.exe")
        } else {
            std::path::PathBuf::from("/bin/false")
        };
        if !stand_in.is_file() {
            return;
        }
        let mut s = crate::testing::session();
        s.settings.engines.tools.chromium = Some(stand_in);
        let e = crate::Engine::new(s);
        let opts = crate::CallOptions::new(crate::Caller::Cli).with_consent(crate::Consent::Granted);
        let started = std::time::Instant::now();
        let err = e.call("web_site_open", json!({"url": "https://example.com", "timeout_secs": 60}), opts).err().unwrap();
        assert!(started.elapsed() < std::time::Duration::from_secs(20), "waited {:?}", started.elapsed());
        assert!(err.message.starts_with("Couldn't start the private browser") && err.message.contains("closed after"), "{}", err.message);
        assert!(err.remediation.is_some_and(|r| r.contains("Settings")));
    }
}
