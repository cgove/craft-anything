//! The app and a builder's MCP server run in different processes.
use craft_anything_engine::{CallOptions, Caller, Consent, Engine, tools::website_tools::SiteBrowser};
use craft_anything_platform::process::Process;
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

#[test]
#[ignore = "requires installed Chromium; private headless browser and loopback fixture only"]
fn mcp_builder_keeps_the_capture_browser_sign_in() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    struct Server(Arc<AtomicBool>, Option<std::thread::JoinHandle<()>>);
    impl Drop for Server {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
            self.1.take().unwrap().join().unwrap();
        }
    }
    let stopping = stop.clone();
    let thread = std::thread::spawn(move || {
        while !stopping.load(Ordering::SeqCst) {
            let Ok((mut stream, _)) = listener.accept() else {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            };
            stream.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let mut request = [0; 4096];
            if stream.read(&mut request).is_err() {
                continue;
            }
            let body = "<!doctype html><body><script>if(location.pathname==='/sign-in')sessionStorage.setItem('fixture-signed-in','yes');document.body.textContent=sessionStorage.getItem('fixture-signed-in')==='yes'?'Authenticated fixture':'Sign in required';</script>";
            let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        }
    });
    let _server = Server(stop, Some(thread));
    let config = tempfile::tempdir().unwrap();
    let output = tempfile::tempdir().unwrap();
    let engine = Engine::new(craft_anything_engine::testing::session());
    engine
        .call(
            "web_site_open",
            json!({"url": format!("{url}/sign-in"), "headless": true, "settle_ms": 100}),
            CallOptions::new(Caller::Cli).with_consent(Consent::Granted),
        )
        .unwrap();
    let handoff = engine.session().ext.get::<SiteBrowser>().unwrap().handoff_path();
    let input = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"fixture","version":"0"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"web_site_open","arguments":{"url":url,"require_existing":true,"settle_ms":100}}}),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"web_site_capture","arguments":{"output_directory":output.path().join("capture"),"widths":[800],"include_html":false}}}),
    ].iter().map(|v| format!("{v}\n")).collect::<String>();
    let child = Process::new(env!("CARGO_BIN_EXE_craft-anything-cli"))
        .args(["mcp", "--deep", "--all-tools", "--allow-run", "--browser-session"])
        .arg(&handoff)
        .env("CRAFT_ANYTHING_CONFIG_DIR", config.path())
        .stdin_bytes(input)
        .timeout(Duration::from_secs(30))
        .run()
        .unwrap();
    assert!(child.success, "{}", child.stderr_text());
    let messages: Vec<Value> = child.stdout_text().lines().map(|line| serde_json::from_str(line).unwrap()).collect();
    for id in [2, 3] {
        let response = messages.iter().find(|v| v["id"] == id).unwrap();
        assert_eq!(response["result"]["isError"], false, "{response}");
    }
    let capture: Value = serde_json::from_slice(&std::fs::read(output.path().join("capture/capture.json")).unwrap()).unwrap();
    assert!(capture["text"].as_str().unwrap().contains("Authenticated fixture"));
    assert!(handoff.exists(), "exiting MCP must not close the app's capture browser");
    engine
        .call("web_site_open", json!({"url":url,"require_existing":true,"settle_ms":100}), CallOptions::new(Caller::Cli).with_consent(Consent::Granted))
        .unwrap();
    engine.call("web_site_close", json!({}), CallOptions::new(Caller::Cli).with_consent(Consent::Granted)).unwrap();
    assert!(!handoff.exists());
    let missing = Process::new(env!("CARGO_BIN_EXE_craft-anything-cli"))
        .args(["mcp", "--deep", "--browser-session"])
        .arg(&handoff)
        .env("CRAFT_ANYTHING_CONFIG_DIR", config.path())
        .timeout(Duration::from_secs(10))
        .run()
        .unwrap();
    assert!(!missing.success, "an expired handoff must fail startup rather than launch signed out");
}
