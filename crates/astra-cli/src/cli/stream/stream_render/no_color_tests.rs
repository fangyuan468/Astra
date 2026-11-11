//! Exercise rendered tool progress in fresh processes; never mutate the test
//! runner's environment or replace a renderer field with a test-only policy.
use super::StreamRenderState;
use serde_json::json;
use std::process::Command;

const CASE: &str = "ASTRA_TEST_TOOL_COLOR_CASE";

#[test]
fn tool_progress_respects_no_color() {
    if let Ok(case) = std::env::var(CASE) {
        render_tool_progress(&case);
        return;
    }
    let name = format!(
        "{}::tool_progress_respects_no_color",
        module_path!().split_once("::").unwrap().1
    );
    let mut colored_text = None;
    let sgr = regex::Regex::new("\x1b\\[[0-9;:]*m").unwrap();
    for (case, value) in [("unset", None), ("set", Some("1")), ("empty", Some(""))] {
        let mut child = Command::new(std::env::current_exe().unwrap());
        child
            .args(["--exact", &name, "--nocapture"])
            .env(CASE, case)
            .env_remove("NO_COLOR");
        if let Some(value) = value {
            child.env("NO_COLOR", value);
        }
        let result = child.output().unwrap();
        assert!(result.status.success(), "{case}: {result:?}");
        let stdout = String::from_utf8(result.stdout).unwrap();
        assert!(stdout.contains("1 passed"), "{stdout}");
        assert!(stdout.contains("tool-output-protocol-sentinel"), "{stdout}");
        let stderr = String::from_utf8(result.stderr).unwrap();
        assert_eq!(sgr.is_match(&stderr), case == "unset", "{case}: {stderr:?}");
        let text = sgr.replace_all(&stderr, "").into_owned();
        for expected in [
            "[1/2]",
            "Reading: sample.txt",
            "Running 2 tools in parallel",
            "boom",
            "skipped (duplicate)",
            "@@",
            "- old",
            "+ new",
            "captured",
            "⚠",
            "●",
        ] {
            assert!(
                text.contains(expected),
                "{case}: missing {expected:?}: {stderr:?}"
            );
        }
        // EL is row geometry, not styling. Removing all CSI would corrupt the
        // existing diff surface contract, even when only color was disabled.
        assert!(stderr.contains("\x1b[K"), "diff row clearing must survive");
        if let Some(expected) = &colored_text {
            assert_eq!(&text, expected);
        } else {
            colored_text = Some(text);
        }
    }
}

fn render_tool_progress(case: &str) {
    let mut state = StreamRenderState::with_term_width(80, true, true);
    state.tool_batch_progress = Some((1, 2));
    let read = json!({"path": "sample.txt"});
    let idx = state.tool_start("read_file", &read);
    if case.ends_with("-pty") {
        wait_for_parent();
    }
    state.tool_done(idx, "read_file", &read, "completed", 125, "first\nsecond\n");
    state.tool_start_parallel_group(2);
    if case.ends_with("-pty") {
        wait_for_parent();
    }
    state.tool_done_inline(
        "bash",
        &json!({"command": "failure-case"}),
        "failed",
        200,
        "Error: boom",
    );
    state.tool_done_inline(
        "bash",
        &json!({"command": "duplicate-case"}),
        "skipped",
        0,
        "",
    );
    state.tool_done_inline(
        "read_file",
        &read,
        "completed",
        50,
        "⚠ WARNING: partial\nfirst\n",
    );
    state.tool_done_inline(
        "bash",
        &json!({"command": "preview-case"}),
        "completed",
        25,
        "line\n",
    );
    state.tool_done_inline("str_replace", &json!({"path": "sample.txt"}), "completed", 42,
        "Replaced successfully\n<<<ASTRA_UNIFIED_DIFF>>>\n--- a/sample.txt\n+++ b/sample.txt\n@@ -1 +1 @@\n-old\n+new\n<<<END_ASTRA_UNIFIED_DIFF>>>");
    state.stop_tool_stderr_running();
    assert!(state.stderr_lines > 6);
    assert!(state.lines_written > 6);
    if case.ends_with("-pty") {
        // Raw-mode running rows are replaced by a worker thread. Wait until
        // the parent has observed that worker's frame before stopping it.
        let mut raw = StreamRenderState::with_term_width(80, false, true);
        raw.tool_start("read_file", &read);
        wait_for_parent();
        drop(raw);
    }
    crate::cli::stream::output_sink::write_stdout_line("tool-output-protocol-sentinel").unwrap();
}

fn wait_for_parent() {
    use std::io::Read;
    std::io::stdin().read_exact(&mut [0]).unwrap();
}
