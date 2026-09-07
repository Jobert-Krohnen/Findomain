//! Integration with the external scanners Findomain drives.
//!
//! Each tool is an optional stage: if the binary is missing the run says so
//! once and carries on, because a missing scanner must never cost the
//! enumeration that already succeeded.

pub mod ffuf;
pub mod nmap;
pub mod nuclei;

use crate::{config::Config, resolve::ResolvData};
use std::{
    collections::HashMap,
    fmt,
    io::{BufRead, BufReader, Read, Write},
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

/// How often the wait loop checks whether the child has exited.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// How long to keep accepting lines once the tool is known to be gone, so
/// that what it wrote in its last moments is not dropped on the floor.
const GRACE: Duration = Duration::from_millis(300);

/// Why an external tool did not produce usable results.
#[derive(Debug)]
pub enum ToolError {
    /// The binary is not installed, or not on `PATH`.
    Missing(String),
    /// The binary ran but failed.
    Failed(String, String),
    /// The binary ran but its output could not be understood.
    Output(String, String),
}

impl fmt::Display for ToolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(tool) => write!(
                formatter,
                "{tool} is not installed or not in PATH, skipping that stage"
            ),
            Self::Failed(tool, reason) => write!(formatter, "{tool} failed: {reason}"),
            Self::Output(tool, reason) => {
                write!(formatter, "could not read the {tool} output: {reason}")
            }
        }
    }
}

impl std::error::Error for ToolError {}

/// How a streamed run ended.
#[derive(Debug)]
pub struct Completion {
    /// The tool was killed at its deadline. Every line it printed before that
    /// already reached the caller; only what it would have printed next is
    /// lost.
    pub timed_out: bool,
}

/// Runs `tool` and returns its standard output.
///
/// `timeout` is in seconds; 0 means the tool may run for as long as it needs.
///
/// # Errors
///
/// Fails when the binary is missing, exits without producing output, or does
/// not finish within `timeout`.
pub fn run(tool: &str, args: &[String], timeout: u64) -> Result<String, ToolError> {
    run_with_stdin(tool, args, timeout, None)
}

/// Runs `tool`, optionally feeding it `stdin`, and returns its standard output.
///
/// A tool that outlives `timeout` is an error here because the callers parse
/// the output as a whole, and half an XML document is worth nothing. A caller
/// that can use partial output should [`stream`] instead.
///
/// # Errors
///
/// Fails when the binary is missing, exits without producing output, or does
/// not finish within `timeout`.
pub fn run_with_stdin(
    tool: &str,
    args: &[String],
    timeout: u64,
    stdin: Option<&str>,
) -> Result<String, ToolError> {
    let mut lines = Vec::new();
    let completion = stream(tool, args, timeout, stdin, &mut |line| {
        lines.push(line.to_owned());
    })?;

    if completion.timed_out {
        return Err(ToolError::Failed(
            tool.to_owned(),
            format!("timed out after {timeout} seconds"),
        ));
    }
    Ok(lines.join("\n"))
}

/// Runs `tool` and hands every line of its standard output to `on_line` as
/// soon as it is written.
///
/// `timeout` is in seconds; 0 means no deadline. When the deadline passes the
/// tool is killed, but the run is not a failure: the lines already delivered
/// stand, and the returned [`Completion`] says what happened so the caller can
/// tell the user the scan was cut short.
///
/// # Errors
///
/// Fails when the binary is missing, cannot be started, or exits unsuccessfully
/// without having printed anything.
pub fn stream(
    tool: &str,
    args: &[String],
    timeout: u64,
    stdin: Option<&str>,
    on_line: &mut dyn FnMut(&str),
) -> Result<Completion, ToolError> {
    let mut child = Command::new(tool)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => ToolError::Missing(tool.to_owned()),
            _ => ToolError::Failed(tool.to_owned(), e.to_string()),
        })?;

    // Both pipes are drained on their own threads, and stdin is fed on
    // another, so a child that outgrows the OS pipe buffer cannot block
    // against this thread. Lines cross back over a channel so that the
    // callback runs here, where the caller's state lives.
    //
    // The reader threads are never joined. A pipe stays open for as long as
    // anything holds its write end, and a helper the tool started can outlive
    // the tool itself; waiting on the pipe would then mean waiting on that
    // helper. The threads end on their own when the pipe finally closes.
    let stdout = child.stdout.take().expect("stdout is piped");
    let mut stderr = child.stderr.take().expect("stderr is piped");
    let (lines_tx, lines_rx) = mpsc::channel::<String>();
    let (stderr_tx, stderr_rx) = mpsc::channel::<Vec<u8>>();
    thread::spawn(move || forward_lines(stdout, &lines_tx));
    thread::spawn(move || {
        let _ = stderr_tx.send(read_to_end(&mut stderr));
    });

    if let (Some(mut pipe), Some(input)) = (child.stdin.take(), stdin) {
        let input = input.to_owned();
        thread::spawn(move || {
            let _ = pipe.write_all(input.as_bytes());
            // Dropping the pipe closes the child's stdin, signalling EOF.
        });
    }

    let deadline = (timeout > 0).then(|| Instant::now() + Duration::from_secs(timeout));
    let mut emitted = 0usize;
    let mut timed_out = false;
    let mut status: Option<ExitStatus> = None;

    loop {
        match lines_rx.recv_timeout(POLL_INTERVAL) {
            Ok(line) => {
                emitted += 1;
                on_line(&line);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    timed_out = true;
                    let _ = child.kill();
                    break;
                }
                // Gone, but something it started may still hold the pipe.
                if let Ok(Some(exit)) = child.try_wait() {
                    status = Some(exit);
                    break;
                }
            }
            // stdout closed: the tool is done writing.
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    // Lines written just before the end are still on their way through the
    // reader. Wait for the channel to go quiet rather than drop them.
    while let Ok(line) = lines_rx.recv_timeout(GRACE) {
        emitted += 1;
        on_line(&line);
    }

    if status.is_none() {
        status = if timed_out {
            child.wait().ok()
        } else {
            // stdout is closed but the process may still be finishing up;
            // give it whatever the deadline has left, or as long as it wants.
            match deadline.map(|deadline| deadline.saturating_duration_since(Instant::now())) {
                None => child.wait().ok(),
                Some(left) => {
                    let exit = wait_until(&mut child, left);
                    if exit.is_none() {
                        timed_out = true;
                        let _ = child.kill();
                        let _ = child.wait();
                    }
                    exit
                }
            }
        };
    }

    if timed_out {
        return Ok(Completion { timed_out: true });
    }

    if emitted == 0 && !status.is_some_and(|status| status.success()) {
        let stderr = stderr_rx.recv_timeout(GRACE).unwrap_or_default();
        let reason = String::from_utf8_lossy(&stderr);
        return Err(ToolError::Failed(
            tool.to_owned(),
            reason.lines().next().unwrap_or("no output").to_owned(),
        ));
    }

    Ok(Completion { timed_out: false })
}

/// Sends every line of `pipe` down `sender` until the pipe closes or the
/// receiver goes away.
///
/// Lines are split by hand rather than with `BufRead::lines` so that a stray
/// non-UTF-8 byte from the tool costs one mangled line, not the whole stream.
fn forward_lines<R: Read>(pipe: R, sender: &mpsc::Sender<String>) {
    let mut reader = BufReader::new(pipe);
    let mut buffer = Vec::new();
    loop {
        buffer.clear();
        match reader.read_until(b'\n', &mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                while matches!(buffer.last(), Some(b'\n' | b'\r')) {
                    buffer.pop();
                }
                if sender
                    .send(String::from_utf8_lossy(&buffer).into_owned())
                    .is_err()
                {
                    break;
                }
            }
        }
    }
}

/// Reads a pipe to the end, returning whatever arrived before any error.
fn read_to_end<R: Read>(pipe: &mut R) -> Vec<u8> {
    let mut buffer = Vec::new();
    let _ = pipe.read_to_end(&mut buffer);
    buffer
}

/// Waits up to `timeout` for `child` to exit.
///
/// Returns `None` when it is still running at the end, leaving the decision
/// to kill it with the caller.
fn wait_until(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() >= deadline => return None,
            Ok(None) => thread::sleep(POLL_INTERVAL),
            Err(_) => return None,
        }
    }
}

/// Findings produced by the optional scanners.
#[derive(Debug, Default)]
pub struct Findings {
    pub vulnerabilities: Vec<nuclei::Finding>,
    pub paths: Vec<ffuf::Hit>,
}

/// Runs the enabled scanners against every host with a live HTTP server.
///
/// Every nuclei finding is printed the moment nuclei reports it and handed to
/// `on_finding` right after, so a long scan shows its results as it goes and
/// the monitoring path can raise an alert without waiting for the end. ffuf
/// writes its report to a file when it exits, so its hits only exist at the
/// end and come back in the returned [`Findings`] alone.
///
/// A scanner that is missing or fails is reported once and skipped: it must
/// never cost the enumeration that already succeeded.
#[must_use]
pub fn scan_live_hosts(
    config: &Config,
    resolv_data: &HashMap<String, ResolvData>,
    on_finding: &mut dyn FnMut(&nuclei::Finding),
) -> Findings {
    let mut findings = Findings::default();
    if !config.nuclei.enabled && !config.ffuf.enabled {
        return findings;
    }

    let mut urls: Vec<String> = resolv_data
        .values()
        .filter(|data| !data.http_data.final_url.is_empty())
        .map(|data| data.http_data.final_url.clone())
        .collect();
    urls.sort_unstable();
    urls.dedup();

    if urls.is_empty() {
        return findings;
    }

    if config.nuclei.enabled {
        let outcome = nuclei::scan(config, &urls, &mut |finding| {
            println!("{finding}");
            on_finding(finding);
        });
        match outcome {
            Ok(found) => findings.vulnerabilities = found,
            Err(e) => eprintln!("nuclei stage skipped: {e}"),
        }
    }
    if config.ffuf.enabled {
        match ffuf::scan(config, &urls) {
            Ok(found) => findings.paths = found,
            Err(e) => eprintln!("ffuf stage skipped: {e}"),
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_binary_is_reported_as_missing() {
        let error = run("findomain-no-such-tool-exists", &[], 5).expect_err("must fail");
        assert!(matches!(error, ToolError::Missing(_)));
        assert!(error.to_string().contains("not installed"));
    }

    #[test]
    fn standard_output_is_captured() {
        let out = run("echo", &["hello".to_owned()], 5).expect("echo exists");
        assert_eq!(out.trim(), "hello");
    }

    #[test]
    fn stdin_reaches_the_tool() {
        let out = run_with_stdin("cat", &[], 5, Some("piped input")).expect("cat exists");
        assert_eq!(out.trim(), "piped input");
    }

    #[test]
    fn a_hanging_tool_is_killed() {
        let error = run("sleep", &["30".to_owned()], 1).expect_err("must time out");
        assert!(error.to_string().contains("timed out"));
    }

    #[test]
    fn output_larger_than_the_pipe_buffer_does_not_deadlock() {
        // 1 MB dwarfs the ~64 KB OS pipe buffer; without concurrent draining
        // the child would block writing and the wait would time out.
        let out = run(
            "sh",
            &[
                "-c".to_owned(),
                "yes ABCDEFGHIJKLMNOP | head -c 1000000".to_owned(),
            ],
            10,
        )
        .expect("must complete well within the timeout");
        assert_eq!(out.len(), 1_000_000);
    }

    #[test]
    fn a_large_stdin_paired_with_large_stdout_does_not_deadlock() {
        // The child echoes a big stdin straight back to stdout; feeding stdin
        // and draining stdout must happen concurrently or both pipes wedge.
        let input = "x".repeat(500_000);
        let out = run_with_stdin("cat", &[], 10, Some(&input)).expect("must complete");
        assert_eq!(out.len(), input.len());
    }

    #[test]
    fn lines_arrive_as_they_are_written_not_at_the_end() {
        // Three lines a fifth of a second apart. If they were delivered only
        // at exit, every timestamp would be the same; streamed, they spread.
        let started = Instant::now();
        let mut seen: Vec<(String, Duration)> = Vec::new();
        let completion = stream(
            "sh",
            &[
                "-c".to_owned(),
                "echo one; sleep 0.2; echo two; sleep 0.2; echo three".to_owned(),
            ],
            10,
            None,
            &mut |line| seen.push((line.to_owned(), started.elapsed())),
        )
        .expect("must complete");

        assert!(!completion.timed_out);
        let lines: Vec<&str> = seen.iter().map(|(line, _)| line.as_str()).collect();
        assert_eq!(lines, ["one", "two", "three"]);
        assert!(
            seen[2].1 - seen[0].1 >= Duration::from_millis(300),
            "lines were buffered until the end: {seen:?}"
        );
    }

    #[test]
    fn a_timed_out_stream_keeps_what_was_already_written() {
        // The tool prints two findings, then hangs. Killing it must not cost
        // the two it already reported: that is the whole point of streaming.
        //
        // The trailing echo keeps the shell from exec-ing sleep in its own
        // place, so sleep is a real child that survives the kill holding the
        // pipe open, exactly the way a scanner's helper process would.
        let started = Instant::now();
        let mut seen = Vec::new();
        let completion = stream(
            "sh",
            &[
                "-c".to_owned(),
                "echo first; echo second; sleep 30; echo never".to_owned(),
            ],
            1,
            None,
            &mut |line| seen.push(line.to_owned()),
        )
        .expect("a timeout is not a failure for a stream");

        assert!(completion.timed_out);
        assert_eq!(seen, ["first", "second"]);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the run waited on the orphaned sleep: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_helper_that_outlives_the_tool_does_not_hold_the_run() {
        // The tool exits cleanly right away, leaving behind a background
        // process that still holds stdout. With no deadline at all, the run
        // must still notice the tool is gone instead of waiting on the pipe.
        let started = Instant::now();
        let mut seen = Vec::new();
        let completion = stream(
            "sh",
            &["-c".to_owned(), "echo first; sleep 30 & exit 0".to_owned()],
            0,
            None,
            &mut |line| seen.push(line.to_owned()),
        )
        .expect("must complete");

        assert!(!completion.timed_out);
        assert_eq!(seen, ["first"]);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the run waited on the orphaned sleep: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_zero_timeout_means_no_deadline() {
        // Longer than any poll interval, shorter than the test budget.
        let mut seen = Vec::new();
        let completion = stream(
            "sh",
            &["-c".to_owned(), "sleep 0.5; echo done".to_owned()],
            0,
            None,
            &mut |line| seen.push(line.to_owned()),
        )
        .expect("must complete");
        assert!(!completion.timed_out);
        assert_eq!(seen, ["done"]);
    }

    #[test]
    fn a_stray_invalid_byte_costs_one_line_not_the_stream() {
        let mut seen = Vec::new();
        stream(
            "sh",
            &[
                "-c".to_owned(),
                "printf 'ok\\n\\377bad\\nstill ok\\n'".to_owned(),
            ],
            5,
            None,
            &mut |line| seen.push(line.to_owned()),
        )
        .expect("must complete");
        assert_eq!(seen.len(), 3);
        assert_eq!(seen[0], "ok");
        assert_eq!(seen[2], "still ok");
        assert!(seen[1].contains("bad"));
    }

    #[test]
    fn a_failing_tool_reports_its_first_error_line() {
        let error = run("ls", &["/definitely/not/here".to_owned()], 5).expect_err("must fail");
        assert!(matches!(error, ToolError::Failed(..)));
    }
}
