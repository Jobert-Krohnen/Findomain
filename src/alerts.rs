//! Monitoring mode: diff against the database and alert on what is new.

use {
    crate::{
        config::Config,
        database, email,
        errors::Result,
        files,
        output::{eval_http, null_ip_checker, ports_string},
        resolve::{self, ResolvData},
        runner,
        session::Session,
        tools::{self, nuclei},
        utils::random_from,
        webhooks::{self, Message},
    },
    reqwest::{
        blocking::Client,
        header::{HeaderMap, RETRY_AFTER, USER_AGENT},
        StatusCode, Url,
    },
    std::{
        collections::{HashMap, HashSet},
        net::IpAddr,
        thread,
        time::Duration,
    },
};

const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(30);

/// Wait used when a 429 comes without a usable Retry-After: Discord's burst
/// window, the shortest that is known to clear.
const RATE_LIMIT_DEFAULT_WAIT: Duration = Duration::from_secs(2);

/// Statuses that mean the webhook took too long rather than that the data was
/// rejected, so `--mtimeout` can still commit the results.
///
/// 408 and 504 are the standard ones; 598 is a proxy convention that never made
/// it into a spec, 524 is Cloudflare and 460 is an AWS load balancer. The chat
/// services this posts to sit behind exactly those two.
const TIMEOUT_STATUSES: [u16; 5] = [408, 504, 598, 524, 460];

/// Resolves the subdomains not seen before and alerts or stores them.
///
/// # Errors
///
/// Fails when the database is unreachable or a webhook cannot be posted to.
pub fn subdomains_alerts(config: &Config, session: &mut Session) -> Result<()> {
    let existing = database::existing_subdomains(config, &session.target)?;
    session.subdomains = session.subdomains.difference(&existing).cloned().collect();

    let output_file = files::open_output_file(&session.file_name, config.output.enabled)?;
    let resolv_data = resolve::resolve_all(config, session, output_file.as_ref())?;
    let new_subdomains = summarize(config, &resolv_data);

    let monitoring = &config.monitoring;
    let client = monitoring.enabled.then(webhook_client);

    // Each actionable finding is pushed the moment nuclei reports it. A scan
    // can run for hours, and a critical finding at minute two should not wait
    // for the end of it. Informational findings are printed and emailed but
    // kept out of the chat, which stops being read once it fills with them.
    let target = session.target.clone();
    let findings = tools::scan_live_hosts(config, &resolv_data, &mut |finding| {
        if let Some(client) = client.as_ref().filter(|_| monitoring.alerts_on_findings()) {
            if finding.is_actionable() {
                alert_finding(config, client, &target, finding);
            }
        }
    });
    runner::report_paths(&findings);

    if config.output.enabled && !new_subdomains.is_empty() {
        write_new_subdomains(config, session, &new_subdomains)?;
    }

    let store_silently = monitoring.no_monitor && !monitoring.enabled;
    let news = is_news(!new_subdomains.is_empty(), monitoring.push_when_empty);

    if store_silently || (!news && !resolv_data.is_empty()) {
        database::commit(config, &session.target, &resolv_data)?;
    } else if let (true, Some(client)) = (news, &client) {
        push_to_webhooks(config, client, session, &new_subdomains, &resolv_data)?;
    }

    // Last and never fatal: the results are already persisted and pushed.
    email_report(config, session, &new_subdomains, findings);

    runner::pause_between_targets(config, session.is_last_target, true);
    Ok(())
}

/// Whether the end of the run has something to say about subdomains.
///
/// Findings do not count here: each one was already sent on its own when
/// nuclei reported it, so the closing alert only covers what is new by name.
const fn is_news(has_new_subdomains: bool, push_when_empty: bool) -> bool {
    push_when_empty || has_new_subdomains
}

/// The HTTP client every webhook post goes through.
fn webhook_client() -> Client {
    Client::builder()
        .timeout(WEBHOOK_TIMEOUT)
        .build()
        .expect("build the webhook HTTP client")
}

/// Posts one finding to every configured webhook, right away.
///
/// Never fatal: a chat service that is down must not stop the scan that is
/// finding things, and the emailed report at the end carries the full list.
fn alert_finding(config: &Config, client: &Client, target: &str, finding: &nuclei::Finding) {
    for message in webhooks::finding_messages(config, &finding.to_string(), target) {
        if let Err(e) = post(config, client, &message) {
            eprintln!("Could not send the finding to {}: {e}", message.url);
        }
    }
}

/// Emails the run's findings, when SMTP was configured.
///
/// Failures are logged rather than propagated: a notification that could not
/// be sent must not undo results that are already stored.
fn email_report(
    config: &Config,
    session: &Session,
    new_subdomains: &HashSet<String>,
    findings: tools::Findings,
) {
    if !config.email.is_configured() {
        return;
    }

    let mut subdomains: Vec<String> = new_subdomains.iter().cloned().collect();
    subdomains.sort_unstable();

    let report = email::Report {
        new_subdomains: subdomains,
        vulnerabilities: findings.vulnerabilities,
        paths: findings.paths,
    };
    if let Err(e) = email::send(config, &session.target, &report) {
        eprintln!("Could not email the report for {}: {e}", session.target);
    }
}

/// Renders one summary line per resolved subdomain.
///
/// When any check ran, hosts without a usable address are left out; with no
/// checks at all every host is reported with placeholder values. The address
/// is parsed as either family, because `--ipv6-only` stores an IPv6 one.
fn summarize(config: &Config, resolv_data: &HashMap<String, ResolvData>) -> HashSet<String> {
    let checked = config.needs_network_checks();

    resolv_data
        .iter()
        .filter(|(_, data)| !checked || data.ip.parse::<IpAddr>().is_ok())
        .map(|(subdomain, data)| {
            format!(
                "HOST: {subdomain},IP: {},HTTP/S: {},OPEN PORTS: {}",
                null_ip_checker(&data.ip),
                eval_http(&data.http_data),
                ports_string(&data.open_ports, config.ports.enabled),
            )
        })
        .collect()
}

/// Writes the new subdomains to their own file next to the main output.
fn write_new_subdomains(
    config: &Config,
    session: &Session,
    new_subdomains: &HashSet<String>,
) -> Result<()> {
    let file_name = files::derived_name(&session.file_name, "new_subdomains.txt");
    files::backup_existing(&file_name)?;

    let file = files::open_output_file(&file_name, true)?;
    for subdomain in new_subdomains {
        files::write_line(subdomain, file.as_ref())?;
    }

    if !config.general.quiet {
        println!(
            ">> 📁 Subdomains for {} were saved in: ./{file_name} 😀",
            session.target
        );
    }
    Ok(())
}

/// Posts every alert and stores the results once the first one goes through.
fn push_to_webhooks(
    config: &Config,
    client: &Client,
    session: &Session,
    new_subdomains: &HashSet<String>,
    resolv_data: &HashMap<String, ResolvData>,
) -> Result<()> {
    let mut stored = false;

    for message in webhooks::messages(config, new_subdomains, &session.target) {
        if !post(config, client, &message)? {
            continue;
        }
        if !stored && !new_subdomains.is_empty() {
            stored = database::commit(config, &session.target, resolv_data).is_ok();
        }
    }

    Ok(())
}

/// Posts a single alert, reporting whether the service accepted it.
///
/// # Errors
///
/// Fails when the request itself could not be made.
/// Posts `message`, waiting out the service's rate limit when it asks.
///
/// A 429 is not a rejection of the data, only of the moment, so the post is
/// retried after the `Retry-After` the service sent, for as long as it keeps
/// asking. Discord allows five requests per two seconds on a webhook and a
/// first run with a thousand subdomains is fourteen messages, so a run of
/// short waits is the normal case. `webhook_max_wait` puts a ceiling on the
/// total wait per message for whoever wants one. Any other refusal is
/// reported and the message is dropped.
fn post(config: &Config, client: &Client, message: &Message) -> Result<bool> {
    let cap = (config.monitoring.webhook_max_wait > 0)
        .then(|| Duration::from_secs(config.monitoring.webhook_max_wait));
    let mut attempt = 0u32;
    let mut waited = Duration::ZERO;
    loop {
        let response = client
            .post(&message.url)
            .header(USER_AGENT, random_from(&config.http.user_agents))
            .json(&message.body)
            .send()?;
        let status = response.status();

        if accepted(status, config.monitoring.push_on_timeout) {
            return Ok(true);
        }

        if status == StatusCode::TOO_MANY_REQUESTS {
            let wait = retry_after(response.headers()).unwrap_or(RATE_LIMIT_DEFAULT_WAIT);
            if cap.is_some_and(|cap| waited + wait > cap) {
                if !config.general.quiet {
                    eprintln!(
                        "The webhook at {} kept rate limiting us past webhook_max_wait ({}s); giving up on this message.",
                        host_of(&message.url),
                        config.monitoring.webhook_max_wait
                    );
                }
                return Ok(false);
            }
            attempt += 1;
            waited += wait;
            if !config.general.quiet {
                eprintln!(
                    "The webhook at {} is rate limiting us, waiting {:.1}s before retrying (attempt {attempt}).",
                    host_of(&message.url),
                    wait.as_secs_f64()
                );
            }
            thread::sleep(wait);
            continue;
        }

        eprintln!(
            "\nAn error occurred when Findomain tried to publish the data to the following webhook {}. \nError description: {status}",
            message.url
        );
        return Ok(false);
    }
}

/// Reads a `Retry-After` given in seconds, whole or fractional.
///
/// The header may also carry an HTTP date, which none of the chat services
/// send; that form is treated as absent and gets the default wait.
fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    headers
        .get(RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<f64>()
        .ok()
        .filter(|seconds| seconds.is_finite() && *seconds >= 0.0)
        .map(Duration::from_secs_f64)
}

/// The host part of a webhook URL, which is all the log needs: the path
/// carries the webhook's secret token.
fn host_of(url: &str) -> String {
    Url::parse(url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_else(|| "the webhook".to_owned())
}

/// Reports whether `status` means the alert can be considered delivered.
fn accepted(status: StatusCode, push_on_timeout: bool) -> bool {
    status == StatusCode::OK
        || status == StatusCode::NO_CONTENT
        || (push_on_timeout && TIMEOUT_STATUSES.contains(&status.as_u16()))
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        fhc::structs::HttpData,
        std::{
            io::{BufRead, BufReader, Read, Write},
            net::TcpListener,
            sync::{
                atomic::{AtomicUsize, Ordering},
                Arc,
            },
            time::Instant,
        },
    };

    fn data(ip: &str, http_status: &str, ports: &[i32]) -> ResolvData {
        ResolvData {
            ip: ip.to_owned(),
            http_data: HttpData {
                http_status: http_status.to_owned(),
                ..HttpData::default()
            },
            open_ports: ports.to_vec(),
            ..ResolvData::default()
        }
    }

    #[test]
    fn accepted_covers_success_and_opt_in_timeouts() {
        assert!(accepted(StatusCode::OK, false));
        assert!(accepted(StatusCode::NO_CONTENT, false));
        assert!(!accepted(StatusCode::REQUEST_TIMEOUT, false));
        assert!(accepted(StatusCode::REQUEST_TIMEOUT, true));
        assert!(accepted(StatusCode::GATEWAY_TIMEOUT, true));
        assert!(!accepted(StatusCode::INTERNAL_SERVER_ERROR, true));
        assert!(!accepted(StatusCode::FORBIDDEN, true));
    }

    /// Answers each connection with the next scripted status, counting the
    /// requests. Just enough HTTP to satisfy the client.
    fn stub_webhook(script: Vec<(u16, Option<&'static str>)>) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}/hook", listener.local_addr().expect("addr"));
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        thread::spawn(move || {
            for (status, retry_after) in script {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                let mut line = String::new();
                let mut content_length = 0usize;
                loop {
                    line.clear();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        content_length = value.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0u8; content_length];
                let _ = reader.read_exact(&mut body);
                counter.fetch_add(1, Ordering::SeqCst);

                let retry = retry_after.map_or(String::new(), |s| format!("Retry-After: {s}\r\n"));
                let reason = if status == 200 {
                    "OK"
                } else {
                    "Too Many Requests"
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} {reason}\r\n{retry}Content-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = stream.flush();
            }
        });
        (url, hits)
    }

    fn quiet_config() -> Config {
        let mut config = Config::default();
        config.general.quiet = true;
        config.http.user_agents = vec!["findomain-test".to_owned()];
        config
    }

    fn message_to(url: String) -> Message {
        Message {
            url,
            body: HashMap::from([("content", "hello".to_owned())]),
        }
    }

    #[test]
    fn a_rate_limited_post_waits_out_retry_after_and_goes_through() {
        let (url, hits) = stub_webhook(vec![(429, Some("1")), (200, None)]);
        let started = Instant::now();

        let delivered =
            post(&quiet_config(), &webhook_client(), &message_to(url)).expect("no transport error");

        assert!(delivered);
        assert_eq!(hits.load(Ordering::SeqCst), 2, "one retry");
        assert!(
            started.elapsed() >= Duration::from_secs(1),
            "did not wait: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn rate_limit_waits_are_honoured_for_as_long_as_the_service_asks() {
        // Seven refusals before the service relents; nothing here decides to
        // stop early, the service does.
        let mut script = vec![(429, Some("0")); 7];
        script.push((200, None));
        let (url, hits) = stub_webhook(script);

        let delivered =
            post(&quiet_config(), &webhook_client(), &message_to(url)).expect("no transport error");

        assert!(delivered);
        assert_eq!(hits.load(Ordering::SeqCst), 8);
    }

    #[test]
    fn a_configured_ceiling_gives_up_once_the_next_wait_would_pass_it() {
        // One second of budget: the first wait of one second fits, the second
        // would take the total to two, so the message is dropped then.
        let (url, hits) = stub_webhook(vec![(429, Some("1")); 4]);
        let mut config = quiet_config();
        config.monitoring.webhook_max_wait = 1;

        let delivered =
            post(&config, &webhook_client(), &message_to(url)).expect("no transport error");

        assert!(!delivered);
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn retry_after_is_seconds_and_anything_else_means_the_default() {
        let mut headers = HeaderMap::new();
        assert_eq!(retry_after(&headers), None);

        headers.insert(RETRY_AFTER, "2".parse().unwrap());
        assert_eq!(retry_after(&headers), Some(Duration::from_secs(2)));

        headers.insert(RETRY_AFTER, "1.5".parse().unwrap());
        assert_eq!(retry_after(&headers), Some(Duration::from_millis(1500)));

        headers.insert(
            RETRY_AFTER,
            "Wed, 21 Oct 2015 07:28:00 GMT".parse().unwrap(),
        );
        assert_eq!(retry_after(&headers), None);

        headers.insert(RETRY_AFTER, "-3".parse().unwrap());
        assert_eq!(retry_after(&headers), None);
    }

    #[test]
    fn the_log_names_the_host_and_never_the_token_in_the_path() {
        assert_eq!(
            host_of("https://discord.com/api/webhooks/123/sEcReTtOkEn"),
            "discord.com"
        );
        assert_eq!(host_of("not a url"), "the webhook");
    }

    #[test]
    fn the_closing_alert_is_about_new_subdomains() {
        assert!(is_news(true, false));
        // Nothing new and not asked to report emptiness: just store.
        assert!(!is_news(false, false));
        // --aempty reports either way.
        assert!(is_news(false, true));
    }

    #[test]
    fn summarize_drops_unresolved_hosts_when_checks_ran() {
        let mut config = Config::default();
        config.resolution.discover_ip = true;

        let resolv_data = HashMap::from([
            ("a.example.com".to_owned(), data("1.2.3.4", "ACTIVE", &[80])),
            ("b.example.com".to_owned(), data("", "INACTIVE", &[])),
        ]);

        let summary = summarize(&config, &resolv_data);
        assert_eq!(
            summary.into_iter().collect::<Vec<_>>(),
            ["HOST: a.example.com,IP: 1.2.3.4,HTTP/S: ACTIVE,OPEN PORTS: [80]"]
        );
    }

    #[test]
    fn summarize_keeps_ipv6_hosts() {
        // --ipv6-only stores an IPv6 address; filtering on IPv4 alone would
        // leave the monitoring report empty on every run.
        let mut config = Config::default();
        config.resolution.discover_ip = true;
        config.resolution.ipv6_only = true;

        let resolv_data = HashMap::from([(
            "a.example.com".to_owned(),
            data("2606:4700::6810:2ca3", "ACTIVE", &[]),
        )]);

        let summary = summarize(&config, &resolv_data);
        assert_eq!(summary.len(), 1);
        assert!(summary
            .into_iter()
            .next()
            .is_some_and(|line| line.contains("IP: 2606:4700::6810:2ca3")));
    }

    #[test]
    fn summarize_keeps_every_host_when_nothing_was_checked() {
        let config = Config::default();
        let resolv_data = HashMap::from([
            ("a.example.com".to_owned(), data("", "NOT CHECKED", &[])),
            ("b.example.com".to_owned(), data("", "NOT CHECKED", &[])),
        ]);

        let summary = summarize(&config, &resolv_data);
        assert_eq!(summary.len(), 2);
        assert!(summary.iter().all(|line| line.contains("IP: NULL")));
    }

    #[test]
    fn summarize_reports_open_ports_when_scanning() {
        let mut config = Config::default();
        config.resolution.discover_ip = true;
        config.ports.enabled = true;

        let resolv_data = HashMap::from([(
            "a.example.com".to_owned(),
            data("1.2.3.4", "NOT CHECKED", &[80, 443]),
        )]);

        let summary = summarize(&config, &resolv_data);
        assert!(summary
            .iter()
            .next()
            .unwrap()
            .ends_with("OPEN PORTS: [80, 443]"));
    }
}
