//! Alert payloads for the supported chat webhooks.
//!
//! Each service wants a different JSON field, a different markup for
//! monospaced text and a different maximum message size, so the list of new
//! subdomains is formatted and split once per destination.

use {
    crate::{config::Config, utils::split_string_at_len},
    std::collections::{HashMap, HashSet},
};

/// A ready to POST alert.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Message {
    pub url: String,
    pub body: HashMap<&'static str, String>,
}

/// The chat services Findomain can alert.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Webhook {
    Discord,
    Slack,
    Telegram,
}

impl Webhook {
    /// Guesses the service behind a bare webhook URL.
    ///
    /// Only Discord and Slack can be addressed by URL alone; Telegram needs a
    /// chat id as well, so it never arrives this way.
    fn from_url(url: &str) -> Self {
        if url.contains("discord") {
            Self::Discord
        } else {
            Self::Slack
        }
    }

    /// Largest payload the service accepts, minus room for the markup.
    const fn max_payload_len(self) -> usize {
        match self {
            Self::Discord => 1900,
            Self::Slack => 15000,
            Self::Telegram => 4000,
        }
    }

    /// JSON field carrying the message text.
    const fn text_field(self) -> &'static str {
        match self {
            Self::Discord => "content",
            Self::Slack | Self::Telegram => "text",
        }
    }

    /// Wraps `body` in the service's monospace markup.
    fn monospace(self, body: &str) -> String {
        match self {
            Self::Discord | Self::Slack => format!("```{body}```"),
            Self::Telegram => format!("<code>{body}</code>"),
        }
    }

    /// Renders `text` in the service's bold markup.
    fn bold(self, text: &str) -> String {
        match self {
            Self::Discord => format!("**{text}**"),
            Self::Slack => format!("*{text}*"),
            Self::Telegram => format!("<b>{text}</b>"),
        }
    }

    /// Builds every chunk of the alert, already wrapped for the service.
    #[must_use]
    pub fn payloads(self, new_subdomains: &HashSet<String>, target: &str) -> Vec<String> {
        let alert = self.bold("Findomain alert:");

        if new_subdomains.is_empty() {
            return vec![self.monospace(&format!("{alert} No new subdomains found for {target}"))];
        }

        let mut payloads = vec![format!(
            "{alert} {} new subdomains found for {target}\n",
            new_subdomains.len()
        )];
        let listing = new_subdomains
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        payloads.extend(split_string_at_len(&listing, self.max_payload_len()));

        payloads
            .iter()
            .map(|payload| self.monospace(payload))
            .collect()
    }

    /// Builds the message for a single finding, sent the moment it appears.
    ///
    /// One finding is far below any service's limit, so there is nothing to
    /// split; the heading keeps it from reading like a hostname.
    #[must_use]
    pub fn finding_payload(self, finding: &str, target: &str) -> String {
        self.monospace(&format!(
            "{} {target}\n{finding}",
            self.bold("Findomain finding:")
        ))
    }
}

/// The configured chat destinations with the fields each one needs on top of
/// the text.
fn destinations(config: &Config) -> Vec<(Webhook, String, HashMap<&'static str, String>)> {
    let monitoring = &config.monitoring;
    let mut destinations = Vec::new();

    if !monitoring.discord_webhook.is_empty() {
        destinations.push((
            Webhook::Discord,
            monitoring.discord_webhook.clone(),
            HashMap::new(),
        ));
    }
    if !monitoring.slack_webhook.is_empty() {
        destinations.push((
            Webhook::Slack,
            monitoring.slack_webhook.clone(),
            HashMap::new(),
        ));
    }
    if let Some(telegram) = &monitoring.telegram {
        destinations.push((
            Webhook::Telegram,
            telegram.webhook.clone(),
            HashMap::from([
                ("chat_id", telegram.chat_id.clone()),
                ("parse_mode", "HTML".to_owned()),
            ]),
        ));
    }

    destinations
}

/// Wraps `payload` as a ready to POST message for one destination.
fn message(
    webhook: Webhook,
    url: &str,
    extra: &HashMap<&'static str, String>,
    payload: String,
) -> Message {
    let mut body = extra.clone();
    body.insert(webhook.text_field(), payload);
    Message {
        url: url.to_owned(),
        body,
    }
}

/// Where a finding goes: the dedicated webhook when one is configured, so
/// that vulnerabilities can land in a different channel from the daily
/// subdomain traffic, else every regular destination.
fn finding_destinations(config: &Config) -> Vec<(Webhook, String, HashMap<&'static str, String>)> {
    let dedicated = &config.monitoring.smart_alerts_webhook;
    if dedicated.is_empty() {
        return destinations(config);
    }
    vec![(
        Webhook::from_url(dedicated),
        dedicated.clone(),
        HashMap::new(),
    )]
}

/// Builds the alert for one finding, one message per destination.
#[must_use]
pub fn finding_messages(config: &Config, finding: &str, target: &str) -> Vec<Message> {
    finding_destinations(config)
        .into_iter()
        .map(|(webhook, url, extra)| {
            message(
                webhook,
                &url,
                &extra,
                webhook.finding_payload(finding, target),
            )
        })
        .collect()
}

/// Builds the end of run alert, one message per chunk per configured
/// destination.
#[must_use]
pub fn messages(config: &Config, new_subdomains: &HashSet<String>, target: &str) -> Vec<Message> {
    destinations(config)
        .into_iter()
        .flat_map(|(webhook, url, extra)| {
            webhook
                .payloads(new_subdomains, target)
                .into_iter()
                .map(|payload| message(webhook, &url, &extra, payload))
                .collect::<Vec<_>>()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use {super::*, crate::config::Telegram};

    fn subdomains(count: usize) -> HashSet<String> {
        (0..count).map(|i| format!("host{i}.example.com")).collect()
    }

    #[test]
    fn an_empty_result_produces_a_single_notice() {
        for webhook in [Webhook::Discord, Webhook::Slack, Webhook::Telegram] {
            let payloads = webhook.payloads(&HashSet::new(), "example.com");
            assert_eq!(payloads.len(), 1);
            assert!(payloads[0].contains("No new subdomains found for example.com"));
        }
    }

    #[test]
    fn each_service_gets_its_own_markup() {
        let found = subdomains(1);
        assert!(Webhook::Discord.payloads(&found, "example.com")[0]
            .starts_with("```**Findomain alert:** 1 new subdomains found"));
        assert!(Webhook::Slack.payloads(&found, "example.com")[0]
            .starts_with("```*Findomain alert:* 1 new subdomains found"));
        assert!(Webhook::Telegram.payloads(&found, "example.com")[0]
            .starts_with("<code><b>Findomain alert:</b> 1 new subdomains found"));
    }

    #[test]
    fn long_results_are_split_to_fit_the_service_limit() {
        let found = subdomains(500);
        let payloads = Webhook::Discord.payloads(&found, "example.com");
        assert!(payloads.len() > 2, "expected the listing to be split");
        // The markup adds 6 characters to each chunk.
        assert!(payloads
            .iter()
            .all(|payload| payload.len() <= Webhook::Discord.max_payload_len() + 6));

        // Every host must survive the split.
        let joined = payloads.concat();
        for host in &found {
            assert!(joined.contains(host), "{host} was dropped");
        }
    }

    #[test]
    fn a_finding_is_announced_as_a_finding_in_every_markup() {
        let line = "[high] https://a.example.com/admin Exposed panel (exposed-panel)";
        assert_eq!(
            Webhook::Discord.finding_payload(line, "example.com"),
            format!("```**Findomain finding:** example.com\n{line}```")
        );
        assert_eq!(
            Webhook::Slack.finding_payload(line, "example.com"),
            format!("```*Findomain finding:* example.com\n{line}```")
        );
        assert_eq!(
            Webhook::Telegram.finding_payload(line, "example.com"),
            format!("<code><b>Findomain finding:</b> example.com\n{line}</code>")
        );
    }

    #[test]
    fn a_finding_goes_to_every_destination_with_its_own_fields() {
        let mut config = Config::default();
        config.monitoring.discord_webhook = "https://discord.test/hook".to_owned();
        config.monitoring.telegram = Some(Telegram {
            webhook: "https://telegram.test/hook".to_owned(),
            chat_id: "42".to_owned(),
        });

        let messages = finding_messages(&config, "[critical] x RCE (cve)", "example.com");
        assert_eq!(
            messages.len(),
            2,
            "one message per destination, no chunking"
        );

        let discord = messages
            .iter()
            .find(|m| m.url.contains("discord"))
            .expect("discord");
        assert!(discord.body["content"].contains("RCE (cve)"));

        let telegram = messages
            .iter()
            .find(|m| m.url.contains("telegram"))
            .expect("telegram");
        assert_eq!(telegram.body["chat_id"], "42");
        assert_eq!(telegram.body["parse_mode"], "HTML");
        assert!(telegram.body["text"].contains("<b>Findomain finding:</b>"));
    }

    #[test]
    fn a_finding_with_no_destinations_goes_nowhere() {
        assert!(finding_messages(&Config::default(), "[high] x", "example.com").is_empty());
    }

    #[test]
    fn a_dedicated_webhook_takes_the_findings_away_from_the_subdomain_channels() {
        let mut config = Config::default();
        config.monitoring.discord_webhook = "https://discord.test/recon".to_owned();
        config.monitoring.slack_webhook = "https://slack.test/recon".to_owned();
        config.monitoring.smart_alerts_webhook = "https://hooks.slack.test/security".to_owned();

        let messages = finding_messages(&config, "[critical] x RCE (cve)", "example.com");
        assert_eq!(messages.len(), 1, "only the dedicated channel");
        assert_eq!(messages[0].url, "https://hooks.slack.test/security");
        assert!(messages[0].body["text"].starts_with("```*Findomain finding:*"));

        // The subdomain summary is unaffected by it.
        let summary = super::messages(&config, &subdomains(1), "example.com");
        assert!(summary.iter().all(|m| !m.url.contains("security")));
        assert_eq!(summary.len(), 2 * 2);
    }

    #[test]
    fn the_dedicated_webhook_service_is_told_from_its_url() {
        assert_eq!(
            Webhook::from_url("https://discord.com/api/webhooks/1/x"),
            Webhook::Discord
        );
        assert_eq!(
            Webhook::from_url("https://hooks.slack.com/services/T/B/x"),
            Webhook::Slack
        );
        // Unknown hosts get Slack's plain "text" field, the more common shape.
        assert_eq!(
            Webhook::from_url("https://example.test/hook"),
            Webhook::Slack
        );
    }

    #[test]
    fn no_destinations_means_no_messages() {
        assert!(messages(&Config::default(), &subdomains(1), "example.com").is_empty());
    }

    #[test]
    fn each_destination_gets_its_own_field_and_url() {
        let mut config = Config::default();
        config.monitoring.discord_webhook = "https://discord.test/hook".to_owned();
        config.monitoring.slack_webhook = "https://slack.test/hook".to_owned();
        config.monitoring.telegram = Some(Telegram {
            webhook: "https://telegram.test/hook".to_owned(),
            chat_id: "42".to_owned(),
        });

        let messages = messages(&config, &subdomains(1), "example.com");
        assert_eq!(messages.len(), 3 * 2, "header plus listing per destination");

        let discord: Vec<_> = messages
            .iter()
            .filter(|m| m.url == "https://discord.test/hook")
            .collect();
        assert_eq!(discord.len(), 2);
        assert!(discord.iter().all(|m| m.body.contains_key("content")));

        let telegram: Vec<_> = messages
            .iter()
            .filter(|m| m.url == "https://telegram.test/hook")
            .collect();
        assert_eq!(telegram.len(), 2);
        assert!(telegram
            .iter()
            .all(|m| m.body.get("chat_id").map(String::as_str) == Some("42")
                && m.body.get("parse_mode").map(String::as_str) == Some("HTML")
                && m.body.contains_key("text")));
    }

    #[test]
    fn a_slack_destination_never_receives_a_telegram_payload() {
        let mut config = Config::default();
        config.monitoring.slack_webhook = "https://slack.test/hook".to_owned();
        config.monitoring.telegram = Some(Telegram {
            webhook: "https://telegram.test/hook".to_owned(),
            chat_id: "42".to_owned(),
        });

        for message in messages(&config, &subdomains(1), "example.com") {
            let text = message.body.get("text").expect("a text field");
            if message.url.contains("slack") {
                assert!(!text.contains("<code>"), "slack got telegram markup");
            } else {
                assert!(text.contains("<code>"), "telegram lost its markup");
            }
        }
    }
}
