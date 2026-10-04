//! The config file: one TOML, written by a human, validated at startup
//! (docs/02 §4). If it is wrong, the daemon refuses to start and says why.

use std::collections::HashSet;
use std::net::SocketAddr;

use anyhow::{bail, Context};
use call::{Device, SwitchConfig};
use serde::Deserialize;

/// The whole config file. Unknown keys are refused: a typo or a section from
/// an older design must not be silently ignored.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    /// Global settings.
    pub general: General,
    /// Call routing rules, in order (docs/03 §4). Optional: without any, a
    /// dialed number simply rings the device with that number.
    #[serde(default)]
    pub routing: Vec<RoutingRule>,
    /// Trunks to other PBXs (docs/06 §1). Optional.
    #[serde(default)]
    pub trunk: Vec<TrunkCfg>,
    /// Devices that may register and be called.
    #[serde(default)]
    pub device: Vec<DeviceCfg>,
}

/// One `[[trunk]]`: a PBX we exchange calls with (docs/06 §1).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrunkCfg {
    /// Label used in `to = "trunk:<name>"` routing rules and in logs.
    pub name: String,
    /// Its address, "ip:port".
    pub peer: String,
    /// Digest credentials, for peers that challenge our INVITEs. Both fields
    /// or neither.
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub secret: Option<String>,
}

/// One `[[routing]]` rule: `match` a dialed number, `to` a destination.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingRule {
    /// Pattern over the dialed number (`*`, `?` wildcards).
    #[serde(rename = "match")]
    pub pattern: String,
    /// "dialed" (ring the device with that number), "reject", or a number.
    pub to: String,
    /// Optional prefix stripped from the dialed number first.
    #[serde(default)]
    pub strip: Option<String>,
}

impl RoutingRule {
    fn to_rule(&self) -> call::Rule {
        let action = match self.to.as_str() {
            "dialed" => call::Action::Dialed,
            "reject" => call::Action::Reject,
            destination => match destination.strip_prefix("trunk:") {
                Some(name) => call::Action::Trunk(name.to_string()),
                None => call::Action::Number(destination.to_string()),
            },
        };
        call::Rule {
            pattern: self.pattern.clone(),
            action,
            strip: self.strip.clone(),
        }
    }
}

/// `[general]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct General {
    /// Realm used in digest authentication.
    pub realm: String,
    /// Where to listen for SIP ("0.0.0.0:5060").
    pub sip_bind: String,
    /// Our address as devices see it, for Via/Contact ("192.0.2.10:5060").
    pub pbx_host: String,
    /// Our IP as devices see it, for SDP media ("192.0.2.10").
    pub rtp_host: String,
    /// First media relay port (two per concurrent call).
    pub rtp_port_base: u16,
    /// How many media ports to bind (two per concurrent call).
    pub rtp_ports: u16,
    /// Where the call log goes (NDJSON, append only).
    pub call_log: String,
}

/// One `[[device]]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceCfg {
    /// Its number ("1001").
    pub number: String,
    /// Display name.
    pub name: String,
    /// Password the device registers with.
    pub secret: String,
}

impl FileConfig {
    /// Reads, parses and validates a config file.
    pub fn load(path: &str) -> anyhow::Result<FileConfig> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read config file {path}"))?;
        Self::parse(&text).with_context(|| format!("{path} is not usable"))
    }

    /// Parses and validates config text (kept separate for testing).
    pub fn parse(text: &str) -> anyhow::Result<FileConfig> {
        let config: FileConfig =
            toml::from_str(text).with_context(|| "not valid TOML".to_string())?;
        config
            .validate()
            .with_context(|| "invalid configuration".to_string())?;
        Ok(config)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.general.realm.is_empty() {
            bail!("general.realm must not be empty");
        }
        self.general
            .sip_bind
            .parse::<SocketAddr>()
            .with_context(|| "general.sip_bind must be ip:port, e.g. \"0.0.0.0:5060\"")?;
        self.general
            .pbx_host
            .parse::<SocketAddr>()
            .with_context(|| "general.pbx_host must be ip:port, e.g. \"192.0.2.10:5060\"")?;
        self.general
            .rtp_host
            .parse::<std::net::IpAddr>()
            .with_context(|| "general.rtp_host must be an ip address, e.g. \"192.0.2.10\"")?;
        if self.general.rtp_ports < 2 {
            bail!("general.rtp_ports must be at least 2 (two ports per call)");
        }
        if self.general.rtp_port_base == 0 {
            bail!("general.rtp_port_base must not be 0");
        }
        if u32::from(self.general.rtp_port_base) + u32::from(self.general.rtp_ports) > 65_536 {
            bail!("general.rtp_port_base + rtp_ports must stay within the port range");
        }
        if self.device.is_empty() {
            bail!("no [[device]] sections: nothing could register");
        }
        for rule in &self.routing {
            if rule.pattern.is_empty() {
                bail!("a [[routing]] rule has an empty match");
            }
            if rule.pattern.len() > 64 {
                bail!("routing match \"{}\" is too long (max 64)", rule.pattern);
            }
            let known = rule.to == "dialed"
                || rule.to == "reject"
                || rule
                    .to
                    .strip_prefix("trunk:")
                    .is_some_and(|name| !name.is_empty())
                || (!rule.to.is_empty() && rule.to.bytes().all(|b| b.is_ascii_digit()));
            if !known {
                bail!(
                    "routing match \"{}\": to must be \"dialed\", \"reject\", \"trunk:<name>\" or a number, got \"{}\"",
                    rule.pattern,
                    rule.to
                );
            }
            if let Some(name) = rule.to.strip_prefix("trunk:") {
                if !self.trunk.iter().any(|trunk| trunk.name == name) {
                    bail!(
                        "routing match \"{}\": no such trunk \"{}\"",
                        rule.pattern,
                        name
                    );
                }
            }
            if let Some(strip) = &rule.strip {
                // strip rewrites the dialed number before the destination sees
                // it: useful with `dialed` ("dial 9 to get out") and with
                // `trunk:` ("dial 9 + strip 9 → the far PBX").
                let rewriteable = rule.to == "dialed"
                    || rule
                        .to
                        .strip_prefix("trunk:")
                        .is_some_and(|name| !name.is_empty());
                if !rewriteable {
                    bail!(
                        "routing match \"{}\": strip only makes sense with to = \"dialed\" or \"trunk:<name>\"",
                        rule.pattern
                    );
                }
                if strip.is_empty() {
                    bail!(
                        "routing match \"{}\": strip must not be empty",
                        rule.pattern
                    );
                }
            }
        }
        let mut trunks = HashSet::new();
        for trunk in &self.trunk {
            if trunk.name.is_empty() {
                bail!("a [[trunk]] has an empty name");
            }
            if !trunks.insert(trunk.name.clone()) {
                bail!("duplicate trunk name \"{}\"", trunk.name);
            }
            trunk
                .peer
                .parse::<std::net::SocketAddr>()
                .with_context(|| format!("trunk \"{}\": peer must be ip:port", trunk.name))?;
            if trunk.username.is_some() != trunk.secret.is_some() {
                bail!("trunk \"{}\": username and secret go together", trunk.name);
            }
        }
        let mut numbers = HashSet::new();
        for device in &self.device {
            if device.number.is_empty() {
                bail!("a [[device]] has an empty number");
            }
            if !numbers.insert(device.number.clone()) {
                bail!("duplicate device number \"{}\"", device.number);
            }
            if device.secret.is_empty() {
                bail!("device \"{}\" has an empty secret", device.number);
            }
        }
        Ok(())
    }

    /// The validated configuration, in the switch's shape.
    pub fn switch_config(&self) -> SwitchConfig {
        SwitchConfig {
            realm: self.general.realm.clone(),
            // The address-of-record domain is the host, without the SIP port
            // (RFC 3261 §19.1.5).
            pbx_uri: format!(
                "sip:{}",
                self.general
                    .pbx_host
                    .parse::<std::net::SocketAddr>()
                    .map(|address| address.ip().to_string())
                    .unwrap_or_else(|_| self.general.pbx_host.clone())
            ),
            pbx_host: self.general.pbx_host.clone(),
            pbx_contact: format!("<sip:{}>", self.general.pbx_host),
            rtp_host: self.general.rtp_host.clone(),
            rtp_port_base: self.general.rtp_port_base,
            rtp_ports: self.general.rtp_ports,
            routing: self.routing.iter().map(RoutingRule::to_rule).collect(),
            trunks: self
                .trunk
                .iter()
                .map(|trunk| call::TrunkConfig {
                    name: trunk.name.clone(),
                    peer: trunk.peer.parse().expect("validated"),
                    username: trunk.username.clone(),
                    secret: trunk.secret.clone(),
                })
                .collect(),
            devices: self
                .device
                .iter()
                .map(|device| Device {
                    number: device.number.clone(),
                    name: device.name.clone(),
                    secret: device.secret.clone(),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::FileConfig;

    const GOOD: &str = r#"
        [general]
        realm = "softpbx"
        sip_bind = "0.0.0.0:5060"
        pbx_host = "192.0.2.10:5060"
        rtp_host = "192.0.2.10"
        rtp_port_base = 10000
        rtp_ports = 100
        call_log = "/tmp/softpbx/calls.ndjson"

        [[device]]
        number = "1001"
        name = "Alice"
        secret = "change-me"
    "#;

    #[test]
    fn good_config_parses() {
        let config = FileConfig::parse(GOOD).expect("valid config");
        assert_eq!(config.general.realm, "softpbx");
        assert_eq!(config.device.len(), 1);
        let switch = config.switch_config();
        assert_eq!(switch.pbx_contact, "<sip:192.0.2.10:5060>");
        assert_eq!(switch.devices[0].number, "1001");
    }

    #[test]
    fn bad_configs_are_refused_with_reasons() {
        for (text, reason) in [
            ("not toml at all", "not valid TOML"),
            ("[general]", "missing field"),
            (
                &GOOD.replace("sip_bind = \"0.0.0.0:5060\"", "sip_bind = \"everywhere\""),
                "sip_bind",
            ),
            (
                &GOOD.replace("rtp_host = \"192.0.2.10\"", "rtp_host = \"host\""),
                "rtp_host",
            ),
            (
                &GOOD.replace("rtp_ports = 100", "rtp_ports = 1"),
                "rtp_ports",
            ),
            (&GOOD.replace("[[device]]", "[[devices]]"), "unknown field"),
            (
                &GOOD.replace("secret = \"change-me\"", "secret = \"\""),
                "secret",
            ),
            (
                &GOOD.replace("number = \"1001\"", "number = \"\""),
                "number",
            ),
        ] {
            let error = FileConfig::parse(text).expect_err("must be refused");
            assert!(
                format!("{error:#}").contains(reason),
                "expected {reason:?} in: {error:#}"
            );
        }
    }

    #[test]
    fn duplicate_numbers_are_refused() {
        let doubled =
            format!("{GOOD}\n[[device]]\nnumber = \"1001\"\nname = \"Twin\"\nsecret = \"x\"\n");
        let error = FileConfig::parse(&doubled).expect_err("duplicate");
        assert!(format!("{error:#}").contains("duplicate"));
    }

    #[test]
    fn routing_rules_validate() {
        let good = format!(
            "{GOOD}\n[[routing]]\nmatch = \"9*\"\nto = \"dialed\"\nstrip = \"9\"\n\n\
             [[routing]]\nmatch = \"0\"\nto = \"1001\"\n\n\
             [[routing]]\nmatch = \"1*\"\nto = \"reject\"\n"
        );
        let config = FileConfig::parse(&good).expect("valid routing");
        assert_eq!(config.routing.len(), 3);
        assert_eq!(config.switch_config().routing.len(), 3);

        let bad_to = format!("{GOOD}\n[[routing]]\nmatch = \"9*\"\nto = \"somewhere\"\n");
        let error = FileConfig::parse(&bad_to).expect_err("unknown destination");
        assert!(format!("{error:#}").contains("dialed"), "{error:#}");

        let empty_match = format!("{GOOD}\n[[routing]]\nmatch = \"\"\nto = \"dialed\"\n");
        assert!(FileConfig::parse(&empty_match).is_err());

        // strip is meaningless unless the rule routes to the dialed number.
        let bad_strip =
            format!("{GOOD}\n[[routing]]\nmatch = \"9*\"\nto = \"reject\"\nstrip = \"9\"\n");
        assert!(FileConfig::parse(&bad_strip).is_err());
    }

    #[test]
    fn trunk_rules_validate() {
        let good = format!(
            "{GOOD}\n[[trunk]]\nname = \"mikopbx\"\npeer = \"192.168.77.108:5060\"\n\n\
             [[routing]]\nmatch = \"3*\"\nto = \"trunk:mikopbx\"\n"
        );
        let config = FileConfig::parse(&good).expect("valid trunk");
        assert_eq!(config.trunk.len(), 1);
        assert_eq!(config.switch_config().trunks.len(), 1);

        // A route to a trunk that does not exist is refused at startup.
        let dangling = format!("{GOOD}\n[[routing]]\nmatch = \"3*\"\nto = \"trunk:nope\"\n");
        let error = FileConfig::parse(&dangling).expect_err("unknown trunk");
        assert!(format!("{error:#}").contains("nope"), "{error:#}");

        // A trunk needs a real address.
        let bad_peer = format!("{GOOD}\n[[trunk]]\nname = \"m\"\npeer = \"over-there:5060\"\n");
        assert!(FileConfig::parse(&bad_peer).is_err());
    }

    #[test]
    fn device_unknown_keys_are_refused() {
        // The same promise as everywhere else: a typo is an error, not silence.
        let typo = GOOD.replace("name = \"Alice\"", "name = \"Alice\"\npin = \"1234\"");
        let error = FileConfig::parse(&typo).expect_err("unknown device key");
        assert!(format!("{error:#}").contains("pin"), "{error:#}");
    }
}
