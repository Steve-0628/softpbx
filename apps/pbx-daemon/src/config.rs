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
    /// Devices that may register and be called.
    #[serde(default)]
    pub device: Vec<DeviceCfg>,
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
            pbx_uri: format!("sip:{}", self.general.pbx_host),
            pbx_host: self.general.pbx_host.clone(),
            pbx_contact: format!("<sip:{}>", self.general.pbx_host),
            rtp_host: self.general.rtp_host.clone(),
            rtp_port_base: self.general.rtp_port_base,
            rtp_ports: self.general.rtp_ports,
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
}
