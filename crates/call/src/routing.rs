//! Call routing: where a dialed number goes (docs/03 §4).
//!
//! A short ordered list of rules — *"when someone dials something matching
//! this pattern, do that"* — first match wins. Pure and tiny on purpose:
//! pattern in, destination out. With no rules at all the behavior is exactly
//! "the dialed number rings the device that has it" (and `404` if none).

/// What a dialed number resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    /// Ring the device with this number.
    Ring(String),
    /// Send the call down a trunk to another PBX, addressed with this number
    /// (docs/03 §4, docs/06 §1).
    Trunk(String, String),
    /// The number is not allowed (docs/03: "dial 0 for an outside line → no").
    Reject,
}

/// One routing rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Pattern over the dialed number: `*` any run, `?` one character,
    /// anything else literal.
    pub pattern: String,
    /// What matching the pattern means.
    pub action: Action,
    /// Optional prefix stripped from the dialed number before the action.
    pub strip: Option<String>,
}

/// What a matching rule does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Ring the device with the (possibly stripped) dialed number.
    Dialed,
    /// Ring this specific number.
    Number(String),
    /// Send it down this trunk, addressed with the (possibly stripped) number.
    Trunk(String),
    /// Refuse the call.
    Reject,
}

/// Resolves a dialed number through the rules. First match wins; no match
/// means "ring the device with that number" (today's behavior).
pub fn route(rules: &[Rule], dialed: &str) -> Destination {
    for rule in rules {
        if !glob_match(&rule.pattern, dialed) {
            continue;
        }
        // Strip the prefix, unless that would leave nothing to ring.
        let number = match &rule.strip {
            Some(prefix) => match dialed.strip_prefix(prefix.as_str()) {
                Some(rest) if !rest.is_empty() => rest,
                _ => dialed,
            },
            None => dialed,
        };
        return match &rule.action {
            Action::Dialed => Destination::Ring(number.to_string()),
            Action::Number(number) => Destination::Ring(number.clone()),
            Action::Trunk(trunk) => Destination::Trunk(trunk.clone(), number.to_string()),
            Action::Reject => Destination::Reject,
        };
    }
    Destination::Ring(dialed.to_string())
}

/// Glob matching: `*` = any run (including empty), `?` = one byte. The
/// classic single-star-backtrack matcher: linear-ish (O(n·m) worst case),
/// no exponential blowup on hostile patterns.
pub fn glob_match(pattern: &str, value: &str) -> bool {
    let p = pattern.as_bytes();
    let v = value.as_bytes();
    let (mut pi, mut vi) = (0usize, 0usize);
    let (mut star, mut mark) = (None, 0usize);
    while vi < v.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == v[vi]) {
            pi += 1;
            vi += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            mark = vi;
            pi += 1;
        } else if let Some(star_at) = star {
            // Backtrack to the last star and let it eat one more byte.
            pi = star_at + 1;
            mark += 1;
            vi = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(pattern: &str, action: Action) -> Rule {
        Rule {
            pattern: pattern.to_string(),
            action,
            strip: None,
        }
    }

    #[test]
    fn no_rules_means_the_dialed_number() {
        assert_eq!(route(&[], "1002"), Destination::Ring("1002".to_string()));
    }

    #[test]
    fn first_match_wins() {
        let rules = vec![
            rule("0", Action::Number("1001".to_string())),
            rule("0*", Action::Reject),
            rule("*", Action::Dialed),
        ];
        assert_eq!(route(&rules, "0"), Destination::Ring("1001".to_string()));
        assert_eq!(route(&rules, "0123"), Destination::Reject);
        assert_eq!(route(&rules, "1002"), Destination::Ring("1002".to_string()));
    }

    #[test]
    fn strip_rewrites_before_the_lookup() {
        let rules = vec![Rule {
            pattern: "9*".to_string(),
            action: Action::Dialed,
            strip: Some("9".to_string()),
        }];
        assert_eq!(
            route(&rules, "91002"),
            Destination::Ring("1002".to_string())
        );
        // A match with nothing to strip keeps the number as dialed.
        assert_eq!(route(&rules, "9"), Destination::Ring("9".to_string()));
    }

    #[test]
    fn glob_shapes() {
        assert!(glob_match("1??", "101"));
        assert!(glob_match("1??", "199"));
        assert!(!glob_match("1??", "19"));
        assert!(!glob_match("1??", "1999"));
        assert!(glob_match("*", ""));
        assert!(glob_match("2*", "2"));
        assert!(glob_match("*55", "55"));
        assert!(!glob_match("2*", "32"));
    }
}
