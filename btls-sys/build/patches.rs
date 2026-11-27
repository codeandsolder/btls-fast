use std::collections::BTreeSet;
use std::io;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Condition {
    Always,
    NonFips,
    Rpk,
    PrefixSymbols,
    AllowCrlExtensionsBadVersion,
    UnderscoreWildcards,
    RelaxCertValidation,
}

pub struct Patch {
    pub condition: Condition,
    pub file: &'static str,
}

/// Shared ordered patch manifest used by Cargo and standalone native tests.
pub fn series() -> io::Result<Vec<Patch>> {
    let mut names = BTreeSet::new();
    include_str!("../patches/series")
        .lines()
        .map(|line| {
            let (condition, file) = line
                .split_once(' ')
                .ok_or_else(|| io::Error::other("invalid patch series entry"))?;
            let condition = match condition {
                "always" => Condition::Always,
                "non-fips" => Condition::NonFips,
                "rpk" => Condition::Rpk,
                "prefix-symbols" => Condition::PrefixSymbols,
                "allow-crl-extensions-bad-version" => Condition::AllowCrlExtensionsBadVersion,
                "underscore-wildcards" => Condition::UnderscoreWildcards,
                "relax-cert-validation" => Condition::RelaxCertValidation,
                _ => {
                    return Err(io::Error::other(format!(
                        "unknown patch condition {condition}"
                    )));
                }
            };
            if !file.ends_with(".patch")
                || !file
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'))
                || !names.insert(file)
            {
                return Err(io::Error::other(format!(
                    "invalid or repeated patch name {file}"
                )));
            }
            Ok(Patch { condition, file })
        })
        .collect()
}
