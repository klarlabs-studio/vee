//! Error markers that let every transport report the same failure class:
//! usage errors (bad input) and configuration errors both map to exit code 3
//! on the CLI; anything else is an execution failure.

#[derive(Debug)]
pub struct ConfigurationFailure(pub String);

impl std::fmt::Display for ConfigurationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ConfigurationFailure {}

#[derive(Debug)]
pub struct UsageFailure(pub String);

impl std::fmt::Display for UsageFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for UsageFailure {}

pub fn configuration_failure(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(ConfigurationFailure(message.into()))
}

pub fn usage_failure(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(UsageFailure(message.into()))
}
