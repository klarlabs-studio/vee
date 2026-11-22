//! `ToView` implementations, one module per bounded context.

mod analysis;
mod findings;
mod gate;
mod governance;
mod history;
mod insights;
mod lists;
pub mod review;
mod setup;
pub(crate) mod verification;
pub(crate) mod work;

/// The serialized (snake_case) name of a unit enum value, as the JSON documents spell it.
pub(crate) fn serde_name<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}
