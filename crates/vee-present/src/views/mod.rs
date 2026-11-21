//! `ToView` implementations, one module per bounded context.

mod findings;
mod gate;
pub mod review;
mod setup;
pub(crate) mod verification;

/// The serialized (snake_case) name of a unit enum value, as the JSON documents spell it.
pub(crate) fn serde_name<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}
