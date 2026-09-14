pub use dmc_model::Error;
pub use dmc_model::Result;

pub fn storage_err(err: dmc_storage::Error) -> Error {
    Error::Io(err.to_string())
}
