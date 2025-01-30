use url::{ParseError, Url};

#[derive(Debug)]
pub enum Error {
    BadScheme,
    ParseError(ParseError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error::*;

        match self {
            BadScheme => write!(f, "URL scheme is not allowed"),
            ParseError(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for Error {}

impl From<ParseError> for Error {
    fn from(err: ParseError) -> Error { Error::ParseError(err) }
}

type Result<T> = core::result::Result<T, Error>;

/// Try to convert some type into a [`Url`].
///
/// This trait is "sealed", such that only types within payjoin can
/// implement it.
///
/// This design is inspired by the `reqwest` crate's design:
/// see <https://docs.rs/reqwest/latest/reqwest/trait.IntoUrl.html>
pub trait IntoUrl: IntoUrlSealed {}

impl IntoUrl for &Url {}
impl IntoUrl for Url {}
impl IntoUrl for &str {}
impl IntoUrl for &String {}
impl IntoUrl for String {}

pub trait IntoUrlSealed {
    /// Besides parsing as a valid `Url`, the `Url` must be a valid
    /// `http::Uri`, in that it makes sense to use in a network request.
    fn into_url(self) -> Result<Url>;

    fn as_str(&self) -> &str;
}

impl IntoUrlSealed for &Url {
    fn into_url(self) -> Result<Url> { self.clone().into_url() }

    fn as_str(&self) -> &str { self.as_ref() }
}

impl IntoUrlSealed for Url {
    fn into_url(self) -> Result<Url> {
        if self.has_host() {
            Ok(self)
        } else {
            Err(Error::BadScheme)
        }
    }

    fn as_str(&self) -> &str { self.as_ref() }
}

impl IntoUrlSealed for &str {
    fn into_url(self) -> Result<Url> { Url::parse(self)?.into_url() }

    fn as_str(&self) -> &str { self }
}

impl IntoUrlSealed for &String {
    fn into_url(self) -> Result<Url> { (&**self).into_url() }

    fn as_str(&self) -> &str { self.as_ref() }
}

impl IntoUrlSealed for String {
    fn into_url(self) -> Result<Url> { (&*self).into_url() }

    fn as_str(&self) -> &str { self.as_ref() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_uri_scheme_is_allowed() {
        let url = "http://localhost".into_url().unwrap();
        assert_eq!(url.scheme(), "http");
    }

    #[test]
    fn https_uri_scheme_is_allowed() {
        let url = "https://localhost".into_url().unwrap();
        assert_eq!(url.scheme(), "https");
    }

    #[test]
    fn into_url_file_scheme() {
        let err = "file:///etc/hosts".into_url().unwrap_err();
        assert_eq!(err.to_string(), "URL scheme is not allowed");
    }

    #[test]
    fn into_url_blob_scheme() {
        let err = "blob:https://example.com".into_url().unwrap_err();
        assert_eq!(err.to_string(), "URL scheme is not allowed");
    }
}
