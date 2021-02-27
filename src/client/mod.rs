use std::collections::HashMap;
use std::fmt;
use std::io::Read;
use std::num::NonZeroU64;
use std::result::Result as StdResult;
use std::str::FromStr;

use crate::client::error::{Error, Result};
use base64;
use reqwest::{
    self,
    blocking::{Client, Response},
    header::CONTENT_TYPE,
    Method,
};
use serde::de::{self, DeserializeOwned, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::TryInto;
use chrono::{DateTime, FixedOffset, NaiveDateTime};
use serde_json;
use std::time::Duration;
use url::Url;

/// Errors
pub mod error;

/// Lease duration.
///
/// Note: Value returned from vault api is assumed to be in seconds.
///
/// ```
/// use hashicorp_vault::client::VaultDuration;
///
/// assert_eq!(VaultDuration::days(1),
///            VaultDuration(std::time::Duration::from_secs(86400)));
/// ```
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct VaultDuration(pub Duration);

impl VaultDuration {
    /// Construct a duration from some number of seconds.
    pub fn seconds(s: u64) -> VaultDuration {
        VaultDuration(Duration::from_secs(s))
    }

    /// Construct a duration from some number of minutes.
    pub fn minutes(m: u64) -> VaultDuration {
        VaultDuration::seconds(m * 60)
    }

    /// Construct a duration from some number of hours.
    pub fn hours(h: u64) -> VaultDuration {
        VaultDuration::minutes(h * 60)
    }

    /// Construct a duration from some number of days.
    pub fn days(d: u64) -> VaultDuration {
        VaultDuration::hours(d * 24)
    }
}

impl Serialize for VaultDuration {
    fn serialize<S>(&self, serializer: S) -> StdResult<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(self.0.as_secs())
    }
}
struct VaultDurationVisitor;
impl<'de> Visitor<'de> for VaultDurationVisitor {
    type Value = VaultDuration;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a positive integer")
    }

    fn visit_u64<E>(self, value: u64) -> StdResult<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(VaultDuration(Duration::from_secs(value)))
    }
}
impl<'de> Deserialize<'de> for VaultDuration {
    fn deserialize<D>(deserializer: D) -> StdResult<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_u64(VaultDurationVisitor)
    }
}

/// Number of uses to be used with tokens.
///
/// Note: Value returned from vault api can be 0 which means unlimited.
///
/// ```
/// use hashicorp_vault::client::VaultNumUses;
/// use std::num::NonZeroU64;
///
/// let num_uses: VaultNumUses = 10.into();
///
/// match num_uses {
///     VaultNumUses::Limited(uses) => assert_eq!(uses.get(), 10),
///     VaultNumUses::Unlimited => panic!("Uses shouldn't be unlimited!"),
/// }
/// ```
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum VaultNumUses {
    /// The number of uses is unlimited
    Unlimited,

    /// The number of uses is limited to the value
    /// specified that is guaranteed to be non zero.
    Limited(NonZeroU64),
}

impl Default for VaultNumUses {
    fn default() -> Self {
        VaultNumUses::Unlimited
    }
}

impl From<u64> for VaultNumUses {
    fn from(v: u64) -> Self {
        match NonZeroU64::new(v) {
            Some(non_zero) => VaultNumUses::Limited(non_zero),
            None => VaultNumUses::Unlimited,
        }
    }
}

impl Serialize for VaultNumUses {
    fn serialize<S>(&self, serializer: S) -> StdResult<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            VaultNumUses::Unlimited => serializer.serialize_u64(0),
            VaultNumUses::Limited(val) => serializer.serialize_u64(val.clone().into()),
        }
    }
}
struct VaultNumUsesVisitor;
impl<'de> Visitor<'de> for VaultNumUsesVisitor {
    type Value = VaultNumUses;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a positive integer")
    }

    fn visit_u64<E>(self, value: u64) -> StdResult<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(value.into())
    }
}
impl<'de> Deserialize<'de> for VaultNumUses {
    fn deserialize<D>(deserializer: D) -> StdResult<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_u64(VaultNumUsesVisitor)
    }
}

/// Used for vault responses that return seconds since unix epoch
/// See: https://github.com/hashicorp/vault/issues/1654
#[derive(Debug)]
pub struct VaultNaiveDateTime(pub NaiveDateTime);
struct VaultNaiveDateTimeVisitor;
impl<'de> Visitor<'de> for VaultNaiveDateTimeVisitor {
    type Value = VaultNaiveDateTime;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a positive integer")
    }

    fn visit_u64<E>(self, value: u64) -> StdResult<Self::Value, E>
    where
        E: de::Error,
    {
        let date_time = NaiveDateTime::from_timestamp_opt(value as i64, 0);

        match date_time {
            Some(dt) => Ok(VaultNaiveDateTime(dt)),
            None => Err(E::custom(format!(
                "Could not parse: `{}` as a unix timestamp",
                value,
            ))),
        }
    }
}
impl<'de> Deserialize<'de> for VaultNaiveDateTime {
    fn deserialize<D>(deserializer: D) -> StdResult<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_u64(VaultNaiveDateTimeVisitor)
    }
}

/// Used for responses that return RFC 3339 timestamps
/// See: https://github.com/hashicorp/vault/issues/1654
#[derive(Debug)]
pub struct VaultDateTime(pub DateTime<FixedOffset>);
struct VaultDateTimeVisitor;
impl<'de> Visitor<'de> for VaultDateTimeVisitor {
    type Value = VaultDateTime;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a timestamp string")
    }

    fn visit_str<E>(self, value: &str) -> StdResult<Self::Value, E>
    where
        E: de::Error,
    {
        let date_time = DateTime::parse_from_rfc3339(value);
        match date_time {
            Ok(dt) => Ok(VaultDateTime(dt)),
            Err(e) => Err(E::custom(format!(
                "Could not parse: `{}` as an RFC 3339 timestamp. Error: \
                 `{:?}`",
                value, e
            ))),
        }
    }
}
impl<'de> Deserialize<'de> for VaultDateTime {
    fn deserialize<D>(deserializer: D) -> StdResult<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(VaultDateTimeVisitor)
    }
}

/// Vault client used to make API requests to the vault
#[derive(Debug)]
pub struct VaultClient<T> {
    /// URL to vault instance
    pub host: Url,
    /// Token to access vault
    pub token: String,
    /// `reqwest::Client`
    client: Client,
    /// Data
    pub data: Option<VaultResponse<T>>,
}

/// Token data, used in `VaultResponse`
#[derive(Deserialize, Debug)]
pub struct TokenData {
    /// Accessor token
    pub accessor: Option<String>,
    /// Creation time
    pub creation_time: VaultNaiveDateTime,
    /// Creation time-to-live
    pub creation_ttl: Option<VaultDuration>,
    /// Display name
    pub display_name: String,
    /// Max time-to-live
    pub explicit_max_ttl: Option<VaultDuration>,
    /// Token id
    pub id: String,
    /// Last renewal time
    pub last_renewal_time: Option<VaultDuration>,
    /// Meta
    pub meta: Option<HashMap<String, String>>,
    /// Number of uses (0: unlimited)
    pub num_uses: VaultNumUses,
    /// true if token is an orphan
    pub orphan: bool,
    /// Path
    pub path: String,
    /// Policies for token
    pub policies: Vec<String>,
    /// True if renewable
    pub renewable: Option<bool>,
    /// Role
    pub role: Option<String>,
    /// Time-to-live
    pub ttl: VaultDuration,
}

/// Secret data, used in `VaultResponse`
///
/// This struct should onlly ever be necessary for advanced users who
/// are creating and parsing Vault responses manually.
#[derive(Deserialize, Serialize, Debug)]
pub struct SecretDataWrapper<D> {
    /// data is an opaque data type that holds the response from Vault.
    pub data: D,
}

/// Actual Secret data, used in `VaultResponse`
#[derive(Deserialize, Serialize, Debug)]
struct SecretData {
    value: String,
}

/// Transit decrypted data, used in `VaultResponse`
#[derive(Deserialize, Serialize, Debug)]
struct TransitDecryptedData {
    plaintext: String,
}

/// Transit encrypted data, used in `VaultResponse`
#[derive(Deserialize, Serialize, Debug)]
struct TransitEncryptedData {
    ciphertext: String,
}

/// Vault auth
#[derive(Deserialize, Debug)]
pub struct Auth {
    /// Client token id
    pub client_token: String,
    /// Accessor
    pub accessor: Option<String>,
    /// Policies
    pub policies: Vec<String>,
    /// Metadata
    pub metadata: Option<HashMap<String, String>>,
    /// Lease duration
    pub lease_duration: Option<VaultDuration>,
    /// True if renewable
    pub renewable: bool,
}

/// Vault response. Different vault responses have different `data` types, so `D` is used to
/// represent this.
#[derive(Deserialize, Debug)]
pub struct VaultResponse<D> {
    /// Request id
    pub request_id: String,
    /// Lease id
    pub lease_id: Option<String>,
    /// True if renewable
    pub renewable: Option<bool>,
    /// Lease duration (in seconds)
    pub lease_duration: Option<VaultDuration>,
    /// Data
    pub data: Option<D>,
    /// Warnings
    pub warnings: Option<Vec<String>>,
    /// Auth
    pub auth: Option<Auth>,
    /// Wrap info, containing token to perform unwrapping
    pub wrap_info: Option<WrapInfo>,
}

impl<D> From<VaultResponse<SecretDataWrapper<D>>> for VaultResponse<D> {
    fn from(v: VaultResponse<SecretDataWrapper<D>>) -> Self {
        Self {
            request_id: v.request_id,
            lease_id: v.lease_id,
            renewable: v.renewable,
            lease_duration: v.lease_duration,
            data: v.data.map(|value| value.data),
            warnings: v.warnings,
            auth: v.auth,
            wrap_info: v.wrap_info,
        }
    }
}

/// Information provided to retrieve a wrapped response
#[derive(Deserialize, Debug)]
pub struct WrapInfo {
    /// Time-to-live
    pub ttl: VaultDuration,
    /// Token
    pub token: String,
    /// Creation time, note this returned in RFC 3339 format
    pub creation_time: VaultDateTime,
    /// Wrapped accessor
    pub wrapped_accessor: Option<String>,
}

/// Wrapped response is serialized json
#[derive(Deserialize, Serialize, Debug)]
pub struct WrapData {
    /// Serialized json string of type `VaultResponse<HashMap<String, String>>`
    response: String,
}

/// Token Types
#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum TokenType {
    /// Batch tokens are encrypted blobs that carry enough information
    /// for them to be used for Vault actions, but they require no
    /// storage on disk to track them.
    Batch,
    /// Service tokens are what users will generally think of as
    /// "normal" Vault tokens.
    Service,
    /// Will use the mount's tuned default.
    Default,
    /// For a token store this will default to batch, unless the client requests
    /// a different type at generation time.
    DefaultBatch,
    /// For a token store this will default to service, unless the client requests
    /// a different type at generation time.
    DefaultService,
}

/// `AppRole` properties
#[derive(Deserialize, Debug)]
pub struct AppRoleProperties {
    /// Require `secret_id` to be presented when logging in using this `AppRole`. Defaults to 'true'.
    pub bind_secret_id: bool,
    /// The secret IDs generated using this role will be cluster local.
    pub local_secret_ids: bool,
    /// List of CIDR blocks; if set, specifies blocks of IP addresses which can
    /// perform the login operation.
    pub secret_id_bound_cidrs: Option<Vec<String>>,
    /// Number of times any particular `SecretID` can be used to fetch a token from this `AppRole`,
    /// after which the `SecretID` will expire.
    pub secret_id_num_uses: VaultNumUses,
    /// Duration in either an integer number of seconds (3600) or an integer time unit (60m) after which any SecretID expires.
    pub secret_id_ttl: VaultDuration,
    /// List of CIDR blocks; if set, specifies blocks of IP addresses which can authenticate successfully,
    /// and ties the resulting token to these blocks as well.
    pub token_bound_cidrs: Option<Vec<String>>,
    /// If set, will encode an explicit max TTL onto the token. This is a hard cap even if token_ttl and
    /// token_max_ttl would otherwise allow a renewal.
    pub token_explicit_max_ttl: Option<VaultDuration>,
    /// If set, the default policy will not be set on generated tokens; otherwise it will be added to
    /// the policies set in token_policies.
    pub token_no_default_policy: Option<bool>,
    /// Duration after which the issued token can no longer be renewed.
    pub token_max_ttl: VaultDuration,
    /// The maximum number of times a generated token may be used (within its lifetime).
    pub token_num_uses: VaultNumUses,
    /// The incremental lifetime for generated tokens.
    /// If set, the token generated using this `AppRole` is a periodic token; so long as it is
    /// renewed it never expires, but the TTL set on the token at each renewal is fixed to the value
    /// specified here. If this value is modified, the token will pick up the new value at its next
    /// renewal.
    pub token_period: Option<VaultDuration>,
    /// List of policies to encode onto generated tokens.
    pub token_policies: Option<Vec<String>>,
    /// The incremental lifetime for generated tokens.
    pub token_ttl: VaultDuration,
    /// The type of token that should be generated. Can be service, batch, or default to use the mount's
    /// tuned default (which unless changed will be service tokens). For token store roles, there are two
    /// additional possibilities: default-service and default-batch which specify the type to return unless
    /// the client requests a different type at generation time.
    pub token_type: TokenType,
}

/// Payload to send to vault when authenticating via `AppId`
#[derive(Deserialize, Serialize, Debug)]
struct AppIdPayload {
    app_id: String,
    user_id: String,
}

/// Payload to send to vault when authenticating via `AppRole`
#[derive(Deserialize, Serialize, Debug)]
struct AppRolePayload {
    role_id: String,
    secret_id: Option<String>,
}

/// Postgresql secret backend
#[derive(Deserialize, Serialize, Debug)]
pub struct PostgresqlLogin {
    /// Password
    pub password: String,
    /// Username
    pub username: String,
}

/// Response sent by vault when listing policies.  We hide this from the
/// caller.
#[derive(Deserialize, Serialize, Debug)]
struct PoliciesResponse {
    policies: Vec<String>,
}

/// Response sent by vault when issuing a `LIST` request.
#[derive(Deserialize, Serialize, Debug)]
pub struct ListResponse {
    /// keys will include the items listed
    pub keys: Vec<String>,
}

/// Options that we use when renewing tokens.
#[derive(Deserialize, Serialize, Debug)]
struct RenewTokenOptions {
    /// Token to renew. This can be part of the URL or the body.
    token: String,
    /// The amount of time for which to renew the lease.  May be ignored or
    /// overriden by vault.
    increment: Option<u64>,
}

/// Options that we use when renewing leases.
#[derive(Deserialize, Serialize, Debug)]
struct RenewLeaseOptions {
    lease_id: String,
    /// The amount of time for which to renew the lease.  May be ignored or
    /// overriden by vault.
    increment: Option<u64>,
}

/// Options for creating a token.  This is intended to be used as a
/// "builder"-style interface, where you create a new `TokenOptions`
/// object, call a bunch of chained methods on it, and then pass the result
/// to `Client::create_token`.
///
/// ```
/// use hashicorp_vault::client::{TokenOptions, VaultDuration};
///
/// let _ = TokenOptions::default()
///   .id("test12345")
///   .policies(vec!("root"))
///   .default_policy(false)
///   .orphan(true)
///   .renewable(false)
///   .display_name("jdoe-temp")
///   .number_of_uses(10)
///   .ttl(VaultDuration::hours(3))
///   .explicit_max_ttl(VaultDuration::hours(13));
/// ```
///
/// If an option is not specified, it will be set according to [Vault's
/// standard defaults for newly-created tokens][token].
///
/// [token]: https://www.vaultproject.io/docs/auth/token.html
#[derive(Default, Serialize, Debug)]
pub struct TokenOptions {
    id: Option<String>,
    policies: Option<Vec<String>>,
    // TODO: `meta`
    no_parent: Option<bool>,
    no_default_policy: Option<bool>,
    renewable: Option<bool>,
    ttl: Option<String>,
    explicit_max_ttl: Option<String>,
    display_name: Option<String>,
    num_uses: VaultNumUses,
}

impl TokenOptions {
    /// Set the `id` of the created token to the specified value.  **This
    /// may make it easy for attackers to guess your token.** Typically,
    /// this is used for testing and similar purposes.
    pub fn id<S: Into<String>>(mut self, id: S) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Supply a list of policies that will be used to grant permissions to
    /// the created token.  Unless you also call `default_policy(false)`, the
    /// policy `default` will be added to this list in modern versions of
    /// vault.
    pub fn policies<I>(mut self, policies: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<String>,
    {
        self.policies = Some(policies.into_iter().map(|p| p.into()).collect());
        self
    }

    /// Should we grant access to the `default` policy?  Defaults to true.
    pub fn default_policy(mut self, enable: bool) -> Self {
        self.no_default_policy = Some(!enable);
        self
    }

    /// Should this token be an "orphan", allowing it to survive even when
    /// the token that created it expires or is revoked?
    pub fn orphan(mut self, orphan: bool) -> Self {
        self.no_parent = Some(!orphan);
        self
    }

    /// Should the token be renewable?
    pub fn renewable(mut self, renewable: bool) -> Self {
        self.renewable = Some(renewable);
        self
    }

    /// For various logging purposes, what should this token be called?
    pub fn display_name<S>(mut self, name: S) -> Self
    where
        S: Into<String>,
    {
        self.display_name = Some(name.into());
        self
    }

    /// How many times can this token be used before it stops working?
    pub fn number_of_uses<D: Into<VaultNumUses>>(mut self, uses: D) -> Self {
        self.num_uses = uses.into();
        self
    }

    /// How long should this token remain valid for?
    pub fn ttl<D: Into<VaultDuration>>(mut self, ttl: D) -> Self {
        self.ttl = Some(format!("{}s", ttl.into().0.as_secs()));
        self
    }

    /// How long should this token remain valid for, even if it is renewed
    /// repeatedly?
    pub fn explicit_max_ttl<D: Into<VaultDuration>>(mut self, ttl: D) -> Self {
        self.explicit_max_ttl = Some(format!("{}s", ttl.into().0.as_secs()));
        self
    }
}

/// http verbs
#[derive(Debug)]
pub enum HttpVerb {
    /// GET
    GET,
    /// POST
    POST,
    /// PUT
    PUT,
    /// DELETE
    DELETE,
    /// LIST
    LIST,
}

#[derive(Debug, Serialize)]
struct SecretContainer<T: Serialize> {
    data: T,
}

#[derive(Debug, Deserialize, Serialize)]
struct DefaultSecretType<T: AsRef<str>> {
    value: T,
}

/// endpoint response variants
#[derive(Debug)]
pub enum EndpointResponse<D> {
    /// Vault response
    VaultResponse(VaultResponse<D>),
    /// Empty, but still successful response
    Empty,
}

impl VaultClient<TokenData> {
    /// Construct a `VaultClient` from an existing vault token
    pub fn new<U, T: Into<String>>(host: U, token: T) -> Result<VaultClient<TokenData>>
    where
        U: TryInto<Url, Err = Error>,
    {
        let host = host.try_into()?;
        let client = Client::new();
        let token = token.into();
        let res = handle_reqwest_response(
            client
                .get(host.join("/v1/auth/token/lookup-self")?)
                .header("X-Vault-Token", token.clone())
                .send(),
        )?;
        let decoded: VaultResponse<TokenData> = parse_vault_response(res)?;
        Ok(VaultClient {
            host,
            token,
            client,
            data: Some(decoded),
        })
    }
}

impl VaultClient<()> {
    /// Construct a `VaultClient` via the `App ID`
    /// [auth backend](https://www.vaultproject.io/docs/auth/app-id.html)
    ///
    /// NOTE: This backend is now deprecated by vault.
    #[deprecated(since = "0.6.1")]
    pub fn new_app_id<U, S1: Into<String>, S2: Into<String>>(
        host: U,
        app_id: S1,
        user_id: S2,
    ) -> Result<VaultClient<()>>
    where
        U: TryInto<Url, Err = Error>,
    {
        let host = host.try_into()?;
        let client = Client::new();
        let payload = serde_json::to_string(&AppIdPayload {
            app_id: app_id.into(),
            user_id: user_id.into(),
        })?;
        let res = handle_reqwest_response(
            client
                .post(host.join("/v1/auth/app-id/login")?)
                .body(payload)
                .send(),
        )?;
        let decoded: VaultResponse<()> = parse_vault_response(res)?;
        let token = match decoded.auth {
            Some(ref auth) => auth.client_token.clone(),
            None => {
                return Err(Error::Vault(format!(
                    "No client token found in response: `{:?}`",
                    &decoded.auth
                )))
            }
        };
        Ok(VaultClient {
            host,
            token,
            client,
            data: Some(decoded),
        })
    }

    /// Construct a `VaultClient` via the `AppRole`
    /// [auth backend](https://www.vaultproject.io/docs/auth/approle.html)
    pub fn new_app_role<U, R, S>(
        host: U,
        role_id: R,
        secret_id: Option<S>,
    ) -> Result<VaultClient<()>>
    where
        U: TryInto<Url, Err = Error>,
        R: Into<String>,
        S: Into<String>,
    {
        let host = host.try_into()?;
        let client = Client::new();
        let secret_id = match secret_id {
            Some(s) => Some(s.into()),
            None => None,
        };
        let payload = serde_json::to_string(&AppRolePayload {
            role_id: role_id.into(),
            secret_id,
        })?;
        let res = handle_reqwest_response(
            client
                .post(host.join("/v1/auth/approle/login")?)
                .body(payload)
                .send(),
        )?;
        let decoded: VaultResponse<()> = parse_vault_response(res)?;
        let token = match decoded.auth {
            Some(ref auth) => auth.client_token.clone(),
            None => {
                return Err(Error::Vault(format!(
                    "No client token found in response: `{:?}`",
                    &decoded.auth
                )))
            }
        };
        Ok(VaultClient {
            host,
            token,
            client,
            data: Some(decoded),
        })
    }

    /// Construct a `VaultClient` where no lookup is done through vault since it is assumed that the
    /// provided token is a single-use token.
    ///
    /// A common use case for this method is when a `wrapping_token` has been received and you want
    /// to query the `sys/wrapping/unwrap` endpoint.
    pub fn new_no_lookup<U, S: Into<String>>(host: U, token: S) -> Result<VaultClient<()>>
    where
        U: TryInto<Url, Err = Error>,
    {
        let client = Client::new();
        let host = host.try_into()?;
        Ok(VaultClient {
            host,
            token: token.into(),
            client,
            data: None,
        })
    }
}

impl<T> VaultClient<T>
where
    T: DeserializeOwned,
{
    /// Renew lease for `VaultClient`'s token and updates the
    /// `self.data.auth` based upon the response.  Corresponds to
    /// [`/auth/token/renew-self`][token].
    ///
    /// ```
    /// # extern crate hashicorp_vault as vault;
    /// # use vault::Client;
    ///
    /// let host = "http://127.0.0.1:8200";
    /// let token = "test12345";
    /// let mut client = Client::new(host, token).unwrap();
    ///
    /// client.renew().unwrap();
    /// ```
    ///
    /// [token]: https://www.vaultproject.io/docs/auth/token.html
    pub fn renew(&mut self) -> Result<()> {
        let res = self.post::<_, String>("/v1/auth/token/renew-self", None, None)?;
        let vault_res: VaultResponse<T> = parse_vault_response(res)?;
        if let Some(ref mut data) = self.data {
            data.auth = vault_res.auth;
        }
        Ok(())
    }

    /// Renew the lease for the specified token.  Requires `root`
    /// privileges.  Corresponds to [`/auth/token/renew[/token]`][token].
    ///
    /// ```
    /// # extern crate hashicorp_vault as vault;
    /// # use vault::Client;
    ///
    /// let host = "http://127.0.0.1:8200";
    /// let token = "test12345";
    /// let client = Client::new(host, token).unwrap();
    ///
    /// let token_to_renew = "test12345";
    /// client.renew_token(token_to_renew, None).unwrap();
    /// ```
    ///
    /// [token]: https://www.vaultproject.io/docs/auth/token.html
    pub fn renew_token<S: Into<String>>(&self, token: S, increment: Option<u64>) -> Result<Auth> {
        let body = serde_json::to_string(&RenewTokenOptions {
            token: token.into(),
            increment,
        })?;
        let res = self.post::<_, String>("/v1/auth/token/renew", Some(&body), None)?;
        let vault_res: VaultResponse<()> = parse_vault_response(res)?;
        vault_res
            .auth
            .ok_or_else(|| Error::Vault("No auth data returned while renewing token".to_owned()))
    }

    /// Revoke `VaultClient`'s token. This token can no longer be used.
    /// Corresponds to [`/auth/token/revoke-self`][token].
    ///
    /// ```
    /// # extern crate hashicorp_vault as vault;
    /// # use vault::{client, Client};
    ///
    /// let host = "http://127.0.0.1:8200";
    /// let token = "test12345";
    /// let client = Client::new(host, token).unwrap();
    ///
    /// // Create a temporary token, and use it to create a new client.
    /// let opts = client::TokenOptions::default()
    ///   .ttl(client::VaultDuration::minutes(5));
    /// let res = client.create_token(&opts).unwrap();
    /// let mut new_client = Client::new(host, res.client_token).unwrap();
    ///
    /// // Issue and use a bunch of temporary dynamic credentials.
    ///
    /// // Revoke all our dynamic credentials with a single command.
    /// new_client.revoke().unwrap();
    /// ```
    ///
    /// Note that we consume our `self` parameter, so you cannot use the
    /// client after revoking it.
    ///
    /// [token]: https://www.vaultproject.io/docs/auth/token.html
    pub fn revoke(self) -> Result<()> {
        let _ = self.post::<_, String>("/v1/auth/token/revoke-self", None, None)?;
        Ok(())
    }

    /// Renew a specific lease that your token controls.  Corresponds to
    /// [`/v1/sys/lease`][renew].
    ///
    /// ```no_run
    /// # extern crate hashicorp_vault as vault;
    /// # use vault::Client;
    /// use serde::Deserialize;
    ///
    /// let host = "http://127.0.0.1:8200";
    /// let token = "test12345";
    /// let client = Client::new(host, token).unwrap();
    ///
    /// #[derive(Deserialize)]
    /// struct PacketKey {
    ///   api_key_token: String,
    /// }
    ///
    /// let res = client.get_secret_engine_creds::<PacketKey>("packet", "1h-read-only-user").unwrap();
    ///
    /// client.renew_lease(res.lease_id.unwrap(), None).unwrap();
    /// ```
    ///
    /// [renew]: https://www.vaultproject.io/docs/http/sys-renew.html
    pub fn renew_lease<S: Into<String>>(
        &self,
        lease_id: S,
        increment: Option<u64>,
    ) -> Result<VaultResponse<()>> {
        let body = serde_json::to_string(&RenewLeaseOptions {
            lease_id: lease_id.into(),
            increment,
        })?;
        let res = self.put::<_, String>("/v1/sys/leases/renew", Some(&body), None)?;
        let vault_res: VaultResponse<()> = parse_vault_response(res)?;
        Ok(vault_res)
    }

    /// Lookup token information for this client's token.  Corresponds to
    /// [`/auth/token/lookup-self`][token].
    ///
    /// ```
    /// # extern crate hashicorp_vault as vault;
    /// # use vault::Client;
    ///
    /// let host = "http://127.0.0.1:8200";
    /// let token = "test12345";
    /// let client = Client::new(host, token).unwrap();
    ///
    /// let res = client.lookup().unwrap();
    /// assert!(res.data.unwrap().policies.len() >= 0);
    /// ```
    ///
    /// [token]: https://www.vaultproject.io/docs/auth/token.html
    pub fn lookup(&self) -> Result<VaultResponse<TokenData>> {
        let res = self.get::<_, String>("/v1/auth/token/lookup-self", None)?;
        let vault_res: VaultResponse<TokenData> = parse_vault_response(res)?;
        Ok(vault_res)
    }

    /// Create a new vault token using the specified options.  Corresponds to
    /// [`/auth/token/create`][token].
    ///
    /// ```
    /// # extern crate hashicorp_vault as vault;
    /// # use vault::{client, Client};
    ///
    /// let host = "http://127.0.0.1:8200";
    /// let token = "test12345";
    /// let client = Client::new(host, token).unwrap();
    ///
    /// let opts = client::TokenOptions::default()
    ///   .display_name("test_token")
    ///   .policies(vec!("root"))
    ///   .default_policy(false)
    ///   .orphan(true)
    ///   .renewable(false)
    ///   .display_name("jdoe-temp")
    ///   .number_of_uses(10)
    ///   .ttl(client::VaultDuration::minutes(1))
    ///   .explicit_max_ttl(client::VaultDuration::minutes(3));
    /// let res = client.create_token(&opts).unwrap();
    ///
    /// # let new_client = Client::new(host, res.client_token).unwrap();
    /// # new_client.revoke().unwrap();
    /// ```
    ///
    /// [token]: https://www.vaultproject.io/docs/auth/token.html
    pub fn create_token(&self, opts: &TokenOptions) -> Result<Auth> {
        let body = serde_json::to_string(opts)?;
        let res = self.post::<_, String>("/v1/auth/token/create", Some(&body), None)?;
        let vault_res: VaultResponse<()> = parse_vault_response(res)?;
        vault_res
            .auth
            .ok_or_else(|| Error::Vault("Created token did not include auth data".into()))
    }

    ///
    /// Saves a secret
    ///
    /// ```
    /// # extern crate hashicorp_vault as vault;
    /// # use vault::Client;
    ///
    /// let host = "http://127.0.0.1:8200";
    /// let token = "test12345";
    /// let client = Client::new(host, token).unwrap();
    /// let res = client.set_secret("hello_set", "world");
    /// assert!(res.is_ok());
    /// ```
    pub fn set_secret<S1: Into<String>, S2: AsRef<str>>(&self, key: S1, value: S2) -> Result<()> {
        let secret = DefaultSecretType {
            value: value.as_ref(),
        };
        self.set_custom_secret(key, &secret)
    }

    /// Saves a secret
    ///
    /// ```
    /// # extern crate hashicorp_vault as vault;
    /// # use vault::Client;
    /// use serde::{Deserialize, Serialize};
    ///
    /// #[derive(Deserialize, Serialize)]
    /// struct MyThing {
    ///   awesome: String,
    ///   thing: String,
    /// }
    /// let host = "http://127.0.0.1:8200";
    /// let token = "test12345";
    /// let client = Client::new(host, token).unwrap();
    /// let secret = MyThing {
    ///   awesome: "I really am cool".into(),
    ///   thing: "this is also in the secret".into(),
    /// };
    /// let res = client.set_custom_secret("hello_set", &secret);
    /// assert!(res.is_ok());
    /// ```
    pub fn set_custom_secret<S1, S2>(&self, secret_name: S1, secret: &S2) -> Result<()>
    where
        S1: Into<String>,
        S2: Serialize,
    {
        let secret = SecretContainer { data: secret };
        let json = serde_json::to_string(&secret)?;
        let _ = self.put::<_, String>(
            &format!("/v1/secret/data/{}", secret_name.into())[..],
            Some(&json),
            None,
        )?;
        Ok(())
    }

    ///
    /// List secrets at specified path
    ///
    /// ```
    /// # extern crate hashicorp_vault as vault;
    /// # use vault::Client;
    ///
    /// let host = "http://127.0.0.1:8200";
    /// let token = "test12345";
    /// let client = Client::new(host, token).unwrap();
    /// let res = client.set_secret("hello/fred", "world");
    /// assert!(res.is_ok());
    /// let res = client.set_secret("hello/bob", "world");
    /// assert!(res.is_ok());
    /// let res = client.list_secrets("hello/");
    /// assert!(res.is_ok());
    /// assert_eq!(res.unwrap(), ["bob", "fred"]);
    /// ```
    pub fn list_secrets<S: AsRef<str>>(&self, key: S) -> Result<Vec<String>> {
        let res = self.list::<_, String>(
            &format!("/v1/secret/metadata/{}", key.as_ref())[..],
            None,
            None,
        )?;
        let decoded: VaultResponse<ListResponse> = parse_vault_response(res)?;
        match decoded.data {
            Some(data) => Ok(data.keys),
            _ => Err(Error::Vault(format!(
                "No secrets found in response: `{:#?}`",
                decoded
            ))),
        }
    }

    ///
    /// Fetches a saved secret
    ///
    /// ```
    /// # extern crate hashicorp_vault as vault;
    /// # use vault::Client;
    ///
    /// let host = "http://127.0.0.1:8200";
    /// let token = "test12345";
    /// let client = Client::new(host, token).unwrap();
    /// let res = client.set_secret("hello_get", "world");
    /// assert!(res.is_ok());
    /// let res = client.get_secret("hello_get");
    /// assert!(res.is_ok());
    /// assert_eq!(res.unwrap(), "world");
    /// ```
    pub fn get_secret<S: AsRef<str>>(&self, key: S) -> Result<String> {
        let secret: DefaultSecretType<String> = self.get_custom_secret(key)?;
        Ok(secret.value)
    }

    ///
    /// Fetches a saved secret
    ///
    /// ```
    /// # extern crate hashicorp_vault as vault;
    /// # use vault::Client;
    /// use serde::{Deserialize, Serialize};
    ///
    /// #[derive(Debug, Deserialize, Serialize)]
    /// struct MyThing {
    ///   awesome: String,
    ///   thing: String,
    /// }
    /// let host = "http://127.0.0.1:8200";
    /// let token = "test12345";
    /// let client = Client::new(host, token).unwrap();
    /// let secret = MyThing {
    ///   awesome: "I really am cool".into(),
    ///   thing: "this is also in the secret".into(),
    /// };
    /// let res1 = client.set_custom_secret("custom_secret", &secret);
    /// assert!(res1.is_ok());
    /// let res2: Result<MyThing, _> = client.get_custom_secret("custom_secret");
    /// assert!(res2.is_ok());
    /// let thing = res2.unwrap();
    /// assert_eq!(thing.awesome, "I really am cool");
    /// assert_eq!(thing.thing, "this is also in the secret");
    /// ```
    pub fn get_custom_secret<S: AsRef<str>, S2: DeserializeOwned + std::fmt::Debug>(
        &self,
        secret_name: S,
    ) -> Result<S2> {
        let res = self.get::<_, String>(
            &format!("/v1/secret/data/{}", secret_name.as_ref())[..],
            None,
        )?;
        let decoded: VaultResponse<SecretDataWrapper<S2>> = parse_vault_response(res)?;
        match decoded.data {
            Some(data) => Ok(data.data),
            _ => Err(Error::Vault(format!(
                "No secret found in response: `{:#?}`",
                decoded
            ))),
        }
    }

    /// Fetch a wrapped secret. Token (one-time use) to fetch secret will be in `wrap_info.token`
    /// https://www.vaultproject.io/docs/secrets/cubbyhole/index.html
    pub fn get_secret_wrapped<S1: AsRef<str>, S2: AsRef<str>>(
        &self,
        key: S1,
        wrap_ttl: S2,
    ) -> Result<VaultResponse<()>> {
        let res = self.get(
            &format!("/v1/secret/data/{}", key.as_ref())[..],
            Some(wrap_ttl.as_ref()),
        )?;
        parse_vault_response(res)
    }

    /// Using a vault client created from a wrapping token, fetch the unwrapped `VaultResponse` from
    /// `sys/wrapping/unwrap`.
    ///
    /// The `data` attribute of `VaultResponse` should contain the unwrapped information, which is
    /// returned as a `HashMap<String, String>`.
    pub fn get_unwrapped_response(&self) -> Result<VaultResponse<HashMap<String, String>>> {
        let res = self.post::<_, String>("/v1/sys/wrapping/unwrap", None, None)?;
        let result: VaultResponse<SecretDataWrapper<HashMap<String, String>>> =
            parse_vault_response(res)?;
        Ok(result.into())
    }

    /// Reads the properties of an existing `AppRole`.
    pub fn get_app_role_properties<S: AsRef<str>>(
        &self,
        role_name: S,
    ) -> Result<VaultResponse<AppRoleProperties>> {
        let res = self.get::<_, String>(
            &format!("/v1/auth/approle/role/{}", role_name.as_ref()),
            None,
        )?;
        parse_vault_response(res)
    }

    /// Encrypt a plaintext via Transit secret backend.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate hashicorp_vault as vault;
    /// # use vault::Client;
    ///
    /// let host = "http://127.0.0.1:8200";
    /// let token = "test12345";
    /// let client = Client::new(host, token).unwrap();
    /// let res = client.transit_encrypt(None, "keyname", b"plaintext");
    /// ```
    pub fn transit_encrypt<S1: Into<String>, S2: AsRef<[u8]>>(
        &self,
        mountpoint: Option<String>,
        key: S1,
        plaintext: S2,
    ) -> Result<Vec<u8>> {
        let path = mountpoint.unwrap_or_else(|| "transit".to_owned());
        let encoded_plaintext = base64::encode(plaintext.as_ref());
        let res = self.post::<_, String>(
            &format!("/v1/{}/encrypt/{}", path, key.into())[..],
            Some(&format!("{{\"plaintext\": \"{}\"}}", encoded_plaintext)[..]),
            None,
        )?;
        let decoded: VaultResponse<TransitEncryptedData> = parse_vault_response(res)?;
        let payload = match decoded.data {
            Some(data) => data.ciphertext,
            _ => {
                return Err(Error::Vault(format!(
                    "No ciphertext found in response: `{:#?}`",
                    decoded
                )))
            }
        };
        if !payload.starts_with("vault:v1:") {
            return Err(Error::Vault(format!(
                "Unrecognized ciphertext format: `{:#?}`",
                payload
            )));
        };
        let encoded_ciphertext = payload.trim_start_matches("vault:v1:");
        let encrypted = base64::decode(encoded_ciphertext)?;
        Ok(encrypted)
    }

    /// Decrypt a ciphertext via Transit secret backend.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate hashicorp_vault as vault;
    /// # use vault::Client;
    ///
    /// let host = "http://127.0.0.1:8200";
    /// let token = "test12345";
    /// let client = Client::new(host, token).unwrap();
    /// let res = client.transit_decrypt(None, "keyname", b"\x02af\x61bcb\x55d");
    /// ```
    pub fn transit_decrypt<S1: Into<String>, S2: AsRef<[u8]>>(
        &self,
        mountpoint: Option<String>,
        key: S1,
        ciphertext: S2,
    ) -> Result<Vec<u8>> {
        let path = mountpoint.unwrap_or_else(|| "transit".to_owned());
        let encoded_ciphertext = "vault:v1:".to_owned() + &base64::encode(ciphertext.as_ref());
        let res = self.post::<_, String>(
            &format!("/v1/{}/decrypt/{}", path, key.into())[..],
            Some(&format!("{{\"ciphertext\": \"{}\"}}", encoded_ciphertext)[..]),
            None,
        )?;
        let decoded: VaultResponse<TransitDecryptedData> = parse_vault_response(res)?;
        let decrypted = match decoded.data {
            Some(data) => data.plaintext,
            _ => {
                return Err(Error::Vault(format!(
                    "No plaintext found in response: `{:#?}`",
                    decoded
                )))
            }
        };
        let plaintext = base64::decode(&decrypted)?;
        Ok(plaintext)
    }

    /// This function is an "escape hatch" of sorts to call any other vault api methods that
    /// aren't directly supported in this library.
    ///
    /// Select the http verb you want, along with the endpoint, e.g. `auth/token/create`, along
    /// with any wrapping or associated body text and the request will be sent.
    ///
    /// See `it_can_perform_approle_workflow` test case for examples.
    pub fn call_endpoint<D: DeserializeOwned>(
        &self,
        http_verb: HttpVerb,
        endpoint: &str,
        wrap_ttl: Option<&str>,
        body: Option<&str>,
    ) -> Result<EndpointResponse<D>> {
        let url = format!("/v1/{}", endpoint);
        match http_verb {
            HttpVerb::GET => {
                let mut res = self.get(&url, wrap_ttl)?;
                parse_endpoint_response(&mut res)
            }
            HttpVerb::POST => {
                let mut res = self.post(&url, body, wrap_ttl)?;
                parse_endpoint_response(&mut res)
            }
            HttpVerb::PUT => {
                let mut res = self.put(&url, body, wrap_ttl)?;
                parse_endpoint_response(&mut res)
            }
            HttpVerb::DELETE => {
                let mut res = self.delete(&url)?;
                parse_endpoint_response(&mut res)
            }
            HttpVerb::LIST => {
                let mut res = self.list(&url, body, wrap_ttl)?;
                parse_endpoint_response(&mut res)
            }
        }
    }

    /// Accesses a given endpoint using the provided `wrap_ttl` and returns a single-use
    /// `wrapping_token` to access the response provided by the endpoint.
    pub fn get_wrapping_token_for_endpoint(
        &self,
        http_verb: HttpVerb,
        endpoint: &str,
        wrap_ttl: &str,
        body: Option<&str>,
    ) -> Result<String> {
        let res = self.call_endpoint::<()>(http_verb, endpoint.as_ref(), Some(wrap_ttl), body)?;
        match res {
            EndpointResponse::VaultResponse(res) => match res.wrap_info {
                Some(wrap_info) => Ok(wrap_info.token),
                _ => Err(Error::Vault(format!(
                    "wrap_info is missing in response: {:?}",
                    res
                ))),
            },
            EndpointResponse::Empty => Err(Error::Vault("Received an empty response".to_string())),
        }
    }

    ///
    /// Deletes a saved secret
    ///
    /// ```
    /// # extern crate hashicorp_vault as vault;
    /// # use vault::Client;
    ///
    /// let host = "http://127.0.0.1:8200";
    /// let token = "test12345";
    /// let client = Client::new(host, token).unwrap();
    /// let res = client.set_secret("hello_delete", "world");
    /// assert!(res.is_ok());
    /// let res = client.delete_secret("hello_delete");
    /// assert!(res.is_ok());
    /// ```
    pub fn delete_secret(&self, key: &str) -> Result<()> {
        let _ = self.delete(&format!("/v1/secret/data/{}", key)[..])?;
        Ok(())
    }

    /// Get postgresql secret backend
    /// https://www.vaultproject.io/docs/secrets/postgresql/index.html
    pub fn get_postgresql_backend(&self, name: &str) -> Result<VaultResponse<PostgresqlLogin>> {
        self.get_secret_engine_creds("postgresql", name)
    }

    /// Get creds from an arbitrary backend
    /// ```no_run
    /// # extern crate hashicorp_vault as vault;
    /// # use vault::Client;
    /// use serde::Deserialize;
    ///
    /// let host = "http://127.0.0.1:8200";
    /// let token = "test12345";
    /// let client = Client::new(host, token).unwrap();
    ///
    /// #[derive(Deserialize)]
    /// struct PacketKey {
    ///   api_key_token: String,
    /// }
    ///
    /// let res = client.get_secret_engine_creds::<PacketKey>("packet", "1h-read-only-user").unwrap();
    /// let api_token = res.data.unwrap().api_key_token;
    /// ```
    pub fn get_secret_engine_creds<K>(&self, backend: &str, name: &str) -> Result<VaultResponse<K>>
    where
        K: DeserializeOwned,
    {
        let res = self.get::<_, String>(&format!("/v1/{}/creds/{}", backend, name)[..], None)?;
        let decoded: VaultResponse<K> = parse_vault_response(res)?;
        Ok(decoded)
    }

    /// Get a list of policy names defined by this vault.  This requires
    /// `root` privileges. Corresponds to [`/sys/policy`][/sys/policy].
    ///
    /// ```
    /// # extern crate hashicorp_vault as vault;
    /// # use vault::Client;
    ///
    /// let host = "http://127.0.0.1:8200";
    /// let token = "test12345";
    /// let client = Client::new(host, token).unwrap();
    ///
    /// let res = client.policies().unwrap();
    /// assert!(res.contains(&"root".to_owned()));
    /// ```
    ///
    /// [/sys/policy]: https://www.vaultproject.io/docs/http/sys-policy.html
    pub fn policies(&self) -> Result<Vec<String>> {
        let res = self.get::<_, String>("/v1/sys/policy", None)?;
        let decoded: PoliciesResponse = parse_vault_response(res)?;
        Ok(decoded.policies)
    }

    fn get<S1: AsRef<str>, S2: Into<String>>(
        &self,
        endpoint: S1,
        wrap_ttl: Option<S2>,
    ) -> Result<Response> {
        let h = self.host.join(endpoint.as_ref())?;
        match wrap_ttl {
            Some(wrap_ttl) => Ok(handle_reqwest_response(
                self.client
                    .request(Method::GET, h)
                    .header("X-Vault-Token", self.token.to_string())
                    .header(CONTENT_TYPE, "application/json")
                    .header("X-Vault-Wrap-TTL", wrap_ttl.into())
                    .send(),
            )?),
            None => Ok(handle_reqwest_response(
                self.client
                    .request(Method::GET, h)
                    .header("X-Vault-Token", self.token.to_string())
                    .header(CONTENT_TYPE, "application/json")
                    .send(),
            )?),
        }
    }

    fn delete<S: AsRef<str>>(&self, endpoint: S) -> Result<Response> {
        Ok(handle_reqwest_response(
            self.client
                .request(Method::DELETE, self.host.join(endpoint.as_ref())?)
                .header("X-Vault-Token", self.token.to_string())
                .header(CONTENT_TYPE, "application/json")
                .send(),
        )?)
    }

    fn post<S1: AsRef<str>, S2: Into<String>>(
        &self,
        endpoint: S1,
        body: Option<&str>,
        wrap_ttl: Option<S2>,
    ) -> Result<Response> {
        let h = self.host.join(endpoint.as_ref())?;
        let body = if let Some(body) = body {
            body.to_string()
        } else {
            String::new()
        };
        match wrap_ttl {
            Some(wrap_ttl) => Ok(handle_reqwest_response(
                self.client
                    .request(Method::POST, h)
                    .header("X-Vault-Token", self.token.to_string())
                    .header(CONTENT_TYPE, "application/json")
                    .header("X-Vault-Wrap-TTL", wrap_ttl.into())
                    .body(body)
                    .send(),
            )?),
            None => Ok(handle_reqwest_response(
                self.client
                    .request(Method::POST, h)
                    .header("X-Vault-Token", self.token.to_string())
                    .header(CONTENT_TYPE, "application/json")
                    .body(body)
                    .send(),
            )?),
        }
    }

    fn put<S1: AsRef<str>, S2: Into<String>>(
        &self,
        endpoint: S1,
        body: Option<&str>,
        wrap_ttl: Option<S2>,
    ) -> Result<Response> {
        let h = self.host.join(endpoint.as_ref())?;
        let body = if let Some(body) = body {
            body.to_string()
        } else {
            String::new()
        };
        match wrap_ttl {
            Some(wrap_ttl) => Ok(handle_reqwest_response(
                self.client
                    .request(Method::PUT, h)
                    .header("X-Vault-Token", self.token.to_string())
                    .header(CONTENT_TYPE, "application/json")
                    .header("X-Vault-Wrap-TTL", wrap_ttl.into())
                    .body(body)
                    .send(),
            )?),
            None => Ok(handle_reqwest_response(
                self.client
                    .request(Method::PUT, h)
                    .header("X-Vault-Token", self.token.to_string())
                    .header(CONTENT_TYPE, "application/json")
                    .body(body)
                    .send(),
            )?),
        }
    }

    fn list<S1: AsRef<str>, S2: Into<String>>(
        &self,
        endpoint: S1,
        body: Option<&str>,
        wrap_ttl: Option<S2>,
    ) -> Result<Response> {
        let h = self.host.join(endpoint.as_ref())?;
        let body = if let Some(body) = body {
            body.to_string()
        } else {
            String::new()
        };
        match wrap_ttl {
            Some(wrap_ttl) => Ok(handle_reqwest_response(
                self.client
                    .request(
                        Method::from_str("LIST".into()).expect("Failed to parse LIST to Method"),
                        h,
                    )
                    .header("X-Vault-Token", self.token.to_string())
                    .header(CONTENT_TYPE, "application/json")
                    .header("X-Vault-Wrap-TTL", wrap_ttl.into())
                    .body(body)
                    .send(),
            )?),
            None => Ok(handle_reqwest_response(
                self.client
                    .request(
                        Method::from_str("LIST".into()).expect("Failed to parse LIST to Method"),
                        h,
                    )
                    .header("X-Vault-Token", self.token.to_string())
                    .header(CONTENT_TYPE, "application/json")
                    .body(body)
                    .send(),
            )?),
        }
    }
}

/// helper fn to check `Response` for success
fn handle_reqwest_response(res: StdResult<Response, reqwest::Error>) -> Result<Response> {
    let mut res = res?;
    if res.status().is_success() {
        Ok(res)
    } else {
        let mut error_msg = String::new();
        let _ = res.read_to_string(&mut error_msg).unwrap_or({
            error_msg.push_str("Could not read vault response.");
            0
        });
        Err(Error::VaultResponse(
            format!(
                "Vault request failed: {:?}, error message: `{}`",
                res, error_msg
            ),
            res,
        ))
    }
}

///
/// Parse a vault response manually
///
/// ```
/// # extern crate hashicorp_vault as vault;
/// # use vault::Client;
/// use std::io::Read;
/// use vault::{Error, Result, client::{VaultResponse, SecretDataWrapper}, TryInto};
/// use std::result::Result as StdResult;
/// use reqwest::{
///    blocking::{Client as ReqwestClient, Response},
///    header::CONTENT_TYPE,
///    Method,
///  };
/// use serde::{Deserialize, Serialize};
/// use url::Url;
///
/// #[derive(Debug, Deserialize, Serialize)]
/// struct MyThing {
///   awesome: String,
///   thing: String,
/// }
///
/// fn handle_reqwest_response(res: StdResult<Response, reqwest::Error>) -> Result<Response> {
///     let mut res = res?;
///     if res.status().is_success() {
///         Ok(res)
///     } else {
///         let mut error_msg = String::new();
///         let _ = res.read_to_string(&mut error_msg).unwrap_or({
///             error_msg.push_str("Could not read vault response.");
///             0
///         });
///         Err(Error::VaultResponse(
///             format!(
///                 "Vault request failed: {:?}, error message: `{}`",
///                 res, error_msg
///             ),
///             res,
///         ))
///     }
/// }
/// fn get<S1: AsRef<str>, S2: Into<String>, U: TryInto<Url, Err = Error>>(
///     host: U,
///     token: &str,
///     endpoint: S1,
///     wrap_ttl: Option<S2>,
/// ) -> Result<Response> {
/// let host = host.try_into()?;
///     let h = host.join(endpoint.as_ref())?;
///     let client = ReqwestClient::new();;
///     match wrap_ttl {
///         Some(wrap_ttl) => Ok(handle_reqwest_response(
///             client
///                 .request(Method::GET, h)
///                 .header("X-Vault-Token", token.to_string())
///                 .header(CONTENT_TYPE, "application/json")
///                 .header("X-Vault-Wrap-TTL", wrap_ttl.into())
///                 .send(),
///         )?),
///         None => Ok(handle_reqwest_response(
///             client
///                 .request(Method::GET, h)
///                 .header("X-Vault-Token", token.to_string())
///                 .header(CONTENT_TYPE, "application/json")
///                 .send(),
///         )?),
///     }
/// }
/// let host = "http://127.0.0.1:8200";
/// let token = "test12345";
/// let client = Client::new(host, token).unwrap();
/// let secret = MyThing {
///   awesome: "I really am cool".into(),
///   thing: "this is also in the secret".into(),
/// };
/// let res1 = client.set_custom_secret("custom_secret", &secret);
/// assert!(res1.is_ok());
/// let res = get::<&str, &str, &str>(
///     host,
///     token,
///     "/v1/secret/data/custom_secret",
///     None,
/// ).unwrap();
/// let decoded: VaultResponse<SecretDataWrapper<MyThing>> = vault::client::parse_vault_response(res).unwrap();
/// let res2 = match decoded.data {
///     Some(data) => Ok(data.data),
///     _ => Err(Error::Vault(format!(
///         "No secret found in response: `{:#?}`",
///         decoded
///     ))),
/// };
/// assert!(res2.is_ok());
/// let thing = res2.unwrap();
/// assert_eq!(thing.awesome, "I really am cool");
/// assert_eq!(thing.thing, "this is also in the secret");
pub fn parse_vault_response<T>(res: Response) -> Result<T>
where
    T: DeserializeOwned,
{
    trace!("Response: {:?}", &res);
    Ok(serde_json::from_reader(res)?)
}

/// checks if response is empty before attempting to convert to a `VaultResponse`
fn parse_endpoint_response<T>(res: &mut Response) -> Result<EndpointResponse<T>>
where
    T: DeserializeOwned,
{
    let mut body = String::new();
    let _ = res.read_to_string(&mut body)?;
    trace!("Response: {:?}", &body);
    if body.is_empty() {
        Ok(EndpointResponse::Empty)
    } else {
        Ok(EndpointResponse::VaultResponse(serde_json::from_str(
            &body,
        )?))
    }
}
