#![deny(missing_docs,
    missing_debug_implementations, missing_copy_implementations,
    trivial_casts, trivial_numeric_casts,
    unsafe_code,
    unstable_features,
    unused_import_braces, unused_qualifications)]

//! # Vigor
//! This library contains a Vigor authentication agent to manage credentials and perform HTTP/HTTPS requests.
//!
//! A note regarding Ed25519: this client library supports Ed25519 authentication, however will only accept PEM-encoded keys.
//! Formats such as OpenSSH are not guaranteed to work.
//! The private key is expected to adhere to RFC 7468, PKCS8 and unencrypted.
//!
//! Minimal format verification is done on private key material. For all intended purposes, assume the library would foolishly accept random noise as a private key.
//! You are responsible for implementing safety checks for inappropriate private keys.
//!
//! Also keep in mind that this library is purely synchronous, for the purposes of simplicity and a less bloated dependency tree.
//! For use cases where blocking execution is inappropriate and/or inadaquete, it should be noted that synchronous code can be executed asynchronously, however not vice versa.
//! If all else fails, the rhetorical question "have you tried threading" should come to mind.
//!
//! ## Usage
//! Use `Vigor::new()` to start an agent instance, after importing.
//! See documentation for a full list of available methods.
//!
//! ```no_run
//! use vigor_agent;
//!
//! fn main() {
//!     // you're advised to apply error handling here, instead of just recklessly using .unwrap()
//!     let mut agent = vigor_agent::Vigor::new().unwrap();
//!     agent.init().unwrap();
//!     println!(agent.get("http://example.com/claims/", vigor_agent::AuthMode::Auto).unwrap());
//! }
//! ```
//!

use std::fs;
use std::fmt;
use std::path::PathBuf;

extern crate dirs;
extern crate serde;
extern crate ureq;
extern crate pem_rfc7468;
extern crate ed25519_dalek;
extern crate hex;
use dirs::home_dir;
use ed25519_dalek::Signer;

/// This library's vender-specific error type.
///
/// Does not yet support error "kinds" like `std::io::Error` does.
#[derive(Debug, Clone)]
pub struct Error {
    message: String
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

/// Configuration structure for Ed25519 authentication, used in `ConfigSchema` structures.
///
/// Can be used in serializing and deserializing configuration data, especially those residing inside `ConfigSchema` structures.
///
/// **This is not the main agent structure.** See `Vigor` instead, your agent is in another castle.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct ConfigEd25519Schema {
    /// Path to the Ed25519 public key.
    pub public: String,
    /// Path to the Ed25519 private key.
    pub private: String,
    /// Whether Ed25519 authentication should be used.
    pub enabled: bool
}

/// Configuration structure, used in `Vigor` structures.
///
/// Can be used in serializing and deserializing configuration data, especially those residing inside `Vigor` structures.
///
/// **This is not the main agent structure.** See `Vigor` instead, your agent is in another castle.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct ConfigSchema {
    /// User's name.
    pub preferred_username: String,
    /// User's email.
    pub email: String,
    /// Plain-text password, if empty password authentication will not be used.
    pub password: String,
    /// Ed25519 authentication configuration structure.
    pub ed25519: ConfigEd25519Schema
}

// definitions for transmission structs.
#[derive(serde::Serialize)]
struct Authentication {
    mode: String,
    answer: String
}

#[derive(serde::Deserialize)]
struct TokenResponse {
    jwt: String
}

#[derive(serde::Deserialize)]
struct ErrorResponse {
    error: String
}

/// Configuration and path information for agent structure. Includes implementations for agent logic.
///
/// Consume implemented methods for initialization, see `new` method.
pub struct Vigor {
    /// Configuration structure.
    pub config: ConfigSchema,
    /// Path to configuration file.
    pub path: PathBuf
}

impl fmt::Debug for Vigor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "path: \"{}\"", self.path.display().to_string())
    }
}

/// Represents mode to perform token retrieval with, specifically the authentication method.
///
/// The modes enumerated are to be passed onto agent methods that retrieve tokens, as arguments.
#[derive(Debug, Copy, Clone)]
pub enum AuthMode {
    /// Instruction to use Ed25519 key signatures to authenticate.
    Ed25519,
    /// Instruction to use password to authenticate.
    Password,
    /// Instruction to automatically select mode, by the following order.
    ///
    /// 1. Ed25519
    /// 2. Password
    ///
    /// If a mode is not available, the next mode will be used.
    Auto
}

impl Vigor {
    fn get_config_path() -> Result<PathBuf, Error> {
        match home_dir() {
            Some(mut home) => {
                home.push(".vigor");
                home.set_extension("conf");
                Ok(home)
            },
            None => Err(Error {message: "Failed to get user's home directory for Vigor configuration file.".to_owned()})
        }
    }

    /// Reads configuration from disk.
    /// Does not check to see if path to configuration file exists.
    pub fn read(&mut self) -> Result<(), Error> {
        match fs::read_to_string(&self.path) {
            Ok(data) => {
                let output: Result<ConfigSchema, serde_json::Error> = serde_json::from_str(&data);
                match output {
                    Ok(config) => {
                        self.config = config;
                        Ok(())
                    },
                    Err(error) => Err(Error {message: error.to_string()})
                }
            },
            Err(error) => Err(Error {message: error.to_string()})
        }
    }

    /// Writes configuration to disk.
    pub fn write(&self) -> Result<(), Error> {
        match fs::write(&self.path, serde_json::to_string(&self.config).unwrap()) {
            Ok(_) => {
                Ok(())
            },
            Err(error) => Err(Error {message: error.to_string()})
        }
    }

    /// Runs initialization for Vigor agent.
    ///
    /// If configuration does not exist, `write` method is called.
    /// If configuration does exist, `read` method is called.
    pub fn init(&mut self) -> Result<(), Error> {
        if !self.path.exists() {
            match Vigor::write(self) {
                Ok(_) => Ok(()),
                Err(error) => Err(error)
            }
        } else {
            match Vigor::read(self) {
                Ok(_) => Ok(()),
                Err(error) => Err(error)
            }
        }
    }

    /// Creates a new `Vigor` agent.
    ///
    /// The default configuration structure as JSON appears as follows:
    ///
    /// ```text
    /// {
    ///     "preferred_username": "nobody",
    ///     "email": "nobody@localhost",
    ///     "password": "hunter2",
    ///     "ed25519": {
    ///         "public": "/path/to/your/keys/vigor.pem.pub",
    ///         "private": "/path/to/your/keys/vigor.pem",
    ///         "enabled": false
    ///     }
    /// }
    /// ```
    ///
    /// # Examples
    ///
    /// To initialize a new instance:
    ///
    /// ```no_run
    /// let mut agent = vigor_agent::Vigor::new().unwrap();
    /// agent.init().unwrap();
    /// ```
    pub fn new() -> Result<Vigor, Error> {
        match Vigor::get_config_path() {
            Ok(config_path) => {
                Ok(Vigor {
                    config: ConfigSchema {
                        preferred_username: "nobody".to_owned(),
                        email: "nobody@localhost".to_owned(),
                        password: "hunter2".to_owned(), // i'm not funny.
                        ed25519: ConfigEd25519Schema {
                            public: "/path/to/your/keys/vigor.pem.pub".to_owned(),
                            private: "/path/to/your/keys/vigor.pem".to_owned(),
                            enabled: false
                        }
                    },
                    path: config_path
                })
            },
            Err(error) => Err(error)
        }
    }

    fn host_finalize(&self, host: &str) -> String {
        let mut url = PathBuf::from(host);
        url.push(&self.config.preferred_username);
        url.display().to_string()
    }

    fn process_request_response(response: Result<ureq::Response, ureq::Error>) -> Result<ureq::Response, Error> {
        match response {
            Ok(response) => Ok(response),
            Err(ureq::Error::Status(code, response)) => {
                match response.into_json::<ErrorResponse>() {
                    Ok(payload) => {
                        let mut message = code.to_string();
                        message.push_str(": ");
                        message.push_str(&payload.error);
                        Err(Error {message: message})
                    },
                    Err(error) => Err(Error {message: error.to_string()})
                }
            }
            Err(error) => Err(Error{message: error.to_string()})
        }
    }

    fn form_account_payload(&self, share_email: bool, use_password: bool, use_ed25519: bool) -> Result<serde_json::Map<String, serde_json::Value>, Error> {
        let mut payload = serde_json::Map::new();
        if share_email {
            payload.insert("email".to_owned(), serde_json::Value::String(self.config.email.to_owned()));
        }
        if use_password {
            match Vigor::get_authentication_password(self) {
                Ok(password) => {
                    payload.insert("password".to_owned(), serde_json::Value::String(password));
                },
                Err(error) => {
                    return Err(error);
                }
            }
        }
        if use_ed25519 {
            match fs::read_to_string(&self.config.ed25519.public) {
                Ok(data) => {
                    payload.insert("ed25519key".to_owned(), serde_json::Value::String(data));
                }
                Err(error) => {
                    return Err(Error {message: error.to_string()})
                }
            }
        }
        Ok(payload)
    }

    /// Performs account creation to a Vigor host.
    ///
    /// This method expects three booleans after the host argument for whether email, password, and/or Ed25519 should be shared, respectively.
    /// At least one authentication method must be shared.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # let mut agent = vigor_agent::Vigor::new().unwrap();
    /// # agent.init().unwrap();
    /// // assuming you already have an instance called "agent"
    /// agent.put("http://example.com/claims/", true, true, true).unwrap();
    /// ```
    pub fn put(&self, host: &str, share_email: bool, use_password: bool, use_ed25519: bool) -> Result<(), Error> {
        if !use_password && !use_ed25519 {
            return Err(Error {message: "At least one authentication method must exist on the new account.".to_owned()})
        }
        match Vigor::form_account_payload(self, share_email, use_password, use_ed25519) {
            Ok(payload) => {
                match Vigor::process_request_response(ureq::put(&Vigor::host_finalize(self, &host)).send_json(payload)) {
                    Ok(_) => Ok(()),
                    Err(error) => Err(error)
                }
            },
            Err(error) => Err(error)
        }
    }

    fn get_authentication_ed25519(&self) -> Result<String, Error> {
        match fs::read_to_string(&self.config.ed25519.private) {
            Ok(data) => {
                match pem_rfc7468::decode_vec(data.as_bytes()) {
                    Ok(data) => {
                        let raw = data.1;
                        if raw.len() < 32  {
                            return Err(Error {message: "Ed25519 private key is not at least 32 bytes.".to_owned()});
                        }
                        let key_as_bytes = &raw[(raw.len() - 32)..]; // drop excess bytes (i.e. ID bytes)
                        match ed25519_dalek::SecretKey::from_bytes(&key_as_bytes) {
                            Ok(secret_key) => {
                                let public_key: ed25519_dalek::PublicKey = (&secret_key).into();
                                let keypair = ed25519_dalek::Keypair {public: public_key, secret: secret_key};
                                match keypair.try_sign("SIGNME".as_bytes()) {
                                    Ok(signature) => {
                                        Ok(hex::encode(signature.to_bytes()))
                                    },
                                    Err(error) => Err(Error {message: error.to_string()})
                                }
                            },
                            Err(error) => Err(Error {message: error.to_string()})
                        }
                    },
                    Err(error) => Err(Error {message: error.to_string()})
                }
            }
            Err(error) => Err(Error {message: error.to_string()})
        }
    }

    fn get_authentication_password(&self) -> Result<String, Error> {
        if self.config.password.is_empty() {
            return Err(Error {message: "Password cannot be of zero length.".to_owned()})
        } else {
            return Ok(self.config.password.to_owned())
        }
    }

    fn form_authentication_ed25519(&self) -> Result<Authentication, Error> {
        match Vigor::get_authentication_ed25519(self) {
            Ok(answer) => {
                Ok(Authentication {mode: "ed25519".to_owned(), answer: answer})
            },
            Err(error) => Err(error)
        }
    }

    fn form_authentication_password(&self) -> Result<Authentication, Error> {
        match Vigor::get_authentication_password(self) {
            Ok(answer) => {
                Ok(Authentication {mode: "password".to_owned(), answer: answer})
            },
            Err(error) => Err(error)
        }
    }

    fn form_authentication(&self, mode: AuthMode) -> Result<Authentication, Error> {
        match mode {
            AuthMode::Ed25519 => {
                Vigor::form_authentication_ed25519(self)
            },
            AuthMode::Password => {
                Vigor::form_authentication_password(self)
            },
            AuthMode::Auto => {
                if self.config.ed25519.enabled {
                    match Vigor::form_authentication_ed25519(self) {
                        Ok(payload) => {
                            return Ok(payload)
                        },
                        Err(_) => {}
                    };
                }
                match Vigor::form_authentication_password(self) {
                    Ok(payload) => {
                        return Ok(payload)
                    },
                    Err(_) => {
                        return Err(Error {message: "No authentication modes available that aren't disabled or erroneous.".to_owned()});
                    }
                };
            }
        }
    }

    /// Performs token retrieval to a Vigor host.
    ///
    /// # Examples
    /// ```no_run
    /// # let mut agent = vigor_agent::Vigor::new().unwrap();
    /// # agent.init().unwrap();
    /// // assuming you already have an instance called "agent"
    /// agent.get("http://example.com/claims/", vigor_agent::AuthMode::Auto).unwrap();
    /// ```
    pub fn get(&self, host: &str, mode: AuthMode) -> Result<String, Error> {
        match Vigor::form_authentication(self, mode) {
            Ok(payload) => {
                match Vigor::process_request_response(ureq::get(&Vigor::host_finalize(self, &host)).send_json(payload)) {
                    Ok(response) => {
                        match response.into_json::<TokenResponse>() {
                            Ok(payload) => Ok(payload.jwt),
                            Err(error) => Err(Error {message: error.to_string()})
                        }
                    },
                    Err(error) => Err(error)
                }
            },
            Err(error) => Err(error)
        }
    }


    /// Performs account deletion to a Vigor host.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # let mut agent = vigor_agent::Vigor::new().unwrap();
    /// # agent.init().unwrap();
    /// // assuming you already have an instance called "agent"
    /// agent.delete("http://example.com/claims/", vigor_agent::AuthMode::Auto).unwrap();
    /// ```
    pub fn delete(&self, host: &str, mode: AuthMode) -> Result<(), Error> {
        match Vigor::form_authentication(self, mode) {
            Ok(payload) => {
                match Vigor::process_request_response(ureq::delete(&Vigor::host_finalize(self, &host)).send_json(payload)) {
                    Ok(_) => Ok(()),
                    Err(error) => Err(error)
                }
            },
            Err(error) => Err(error)
        }
    }

    /// Performs account modification to a Vigor host.
    ///
    /// This method expects three booleans after the host argument for whether email, password, and/or Ed25519 should be updated, respectively.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # let mut agent = vigor_agent::Vigor::new().unwrap();
    /// # agent.init().unwrap();
    /// // assuming you already have an instance called "agent"
    /// agent.patch("http://example.com/claims/", vigor_agent::AuthMode::Auto).unwrap();
    /// ```
    pub fn patch(&self, host: &str, mode: AuthMode, share_email: bool, use_password: bool, use_ed25519: bool) -> Result<(), Error> {
        if !share_email && !use_password && !use_ed25519 {
            return Err(Error {message: "At least one account property needs to be updated.".to_owned()});
        }
        match Vigor::form_authentication(self, mode) {
            Ok(payload) => {
                let mut payload_mod: serde_json::Map<String, serde_json::Value> = serde_json::to_value(payload).unwrap().as_object().unwrap().clone();
                match Vigor::form_account_payload(self, share_email, use_password, use_ed25519) {
                    Ok(changes) => {
                        payload_mod.insert("new".to_string(), serde_json::Value::Object(changes));
                        match Vigor::process_request_response(ureq::patch(&Vigor::host_finalize(self, &host)).send_json(&payload_mod)) {
                            Ok(_) => Ok(()),
                            Err(error) => Err(error)
                        }
                    },
                    Err(error) => Err(error)
                }
            },
            Err(error) => Err(error)
        }
    }
}
