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

use std::fs;
use std::fmt;
use std::path::PathBuf;

extern crate dirs;
extern crate serde;
extern crate reqwest;
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

// definitions for configuration structs.
#[derive(serde::Serialize, serde::Deserialize)]
struct ConfigEd25519Schema {
    public: String,
    private: String,
    enabled: bool
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ConfigSchema {
    preferred_username: String,
    email: String,
    password: String,
    ed25519: ConfigEd25519Schema
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

/// Represents configuration and path information for agent structure.
///
/// Consume implemented methods for initialization, see `new` method.
pub struct Vigor {
    config: ConfigSchema,
    path: PathBuf,
    client: reqwest::blocking::Client
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
            Some(home) => {
                let mut path = PathBuf::from(home);
                path.set_file_name(".vigor");
                path.set_extension(".conf");
                Ok(path)
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
    /// # Examples
    ///
    /// To initialize a new instance:
    ///
    /// ```ignore
    /// let mut agent = Vigor::new().unwrap();
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
                    path: config_path,
                    client: reqwest::blocking::Client::new()
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

    fn process_reqwest_response(response: reqwest::Result<reqwest::blocking::Response>) -> Result<reqwest::blocking::Response, Error> {
        match response {
            Ok(response) => {
                // handling for cases where there is a response available.
                // does not exclusively imply result is Ok.
                match response.status() {
                    reqwest::StatusCode::OK => Ok(response),
                    _ => {
                        match response.json::<ErrorResponse>() {
                            Ok(payload) => {
                                Err(Error {message: payload.error})
                            },
                            Err(error) => Err(Error {message: error.to_string()})
                        }
                    }
                }
            }
            Err(error) => {
                // handling for cases where there is no response available.
                let mut message = error.to_string();

                // looked at source for fmt::Display trait of reqwest:Error, wrote extra cases.
                if error.is_timeout() {
                    message.push_str(" due to time out"); // no timeout warning, adding here instead.
                }
                if error.is_connect() {
                    message.push_str(" due to connection"); // no connection warning, adding here instead.
                }
                Err(Error {message: message})
            }
        }
    }

    /// Performs account creation to a Vigor host.
    ///
    /// This method expects three booleans after the host argument for whether email, password, and/or Ed25519 should be shared.
    /// At least one authentication method must be shared.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // assuming you already have an instance called "agent"
    /// agent.put("http://example.com/claims/", true, true, true).unwrap();
    /// ```
    pub fn put(&self, host: &str, share_email: bool, use_password: bool, use_ed25519: bool) -> Result<(), Error> {
        let mut payload = serde_json::Map::new();
        if !use_password && !use_ed25519 {
            return Err(Error {message: "At least one authentication method must exist on the new account.".to_owned()})
        }
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
        match Vigor::process_reqwest_response(self.client.put(Vigor::host_finalize(self, &host)).json(&serde_json::to_string(&payload).unwrap()).send()) {
            Ok(_) => Ok(()),
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

    fn form_authentication_ed25519(&self) -> Result<String, Error> {
        match Vigor::get_authentication_ed25519(self) {
            Ok(answer) => {
                let json = Authentication {
                    mode: "ed25519".to_owned(),
                    answer: answer
                };
                Ok(serde_json::to_string(&json).unwrap())
            },
            Err(error) => Err(error)
        }
    }

    fn form_authentication_password(&self) -> Result<String, Error> {
        match Vigor::get_authentication_password(self) {
            Ok(answer) => {
                let json = Authentication {
                    mode: "password".to_owned(),
                    answer: answer
                };
                Ok(serde_json::to_string(&json).unwrap())
            },
            Err(error) => Err(error)
        }
    }

    fn form_authentication(&self, mode: AuthMode) -> Result<String, Error> {
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
    /// ```ignore
    /// // assuming you already have an instance called "agent"
    /// agent.get("http://example.com/claims/", vigor_agent::AuthMode::Auto).unwrap();
    /// ```
    pub fn get(&self, host: &str, mode: AuthMode) -> Result<String, Error> {
        match Vigor::form_authentication(self, mode) {
            Ok(payload) => {
                match Vigor::process_reqwest_response(self.client.get(Vigor::host_finalize(self, &host)).json(&payload).send()) {
                    Ok(response) => {
                        match response.json::<TokenResponse>() {
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
    /// ```ignore
    /// // assuming you already have an instance called "agent"
    /// agent.delete("http://example.com/claims/", vigor_agent::AuthMode::Auto).unwrap();
    /// ```
    pub fn delete(&self, host: &str, mode: AuthMode) -> Result<(), Error> {
        match Vigor::form_authentication(self, mode) {
            Ok(payload) => {
                match Vigor::process_reqwest_response(self.client.delete(Vigor::host_finalize(self, &host)).json(&payload).send()) {
                    Ok(_) => Ok(()),
                    Err(error) => Err(error)
                }
            },
            Err(error) => Err(error)
        }
    }

    // function here to patch

    // function here to perform request with token automatically as header.
}
