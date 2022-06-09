#![deny(missing_docs,
    missing_debug_implementations, missing_copy_implementations,
    trivial_casts, trivial_numeric_casts,
    unsafe_code,
    unstable_features,
    unused_import_braces, unused_qualifications)]

//! # Vigor
//! This library contains a Vigor authentication agent to manage credentials and perform HTTP/HTTPS requests.

use std::fs;
use std::fmt;
use dirs::home_dir;
use std::path::PathBuf;
use serde::{Serialize, Deserialize};

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
#[derive(Serialize, Deserialize)]
struct ConfigEd25519Schema {
    public: String,
    private: String,
    enabled: bool
}

#[derive(Serialize, Deserialize)]
struct ConfigSchema {
    preferred_username: String,
    email: String,
    password: String,
    ed25519: ConfigEd25519Schema
}

/// Represents configuration and path information for agent structure.
///
/// Consume implemented methods for initialization, see `new` method.
pub struct Vigor {
    config: ConfigSchema,
    path: PathBuf
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
                        preferred_username: String::from("nobody"),
                        email: String::from("nobody@localhost"),
                        password: String::from("hunter2"), // i'm not funny.
                        ed25519: ConfigEd25519Schema {
                            public: String::from("/path/to/your/keys/vigor.pem.pub"),
                            private: String::from("/path/to/your/keys/vigor.pem"),
                            enabled: false
                        }
                    },
                    path: config_path
                })
            },
            Err(error) => Err(error)
        }
    }
}

// function here to put

// function here to delete

// function here to patch

// function here to get token.

// function here to perform request with token automatically as header.
