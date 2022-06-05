use std::fs;
use dirs::home_dir;
use std::path::{PathBuf, Path};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct ConfigSchemaChildEd25519 {
    public: String,
    private: String,
    enabled: bool
}

#[derive(Serialize, Deserialize)]
pub struct ConfigSchema {
    preferred_username: String,
    email: String,
    password: String,
    ed25519: ConfigSchemaChildEd25519
}

pub fn get_config_path() -> String {
    let mut path = PathBuf::from(home_dir().expect("Failed to get user's home directory for Vigor configuration file."));
    path.set_file_name(".vigor");
    path.set_extension(".conf");
    String::from(path.display().to_string())
}

pub fn init_config() {
    let config_path: String = get_config_path();
    if !Path::new(&config_path).exists() {
        let default = ConfigSchema {
            preferred_username: String::from("nobody"),
            email: String::from("nobody@localhost"),
            password: String::from("hunter2"), // i'm not funny.
            ed25519: ConfigSchemaChildEd25519 {
                public: String::from("/path/to/your/keys/vigor.pem.pub"),
                private: String::from("/path/to/your/keys/vigor.pem"),
                enabled: false
            }
        };
        fs::write(config_path, serde_json::to_string(&default).unwrap()).expect("Failed to write default Vigor configuration file.");
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
