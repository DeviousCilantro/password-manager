use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{OsRng, KeyInit, AeadCore, Aead},
};
use argon2::{
    Argon2,
    password_hash::SaltString,
};
use sha3::{Digest, Keccak512};
use generic_array::GenericArray;
use std::io::{self, Write};
use std::collections::HashMap;
use std::error::Error;

#[derive(Debug, Eq, Hash, PartialEq, Clone)]
struct LoginData {
    identifier: String,
    login_data: String,
    encoded_nonce: String,
}


impl LoginData {
    fn add_login(credentials: &str) -> Result<Self, Box<dyn Error>> {
        let credentials: Vec<&str> = credentials.split('&').collect();
        let mut key = [0u8; 32];
        if let Err(e) = Argon2::default().hash_password_into(
            credentials[1].as_bytes(), 
            credentials[0].as_bytes(), 
            &mut key) 
        {
            panic!("{e}");
        };

        let identifier = read_input("Enter identifier: ")?;
        let username = read_input("Enter username: ")?;
        let password = rpassword::prompt_password("Enter password: ")?;
        let confirm_password = rpassword::prompt_password("Confirm password: ")?;
        assert_eq!(password, confirm_password, "Passwords do not match");
        let mut login_data = format!("{username}:{password}");
        let key = GenericArray::from_slice(&key);
        let cipher = XChaCha20Poly1305::new(key);
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let encoded_nonce = hex::encode(nonce);

        let ciphertext = cipher.encrypt(&nonce, login_data.as_ref());

        if let Ok(value) = ciphertext  {
            login_data = hex::encode(value);
        } else if let Err(e) = ciphertext  {
            panic!("{e}");
        };

        Ok(LoginData {
            identifier,
            login_data,
            encoded_nonce,
        })
    }

    fn retrieve_login(&self, credentials: &str) -> Result<String, Box<dyn Error>> {
        let credentials: Vec<&str> = credentials.split('&').collect();
        let mut key = [0u8; 32];
        if let Err(e) = Argon2::default().hash_password_into(
            credentials[1].as_bytes(), 
            credentials[0].as_bytes(), 
            &mut key) 
        {
            panic!("{e}");
        };
        let key = GenericArray::from_slice(&key);
        let cipher = XChaCha20Poly1305::new(key);
        let nonce = hex::decode(&self.encoded_nonce)?;
        let nonce = GenericArray::from_slice(&nonce);
        let ciphertext = hex::decode(&self.login_data)?;
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref());
        let mut credentials = String::new();

        if let Ok(value) = plaintext {
            credentials = String::from_utf8(value)?;
        } else if let Err(e) = plaintext {
            panic!("{e}");
        }

        Ok(credentials)
    }
}

fn read_input(prompt: &str) -> Result<String, Box<dyn Error>> {
    let mut input = String::new();
    print!("{prompt}");
    io::stdout().flush()?;
    io::stdin().read_line(&mut input)?;
    Ok(input.clone().trim().to_string())
}

fn hashed_credentials(register: bool) -> Result<String, Box<dyn Error>> {
    let mut hasher = Keccak512::new();
    let email = read_input("Enter username or email ID: ")?;
    let password = rpassword::prompt_password("Enter master password: ")?;
    hasher.update(format!("{email}:{password}"));
    if register {
        let confirm_password = rpassword::prompt_password("Confirm master password: ")?;
        assert_eq!(password, confirm_password, "Passwords do not match");
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn main() -> Result<(), Box<dyn Error>> {

    let mut database: HashMap<String, Vec<LoginData>> = HashMap::new();

    loop {
        let choice = read_input("\n[R]egister / [A]uthenticate / [E]xit? (r/a/e) ")?;

        match choice.as_str() {
            "R" | "r" => {
                let authenticator = hashed_credentials(true)?;
                if let Some((_, _)) = database
                    .clone()
                        .iter()
                        .find(|(key, _)| key.contains(&authenticator))
                        {
                            eprintln!("\nUser exists.");
                            continue;
                        }
                let salt = SaltString::generate(&mut OsRng).as_str().to_string();
                let credentials = format!("{salt}&{authenticator}");
                database.insert(credentials, Vec::new());
            },
            "A" | "a" => {
                let authenticator = hashed_credentials(false)?;
                if let Some((key, _)) = database
                    .clone()
                        .iter()
                        .find(|(key, _)| key.contains(&authenticator))
                        {
                            println!("\nAuthentication sucessful.");
                            loop {
                                let choice = read_input("\n[A]dd entry / [R]etrieve entry / [L]ogout? (a/r/l) ")?;
                                match choice.as_str() {
                                    "A" | "a" => {
                                        if let Some(vector) = database.get_mut(key) {
                                            vector.push(LoginData::add_login(key)?);
                                            println!("Added entry to database: {vector:?}");
                                        }
                                    },
                                    "R" | "r" => {
                                        let identifier = read_input("\nEnter identifier: ")?;
                                        if let Some(vector) = database.get(key) {
                                            if let Some(login_data) = vector
                                                .clone()
                                                    .iter()
                                                    .find(|item| item.identifier == identifier)
                                                    {
                                                        let credentials = login_data.retrieve_login(key)?;
                                                        let credentials: Vec<&str> = credentials.split(':').collect();
                                                        println!("\nUsername: {}", credentials[0]);
                                                        println!("Password: {}", credentials[1]);
                                                    } else {
                                                        eprintln!("\nInvalid identifier.");
                                                    }
                                        }
                                    },
                                    "L" | "l" => break,
                                    _ => eprintln!("\nInvalid input."),
                                };
                            };
                        } else {
                            eprintln!("\nInvalid credentials.");
                        }
            },
            "E" | "e" => break,
            _ => eprintln!("\nInvalid input"),
        }
    }

    Ok(())
}
