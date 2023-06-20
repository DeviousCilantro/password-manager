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
use std::io::{
    Write, BufRead, BufReader
};
use std::collections::HashMap;
use std::error::Error;
use std::os::unix::net::{UnixStream, UnixListener};
use std::fs::{metadata, remove_file};

#[derive(Debug, Eq, Hash, PartialEq, Clone)]
struct LoginData {
    identifier: String,
    login_data: String,
    encoded_nonce: String,
}

impl LoginData {
    fn add_login(credentials: &str, stream: &UnixStream) -> Result<Self, Box<dyn Error>> {
        let credentials: Vec<&str> = credentials.split('&').collect();
        let mut key = [0u8; 32];
        if let Err(e) = Argon2::default().hash_password_into(
            credentials[1].as_bytes(), 
            credentials[0].as_bytes(), 
            &mut key) 
        {
            panic!("{e}");
        };

        write(stream, "\nEnter identifier: ");
        let identifier = read(stream)?;
        write(stream, "Enter username: ");
        let username = read(stream)?;
        write(stream, "Enter password on the server-side terminal. Waiting...\n");
        let password = rpassword::prompt_password("\nEnter password: ")?;
        write(stream, "\nConfirm password on the server-side terminal. Waiting...\n");
        let confirm_password = rpassword::prompt_password("Confirm password: ")?;
        assert_eq!(password, confirm_password, "Passwords do not match");
        println!("\nPasswords match.");
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

fn hashed_credentials(register: bool, stream: &UnixStream) -> Result<String, Box<dyn Error>> {
    let mut hasher = Keccak512::new();
    write(stream, "Enter username or email ID: ");
    let email = read(stream)?;
    write(stream, "Enter master password on the server-side terminal. Waiting...\n");
    let password = rpassword::prompt_password("\nEnter password: ")?;
    hasher.update(format!("{email}:{password}"));
    if register {
        write(stream, "\nConfirm master password on the server-side terminal. Waiting...\n");
        let confirm_password = rpassword::prompt_password("Confirm password: ")?;
        assert_eq!(password, confirm_password, "Passwords do not match");
        println!("\nPasswords match.");
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn read(stream: &UnixStream) -> Result<String, Box<dyn Error>> {
    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader.read_line(&mut response)?;
    let response = response.trim().to_string();
    Ok(response)

}


fn write(stream: &UnixStream, text: &str) {
    let Ok(mut unix_stream) = stream.try_clone() else { 
        panic!("\nCannot clone stream");
    };

    if let Err(e) = unix_stream.write(text.as_bytes()) {
        panic!("{e}");
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let socket_path = "/tmp/password-manager.sock";
    if metadata(socket_path).is_ok() {
        println!("\nA socket is already present at {}. Deleting...", &socket_path);
        remove_file(socket_path)?;
    }
    let listener = UnixListener::bind(socket_path)?;
    println!("\nCreating UNIX socket at {socket_path}...");
    println!("\nCommunicate using a utility like netcat. For instance, execute `nc -U /tmp/password-manager.sock` on a separate terminal.");
    let stream = listener.accept()?.0;
    let mut database: HashMap<String, Vec<LoginData>> = HashMap::new();


    loop {

        write(&stream, "\n[R]egister / [A]uthenticate / [E]xit? (r/a/e) ");

        let choice = read(&stream)?;
        match choice.as_str() {
            "R" | "r" => {
                let authenticator = hashed_credentials(true, &stream)?;
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
                let authenticator = hashed_credentials(false, &stream)?;
                if let Some((key, _)) = database
                    .clone()
                        .iter()
                        .find(|(key, _)| key.contains(&authenticator))
                        {
                            write(&stream, "\nAuthentication sucessful.\n");
                            loop {
                                write(&stream, "\n[A]dd entry / [R]etrieve entry / [L]ogout? (a/r/l) ");
                                let choice = read(&stream)?;
                                match choice.as_str() {
                                    "A" | "a" => {
                                        if let Some(vector) = database.get_mut(key) {
                                            vector.push(LoginData::add_login(key, &stream)?);
                                            write(&stream, &format!("Added entry to database: {vector:?}"));
                                        }
                                    },
                                    "R" | "r" => {
                                        write(&stream, "\nEnter identifier: ");
                                        let identifier = read(&stream)?;
                                        if let Some(vector) = database.get(key) {
                                            if let Some(login_data) = vector
                                                .clone()
                                                    .iter()
                                                    .find(|item| item.identifier == identifier)
                                                    {
                                                        let credentials = login_data.retrieve_login(key)?;
                                                        let credentials: Vec<&str> = credentials.split(':').collect();
                                                        write(&stream, &format!("\nUsername: {}", credentials[0]));
                                                        write(&stream, &format!("\nPassword: {}\n", credentials[1]));
                                                    } else {
                                                        write(&stream, "\nInvalid identifier.\n");
                                                    }
                                        }
                                    },
                                    "L" | "l" => break,
                                    _ => { 
                                        write(&stream, "\nInvalid input.\n");
                                    }
                                };
                            };
                        } else {
                            write(&stream, "\nInvalid credentials.\n");
                        }
            },
            "E" | "e" => break,
            _ => {
                write(&stream, "\nInvalid input\n");
            },
        }
    }

    Ok(())
}
