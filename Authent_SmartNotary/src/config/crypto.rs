use actix_web::web::block;
use argonautica::{Hasher, Verifier};
use chrono::{Duration, Utc};
use color_eyre::Result;
use eyre::eyre;
use futures::compat::Future01CompatExt;
use jsonwebtoken::{decode as jwtdecode, encode as jwtencode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::instrument;
use uuid::Uuid;

extern crate base64;
use base64::{encode as b64encode, decode as b64decode};
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::io::Write;
//use std::io::Result;
use std::path::Path;
/* Hash */
use rand::Rng;
//use argon2::{self, Config, ThreadMode, Variant, Version};
/* AES */
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};




#[derive(Debug, Clone)]
pub struct CryptoService {
    pub key: Arc<String>,
    pub jwt_secret: Arc<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub exp: i64,
    // aud
    // role
    // perms
}

#[derive(Serialize)]
pub struct Auth {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct DataAES {
    //pub iv: String,
    pub key_aes: String,
    pub ciphertext_aes: String,
}

#[derive(Serialize)]
pub struct KeyValue {
    pub uid: String,
    pub key_aes: String,
}


impl CryptoService {    
    pub async fn random_salt() -> Result<[u8;32]> {
        let rnd_salt: [u8; 32] = rand::thread_rng().gen();  
        println!("\nrandom_salt = {:?}\n", rnd_salt);
        //return rnd_salt;    // salt: 256-bits
        Ok(rnd_salt)
    }

    #[instrument(skip(self, password), err)]
    pub async fn hash_password(&self, password: String) -> Result<String> {
        Hasher::default()
            .with_secret_key(&*self.key)
            .with_password(password)
            .hash_non_blocking()
            .compat()
            .await
            .map_err(|err| eyre!("Hashing error: {}", err))
    }

    #[instrument(skip(self, password, password_hash))]
    pub async fn verify_password(&self, password: &str, password_hash: &str) -> Result<bool> {
        Verifier::default()
            .with_secret_key(&*self.key)
            .with_hash(password_hash)
            .with_password(password)
            .verify_non_blocking()
            .compat()
            .await
            .map_err(|err| eyre!("Verifying error: {}", err))
    }


    #[instrument(skip(self))]
    pub async fn generate_jwt(&self, user_id: Uuid) -> Result<String> {
        let jwt_key = self.jwt_secret.clone();
        block(move || {
            let headers = Header::default();
            let encoding_key = EncodingKey::from_secret(jwt_key.as_bytes());
            let now = Utc::now() + Duration::days(1); // Expires in 1 day
            let claims = Claims {
                sub: user_id,
                exp: now.timestamp(),
            };
            jwtencode(&headers, &claims, &encoding_key)
        })
        .await
        .map_err(|err| eyre!("Creating jwt token: {}", err))
    }

    #[instrument(skip(self, token))]
    pub async fn verify_jwt(&self, token: String) -> Result<TokenData<Claims>> {
        let jwt_key = self.jwt_secret.clone();
        block(move || {
            let decoding_key = DecodingKey::from_secret(jwt_key.as_bytes());
            let validation = Validation::default();
            jwtdecode::<Claims>(&token, &decoding_key, &validation)
        })
        .await
        .map_err(|err| eyre!("Verifying jwt token: {}", err))
    }



    pub async fn encodeur_b64(value: String) -> Result<String> {
        let enc_value: String = b64encode(&value.as_bytes());
        Ok(enc_value)
    }

    
    pub async fn decodeur_b64(enc_value: String) -> Result<Vec<u8>> {
        let value: Vec<u8> = b64decode(&enc_value).unwrap();
        Ok(value)
    }

    #[instrument(skip(self))]
    pub async fn aes_gcm_encrypt(&self, plaintext: String) -> Result<DataAES> {
        // aes key: 256-bits; unique/user
        let aes_key: [u8; 32] = rand::thread_rng().gen();
        let secret_key = Key::from_slice(&aes_key);
        let cipher = Aes256Gcm::new(secret_key);
        // IV: 96-bits; unique per message
        //let rnd: [u8; 12] = rand::thread_rng().gen();
        let init_vect: &[u8] = b"000000000000";
        let iv = Nonce::from_slice(init_vect);    
        // encrypt
        let ciphertext: Vec<u8> = cipher.encrypt(iv, plaintext.as_bytes().as_ref())
            .expect("encryption failure!");    
        assert_ne!(&plaintext.as_bytes(), &ciphertext);        
        println!("iv = {:?}\n\nkey_aes = {:?}\n\nciphertext = {:?}\n", iv, aes_key, ciphertext);   
        let aes_key_ = String::from_utf8_lossy(&aes_key);
        let ciphertext_ = String::from_utf8_lossy(&ciphertext);
        let enc_aes = DataAES{key_aes: (&aes_key_).to_string(), ciphertext_aes: (&ciphertext_).to_string()};
        // base64 
        //let iv: String = encode(init_vect);
        //let cipher_hash: String = encode(&ciphertext);
        //let key: String = encode(&key);
        //let enc_data = EncDataAES{key_aes: key, ciphertext: cipher_hash};
        //println!("key1_enc = {:?}\n\nciphertext1_enc = {:?}\n", enc_data.key_aes, enc_data.ciphertext_aes);        
        Ok(enc_aes)
    }

    #[instrument(skip(self, ciphertext, key_aes))]
    pub async fn aes_gcm_decrypt(&self, key_aes: Vec<u8>, ciphertext: Vec<u8>) -> Result<Vec<u8>> {  
        let secret_key = Key::from_slice(&key_aes);
        let cipher = Aes256Gcm::new(secret_key);  
        let init_vec: &[u8] = b"000000000000";  
        let nonce = Nonce::from_slice(init_vec);
        // decrypt
        let plaintext: Vec<u8> = cipher.decrypt(nonce, ciphertext.as_ref())
        .expect("decryption failure!");
        /* let plaintext = cipher.decrypt(&nonce, encrypted_message.cipherText.as_ref())
        .expect("decryption failure!"); */
        assert_ne!(&plaintext, &ciphertext);
        Ok(plaintext)
    }

    #[instrument(skip(self, uid))]
    pub async fn protect_key(&self, uid: &String, data: &DataAES) -> Result<()> {
        let path = Path::new("key.conf");        
            if path.exists() {
                // get contents of file 
                let file = File::open("key.conf").unwrap();
                let mut buf_reader = BufReader::new(file);
                let mut contents = String::new();
                buf_reader.read_to_string(&mut contents);
                // push contents + new key in file
                let mut file = File::create(path).unwrap();
                file.write(&contents.as_bytes()).unwrap();
                writeln!(&mut file, " ").unwrap();
                //file.write(uid.as_bytes()).unwrap();
                file.write(data.key_aes.as_bytes()).unwrap();
                println!("update file\n");
            }
            else {
                let mut file = File::create(path).unwrap();
                //writeln!(&mut file, "\nkey").unwrap();
                //file.write(&uid.as_bytes()).unwrap();
                file.write(&data.key_aes.as_bytes()).unwrap();
                println!("file create\n");
            }        
        Ok(())
    }

    
    pub fn reader_key() -> Result<Vec<u8>> {
        let file = File::open("key.conf").unwrap();
        let mut buf_reader = BufReader::new(file);
        let mut contents = String::new();
        buf_reader.read_to_string(&mut contents);
        println!("file contents: {}\n", contents);
        // get just row
        let dec_key = b64decode(contents).unwrap();
        Ok(dec_key)
    }

}