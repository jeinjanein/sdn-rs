use std::{error::Error, io::ErrorKind};

use argon2::{
    Argon2, PasswordHasher,
    password_hash::{SaltString, rand_core::OsRng},
};

fn main() -> Result<(), Box<dyn Error>> {
    let password = rpassword::prompt_password("Password: ")?;

    let confirm_password = rpassword::prompt_password("Confirm password:")?;

    if password != confirm_password {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            "the supplied passwords do not match",
        )
        .into());
    }

    let salt = SaltString::generate(&mut OsRng);

    let password_hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)?
        .to_string();

    println!("{password_hash}");

    Ok(())
}
