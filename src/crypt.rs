use std::io::{Read, Write};

use age::armor::{ArmoredReader, ArmoredWriter, Format};
use age::secrecy::SecretString;
use age::{DecryptError, Decryptor, Encryptor, ssh};
use anyhow::{Context, Result, anyhow, bail};

/// Fetches `https://github.com/<user>.keys`.
pub fn fetch_keys(user: &str) -> Result<String> {
    // GitHub usernames are alphanumerics and hyphens, max 39 chars. Checked before
    // the name goes into the URL.
    let valid = (1..=39).contains(&user.len())
        && user.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    if !valid {
        bail!("invalid GitHub username: {user:?}");
    }

    match ureq::get(&format!("https://github.com/{user}.keys")).call() {
        Ok(mut res) => res
            .body_mut()
            .read_to_string()
            .context("failed to read GitHub response"),
        Err(ureq::Error::StatusCode(404)) => bail!("GitHub user not found: {user}"),
        Err(e) => Err(e).context("failed to fetch keys from GitHub"),
    }
}

/// Splits a `.keys` body into age-usable recipients and the key types it skipped.
pub fn parse_keys(body: &str) -> (Vec<ssh::Recipient>, Vec<String>) {
    let mut recipients = Vec::new();
    let mut skipped = Vec::new();
    for line in body.lines().map(str::trim).filter(|l| !l.is_empty()) {
        match line.parse() {
            Ok(r) => recipients.push(r),
            Err(_) => skipped.push(line.split_whitespace().next().unwrap_or(line).to_owned()),
        }
    }
    (recipients, skipped)
}

/// Encrypts to every recipient, ASCII-armored.
pub fn encrypt(recipients: &[ssh::Recipient], plaintext: &[u8]) -> Result<String> {
    let encryptor =
        Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))?;
    let mut out = Vec::new();
    let armor = ArmoredWriter::wrap_output(&mut out, Format::AsciiArmor)?;
    let mut writer = encryptor.wrap_output(armor)?;
    writer.write_all(plaintext)?;
    writer.finish()?.finish()?;
    Ok(String::from_utf8(out)?)
}

/// Decrypts armored or binary age data with an SSH private key (`key`, read from `key_name`).
pub fn decrypt(ciphertext: &[u8], key: &[u8], key_name: &str) -> Result<Vec<u8>> {
    let decryptor = Decryptor::new_buffered(ArmoredReader::new(ciphertext))
        .map_err(|_| anyhow!("input is not age-encrypted data"))?;

    let identity = match ssh::Identity::from_buffer(key, Some(key_name.to_owned()))
        .with_context(|| format!("invalid SSH private key: {key_name}"))?
    {
        ssh::Identity::Encrypted(enc) => {
            let pass = dialoguer::Password::new()
                .with_prompt(format!("Passphrase for {key_name}"))
                .interact()?;
            enc.decrypt(SecretString::from(pass))
                .map_err(|_| anyhow!("wrong passphrase for {key_name}"))?
                .into()
        }
        ssh::Identity::Unsupported(_) => bail!("unsupported SSH key type: {key_name}"),
        id => id,
    };

    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| match e {
            DecryptError::NoMatchingKeys => anyhow!("not encrypted to {key_name}"),
            e => anyhow!(e).context("decryption failed"),
        })?;
    let mut out = Vec::new();
    reader.read_to_end(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Throwaway key generated for these tests only.
    const KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDU7t8vqv4+2KbgXzT/3ZdAtxhWQV3+Yb20y30O3Cy+2AAAAIjAZBI7wGQS
OwAAAAtzc2gtZWQyNTUxOQAAACDU7t8vqv4+2KbgXzT/3ZdAtxhWQV3+Yb20y30O3Cy+2A
AAAEDG9uraW61urR+iXDKHXYshLfrCtnhCY37dKOuhA8O6zNTu3y+q/j7YpuBfNP/dl0C3
GFZBXf5hvbTLfQ7cLL7YAAAABHRlc3QB
-----END OPENSSH PRIVATE KEY-----
";
    const PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINTu3y+q/j7YpuBfNP/dl0C3GFZBXf5hvbTLfQ7cLL7Y";

    #[test]
    fn round_trip() {
        let (recipients, _) = parse_keys(PUB);
        let armored = encrypt(&recipients, b"hello").unwrap();
        assert!(armored.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
        assert_eq!(decrypt(armored.as_bytes(), KEY.as_bytes(), "test").unwrap(), b"hello");
    }

    #[test]
    fn parse_skips_unsupported() {
        let body = format!(
            "{PUB}\necdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY=\n\
             sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29t\n"
        );
        let (recipients, skipped) = parse_keys(&body);
        assert_eq!(recipients.len(), 1);
        assert_eq!(skipped, ["ecdsa-sha2-nistp256", "sk-ssh-ed25519@openssh.com"]);
    }
}
