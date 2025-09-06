use std::{borrow::Cow, collections::HashMap};

const BCRYPT_ID: &str = "$2y$";
const SHA1_ID: &str = "{SHA}";
const MD5_ID: &str = "$apr1$";

pub(crate) struct Htpasswd<'a>(HashMap<Cow<'a, str>, Hash<'a>>);

#[derive(Debug, Eq, PartialEq)]
enum Hash<'a> {
    MD5(), // NOT SUPPORTED
    BCrypt(Cow<'a, str>),
    Sha1(Cow<'a, str>),  // NOT SUPPORTED
    Crypt(Cow<'a, str>), // NOT SUPPORTED (just plain)
}

impl<'a> Htpasswd<'a> {
    pub(crate) fn new(bytes: &'a str) -> Htpasswd<'a> {
        let lines = bytes.split('\n');
        let hashes = lines
            .filter_map(parse_hash_entry)
            .collect::<HashMap<_, _>>();
        Htpasswd(hashes)
    }

    pub(crate) fn check<S: AsRef<str>>(&self, username: S, password: S) -> bool {
        self.0
            .get(username.as_ref())
            .map(|hash| hash.check(password))
            .unwrap_or_default()
    }

    pub(crate) fn into_owned(self) -> Htpasswd<'static> {
        Htpasswd(
            self.0
                .into_iter()
                .map(|(username, hash)| (Cow::Owned(username.to_string()), hash.to_owned()))
                .collect(),
        )
    }
}

impl<'a> From<&'a str> for Htpasswd<'a> {
    fn from(value: &'a str) -> Self {
        Htpasswd::new(value)
    }
}

impl<'a> Hash<'a> {
    fn parse(hash: &'a str) -> Hash<'a> {
        if hash.starts_with(MD5_ID) {
            Hash::MD5()
        } else if hash.starts_with(BCRYPT_ID) {
            Hash::BCrypt(Cow::Borrowed(hash))
        } else if hash.starts_with(SHA1_ID) {
            Hash::Sha1(Cow::Borrowed(&hash[SHA1_ID.len()..]))
        } else {
            // crypt or plain
            Hash::Crypt(Cow::Borrowed(hash))
        }
    }

    fn check<S: AsRef<str>>(&self, password: S) -> bool {
        let password = password.as_ref();
        match self {
            Hash::MD5() => false,
            Hash::BCrypt(hash) => bcrypt::verify(password, hash).unwrap(),
            Hash::Sha1(_) =>
            /* check with SHA1 */
            {
                false
            }
            Hash::Crypt(hash) =>
            /* check unix crypt || */
            {
                password == hash
            }
        }
    }

    fn to_owned(&'a self) -> Hash<'static> {
        match self {
            Hash::MD5() => Hash::MD5(),
            Hash::BCrypt(hash) => Hash::BCrypt(Cow::Owned(hash.to_string())),
            Hash::Sha1(hash) => Hash::Sha1(Cow::Owned(hash.to_string())),
            Hash::Crypt(hash) => Hash::Crypt(Cow::Owned(hash.to_string())),
        }
    }
}

fn parse_hash_entry(entry: &'_ str) -> Option<(Cow<'_, str>, Hash<'_>)> {
    let index = entry.find(":")?;
    let username = &entry[..index];
    let hash = &entry[(index + 1)..];
    Some((Cow::Borrowed(username), Hash::parse(hash)))
}

#[cfg(test)]
mod tests {
    use super::*;

    static DATA: &str = "user_crypt:rXlDt0iIp4NDY
user_sha1:{SHA}cRDtpNCeBiql5KOQsKVyrA0sAiA=
user_md5:$apr1$L8CvWvSe$36HEZweAWUxi2P4NvF4xz0
user_bcrypt:$2y$05$QzPnkkUycoy1OlP26Ruw6eqvy8GNqTFPwcfITNqzpkKLNHc3F0Hke
user_plain:1234
";
    static PASSWORD: &str = "1234";
    static WRONG_PASSWORD: &str = "4321";

    #[test]
    fn unix_crypt_verify_htpasswd() {
        let htpasswd = Htpasswd::from(DATA);
        // NOTE: not supported
        assert_eq!(htpasswd.check("user_crypt", PASSWORD), false);
        assert_eq!(htpasswd.check("user_crypt", WRONG_PASSWORD), false);
    }

    #[test]
    fn md5_verify_htpasswd() {
        let htpasswd = Htpasswd::from(DATA);
        // NOTE: not supported
        assert_eq!(htpasswd.check("user_md5", PASSWORD), false);
        assert_eq!(htpasswd.check("user_md5", WRONG_PASSWORD), false);
    }

    #[test]
    fn sha1_verify_htpasswd() {
        let htpasswd = Htpasswd::from(DATA);
        // NOTE: not supported
        assert_eq!(htpasswd.check("user_sha1", PASSWORD), false);
        assert_eq!(htpasswd.check("user_sha1", WRONG_PASSWORD), false);
    }

    #[test]
    fn bcrypt_verify_htpasswd() {
        let htpasswd = Htpasswd::from(DATA);
        assert_eq!(htpasswd.check("user_bcrypt", PASSWORD), true);
        assert_eq!(htpasswd.check("user_bcrypt", WRONG_PASSWORD), false);
    }

    #[test]
    fn no_user_httpasswd() {
        let htpasswd = Htpasswd::from(DATA);
        assert_eq!(htpasswd.check("user", PASSWORD), false);
    }
}
