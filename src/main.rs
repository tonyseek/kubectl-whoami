use base64::prelude::*;

use kube::config::Kubeconfig;
use openssl::nid::Nid;
use openssl::x509::X509;

type AsyncResult<T> = Result<T, Box<dyn std::error::Error>>;

#[tokio::main]
async fn main() -> AsyncResult<()> {
    let user = whoami().await?;
    println!("User: {}", user.name);
    println!("Groups: {}", user.groups.join(", "));
    Ok(())
}

async fn whoami() -> AsyncResult<UserInfo> {
    let c = Kubeconfig::read()?;

    let mut auth_info = None;
    for user in c.auth_infos {
        if Some(user.name) == c.current_context {
            auth_info = Some(user.auth_info);
        }
    }

    let auth_info = auth_info.ok_or_else(|| Box::new(UserNotFound {}))?;
    if let Some(client_pem) = auth_info
        .as_ref()
        .and_then(|auth_info| auth_info.client_certificate_data.as_ref())
    {
        let client_pem = X509::from_pem(&BASE64_STANDARD.decode(client_pem)?)?;
        UserInfo::from_x509(&client_pem)
    } else {
        let name = auth_info
            .and_then(|auth_info| auth_info.username)
            .ok_or_else(|| Box::new(UserNotFound {}))?;
        Ok(UserInfo::new(name, vec![]))
    }
}

#[derive(Debug)]
struct UserInfo {
    pub name: String,
    pub groups: Vec<String>,
}

impl UserInfo {
    pub fn new(name: String, groups: Vec<String>) -> Self {
        Self { name, groups }
    }

    pub fn from_x509(pem: &X509) -> Result<Self, Box<dyn std::error::Error>> {
        let mut name: Option<String> = None;
        let mut groups: Vec<String> = Vec::with_capacity(1);
        for entry in pem.subject_name().entries() {
            let s = entry.data().as_utf8()?;
            match entry.object().nid() {
                Nid::ORGANIZATIONNAME => groups.push(s.to_string()),
                Nid::COMMONNAME => name = Some(s.to_string()),
                _ => (),
            }
        }
        let name = name.ok_or_else(|| Box::new(UserNotFound {}))?;
        Ok(Self::new(name, groups))
    }
}

#[derive(Debug)]
struct UserNotFound {}

impl std::error::Error for UserNotFound {}

impl std::fmt::Display for UserNotFound {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "user not found")
    }
}
