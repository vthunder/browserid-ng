//! Minimal agent CLI for driving the full v0.4 flow against a live broker —
//! the prod smoke-test harness.
//!
//! ```text
//! # 1. Create an agent key at https://browserid.me/agents, download
//! #    agent-credential.json, then:
//! cargo run -p browserid-agent --example agent_cli -- agent-credential.json provision attestor
//!
//! # 2. Authenticate to an RP cold (challenge → consent → token). The CLI
//! #    prints the consent URL; open it, approve, and the token appears.
//! cargo run -p browserid-agent --example agent_cli -- agent-credential.json token https://api.example.com/data
//!
//! # Or lower-level: get a warrant-backed assertion for an audience.
//! cargo run -p browserid-agent --example agent_cli -- agent-credential.json assert https://api.example.com
//! ```
//!
//! The provisioned identity (agent key, cert, warrants) persists next to the
//! credential as `<credential>.identity.json`.

use browserid_agent::{AgentCredential, AgentError, AgentIdentity};

fn usage() -> ! {
    eprintln!(
        "usage: agent_cli <credential.json> <command> [...]\n\
         commands:\n  \
         provision [name]      provision (or refresh) the agent identity\n  \
         grant <aud> [aud...]  request warrants for one or more audiences (one consent)\n  \
         assert <audience>     print a warrant-backed assertion (runs consent if needed)\n  \
         token <resource-url>  full flow: challenge -> consent -> RP bearer token\n  \
         warrants              list audiences this agent holds warrants for\n  \
         revoke                revoke the agent identity at the IdP"
    );
    std::process::exit(2);
}

fn identity_path(credential_path: &str) -> String {
    format!("{credential_path}.identity.json")
}

/// Load the persisted identity, or provision a fresh one.
async fn load_or_provision(
    credential: &AgentCredential,
    credential_path: &str,
    name: Option<&str>,
) -> Result<AgentIdentity, AgentError> {
    let path = identity_path(credential_path);
    if std::path::Path::new(&path).exists() {
        let agent = AgentIdentity::load(&path, credential)?;
        eprintln!("loaded identity {} from {path}", agent.email());
        Ok(agent)
    } else {
        let agent = AgentIdentity::provision(credential, name).await?;
        agent.save(&path)?;
        eprintln!("provisioned {} (saved to {path})", agent.email());
        Ok(agent)
    }
}

/// Make sure a warrant for `audience` exists, running the consent flow if
/// not: prints the consent URL for the human and polls until they respond.
async fn ensure_warrant(
    agent: &mut AgentIdentity,
    audience: &str,
    scopes: Option<Vec<String>>,
) -> Result<(), AgentError> {
    if agent.warrant_for(audience).is_some() {
        return Ok(());
    }
    eprintln!("no warrant for {audience} — requesting consent…");
    agent
        .obtain_warrant(audience, scopes, |handle| {
            eprintln!("\n  ==> approve at: {}\n", handle.verification_uri);
        })
        .await
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        usage();
    }
    let credential_path = &args[0];
    let credential = match AgentCredential::load(credential_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to load {credential_path}: {e}");
            std::process::exit(1);
        }
    };

    let result = run(&args, credential_path, credential).await;
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run(
    args: &[String],
    credential_path: &str,
    credential: AgentCredential,
) -> Result<(), AgentError> {
    let ipath = identity_path(credential_path);
    match args[1].as_str() {
        "provision" => {
            let name = args.get(2).map(String::as_str);
            let agent = load_or_provision(&credential, credential_path, name).await?;
            println!("{}", agent.email());
        }
        "grant" => {
            let audiences: Vec<&str> = args[2..].iter().map(String::as_str).collect();
            if audiences.is_empty() {
                usage();
            }
            let mut agent = load_or_provision(&credential, credential_path, None).await?;
            let grants = audiences
                .iter()
                .map(|a| browserid_core::WarrantGrant { aud: a.to_string(), scopes: None })
                .collect();
            agent
                .obtain_warrants(grants, |handle| {
                    eprintln!("\n  ==> approve at: {}\n", handle.verification_uri);
                })
                .await?;
            agent.save(&ipath)?;
            for a in audiences {
                eprintln!("warrant held for {a}");
            }
        }
        "assert" => {
            let audience = args.get(2).map(String::as_str).unwrap_or_else(|| usage());
            let mut agent = load_or_provision(&credential, credential_path, None).await?;
            ensure_warrant(&mut agent, audience, None).await?;
            let assertion = agent.assertion_for(audience).await?;
            agent.save(&ipath)?;
            println!("{assertion}");
        }
        "token" => {
            let url = args.get(2).map(String::as_str).unwrap_or_else(|| usage());
            let mut agent = load_or_provision(&credential, credential_path, None).await?;
            let challenge = agent.discover_challenge(url).await?;
            let scopes = (!challenge.scopes.is_empty()).then(|| challenge.scopes.clone());
            ensure_warrant(&mut agent, &challenge.audience, scopes).await?;
            let token = agent.exchange_for_token(&challenge).await?;
            agent.save(&ipath)?;
            println!("{}", serde_json::to_string_pretty(&token).unwrap());
        }
        "warrants" => {
            let agent = load_or_provision(&credential, credential_path, None).await?;
            for aud in agent.warranted_audiences() {
                println!("{aud}");
            }
        }
        "revoke" => {
            let agent = load_or_provision(&credential, credential_path, None).await?;
            let email = agent.email().to_string();
            agent.revoke().await?;
            let _ = std::fs::remove_file(&ipath);
            eprintln!("revoked {email}");
        }
        _ => usage(),
    }
    Ok(())
}
