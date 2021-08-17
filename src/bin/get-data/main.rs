use std::env;
use std::vec;
use std::fs::File;
use std::io::Write;
use futures::future;
use tokio::task;
use tokio::task::JoinHandle;
use log::{debug, info, error};
use std::time::Instant;
use env_logger::Env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let env = Env::default()
        .filter_or("LOG_LEVEL", "info")
        .write_style_or("LOG_STYLE", "always");
    env_logger::init_from_env(env);

    let endpoints: Vec<&str> = vec!["identities", "denial", "intrusion", "executable", "misuse", "unauthorized", "probing", "other"];

    let mut tasks: Vec<JoinHandle<Result<(), ureq::Error>>>= vec![];

    for endpoint in endpoints {
        tasks.push(task::spawn(process_endpoint(&endpoint)));
    }

    let before = Instant::now();
    info!("started {} tasks. Waiting...", tasks.len());
    future::join_all(tasks).await;
    info!("finished processing all tasks. took {:.2?}", before.elapsed());

    Ok(())
}

async fn process_endpoint(
    endpoint: &str
) -> Result<(), ureq::Error> {
    let url = match endpoint {
        "identities" => format!("https://incident-api.use1stag.elevatesecurity.io/{}/", &endpoint),
        _ => format!("https://incident-api.use1stag.elevatesecurity.io/incidents/{}/", &endpoint)
    };
    
    let username = env::var("HTTP_USERNAME").unwrap();
    let password = env::var("HTTP_PASSWORD").unwrap();
    let encoded_credentials = format!("Basic {}", base64::encode(format!("{}:{}", username, password)));
    
    let body: String = ureq::get(&url)
        .set("Authorization", &encoded_credentials)
        .call()?
        .into_string()?;
    let filename = format!("data/{}.json", endpoint);
    let mut output_file = File::create(&filename)?;
    match write!(output_file, "{}", body) {
        Ok(_) => debug!("finished writing {}", filename),
        Err(e) => error!("error writing {} {}", filename, e)
    }

    info!("writing {} bytes to {}", body.len(), &filename);            
    Ok(())
}
