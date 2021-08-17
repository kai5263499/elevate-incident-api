use serde_json::{Value, Map};
use incident::{IdentityMapping, ApiResults, to_identity_mappings, to_incident_results};
use std::fs::File;
use std::io::BufReader;
use log::{debug, error};
use env_logger::Env;
use std::time::Instant;
use futures::future;
use tokio::task::JoinHandle;
use std::collections::HashMap;
use ordered_float::OrderedFloat;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let env = Env::default()
        .filter_or("LOG_LEVEL", "debug")
        .write_style_or("LOG_STYLE", "always");

    env_logger::init_from_env(env);

    let identity_mapping = load_identities();

    let mut tasks: Vec<JoinHandle<ApiResults>>= vec![];

    let endpoints: Vec<&str> = vec!["denial", "intrusion", "executable", "misuse", "unauthorized", "probing", "other"];
    for endpoint in endpoints {
        tasks.push(tokio::spawn(load_file(&endpoint)));
    }

    let mut before = Instant::now();
    debug!("started {} tasks. Waiting...", tasks.len());
    let futures = future::join_all(tasks).await;
    debug!("finished processing all loading tasks. took {:.2?}", before.elapsed());

    before = Instant::now();
    let mut results: HashMap<OrderedFloat<f64>, Map<String, Value>> = HashMap::new();

    for f in futures {
        match f {
            Ok(r) => {
                let e = r.endpoint.as_ref().unwrap();
                for i in r.results {
                    let i_str = serde_json::to_string(&i).unwrap();
                    let mut i2: Map<String, Value> = serde_json::from_str(&i_str).unwrap();
                    i2.insert("type".to_string(), Value::String(e.to_string()));

                    results.insert(OrderedFloat(i.get("timestamp").unwrap().as_f64().unwrap()), i2);
                }
                
                ()
            },
            Err(_) => error!("future returned an error")
        }
    }

    debug!("populated {} results", results.len());

    let incident_results = to_incident_results(identity_mapping, results);
    debug!("finished processing all tasks. took {:.2?}", before.elapsed());
    debug!("populated {} incident_results", incident_results.len());

    Ok(())
}

fn load_identities() -> IdentityMapping {
    debug!("loading identities");

    let filename = "data/identities.json";
    let contents = BufReader::new(File::open(&filename).unwrap());
    let data: Map<String, Value> = serde_json::from_reader(contents).unwrap();

    debug!("loaded {} identities from {}", data.len(), &filename);    

    to_identity_mappings(data)
}

async fn load_file(endpoint: &str) -> ApiResults {
    let filename = format!("data/{}.json", &endpoint);
    let contents = BufReader::new(File::open(&filename).unwrap());

    let mut results: ApiResults = serde_json::from_reader(contents).unwrap();
    results.endpoint = Some(endpoint.to_string());

    debug!("loaded {} {} from {}", results.results.len(), &endpoint, &filename);

    results
}