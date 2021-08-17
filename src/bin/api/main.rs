use std::env;
use log::{debug, error};
use env_logger::Env;
use tokio::task;
use tokio::task::JoinHandle;
use futures::future;
use std::time::Instant;
use serde_json::{Value, Map};
use incident::{IdentityMapping, ApiResults, to_identity_mappings, to_incident_results};
use actix_web::{web, App, HttpRequest, HttpServer, Responder};
use std::collections::HashMap;
use ordered_float::OrderedFloat;
use std::str;

async fn greet(req: HttpRequest) -> impl Responder {
    let name = req.match_info().get("name").unwrap_or("World");
    format!("Hello {}!", &name)
}

#[actix_web::main()]
async fn main() -> std::io::Result<()> {
  let env = Env::default()
        .filter_or("LOG_LEVEL", "debug")
        .write_style_or("LOG_STYLE", "always");

    env_logger::init_from_env(env);

    HttpServer::new(move || {
        App::new()
            .route("/", web::get().to(process_endpoints))
            .route("/{name}", web::get().to(greet))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await?;
    
    Ok(())
}

async fn process_endpoints(_req: HttpRequest) -> impl Responder {
  let endpoints: Vec<&str> = vec!["denial", "intrusion", "executable", "misuse", "unauthorized", "probing", "other"];

    let mut tasks: Vec<JoinHandle<Result<ApiResults, reqwest::Error>>>= vec![];

    for endpoint in endpoints {
        tasks.push(task::spawn(process_incidents_endpoint(&endpoint)));
    }

    debug!("loading identities");

    let future_contents = process_identities_endpoint().await;
    let identity_mapping = match future_contents {
      Ok(c) => c,
      Err(_) => {
        error!("error retrieving identities");
        IdentityMapping{
          id_to_ip: HashMap::new(),
          ip_to_id: HashMap::new()
        }
      }
    };

    let mut before = Instant::now();
    debug!("started {} tasks. Waiting...", tasks.len());
    let futures = future::join_all(tasks).await;
    debug!("finished processing all tasks. took {:.2?}", before.elapsed());

    before = Instant::now();
    let mut results: HashMap<OrderedFloat<f64>, Map<String, Value>> = HashMap::new();

    for f in futures {
        match f {
            Ok(future_result) => {
              match future_result {
                Ok(api_result) => {
                  let e = api_result.endpoint.as_ref().unwrap();
                  for i in api_result.results {
                      let i_str = serde_json::to_string(&i).unwrap();
                      let mut i2: Map<String, Value> = serde_json::from_str(&i_str).unwrap();
                      i2.insert("type".to_string(), Value::String(e.to_string()));
                      results.insert(OrderedFloat(i.get("timestamp").unwrap().as_f64().unwrap()), i2);
                  }
                
                ()
                },
                Err(_) => error!("future_result returned an error")
              }
            },
            Err(_) => error!("future returned an error")
        }
    }

    debug!("populated {} results", results.len());

    let incident_results = to_incident_results(identity_mapping, results);
    debug!("finished processing all tasks. took {:.2?}", before.elapsed());
    debug!("populated {} incident_results", incident_results.len());

  serde_json::to_string(&incident_results).unwrap()
}

async fn process_identities_endpoint() -> Result<IdentityMapping, reqwest::Error> {
  let url = "https://incident-api.use1stag.elevatesecurity.io/identities/";

  let username = env::var("HTTP_USERNAME").unwrap();
  let password = env::var("HTTP_PASSWORD").unwrap();
  
  let client = reqwest::Client::new();
  let body = client.get(url)
      .basic_auth(username, Some(&password))
      .send()
      .await?
      .text()
      .await?;

  debug!("returning {} bytes from identities endpoint", body.len());

  let data: Map<String, Value> = serde_json::from_str(&body).unwrap();

  debug!("loaded {} identities", data.len());    

  Ok(to_identity_mappings(data))
}

async fn process_incidents_endpoint(
  endpoint: &str
) -> Result<ApiResults, reqwest::Error> {
  let url = format!("https://incident-api.use1stag.elevatesecurity.io/incidents/{}/", &endpoint);
  
  let username = env::var("HTTP_USERNAME").unwrap();
  let password = env::var("HTTP_PASSWORD").unwrap();
  
  let client = reqwest::Client::new();
  let body = client.get(url)
      .basic_auth(username, Some(&password))
      .send()
      .await?
      .text()
      .await?;

  debug!("returning {} bytes from {}", body.len(), endpoint);

  let mut results: ApiResults = serde_json::from_str(&body).unwrap();
  results.endpoint = Some(endpoint.to_string());

  Ok(results)
}
