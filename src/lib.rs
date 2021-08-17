use serde_with::serde_as;
use serde_json::{Value, Map};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use std::collections::HashMap;
use ordered_float::OrderedFloat;
use itertools::Itertools;

pub struct IdentityMapping {
    pub ip_to_id: HashMap<String, u64>,
    pub id_to_ip: HashMap<u64, String>
}

#[derive(Debug, PartialEq, enum_utils::FromStr)]
#[enumeration(case_insensitive)]
pub enum EndpointType {
    Denial,
    Executable,
    Intrusion,
    Misuse,
    Other,
    Probing,
    Unauthorized
}

#[serde_as]
#[derive(Deserialize, Serialize)]
pub struct Unauthorized {
    pub priority: String,
    pub employee_id: u64,
    #[serde_as(as = "serde_with::TimestampSecondsWithFrac<f64>")]
    pub timestamp: SystemTime,
}

#[serde_as]
#[derive(Deserialize, Serialize)]
pub struct ApiResults {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    pub results: Vec<Map<String, Value>>
}

pub fn to_identity_mappings(data: Map<String, Value>) -> IdentityMapping {
    let mut ip_to_id: HashMap<String, u64> = HashMap::with_capacity(data.len());
    let mut id_to_ip: HashMap<u64, String> = HashMap::with_capacity(data.len());

    for k in data.keys() {
        let employee_id = data.get(k).unwrap().as_u64().unwrap();
        ip_to_id.insert(k.to_string(), employee_id);
        id_to_ip.insert(employee_id, k.to_string());
    }

    IdentityMapping{
        ip_to_id: ip_to_id, 
        id_to_ip: id_to_ip,
    }
}

#[serde_as]
#[derive(Clone, Deserialize, Serialize)]
pub struct IncidentResponse {
    count: u64,
    incidents: Vec<Map<String, Value>>
}

pub fn to_incident_results(
    identity_mapping: IdentityMapping, 
    api_results: HashMap<OrderedFloat<f64>, Map<String, Value>>
) -> HashMap<String, HashMap<String, IncidentResponse>> {
    let mut incident_map: HashMap<String, HashMap<String, IncidentResponse>> = HashMap::new();
    
    for k in api_results.keys().sorted() {
        let incident = api_results.get(k).unwrap();
        let endpoint = incident.get("type").unwrap().as_str().unwrap();

        let id = match endpoint {
            "denial" => incident.get("reported_by").unwrap().as_u64().unwrap(),
            "executable" => identity_mapping.ip_to_id.get(incident.get("machine_ip").unwrap().as_str().unwrap()).unwrap().to_owned(),
            "intrusion" => identity_mapping.ip_to_id.get(incident.get("internal_ip").unwrap().as_str().unwrap()).unwrap().to_owned(),
            "misuse" => incident.get("employee_id").unwrap().as_u64().unwrap(),
            "other" => {
                match incident.get("identifier").unwrap().as_str() {
                    Some(ip) => identity_mapping.ip_to_id.get(ip).unwrap().to_owned(),
                    None => incident.get("identifier").unwrap().as_u64().unwrap()
                }
            },
            "probing" => identity_mapping.ip_to_id.get(incident.get("ip").unwrap().as_str().unwrap()).unwrap().to_owned(),
            "unauthorized" => incident.get("employee_id").unwrap().as_u64().unwrap(),
            _ => u64::MIN
        };

        let id_str = id.to_string();
        if !incident_map.contains_key(&id_str) {
            let levels: HashMap<String, IncidentResponse> = [
                ("low".to_string(), IncidentResponse{
                    count: 0,
                    incidents: vec![]
                }), 
                ("medium".to_string(), IncidentResponse{
                    count: 0,
                    incidents: vec![]
                }), 
                ("high".to_string(), IncidentResponse{
                    count: 0,
                    incidents: vec![]
                }), 
                ("critical".to_string(), IncidentResponse{
                    count: 0,
                    incidents: vec![]
                })
            ].iter().cloned().collect();
            incident_map.insert(id.to_string(), levels);
        }
        let levels = incident_map.get_mut(&id_str).unwrap();
        let level = incident.get("priority").unwrap().as_str().unwrap();
        let ir = levels.get_mut(level).unwrap();
        ir.count += 1;
        let i_str = serde_json::to_string(&incident).unwrap();
        let i2: Map<String, Value> = serde_json::from_str(&i_str).unwrap();
        ir.incidents.push(i2);
    }

    incident_map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_test() {
        assert_eq!("denial".parse(), Ok(EndpointType::Denial));
        assert_eq!("executable".parse(), Ok(EndpointType::Executable));
        assert_eq!("Intrusion".parse(), Ok(EndpointType::Intrusion));
        assert_eq!("misuse".parse(), Ok(EndpointType::Misuse));
        assert_eq!("other".parse(), Ok(EndpointType::Other));
        assert_eq!("probing".parse(), Ok(EndpointType::Probing));
        assert_eq!("unauthorized".parse(), Ok(EndpointType::Unauthorized));
        assert_eq!("something".parse::<EndpointType>(), Err(()));
    }
}
