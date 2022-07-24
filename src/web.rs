use crate::connection;
use actix_web::{post, web, App, HttpServer, Responder};
use redbpf::Map;
use serde::Deserialize;
use serde_json::json;

#[derive(Clone)]
struct AppState {
    map: Map,
}

#[derive(Deserialize)]
struct Request {
    url: String,
}

#[post("/scanurl")]
async fn scan_url(form: web::Json<Request>, data: web::Data<AppState>) -> impl Responder {
    let url = &form.url;
    let result = connection::connect(url.as_str(), &data.map).await;
    let mut notices: Vec<String> = vec![];
    let mut errors: Vec<String> = vec![];
    let mut warnings: Vec<String> = vec![];
    match result {
        Ok(result) => {
            let result = result.to_printable();
            notices = result.notices;
            warnings = result.warnings;
            errors = result.errors;
        }
        Err(err) => {
            errors.push(err.to_string());
        }
    }
    web::Json(json!({ "notices" : notices, "errors" : errors, "warnings": warnings}))
}

pub async fn web_main(bind_ip: &str, bind_port: u16, map: Map) {
    let state = AppState { map };
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .service(scan_url)
    })
    .bind((bind_ip, bind_port))
    .expect("Failed to bind server to given address")
    .run()
    .await
    .expect("Server failed");
}
