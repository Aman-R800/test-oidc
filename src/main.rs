use std::collections::HashMap;

use actix_web::{get, http::header, middleware::Identity, post, web, App, HttpResponse, HttpServer, Responder};
use jsonwebtoken::{jwk::Jwk, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use base64;


#[derive(Deserialize)]
struct Authorization{
    code: String
}

#[derive(Deserialize)]
struct TokenData{
    access_token: String,
    id_token: String,
    scope: String,
    expires_in: u64,
    token_type: String
}

#[derive(Deserialize, Debug)]
struct IdentityClaims{
    given_name: String,
    family_name: String,
    nickname: String,
    name: String,
    picture: String,
    updated_at: String,
    email: String,
    email_verified: bool,
    sub: String
}

#[post("/auth")]
async fn auth_code(auth: web::Json<Authorization>) -> HttpResponse{
    let client = reqwest::Client::new();
    let url = "https://dev-g4v4xush624yyr7l.us.auth0.com/oauth/token/";

    let mut params = HashMap::new();
    params.insert("grant_type", "authorization_code");
    params.insert("client_id", "-------");
    params.insert("client_secret", "-----");
    params.insert("redirect_uri", "http://localhost:8000/redirect.html");
    params.insert("code", &auth.code);

    let token_data: TokenData;
    match client.post(url).form(&params).send().await{
        Ok(resp) => {
            token_data = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
            println!("{}", token_data.id_token)
        },
            Err(e) => {println!("Error: {:#?}", e)}
    }

    HttpResponse::Ok().body("Ok")
}

#[actix_web::main]
async fn main() -> std::io::Result<()>{
    HttpServer::new(|| { 
        App::new()
            .service(auth_code)
    })
    .bind(("localhost", 8080))?
    .run()
    .await
}
