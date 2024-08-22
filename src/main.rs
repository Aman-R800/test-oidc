use std::collections::HashMap;

use actix_web::{cookie::{time::Duration, CookieBuilder, SameSite}, post, web, App, HttpResponse, HttpServer};
use alcoholic_jwt::{token_kid, Validation, JWKS};
use serde::Deserialize;


#[derive(Deserialize)]
struct Authorization{
    code: String
}

#[derive(Deserialize)]
struct TokenData{
    access_token: String,
    id_token: String,
    _scope: String,
    _expires_in: u64,
    _token_type: String
}


async fn jwks_fetching_function(url: &str) -> JWKS{
    let body = reqwest::get(url).await.unwrap().text().await.unwrap();
    return serde_json::from_str::<JWKS>(&body).unwrap();
}

#[post("/auth")]
async fn auth_code(auth: web::Json<Authorization>) -> HttpResponse{
    let client = reqwest::Client::new();
    let url = "https://dev-g4v4xush624yyr7l.us.auth0.com/oauth/token/";

    let mut params = HashMap::new();
    params.insert("grant_type", "authorization_code");
    params.insert("client_id", "------");
    params.insert("client_secret", "------");
    params.insert("redirect_uri", "http://localhost:8000/redirect.html");
    params.insert("code", &auth.code);

    let token_data: TokenData;
    match client.post(url).form(&params).send().await{
        Ok(resp) => {
            token_data = serde_json::from_str(&resp.text().await.unwrap()).unwrap();

            let jwks: JWKS = jwks_fetching_function("https://dev-g4v4xush624yyr7l.us.auth0.com/.well-known/jwks.json").await;
            let validations = vec![
                Validation::Issuer("https://dev-g4v4xush624yyr7l.us.auth0.com/".into()),
                Validation::Audience("vgz6FLZvvBBlQ4AdGS1arjZHPIm9RIii".into())
            ];

            let kid = token_kid(&token_data.id_token)
                .expect("Failed to decode token headers")
                .expect("No 'kid' claim present in token");

            let jwk = jwks.find(&kid).expect("Specified Key Not Found");
            alcoholic_jwt::validate(&token_data.id_token, jwk, validations).unwrap();

            let access_token_cookie = CookieBuilder::new("access_token", token_data.access_token)
                .http_only(true)
                .secure(true)
                .same_site(SameSite::Strict)
                .max_age(Duration::hours(24))
                .finish();

            let id_token_cookie = CookieBuilder::new("id_token", token_data.id_token)
                .http_only(true)
                .secure(true)
                .same_site(SameSite::Strict)
                .max_age(Duration::hours(24))
                .finish();

            return HttpResponse::Ok()
                    .cookie(access_token_cookie)
                    .cookie(id_token_cookie)
                    .body("Logged in successfully!")
        },

        Err(_e) => {
            return HttpResponse::Unauthorized().body("Exchange failed")   
        }
    }
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
