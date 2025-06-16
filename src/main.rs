use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use oauth2::{basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointNotSet, EndpointSet, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse, TokenUrl};
use serde::Deserialize;
use std::sync::{Arc, Mutex};

type FullyconfiguredClient = BasicClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet>;

#[actix_web::main]
async fn main()->std::io::Result<()> {
    println!("Server starting");
    let client = BasicClient::new(ClientId::new("30_2w53177iozwg48ko8sokkk0sog04wwo48wosswcggk0kwks08o".into()))
        .set_client_secret(ClientSecret::new("zgha7u74vmog8808s8o404s0osoc8kk4ck8os48o048w0cwc".into()))
        .set_redirect_uri(RedirectUrl::new("http://localhost:8080/token".into()).unwrap())
        .set_auth_uri(AuthUrl::new("https://my.centrale-assos.fr/oauth/v2/auth".into()).unwrap())
        .set_token_uri(TokenUrl::new("https://my.centrale-assos.fr/oauth/v2/token".into()).unwrap());

    let (pkce_challenge, pkceverifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        // Set the desired scopes.
        .add_scope(Scope::new("scope_users".to_string()))
        // Set the PKCE code challenge.
        .set_pkce_challenge(pkce_challenge)
        .url();

    println!("Browse to: {}", auth_url);

    let app_state = Arc::new(App_State{
        csrftok:csrf_token,
        pkce:Mutex::new(Some(pkceverifier)),
        client:client
    });

    HttpServer::new(move || App::new()
        .service(token_state)
        .app_data(web::Data::from(
            Arc::clone(&app_state)
        )))
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

#[derive(Deserialize)]
struct Token_URL{
    code:String,
    state: String
}

struct App_State{
    csrftok:CsrfToken,
    pkce:Mutex<Option<PkceCodeVerifier>>,
    client: FullyconfiguredClient,
}

#[get("/token")]
async fn token_state(res: web::Query<Token_URL>, data:web::Data<App_State>)->impl Responder{
    if data.csrftok.clone().into_secret() != res.state{
        return HttpResponse::Forbidden().body("CSRF Token mismatched")
    } else {

        let http_client = reqwest::ClientBuilder::new()
            // Following redirects opens the client up to SSRF vulnerabilities.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Client should build");

        let code = AuthorizationCode::new(res.code.clone());
        let mut pkcever = data.pkce.lock().unwrap();
        let pkforever = match pkcever.take() {
            Some(pk) => pk,
            None => {
                return HttpResponse::BadRequest().body("quoicoubeh")
            }
        };
        // Perform the token exchange
        let token_result = data.client
            .exchange_code(code)
            .set_pkce_verifier(pkforever)
            .request_async(&http_client) // Use the async http client
            .await;

        match token_result {
            Ok(token_response) => {
                // You can now access the access token, refresh token, etc.
                // For example: token_response.access_token().secret()
                println!("Access Token: {:?}", token_response.access_token().secret());
                // Handle the token response as needed
                HttpResponse::Ok().body(format!("Successfully exchanged code for token! Access Token (partial): {}", &token_response.access_token().secret()[..10]))
            },
            Err(e) => {
                eprintln!("Error exchanging code: {:?}", e);
                HttpResponse::InternalServerError().body(format!("Failed to exchange code: {:?}", e))
            }
        }
    }
}