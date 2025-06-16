use actix_web::{get, web, App, HttpRequest, HttpServer, HttpResponse, Responder};
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenUrl,
    StandardTokenResponse, EmptyExtraFields,
};
use serde::{Deserialize, Serialize}; // Add Serialize for optional debugging
use std::sync::Arc; // For shared state
use url::Url; // For parsing redirect URL parameters
use futures::lock::Mutex as AsyncMutex; // Use an async-aware Mutex if you need shared mutable state later, though for this initial setup, Arc is often enough.

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Server starting...");

    // 1. Initialize the OAuth client and PKCE verifier
    let client = BasicClient::new(ClientId::new("30_2w53177iozwg48ko8sokkk0sog04wwo48wosswcggk0kwks08o".into()))
        .set_client_secret(ClientSecret::new("zgha7u74vmog8808s8o404s0osoc8kk4ck8os48o048w0cwc".into()))
        .set_redirect_uri(RedirectUrl::new("http://localhost:8080/token".into()).unwrap())
        .set_auth_uri(AuthUrl::new("https://my.centrale-assos.fr/oauth/v2/auth".into()).unwrap())
        .set_token_uri(TokenUrl::new("https://my.centrale-assos.fr/oauth/v2/token".into()).unwrap());

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("scope_users".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    // 2. Store the necessary OAuth values in a shared application state
    // We wrap PkceCodeVerifier and CsrfToken in a Mutex because they are consumed
    // when used for token exchange/verification. If you expect multiple concurrent
    // login flows, you'd need a more sophisticated per-session storage (e.g., Redis).
    // For a simple example where only one flow is expected at a time, or if you
    // restart the server for each login, this is fine.
    // If you only need to store the client (which is immutable), Arc is enough.
    let app_state = Arc::new(AppState {
        oauth_client: client,
        pkce_verifier: AsyncMutex::new(Some(pkce_verifier)), // Option<T> to consume it
        csrf_token: AsyncMutex::new(Some(csrf_token)),       // Option<T> to consume it
    });

    println!("Browse to: {}", auth_url); // Instruct the user to open this URL

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::from(Arc::clone(&app_state))) // Pass the shared state to the app
            .service(token_state)
            .route("/", web::get().to(index_handler)) // Add a simple root handler to demonstrate
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

// Struct to hold the shared application state
struct AppState {
    oauth_client: BasicClient,
    // Use AsyncMutex to protect values that will be consumed or mutated across async tasks.
    // Option<T> allows us to take ownership once they are used.
    pkce_verifier: AsyncMutex<Option<PkceCodeVerifier>>,
    csrf_token: AsyncMutex<Option<CsrfToken>>,
}

// The query parameters from the OAuth redirect
#[derive(Deserialize, Debug)]
struct OAuthCallbackParams {
    code: String,
    state: String,
}

// Simple handler for the root path
async fn index_handler() -> impl Responder {
    HttpResponse::Ok().body("Hello! Please go to the generated OAuth URL to log in.")
}

#[get("/token")]
async fn token_state(
    params: web::Query<OAuthCallbackParams>, // Use the descriptive struct for query params
    data: web::Data<AppState>,              // Access the shared application state
) -> impl Responder {
    println!("Received callback: code = {}, state = {}", params.code, params.state);

    // Take ownership of the CSRF token from the shared state
    let csrf_token_guard = data.csrf_token.lock().await;
    let csrf_token = csrf_token_guard.as_ref(); // Get a reference to the Option<CsrfToken>
    let expected_csrf_token = match csrf_token {
        Some(t) => t.secret(),
        None => {
            eprintln!("Error: CSRF token already consumed or not set.");
            return HttpResponse::InternalServerError().body("Error: CSRF token missing.");
        }
    };

    // IMPORTANT: In a real application, you'd verify `params.state` against the `csrf_token`
    // stored in your session or application state to prevent CSRF attacks.
    // For this example, we'll just print it.
    if params.state != expected_csrf_token {
        eprintln!("CSRF token mismatch! Expected: {}, Got: {}", expected_csrf_token, params.state);
        // You should return an error page or a 403 Forbidden here
        return HttpResponse::Forbidden().body("CSRF token mismatch!");
    } else {
        println!("CSRF token matched!");
    }


    // Take ownership of the PKCE verifier from the shared state
    let pkce_verifier_guard = data.pkce_verifier.lock().await;
    let pkce_verifier = pkce_verifier_guard.as_ref();

    let pkce_verifier = match pkce_verifier {
        Some(verifier) => verifier,
        None => {
            eprintln!("Error: PKCE verifier already consumed or not set.");
            return HttpResponse::InternalServerError().body("Error: PKCE verifier missing.");
        }
    };


    // Exchange the authorization code for an access token
    let token_response = data
        .oauth_client
        .exchange_code(AuthorizationCode::new(params.code.clone()))
        .set_pkce_verifier(pkce_verifier.clone()) // Clone for use in the request
        .request_async(oauth2::reqwest::async_http_client)
        .await;

    match token_response {
        Ok(res) => {
            println!("Token exchange successful!");
            println!("Access Token: {:?}", res.access_token().secret());
            // Optionally, print refresh token if available
            if let Some(refresh_token) = res.refresh_token() {
                println!("Refresh Token: {:?}", refresh_token.secret());
            }
            // Optionally, print ID token if available (e.g., for OpenID Connect)
            if let Some(id_token) = res.id_token() {
                println!("ID Token: {:?}", id_token.claims());
            }

            // Now you have the access token! You can store it, use it to make API calls, etc.
            HttpResponse::Ok().body(format!("Authentication successful! Access Token: {}", res.access_token().secret()))
        }
        Err(e) => {
            eprintln!("Token exchange failed: {:?}", e);
            HttpResponse::InternalServerError().body(format!("Token exchange failed: {:?}", e))
        }
    }
}