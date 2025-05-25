#[tokio::main]
async fn main() {
    println!("Hello, world!");
    oauth().await;
}

use oauth2::{basic::BasicClient, http::Error, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl, Scope, TokenUrl};

async fn oauth(){
    let client = BasicClient::new(ClientId::new("30_2w53177iozwg48ko8sokkk0sog04wwo48wosswcggk0kwks08o".into()))
        .set_client_secret(ClientSecret::new("zgha7u74vmog8808s8o404s0osoc8kk4ck8os48o048w0cwc".into()))
        .set_redirect_uri(RedirectUrl::new("http://localhost:3000".into()).unwrap())
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

    // Once the user has been redirected to the redirect URL, you'll have access to the
    // authorization code. For security reasons, your code should verify that the `state`
    // parameter returned by the server matches `csrf_token`.

    let http_client = reqwest::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Client should build");

    // Now you can trade it for an access token.
    let token_result = client
        .exchange_code(AuthorizationCode::new("some authorization code".to_string()))
        // Set the PKCE code verifier.
        .set_pkce_verifier(pkceverifier)
        .request_async(&http_client)
        .await.unwrap();
    
}   

