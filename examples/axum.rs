#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let app = axum::Router::new()
        .route("/auth/azure/callback", axum::routing::post(callback))
        .layer(tower_azuread_oidc::AzureADOIDCLayer::<UserInfo>::new(
            // Tenant ID
            "ad6b103d-0ff9-428d-b3e2-3c9c389c74a7".to_owned(),
            // Client ID
            "53b4dd83-2549-48f3-b4ea-447916b6c7e1".to_owned(),
            // Callback URL
            "http://localhost:3000/auth/azure/callback".to_owned(),
        ));

    if let Some(l) = listenfd::ListenFd::from_env().take_tcp_listener(0)? {
        axum::Server::from_tcp(l)?
    } else {
        axum::Server::bind(&std::net::SocketAddr::from(([127, 0, 0, 1], 3000)))
    }
    .serve(app.into_make_service())
    .await?;
    Ok(())
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
// Define user information you want in ID token.
// See also:
//   - https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens
//   - https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-optional-claims
pub struct UserInfo {
    pub sub: String,
    pub nonce: String,
    pub name: String,
    pub preferred_username: String,
    pub groups: Option<Vec<String>>,
    #[serde(flatten)]
    pub rest: serde_json::Value,
}

async fn callback(
    data: axum::extract::Extension<tower_azuread_oidc::Callback<UserInfo>>,
) -> String {
    match data.as_ref() {
        tower_azuread_oidc::CallbackData::Ok(ref user_info) => {
            format!("{}", serde_json::to_string_pretty(&user_info).unwrap())
        }
        tower_azuread_oidc::CallbackData::Err(ref e) => {
            format!("{:?}", e)
        }
    }
}
