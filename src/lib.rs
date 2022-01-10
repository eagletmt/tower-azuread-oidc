#[derive(Debug)]
pub struct AzureADOIDCLayer<T> {
    tenant_id: std::sync::Arc<String>,
    client_id: std::sync::Arc<String>,
    callback_url: std::sync::Arc<String>,
    phantom: std::marker::PhantomData<T>,
}

impl<T> AzureADOIDCLayer<T> {
    pub fn new(tenant_id: String, client_id: String, callback_url: String) -> Self {
        Self {
            tenant_id: std::sync::Arc::new(tenant_id),
            client_id: std::sync::Arc::new(client_id),
            callback_url: std::sync::Arc::new(callback_url),
            phantom: std::marker::PhantomData,
        }
    }
}

impl<S, T> tower::Layer<S> for AzureADOIDCLayer<T> {
    type Service = AzureADOIDC<S, T>;

    fn layer(&self, service: S) -> Self::Service {
        AzureADOIDC {
            inner: service,
            tenant_id: self.tenant_id.clone(),
            client_id: self.client_id.clone(),
            callback_url: self.callback_url.clone(),
            phantom: std::marker::PhantomData,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AzureADOIDC<S, T> {
    inner: S,
    tenant_id: std::sync::Arc<String>,
    client_id: std::sync::Arc<String>,
    callback_url: std::sync::Arc<String>,
    phantom: std::marker::PhantomData<T>,
}
impl<S, T, ReqBody, ResBody> tower::Service<http::Request<ReqBody>> for AzureADOIDC<S, T>
where
    S: tower::Service<http::Request<AzureADOIDCBody<ReqBody>>, Response = http::Response<ResBody>>
        + Clone
        + Send
        + 'static,
    S::Future: Send,
    T: serde::de::DeserializeOwned + Send + Sync + 'static,
    ReqBody: http_body::Body + Send + 'static,
    ReqBody::Data: Send,
{
    type Response = http::Response<AzureADOIDCBody<ResBody>>;
    type Error = S::Error;
    type Future = futures_util::future::BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<ReqBody>) -> Self::Future {
        let clone = self.inner.clone();
        // https://github.com/tower-rs/tower/issues/547
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let tenant_id = self.tenant_id.clone();
        let client_id = self.client_id.clone();
        let callback_url = self.callback_url.clone();

        Box::pin(async move {
            // TODO: Make routes customizable
            if req.method() == http::Method::GET && req.uri().path() == "/auth/azure" {
                Ok(authorize(&tenant_id, &client_id, &callback_url).await)
            } else if req.method() == http::Method::POST
                && req.uri().path() == "/auth/azure/callback"
            {
                let (mut parts, body) = req.into_parts();
                let data = handle_callback::<_, T>(body, &tenant_id, &client_id).await;
                parts.extensions.insert(std::sync::Arc::new(data));
                let req = http::Request::from_parts(
                    parts,
                    AzureADOIDCBody {
                        inner: BodyInner::Empty {
                            empty: http_body::Empty::new(),
                        },
                    },
                );
                let res = inner.call(req).await?;
                Ok(res.map(|b| AzureADOIDCBody {
                    inner: BodyInner::Inner { inner: b },
                }))
            } else {
                let req = req.map(|body| AzureADOIDCBody {
                    inner: BodyInner::Inner { inner: body },
                });
                let res = inner.call(req).await?;
                Ok(res.map(|b| AzureADOIDCBody {
                    inner: BodyInner::Inner { inner: b },
                }))
            }
        })
    }
}

async fn authorize<B>(
    tenant_id: &str,
    client_id: &str,
    callback_url: &str,
) -> http::Response<AzureADOIDCBody<B>> {
    let nonce = uuid::Uuid::new_v4().to_hyphenated().to_string();
    let mut u = url::Url::parse("https://login.microsoftonline.com").unwrap();
    u.path_segments_mut()
        .unwrap()
        .push(tenant_id)
        .push("oauth2")
        .push("v2.0")
        .push("authorize");
    u.query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("response_type", "id_token")
        .append_pair("redirect_url", callback_url)
        .append_pair("response_mode", "form_post")
        // TODO: Make scope customizable
        .append_pair("scope", "openid profile")
        .append_pair("nonce", &nonce);
    http::Response::builder()
        .status(http::StatusCode::FOUND)
        .header(http::header::LOCATION, u.as_str())
        .body(AzureADOIDCBody {
            inner: BodyInner::Empty {
                empty: http_body::Empty::new(),
            },
        })
        .unwrap()
}

#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
enum Form {
    Ok(FormData),
    Err(CallbackError),
}

#[derive(Debug, serde::Deserialize)]
struct FormData {
    id_token: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct CallbackError {
    pub error: String,
    pub error_description: String,
}

#[derive(Debug)]
pub enum CallbackData<T> {
    Ok(T),
    Err(CallbackError),
}

pub type Callback<T> = std::sync::Arc<CallbackData<T>>;

#[derive(Debug, serde::Deserialize)]
pub struct UserInfo {}

#[derive(Debug, serde::Deserialize)]
struct OpenidConfiguration {
    issuer: String,
    jwks_uri: String,
}

#[derive(Debug, serde::Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}
#[derive(Debug, serde::Deserialize)]
struct Jwk {
    e: String,
    kid: String,
    n: String,
}

async fn handle_callback<B, T>(body: B, tenant_id: &str, client_id: &str) -> CallbackData<T>
where
    B: http_body::Body,
    B::Data: Send,
    T: serde::de::DeserializeOwned,
{
    // TODO: Handle errors
    // TODO: Cache OpenidConfiguration

    let body = hyper::body::to_bytes(body)
        .await
        .map_err(|_| "failed to read body".to_owned())
        .unwrap();
    let form: Form = serde_urlencoded::from_bytes(&body).unwrap();
    let form_data = match form {
        Form::Ok(d) => d,
        Form::Err(e) => return CallbackData::Err(e),
    };

    let header = jsonwebtoken::decode_header(&form_data.id_token).unwrap();
    tracing::info!(?header);
    let kid = header.kid.unwrap();

    let client = reqwest::Client::new();
    let config_uri = format!(
        "https://login.microsoftonline.com/{}/v2.0/.well-known/openid-configuration",
        tenant_id
    );
    tracing::info!(%config_uri);
    let config: OpenidConfiguration = client
        .get(config_uri)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    tracing::info!(?config);
    let jwks: Jwks = client
        .get(&config.jwks_uri)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let jwk = jwks.keys.into_iter().find(|k| k.kid == kid).unwrap();
    tracing::info!(?jwk);
    let key = jsonwebtoken::DecodingKey::from_rsa_components(&jwk.n, &jwk.e);
    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.set_audience(&[client_id]);
    validation.validate_nbf = true;
    validation.iss = Some(config.issuer);
    let jwt: jsonwebtoken::TokenData<T> =
        jsonwebtoken::decode(&form_data.id_token, &key, &validation).unwrap();
    // FIXME: nonce should be verified. but how?
    CallbackData::Ok(jwt.claims)
}

pin_project_lite::pin_project! {
    pub struct AzureADOIDCBody<B> {
        #[pin]
        inner: BodyInner<B>,
    }
}
pin_project_lite::pin_project! {
    #[project = BodyInnerProj]
    enum BodyInner<B> {
        Inner {
            #[pin]
            inner: B,
        },
        Empty {
            #[pin]
            empty: http_body::Empty<bytes::Bytes>,
        },
    }
}

impl<B> http_body::Body for AzureADOIDCBody<B>
where
    B: http_body::Body,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    type Data = bytes::Bytes;
    type Error = tower::BoxError;

    fn poll_data(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Self::Data, Self::Error>>> {
        match self.project().inner.project() {
            BodyInnerProj::Inner { inner } => match futures_util::ready!(inner.poll_data(cx)) {
                Some(Ok(mut buf)) => {
                    use bytes::Buf as _;
                    std::task::Poll::Ready(Some(Ok(buf.copy_to_bytes(buf.remaining()))))
                }
                Some(Err(e)) => std::task::Poll::Ready(Some(Err(e.into()))),
                None => std::task::Poll::Ready(None),
            },
            BodyInnerProj::Empty { empty } => empty.poll_data(cx).map_err(Into::into),
        }
    }

    fn poll_trailers(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<Option<http::HeaderMap>, Self::Error>> {
        match self.project().inner.project() {
            BodyInnerProj::Inner { inner } => inner.poll_trailers(cx).map_err(Into::into),
            BodyInnerProj::Empty { empty } => empty.poll_trailers(cx).map_err(Into::into),
        }
    }
}
