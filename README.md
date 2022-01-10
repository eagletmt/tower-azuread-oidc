# tower-azuread-oidc
Tower layer for handling Azure ActiveDirectory OIDC

## Usage
See [examples/axum.rs](examples/axum.rs).

```
% cargo run --example axum
```

The example app shows how Azure AD OIDC works.

1. Open http://localhost:3000/auth/azure
2. Redirected to Azure AD
    - This redirection is fully handled in the Tower layer. You don't need to add handler for this path.
3. Redirected to http://localhost:3000/auth/azure/callback
    - The Tower layer decodes ID token returned from Azure AD.
    - You can access the decoded result via request extensions.
