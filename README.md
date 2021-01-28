# Custom-JWT-Token-Issuer

Buid the source and copy the 'CustomTokenIssuer-1.0-SNAPSHOT.jar' file to the '<APIM_HOME>/repository/components/lib' directory.

Add the below configurations to '<APIM_HOME>/repository/conf/deployment.toml' file.

```
[[oauth.extensions.token_types]]
name = "JWT"
issuer = "com.wso2.customTokenIssuer.CustomIssuerJWT"
persist_access_token_alias = true
```

Then restart the APIM server and it will have JWT with additional claims of application,tierInfo,keytype,subscribedAPIs and consumerKey.
