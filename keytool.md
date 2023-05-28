To achieve the equivalent functionality using the `keytool` command-line tool, you can follow these
steps:

1. Generate the private key and the self-signed certificate for the root authority:

```
keytool -genkeypair -alias myRootCertificate -keyalg RSA -keysize 2048 -keystore myStore.pkcs12 -storetype PKCS12 -storepass password -validity 365 -ext bc=ca:true
```

2. Export the root certificate to a separate file (optional):

```
keytool -exportcert -alias myRootCertificate -keystore myStore.pkcs12 -storetype PKCS12 -storepass password -rfc -file root.crt
```

Note: The exported certificate (`root.crt`) can be used for certificate distribution or to import
into trust stores.

3. Verify the contents of the generated keystore (optional):

```
keytool -list -keystore myStore.pkcs12 -storetype PKCS12 -storepass password
```

The above commands will perform the same actions as the Java code provided, generating a PKCS12
keystore (`myStore.pkcs12`) with a root certificate and a corresponding private key.