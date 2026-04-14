# auth_saml
EliteA auth: SAML backend

## Hint

Export Certificates and Private Key from a PKCS#12 File with OpenSSL.

https://www.ssl.com/how-to/export-certificates-private-key-from-pkcs12-file-with-openssl/

1. You need to run this command to get a file with cert data:

   `openssl pkcs12 -in keystore.p12 -out OUTFILE.crt -nodes`

   After that you can copy cert data without header and pass it to sp_cert in the config

2. You need to run this command to get a file with private key data:

   `openssl pkcs12 -in keystore.p12 -out OUTFILE.key -nodes -nocerts`

   After that you can copy your private key without header (second one from the list) and pass it to sp_key in the config.
