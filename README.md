oauth2-oidc-experiment
======================

Experiment codes to learn OAuth2 and OpenID Connect.


## required packages

Install required packages with pip command.

  * `pip install bottle`
  * `pip install Beaker`
  * `pip install Paste`
  * `pip install pyOpenSSL`

## create your server certificate

With openssl command, create server certificate pem file which contains
both public key and private key. Then place the file in `certs/` directory
with name `server.pem`.

## modify script

Modify following@ parts of `app.py`.

  * line 30: `{{{_YOUR_SERVER_FQDN_}}}`
  * line 42: `{{{_CLIENT_ID_FOR_GOOGLE_}}}`
  * line 43: `{{{__CLIENT_SECRET_FOR_GOOGLE_}}}`
  * line 59: `{{{_CLIENT_ID_FOR_YCONNECT_}}}`
  * line 60: `{{{__CLIENT_SECRET_FOR_YCONNECT_}}}`

## try it !

Run the server with command line `$ python app.py` and access to url
`http://{{{_YOUR_SERVER_FQDN_}}}/app`.

## todo

  * OAuth2 Implicit Flow.
  * OAuth2 Authorization Server.
  * OpenID Connect RP and OP.
  * ...
