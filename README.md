oauth2-oidc-experiment
======================

Experiment codes to learn OAuth2 and OpenID Connect.


## required packages

Install required packages with pip command.

  * `pip install pycrypto`
  * `pip install bottle`
  * `pip install Beaker`
  * `pip install Paste`
  * `pip install pyOpenSSL`

## create your server certificate

With openssl command, create server certificate pem file which contains
both public key and private key. Then place the file in `certs/` directory
with name `server.pem`.

Read [python paste document](http://pythonpaste.org/modules/httpserver.html)
for more datail.


## configure app

Modify `app_config.py`.

  * line 3: `{{_YOUR_SERVER_FQDN_}}`
  * line 10: `{{_CLIENT_ID_FOR_GOOGLE_WEB_APPLICATION_TYPE_}}`
  * line 11: `{{_CLIENT_SECRET_FOR_GOOGLE_WEB_APPLICATION_TYPE_}}`
  * line 14: `{{_CLIENT_ID_FOR_YCONNECT_SERVER_SIDE_APP_}}`
  * line 15: `{{_CLIENT_SECRET_FOR_YCONNECT_SERVER_SIDE_APP_}}`

## try it !

Run the server with command line `$ python app.py` and access to url
`https://{{_YOUR_SERVER_FQDN_}}/`.

## restriction

  * This program is tested in python2.7 environment. 
    This program may not be work with python3 yet.
  * This proguram is not work on windows platform.

## todo

  * Verify IDToken function.
  * OAuth2 Implicit Grant Client.
  * OAuth2 Authorization Server.
  * OpenID Connect Implicit Flow RP.
  * OpenID Connect OP.
  * ...

## changelog

  * release2
    * [new] demo for openid connect authorization code flow client.
    * [new] start web page.
    * [modify] refactoring oauth2py module.
  * first release
    * [new] demo app for oauth2 authorization code grant client.
