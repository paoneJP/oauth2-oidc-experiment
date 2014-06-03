app_config = dict(
    server = dict(
        server='https://{{_YOUR_SERVER_FQDN_}}',
        bind_ip='0.0.0.0',
        bind_port=443,
        use_ssl=True,
        server_cert='certs/server.pem'
    ),
    google_web_application_type = dict(
        client_id='{{_CLIENT_ID_FOR_GOOGLE_WEB_APPLICATION_TYPE_}}',
        client_secret='{{_CLIENT_SECRET_FOR_GOOGLE_WEB_APPLICATION_TYPE_}}'
    ),
    yconnect_server_side_app = dict(
        client_id='{{_CLIENT_ID_FOR_YCONNECT_SERVER_SIDE_APP_}}',
        client_secret='{{_CLIENT_SECRET_FOR_YCONNECT_SERVER_SIDE_APP_}}'
    )
)
