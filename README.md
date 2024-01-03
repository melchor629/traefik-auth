# traefik-auth

A small project to protect services using other kind of authentication methods appart from Basic and Digest, to be used with [Forward Auth middleware][forward-auth]. The service allows to configure several authentication providers and use them in authentication pipelines.

## Deploy

Pull image from Docker Hub [`melchor9000/traefik-auth`][docker-hub]. Supported architectures are Intel/AMD 64 and ARM 64.

Use a container runtime to run the service, either docker or podman, or run inside a container orquestrator (like swarm or kubernetes).

See below an example for docker compose:

```yaml
services:
  traefik-auth:
    image: melchor9000/traefik-auth
    restart: on-failure
    networks:
      - traefiknet # shared network with traefik I use internally
    volumes:
      # send config to the container
      - './config.yml:/config/config.yml:ro'
      # volume where to store the generated keys
      - './data:/data'
    # recommended: use a different user to run the service
    user: '1000:1000'
    # recommended: lock the filesystem inside the container
    read_only: true
    # optional: configure service, router and middleware from here
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.traefik-auth.entrypoints=https"
      - "traefik.http.routers.traefik-auth.rule=Host(`example.com`) && Path(`/oauth2/callback`)"
      - "traefik.http.services.traefik-auth.loadbalancer.server.port=8080"
      - "traefik.http.middlewares.traefik-auth.forwardauth.address=http://traefik-auth:8080/auth"
      - "traefik.http.middlewares.traefik-auth.forwardauth.authrequestheaders=Authorization,Cookie"
      - "traefik.http.middlewares.traefik-auth.forwardauth.authresponseheaders=Set-Cookie"

networks:
  # shared network with traefik
  traefiknet:
    external: true
```

## Configure

To configure the app, write a file in `./config/config.{json,yml}` with your own settings. See below for examples:

```yaml
logger:
  level: INFO
  # optional: granular log level configuration
  levels:
    actix_web: INFO
    # if something does not work fine, try putting this into DEBUG
    traefik_auth: INFO

# public url of service (see set-up section for more)
public_url: https://example.com
# optional: path where to store the internal keys
keys_path: '/data/keys'

# authentication providers
providers:
  # providers are identified by this key
  basic-inline:
    # NOTE: format is htpasswd, but only supports bcrypt (the others are insecure)
    basic:
      contents: 'htpasswd file contents here'
  basic-file:
    # NOTE: format is htpasswd, but only supports bcrypt (the others are insecure)
    basic:
      file: '/path/to/htpasswd/file'
    # optional: list of claims to add to the token for the users in this provider
    #           this can help allow users to access several service based on claims
    claims:
      role: admin
  oauth2:
    oauth2:
      client_id: client id
      # optional
      client_secret: client secret
      issuer: https://url.to.issuer
      scopes: [scope1, scope2, scope3, '...']
      # optional: map other claims from the access token to this service's token
      #           can be used to allow access to services based on claims
      map_claims:
        # maps a claim named `oauth_claim` from the OIDC provider to `service_claim` in this service
        oauth_claim: service_claim
        # maps email to email :)
        email: email

# authentication pipelines (rules run sequentially)
pipelines:
  # optional: rules apply using && (and) operator
  # leave empty to always apply this pipeline
  - rules:
      - http_host: host
      - http_path: /whole/path
      - http_path_prefix: /path/prefix
      - http_method: [get, post]
      - http_protocol: https
      # run rules using || (or) operator
      - or:
          - http_host: host
          - '...'
      # run rules using && (and) operator
      - and:
          - http_host: host
          - '...'
    # optional: allow access to users that matches the following claims
    claims:
      # optional: usernames that will be allowed to access (checks `sub` claim in OAuth2)
      sub: [a, b, c]
      # optional: other values will be checked against the claims stored in the service token
      role: admin
      service_claim: example
    providers: [basic-inline, basic-file, oauth2]
    # optional: customize login cookie
    cookie:
      # optional: in some cases, the cookie does not make sense to be created, this will prevent creation
      ignore: false
      # optional: change cookie domain (by default uses the one provided by traefik)
      domain: '...'
  # this will work as default pipeline
  -  providers: [oauth2]
```

## Setup

This service requires at least one route to be publicly available **if** using OAuth2: `/oauth2/callback`. If using it, then publish this path in traefik and ensure the public url points to the root of the exposed service.

Example exposing using yaml config and docker compose labels:

``` yaml
# yaml config
http:
  routers:
    traefik-auth:
      entryPoints: [https]
      middlewares: [login]
      service: traefik-auth
      rule: Host(`example.com`) && PathPrefix(`/`)
  services:
    traefik-auth:
      loadBalancer:
        servers:
          - url: http://localhost:8080

# compose labels
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.traefik-auth.entrypoints=https"
  - "traefik.http.routers.traefik-auth.rule=Host(`example.com`) && Path(`/oauth2/callback`)"
  - "traefik.http.services.traefik-auth.loadbalancer.server.port=8080"
```

Then, configure a middleware to be used in the services to protect:

```yaml
# yaml config
http:
  middlewares:
    login:
      forwardAuth:
        address: http://localhost:8080/auth
        authRequestHeaders: [Authorization, Cookie]
        authResponseHeaders: [Set-Cookie]

# compose labels
labels:
  - "traefik.http.middlewares.traefik-auth.forwardauth.address=http://traefik-auth:8080/auth"
  - "traefik.http.middlewares.traefik-auth.forwardauth.authrequestheaders=Authorization,Cookie"
  - "traefik.http.middlewares.traefik-auth.forwardauth.authresponseheaders=Set-Cookie"
```

And then you are ready to use the middleware in your services :)

## OAuth2: Examples

### Google

```yaml
providers:
  - oauth2:
      client_id: <GOOGLE_CLIENT_ID>
      client_secret: <GOOGLE_CLIENT_SECRET>
      issuer: https://accounts.google.com
      scopes:
        - https://www.googleapis.com/auth/plus.me
```

  [forward-auth]: https://doc.traefik.io/traefik/middlewares/http/forwardauth/
  [docker-hub]: https://hub.docker.com/repository/docker/melchor9000/traefik-auth
