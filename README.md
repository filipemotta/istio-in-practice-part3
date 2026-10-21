# istio-in-practice-part3

Companion repository for *Istio, Hands-On, Part 3*: who may call whom in the
mesh, proved by being refused.

The story continues on the payments platform of Parts 1 and 2. `payments-api`
calls `fraud-check`, which calls `risk-score`; an old batch job outside the
mesh still calls `fraud-check` directly. An audit asks who can call
`payments-api` and its dependencies, and "the mesh has mTLS" is not an answer:
by default Istio accepts plain text, an AuthorizationPolicy only protects what
it names, and a JWT policy without an authorization rule accepts requests with
no token at all. Everything here runs on a local `kind` cluster, at zero cost,
with assertions that count what actually happened: HTTP codes, curl exit codes,
error strings, access log fields, Envoy stats, Prometheus series, Kiali edges
and certificate fields.

The hardening sequence, one script per step:

1. where a workload identity comes from (SPIFFE certificate, istiod CA, 24h lifetime);
2. inventory plain-text callers, then switch a namespace to STRICT mTLS;
3. deny by default, then open each path by principal, method and path;
4. require an end-user JWT at the ingress gateway;
5. TLS at both edges: HTTPS on the gateway, TLS origination to an external API;
6. the same controls in ambient mode, where ztunnel enforces L4 and the waypoint L7.

## Pinned versions

| Component | Version |
|---|---|
| Istio | 1.31.2, `ambient` profile (istiod + istio-cni + ztunnel); no mTLS setting (mesh default PERMISSIVE) |
| Gateway API CRDs | v1.6.0, standard channel (`standard-install.yaml`) |
| Observability addons | `samples/addons` of Istio 1.31.2: Prometheus v3.10.0, Kiali v2.31 |
| kind | v0.32.0 (node image `kindest/node:v1.36.1`, pinned by digest) |
| kubectl | v1.36.1 (downloaded into `./bin`) |
| yq | v4.54.1 (mikefarah/yq, downloaded into `./bin`, SHA-256 checked) |
| promtool | 3.10.0 (downloaded into `./bin`, SHA-256 checked; same version as the addon Prometheus) |
| Demo images | `fortio/fortio:1.75.3` (fraud-check, risk-score, payments-api server), `curlimages/curl:8.22.0` (payments-api client, legacy job) |

## Prerequisites

- Docker with about 4 CPUs and 6 GB available (Docker Desktop, Colima or Linux).
- `kind` v0.32.0, `jq`, `curl`, `tar`, `openssl`; `shellcheck` and `kubeconform` for `validate.sh`.
- macOS or Linux, arm64 or amd64, with Internet access: images, release
  manifests, and step 06 sends two requests to `http://api.github.com/zen`
  from inside the cluster.
- `istioctl`, `kubectl`, `yq` and `promtool` are downloaded by `tools/install-cli.sh`
  into `./bin`. Every script passes `--context kind-istio-p3` and refuses to run
  if that context does not point at a local kind API server: the lab never uses
  your current kubectl context. `mtls/plaintext-inventory.sh` is read-only and
  has no guard on purpose, so you can point it at your own cluster: it always
  passes `--context` (default `kind-istio-p3`), never your current context.

## The workloads

- **payments-api** (`payments`, ServiceAccount `payments-api`): its `app`
  container is curl, standing in for the service code that makes outbound
  calls; its `load` container is a fortio echo server on 9080, the backend of
  the ingress Gateway (Service port 8080 -> container port 9080).
- **fraud-check** (2 replicas, ServiceAccount `fraud-check`): fortio echo
  server on 8080. With `-loglevel Verbose` it logs one JSON line per request,
  headers included, which is how the lab counts the requests that reached it
  and reads `x-forwarded-client-cert`. Port 8090 is fraud-check calling
  `risk-score` with its own identity (fortio's `-M` proxy).
- **risk-score** (ServiceAccount `risk-score`): fortio echo server.
- **legacy/settlement-batch**: a curl pod in a namespace with no sidecar
  injection: no proxy, no certificate, no identity.
- **payments-ambient**: the same three workloads in ambient mode, plus a
  waypoint that the namespace only starts using in step 07.
- **payments-ingress/payments-gateway**: a Gateway API Gateway
  (`gatewayClassName: istio`) for `api.payments.example`; istiod deploys it as
  `payments-gateway-istio` with a ClusterIP Service (kind has no load balancer).
- **ledger** (step 03 only): a copy of risk-score whose pod opts out of the
  probe rewrite.

## Layout

```
tools/install-cli.sh            pinned istioctl, kubectl, yq and promtool into ./bin
tools/gen-ambient-apps.sh       regenerates apps/payments-ambient.yaml from the sidecar one
tools/gen-jwt.sh                local JWT issuer with openssl: RSA key, JWKS, valid/expired/
                                wrong-issuer/forged tokens (out/jwt, gitignored)
tools/gen-tls-cert.sh           private CA + certificate for api.payments.example (out/tls, gitignored)
kind/cluster.yaml               1 control plane + 2 workers
istio/install.yaml              IstioOperator: ambient profile, access logs; no PeerAuthentication
apps/                           the workloads above (sidecar, ambient, legacy, probe opt-out)
mtls/peer-authentication-strict.yaml   STRICT for the payments namespace
mtls/fraud-check-port-exception.yaml   portLevelMtls: STRICT except container port 8090
mtls/plaintext-inventory.sh     Prometheus inventory of plain-text callers; exits 1 if any, 2 on an empty window (gate before STRICT)
authz/00-allow-nothing.yaml     deny by default for the namespace (spec: {})
authz/10..12                    ALLOW by principal + method + path (fraud-check, risk-score, payments-api from the gateway)
authz/20-fraud-check-deny-export.yaml   explicit DENY that wins over the ALLOWs
authz/30-fraud-check-audit.yaml AUDIT on POST
authz/40-fraud-check-deny-post-dry-run.yaml   DENY under the istio.io/dry-run annotation
authz/41-fraud-check-keep-client-protocol.yaml   DestinationRule (useClientProtocol) that keeps HTTP/2 between
                                the sidecars, for the method-case check of GHSA-w44g-8m76-8gc5
authz/90-deny-all-emergency.yaml        the real deny-all (action DENY, rules: [{}])
ingress/                        Gateway (HTTP, then HTTP + HTTPS) and HTTPRoute to payments-api
jwt/                            RequestAuthentication (JWKS injected at apply time) and the policy that requires a token
egress/                         TLS origination to api.github.com (ServiceEntry + DestinationRule),
                                and a probe that proves the sidecar verifies the server certificate
ambient/                        waypoint, L4 policy on ztunnel, L7 policy on the waypoint, ztunnel admits only the waypoint
silent-errors/                  manifests the API server accepts and that do less than they seem to
observability/alerts.yaml       Prometheus alerting rules: plain text inbound, RBAC denials, dry-run would deny
observability/alerts_test.yaml  promtool unit tests for those rules
scripts/01-cluster.sh .. 07-ambient.sh   one step of the article each, with assertions
scripts/test-all.sh             runs the offline tests in ci/, then 01..07; non-zero exit on any failure
scripts/teardown.sh             deletes the kind cluster and the generated keys
ci/security-lint.sh             offline checks for CI (istioctl analyze + static checks)
ci/test-security-lint.sh        tests for the lint: working sets pass, silent errors fail with their own message
ci/testdata/                    extra lint fixtures
ci/test-alerts.sh               promtool check + unit tests of the alert rules, and mutants they must reject
ci/test-tools.sh                offline tests of the JWT and certificate generators and of the inventory exit codes
ci/test-context-guard.sh        every lab step refuses a context that is not a local kind cluster
.github/workflows/security-lint.yml   GitHub Actions example running the offline tests
validate.sh                     static checks: bash -n, shellcheck, kubeconform
```

## Running

```bash
bash tools/install-cli.sh        # optional, the scripts call it
bash scripts/test-all.sh         # offline tests first, then steps 01..07; about 34 minutes from no cluster
```

Or one step at a time, in the order of the article:

```bash
bash scripts/01-cluster.sh       # kind, Gateway API CRDs, Istio, addons, workloads
bash scripts/02-identity.sh      # certificates: SPIFFE URI, lifetime, root CA (read-only)
bash scripts/03-mtls.sh          # PERMISSIVE -> inventory -> STRICT, probes, port exception
bash scripts/04-authz.sh         # deny by default, ALLOW by principal/method/path, DENY, AUDIT, dry run
bash scripts/05-jwt.sh           # Gateway + RequestAuthentication + requestPrincipals
bash scripts/06-tls-edges.sh     # HTTPS listener, TLS origination to api.github.com
bash scripts/07-ambient.sh       # ztunnel L4, L7 on ztunnel (fails safe), waypoint L7
```

Steps 02 to 07 can be re-run on their own: each one starts by removing the
policies of the namespaces it uses. Step 05 re-applies the end state of step 04.

## What the steps check

Every check is an assertion with an expected value; a step exits non-zero if
any fails. In short:

- **01-cluster**: istiod, one ztunnel per node, the addons and the alert rules
  are up; no PeerAuthentication or AuthorizationPolicy exists; `istioctl
  proxy-status` lists every proxy on the pinned version without `--insecure`,
  and a wrong `--authority` fails the TLS handshake with istiod (istioctl
  verifies istiod's certificate on XDS since 1.31.2).
- **02-identity**: the certificate in payments-api's sidecar has the SAN URI
  `spiffe://cluster.local/ns/payments/sa/payments-api` and an empty subject;
  each workload has its own ServiceAccount's URI; validity span 86520 s (24h
  TTL + notBefore 2 minutes in the past); the trust anchor in the proxy is the
  `ca-cert.pem` of `istio-system/istio-ca-secret` and of the
  `istio-ca-root-cert` ConfigMap, valid for 3650 days; ztunnel holds the
  certificates of ambient pods, signed by the same root.
- **03-mtls**: PERMISSIVE accepts the legacy job (200) and the mesh caller
  (200); the application sees `x-forwarded-client-cert` only behind mTLS;
  Prometheus labels the legacy series `connection_security_policy="none"`,
  `source_principal="unknown"`; `mtls/plaintext-inventory.sh` exits 1 naming
  it; Kiali shows the edge without mTLS; the plain-text alert goes pending.
  After STRICT: the legacy caller gets curl exit 56, `Recv failure: Connection
  reset by peer`, and the sidecar logs `NR filter_chain_not_found`; mesh
  callers keep 200; pods stay Ready because of the probe rewrite, and a pod
  that opts out of it never becomes Ready. The port exception opens 8090 only;
  the Service-port version of it does nothing; `portLevelMtls` without a
  selector is rejected by the API server.
- **04-authz**: allow-nothing turns every call into 403 `RBAC: access
  denied`; the named paths come back one by one; DENY wins over ALLOW; an ALLOW
  with an empty rule opens everything; principals without the trust domain or
  with the wrong namespace never match; DENY with `notPrincipals` blocks the
  service that was supposed to keep working; AUDIT changes no decision; a
  dry-run DENY counts the requests it would refuse in stats, logs and
  Prometheus, then refuses them once enforced. GHSA-w44g-8m76-8gc5: the
  enforced DENY on POST compiles to a case-insensitive `:method` matcher;
  `post` sent over HTTP/2 gets 400 from fraud-check's HTTP/1 codec while the
  hop between the sidecars is HTTP/1.1, and 403 from that DENY rule once
  `authz/41` keeps HTTP/2 end to end.
- **05-jwt**: the gateway is refused by payments-api until its identity is
  allowed; with RequestAuthentication alone, a valid token gets 200, expired /
  wrong-issuer / forged / malformed tokens get 401 with Envoy's message, and no
  token at all gets 200; with the `requestPrincipals` policy, no token gets 403.
- **06-tls-edges**: TLS 1.3 handshake on the HTTPS listener with the lab CA,
  curl exit 60 without it; TLS origination to api.github.com logged by name with
  the upstream on port 443; the same ServiceEntry without the DestinationRule
  gets 503 UC; the sidecar verifies the server certificate with no
  `caCertificates` set, despite `istioctl analyze` IST0129.
- **07-ambient**: ztunnel enforces principals; an L7 rule enforced by ztunnel
  resets the very caller it allows; on the waypoint the same rule gives 200 /
  403, `post` over HTTP/2 gets 403 too and `get` over HTTP/2 counts as GET;
  traffic that skips the waypoint skips its policy; an L4 policy naming
  the caller breaks the waypoint path (503) once its pooled connections close;
  admitting only the waypoint identity closes the bypass.

## What the lab measured

Outputs below are from a full run from no cluster (`scripts/teardown.sh` then
`scripts/test-all.sh`) on macOS arm64, Docker Desktop with 5 CPUs and 8 GB,
on 2026-10-16, Istio 1.31.2. Serial numbers, IPs, timestamps and request ids
change on every run, and so do the request counts of the inventory (they depend
on how long the traffic trickles); codes, messages and labels do not.

### Control plane (step 01)

```
$ istioctl proxy-status          (no --insecure)
8 proxies listed, all 1.31.2: 4 sidecars, the waypoint, 3 ztunnels

$ istioctl proxy-status --authority wrong.example.com
Error: could not get XDS from discovery pod "istiod-...": ... tls: failed to verify certificate:
x509: certificate is valid for istio-pilot.istio-system.svc, istiod-remote.istio-system.svc, istiod.istio-system.svc, not wrong.example.com
```

- Since 1.31.2, istioctl verifies istiod's certificate when it talks XDS
  (`proxy-status` and friends) against the root in the `istio-ca-root-cert`
  ConfigMap. Nothing in the lab needs `--insecure`.

### Identity (step 02)

```
$ istioctl proxy-config secret deploy/payments-api -n payments
RESOURCE NAME     TYPE           STATUS     VALID CERT     SERIAL NUMBER                        NOT AFTER                NOT BEFORE
default           Cert Chain     ACTIVE     true           6cf3bcd65bc4040bf6df805c2010234d     2026-10-17T22:07:38Z     2026-10-16T22:05:38Z
ROOTCA            CA             ACTIVE     true           7002dab4f7b88a3be07eb16178011e2e     2036-10-13T22:06:00Z     2026-10-16T22:06:00Z

subject=
issuer=O=cluster.local
X509v3 Subject Alternative Name: critical
    URI:spiffe://cluster.local/ns/payments/sa/payments-api
```

- Validity span of the workload certificate: **86520 s** = 24h TTL + 2 minutes,
  because istiod sets `notBefore` 2 minutes in the past (clock skew grace). The
  pod sets no `SECRET_TTL`, so the 24h default applies.
- Root: `O=cluster.local`, self-signed, **3650 days**; the same certificate as
  `istio-system/istio-ca-secret` (`ca-cert.pem`) and the `istio-ca-root-cert`
  ConfigMap in the namespace.
- Ambient pods have no proxy: the ztunnel of their node holds their
  certificate (`spiffe://cluster.local/ns/payments-ambient/sa/payments-api`,
  same root, same 86520 s span).

### mTLS, PERMISSIVE to STRICT (step 03)

```
PERMISSIVE  legacy/settlement-batch (plain text) x10 -> 200=10
            payments/payments-api (mTLS)        x10 -> 200=10

x-forwarded-client-cert seen by fraud-check (mTLS only):
  By=spiffe://cluster.local/ns/payments/sa/fraud-check;Hash=...;Subject="";URI=spiffe://cluster.local/ns/payments/sa/payments-api

Prometheus, istio_requests_total{reporter="destination", destination_workload="fraud-check"}:
  legacy/settlement-batch  connection_security_policy=none        source_principal=unknown
  payments/payments-api    connection_security_policy=mutual_tls  source_principal=spiffe://cluster.local/ns/payments/sa/payments-api

$ mtls/plaintext-inventory.sh payments kind-istio-p3 1h      (exit 1)
  mutual_tls  payments/payments-api   -> fraud-check  requests=32  principal=spiffe://cluster.local/ns/payments/sa/payments-api
  mutual_tls  payments/payments-api   -> risk-score   requests=27  principal=spiffe://cluster.local/ns/payments/sa/payments-api
  none        legacy/settlement-batch -> fraud-check  requests=28  principal=unknown
  NOT READY for STRICT: 1 caller/destination pair(s) still send plain text

Kiali graph (securityPolicy appender):
  legacy/settlement-batch -> payments/fraud-check  isMTLS=none
  payments/payments-api   -> payments/fraud-check  isMTLS=100

STRICT      legacy x10 -> 000=10
            curl: (56) Recv failure: Connection reset by peer
            fraud-check sidecar: "- - -" 0 NR filter_chain_not_found ... <legacy pod IP>:<port>
            payments-api x10 -> 200=10
```

- The destination sidecar names a plain-text caller's workload
  (`settlement-batch`, namespace `legacy`), but its principal is `unknown`:
  without a certificate there is no identity for a policy to match.
- Alert `IstioPlaintextInbound` went pending as soon as Prometheus evaluated it.
- Probes under STRICT: fraud-check's readiness probe is rewritten to
  `{"path":"/app-health/fortio/readyz","port":15020}` and every pod stays
  Ready. The `ledger` pod, annotated `sidecar.istio.io/rewriteAppHTTPProbers:
  "false"`, never becomes Ready: `Readiness probe failed: Get
  "http://<pod IP>:8080/debug": read tcp ...: read: connection reset by peer`.
- Port exception (`portLevelMtls` 8090 PERMISSIVE on fraud-check): legacy ->
  :8090 `200=5`, legacy -> :8080 `000=5`. The same exception written with the
  Service port of payments-api (8080, container port 9080): accepted, legacy
  still `000=5`; with 9080: `200`. Without a selector the API server answers
  `Invalid value: portLevelMtls requires selector`.

### Authorization (step 04), 5 requests per line

```
no policy                     payments-api -> risk-score             200=5
allow-nothing (spec: {})      payments-api -> fraud-check            403=5   body "RBAC: access denied"
                              access log: 403 - rbac_access_denied_matched_policy[none]
                              requests that reached the fraud-check container: 0; pods still Ready
ALLOW by principal/method/path
                              GET  /v1/check/1                       200=5
                              POST /v1/check                         200=5
                              DELETE /v1/check/1                     403=5
                              GET  /admin                            403=5
                              fraud-check:8090 -> risk-score         200=5 (5 reached risk-score)
                              payments-api -> risk-score             403=5
                              legacy -> fraud-check                  000=5 (STRICT, before any policy)
DENY /v1/check/export         GET /v1/check/export                   403=5
                              rbac_access_denied_matched_policy[ns[payments]-policy[fraud-check-deny-export]-rule[0]]
ALLOW "deny-all" rules: [{}]  payments-api -> risk-score             200=5 (opened)
                              GET /admin                             200=5 (opened)
                              GET /v1/check/export                   403=5 (the DENY still wins)
DENY  deny-all rules: [{}]    GET /v1/check/1                        403=5  matched policy deny-all
principal "ns/payments/sa/payments-api"            -> Envoy exact match spiffe://ns/payments/sa/payments-api: 403=5
principal "cluster.local/ns/payment/sa/payments-api" -> 403=5
DENY notPrincipals [payments-api] on risk-score   fraud-check -> risk-score 403=5 (matched policy deny-legacy)
AUDIT on POST                 POST 200=5, DELETE 403=5; RBAC filter action LOG; access_log_hint=true in the debug log
DENY POST, istio.io/dry-run   POST x10 -> 200=10; rbac.istio_dry_run_deny_.shadow_denied +10;
                              debug log x10: shadow denied, matched policy ns[payments]-policy[fraud-check-deny-post]-rule[0]
                              Prometheus envoy_http_rbac{authz_dry_run_action="deny",authz_dry_run_result="denied"} = 10
                              dry-run=false -> POST 403=5
GHSA-w44g-8m76-8gc5, the DENY on POST enforced
                              :method matcher {"exact":"POST","ignoreCase":true}
                              "post" over HTTP/2, HTTP/1.1 between the sidecars   400=5
                                fraud-check sidecar: "- - HTTP/1.1" 400 DPE http1.codec_error
                              + authz/41 (useClientProtocol), "post" over HTTP/2 403=5
                                fraud-check sidecar: "post /v1/check?id=... HTTP/2" 403 -
                                rbac_access_denied_matched_policy[ns[payments]-policy[fraud-check-deny-post]-rule[0]]
                                requests that reached the fraud-check container: 0
                              GET over HTTP/2                         200=5
```

- The method-case bypass needs HTTP/2 all the way to the proxy that enforces
  the rule. Between two sidecars an `http` port is HTTP/1.1 by default, and
  the HTTP/1 codec of the receiving sidecar refuses a lowercase method (400)
  before authorization runs. With `useClientProtocol` (or `h2UpgradePolicy:
  UPGRADE`, or a gRPC/HTTP2 port) the method arrives as sent, and only a
  case-insensitive matcher stops it. Since 1.31.2 every method matcher,
  ALLOW lists included, ignores case, so an ALLOW listing `POST` also admits
  `post` over HTTP/2.

- A DENY rule with only HTTP attributes and no port is accepted with a warning:
  `configured AuthorizationPolicy will deny all traffic to TCP ports under its
  scope due to the use of only HTTP attributes in a DENY rule; it is
  recommended to explicitly specify the port`.
- After each policy change the new decision reaches each proxy within seconds,
  but connections opened before it keep the old filter chain until Envoy
  drains them: `listener_manager.total_filter_chains_draining` stayed at 8
  for about 45 s on each fraud-check pod (`drain_time` 45s, strategy
  Immediate, from `pilot-agent request GET server_info`). The step waits for that gauge to
  return to 0 before every assertion.
- Alerts `IstioAuthzDryRunWouldDeny` and `IstioAuthorizationDenied` went pending.

### End-user JWT at the gateway (step 05), 5 requests per line

```
gateway -> payments-api, gateway identity not allowed      403=5
with authz/12 (cluster.local/ns/payments-ingress/sa/payments-gateway-istio)  200=5

RequestAuthentication only
  valid token (exp in 10 years)        200=5
  expired                              401=5  "Jwt is expired"
  other issuer                         401    "Jwt issuer is not configured"
  signed by another key, same kid      401=5  "Jwt verification fails"
  not a JWT                            401    "Jwt is not in the form of Header.Payload.Signature with two dots and 3 sections"
  NO token                             200=5
  access log: 401 - jwt_authn_access_denied{Jwt_is_expired}

+ AuthorizationPolicy requestPrincipals ["https://issuer.payments.example/*"]
  NO token                             403=5  "RBAC: access denied"
  valid token                          200=5
  expired token                        401=5
```

### TLS at the edges (step 06)

```
HTTPS listener, lab CA trusted         200=5
  * SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384 / x25519 / RSASSA-PSS
  *   subject: O=Payments Lab; CN=api.payments.example
  *   issuer: O=Payments Lab; CN=Payments Lab CA
  < HTTP/2 200
without the CA                         curl exit 60: SSL certificate OpenSSL verify result: unable to get local issuer certificate (20)
HTTP listener on the same Gateway      200=5

TLS origination, payments-api: curl http://api.github.com/zen -> 200
  cluster outbound|80||api.github.com: UpstreamTlsContext, validation file-root:system, autoSni true, autoSanValidation true
  access log: "GET /zen HTTP/1.1" 200 - via_upstream ... "api.github.com" "<GitHub IP>:443" outbound|80||api.github.com
without the DestinationRule            503  "GET /zen HTTP/1.1" 503 UC upstream_reset_before_response_started{connection_termination}

SIMPLE without caCertificates, server cert from the lab CA (istioctl analyze warns IST0129: "no caCertificates are set to validate server identity")
                                       503 URX,UF ... CERTIFICATE_VERIFY_FAILED ... unable_to_get_local_issuer_certificate
same rule with insecureSkipVerify: true  200
```

The sidecar does verify the server certificate when `caCertificates` is not
set: it uses the OS CA bundle (`file-root:system`), as the DestinationRule
reference says. The IST0129 wording ("no verification") does not match what
Istio 1.31.2 does.

### Ambient (step 07), 5 requests per line

```
no policy, no waypoint        payments-api 200=5, risk-score 200, legacy 200=5
L4 ALLOW principals [payments-api] (ztunnel)
                              payments-api 200=5, risk-score reset, legacy 000=5 (curl 56)
                              ztunnel: connection closed due to policy rejection: allow policies exist, but none allowed
L7 rule (GET /v1/check*) with a selector, enforced by ztunnel
                              ztunnel holds {"action":"Allow","rules":[]}
                              payments-api GET /v1/check/1 (the allowed request) 000=5, curl exit 56
waypoint + same rule with targetRefs Service fraud-check (WaypointAccepted=True)
                              GET 200=5, POST 403=5, GET /admin 403=5 "RBAC: access denied"
                              :method matcher {"exact":"GET","ignoreCase":true}
                              "post" over HTTP/2 403=5 (the waypoint logs "post /v1/check/... HTTP/2" 403)
                              "get" over HTTP/2 200=5 (counts as GET)
                              legacy -> Service /admin 200=5 (no waypoint on its path)
                              payments-api -> pod IP /admin 200=5 (skips the waypoint)
L4 ALLOW [payments-api] again, waypoint in the path
                              existing waypoint connections, kept busy for 60 s: only 200
                              ztunnel closed none of them ("no longer allowed after a policy update": 0)
                              after 40 s idle, new connections: 503=5, waypoint "- - -" 0 UF,URX "tunnel_response:401"
L4 ALLOW [waypoint] (the fix)  GET 200=5, POST 403=5, pod IP /admin 000=5, legacy 000=5
```

### Totals

Final runs from no cluster on Istio 1.31.2, all steps passed: 60 offline
assertions (`ci/`) + 203 in the lab = 263, about 33 to 34 minutes each (most of it waiting for
filter chains to drain after each policy change in steps 04 and 05).

## The silent errors

Each one is accepted by the API server and does less than it appears to; each
is reproduced live by a step and fails `ci/security-lint.sh` with its own
message.

1. `jwt/request-authentication.yaml` applied alone: invalid tokens get 401,
   but a request with no token gets 200 (step 05). Fix: `jwt/require-jwt.yaml`.
2. `silent-errors/02-pa-port-level-service-port.yaml`: a `portLevelMtls`
   exception on the Service port (8080) of a container listening on 9080 never
   applies (step 03).
3. `silent-errors/03-ap-allow-empty-rule.yaml`: an ALLOW policy named
   `deny-all` with `rules: [{}]` allows every request in the namespace (step 04).
4. `silent-errors/04-ap-principal-without-trust-domain.yaml`: the principal
   `ns/payments/sa/payments-api` becomes `spiffe://ns/payments/sa/payments-api`
   and never matches (step 04).
5. `silent-errors/05-ap-principal-wrong-namespace.yaml`: one letter off in the
   namespace, never matches, nothing validates it (step 04).
6. `silent-errors/06-ap-deny-not-principals.yaml`: a DENY with
   `notPrincipals` meant for one caller blocks every other one, including
   fraud-check -> risk-score (step 04).
7. `silent-errors/07-ap-l7-enforced-by-ztunnel.yaml`: methods and paths in a
   selector policy of an ambient namespace; ztunnel receives it with no rules
   and refuses the caller it was meant to allow (step 07).

Related mistakes the lint also catches, which are not silent: an L4 policy
naming the original caller once a waypoint is in the path (503 through the
waypoint, step 07), a DENY rule with HTTP attributes and no port (istiod
warns), `portLevelMtls` without a selector (the API server rejects it), a
workload-level or port-level PERMISSIVE under STRICT with no owner or past its
expiry date, and a ServiceEntry that sends plain HTTP to port 443 without the TLS-originating
DestinationRule (503 UC, step 06).

## Security checks in CI (no cluster)

`ci/security-lint.sh` runs `istioctl analyze --use-kube=false --all-namespaces`
and a set of static checks on the files you give it. Give it the whole set you
apply together: cross-resource checks (a RequestAuthentication without the
policy that requires a token; a principal naming a ServiceAccount that does not
exist; a `portLevelMtls` port that is not a container port) only see the files
they are given.

```bash
bash ci/security-lint.sh apps/payments-sidecar.yaml apps/legacy.yaml \
  mtls/peer-authentication-strict.yaml authz/00-allow-nothing.yaml \
  authz/10-fraud-check-allow.yaml authz/11-risk-score-allow.yaml \
  authz/12-payments-api-allow-ingress.yaml authz/20-fraud-check-deny-export.yaml \
  ingress/ jwt/ egress/
```

A PERMISSIVE or DISABLE left in a PeerAuthentication with a selector, on the
whole workload or on one port, overrides a namespace-wide or mesh-wide STRICT
for the pods it selects, because Istio applies the narrowest matching policy.
The lint fails on every such exception under STRICT unless it carries an owner
and an expiry date at most a year ahead, and fails again once the date has
passed:

```yaml
metadata:
  annotations:
    exception.istio-in-practice/owner: team-payments
    exception.istio-in-practice/expires: "2027-06-30"
```

`mtls/fraud-check-port-exception.yaml` carries both. Before switching a
namespace to STRICT, lint it together with the selector policies already in
the cluster (`kubectl get peerauthentication -A -o yaml`), since an old one is
exactly what this check is for.

`ci/test-security-lint.sh` proves the lint both ways: the working sets of the
lab pass, and each silent error fails with its own message. One mistake is not
detectable offline: switching to STRICT while a plain-text caller is still in
production traffic. For that one, run `mtls/plaintext-inventory.sh <namespace>
<context>` against the cluster before applying STRICT; it exits 1 while any
caller reached the namespace without mTLS in the window.

`istioctl analyze` on its own flags none of the silent errors in
`silent-errors/`. It does flag two related mistakes (IST0106 for
`portLevelMtls` without a selector, IST0133 for a DENY rule with HTTP
attributes and no port), and it warns IST0129 on the TLS origination
DestinationRule, a warning the lab shows to be wrong for 1.31 (step 06).

## Teardown

```bash
bash scripts/teardown.sh         # deletes the kind cluster istio-p3 and out/jwt, out/tls
```

Nothing else is created outside the cluster: the CLIs live in `./bin` and the
generated keys, tokens, certificates and logs in `./out`, both gitignored.

## License

MIT, see `LICENSE`.
