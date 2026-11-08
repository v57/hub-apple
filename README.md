<h1>
  <img alt="Containerization logo" src="./icon.png" width="70" valign="middle">
  &nbsp;Login with Apple
</h1>

> Made for [Hub](https://hub.v57.dev)

Apple service allows you to verify Login with Apple and StoreKit2 transaction tokens without adding a all dependencies to your server, so it can stay lightweight. 

Run from multiple machines or multiple processes for better performance and uptime

Use Hub Launcher to easily scale it up, increasing number of running processes. As Bun/js/ts is a single core process

## Login with Apple

```ts
const request: Login
const userId: String = await service.send('apple/login/lite', request)
```
### Detailed login
```ts
const request: Login
const userInfo: any = await service.send('apple/login', request)
```
## Verify and Decode StoreKit2 transaction
```ts
const request: string
const transaction: any = await service.send('apple/storekit2', request)
```

## Types
```ts
interface Login {
  token: string
  app: string
}
```

## Service reference

### What it does

hub-apple checks Apple-signed data for your servers and services. `apple/login` and `apple/login/lite` verify a Sign in
with Apple identity token: the signature against Apple's published keys (fetched from Apple and cached for an hour,
fetched again when a token names a key it doesn't know), the issuer, the expiry, and that the token was issued for
your app. `apple/storekit2` decodes a StoreKit 2 signed transaction or renewal info after checking that its
certificate chain ends at Apple Root CA G3. It holds no secrets and keeps no state: the app's client id comes with
each call. Its only outgoing requests go to Apple for the Sign in with Apple keys.

### Installing it on a Hub

**From the launcher.** The launcher's app catalogue ([hub-store](https://github.com/v57/hub-store) `apps.json`) lists
it as **Login with Apple** (`v57/apple`, repository `v57/hub-apple`). An owner installs it in the Hub app:
**Launcher**, **Get More**, then **Get** (see the Hub app guide's
[Launcher](https://github.com/v57/hub-app/blob/main/docs/Launcher.md) page). The launcher on the hub's machine clones
the repository into its `apps/` folder (`~/Hub/Launcher/apps/hub-apple` when it was started with the
[`hub`](https://github.com/v57/hub) CLI), runs `bun install --production --frozen-lockfile` and starts it with `bun .`.
**Instances** in the app's details runs more copies.

**By hand**, on any machine that reaches the hub:

```sh
git clone https://github.com/v57/hub-apple.git && cd hub-apple
bun install
HUB=ws://127.0.0.1:1997 bun .
# or, for a hub on this machine: bun . --port 1997
```

Configuration:

| Name | Kind | What |
| --- | --- | --- |
| `HUB` | environment | The hub's address. A bare number is a port on this machine. Default `1997`. |
| `-p`, `--port` | argument | Connect to `ws://localhost:<port>` instead of `HUB`. |
| `auth` | file in the working directory | The service's own key, created on the first run. Keep it: the hub approves the service by this key. |

No Apple key or client secret is needed. The client id is not configured on the service: each call names it (`app`,
your bundle id or Services ID), and a token issued for another app fails. The hub-service SDK reads a few more
variables (device key, instance name); see the [hub-service README](https://github.com/v57/hub-service).

**Hosting approval.** When the service connects, it asks the hub to post its three paths. The hub routes no calls to
it until an owner allows that: the Hub app lists the paths as **Needs approval** on **Services** and the request on
**Requests**, where **Allow** approves exactly those paths for the service's key. The owner call behind it is
`hub/host/update { key, allow: [paths] }`. A service whose key is an owner's needs no approval.

### APIs

The descriptions come from `descriptions.ts`, which the service sends to the hub; `hub/api/list` returns them (the Hub
protocol, `Docs/Devices/protocol.md` section 15 in the Hub workspace).

| Path | Kind | Title | Takes | Returns |
| --- | --- | --- | --- | --- |
| `apple/login` | post | Verify Sign in with Apple | `{ token, app }` | the token's claims: `sub`, `aud`, `iss`, `iat`, `exp`, and `email`, `email_verified`, `is_private_email` when shared |
| `apple/login/lite` | post | Sign in with Apple user id | `{ token, app }` | `sub`, the user's stable id, as a string |
| `apple/storekit2` | post | Decode a StoreKit 2 transaction | the signed transaction (JWS) as a string | the decoded payload: `transactionId`, `originalTransactionId`, `productId`, `bundleId`, `purchaseDate`, `expiresDate`, `environment`, ... |

- `token` is the identity token (a JWT) Sign in with Apple gave the app; `app` is the bundle id or Services ID the
  token's audience must match.
- The login paths fail with `invalid jwt`, `key not found` (no Apple key with the token's key id), or the
  verification error for a bad signature, audience, issuer or expiry.
- `apple/storekit2` fails when the JWS is malformed or its certificate chain isn't Apple's. It takes the JWS from
  StoreKit 2 or from App Store Server Notifications.

### Permissions

The service doesn't guard its paths (there is no `access.ts`) and doesn't mark them `public`, so the hub decides:

| Caller | On a `default-deny` hub (every new hub) | On an older `default-allow` hub |
| --- | --- | --- |
| An owner of the hub | allowed | allowed |
| A caller an owner granted the path (or a prefix of it) | allowed | allowed |
| Anyone else | refused | allowed, unless a permission group names the path |

Most setups call these paths from a backend server, which then signs the user in. An owner lets that server call
them with a grant (Hub protocol section 6):

```
hub/grant/add { "subject": { "key": "<the server's public key>" }, "object": { "prefix": "apple/" } }
```

`subject` may also be `{ "device": "<device id>" }`, `{ "group": "<group>" }` or `{ "everyone": true }`; `object` may
be `{ "path": "apple/login/lite" }` for one path, or `{ "prefix": "apple/login" }` for both login paths. In the Hub
app, the same is **Grant** on a device's **Access** list.

### Testing

```sh
bun install
bun test
```

- `login.test.ts` tests the Sign in with Apple verifier with generated RSA keys and a stubbed fetch: the key cache,
  a key rotation (a new key id), and falling back to cached keys while a refresh fails.
- `descriptions.test.ts` checks that every registered path and kind is described, and that the schemas stay in the
  subset hub-service accepts (hub-service `docs/api-descriptions.md`).

`apple/storekit2` has no test yet. The tests make no network requests.
