# SLH 2026 - Lab 1 "SecuBank"

This folder holds the SecuBank lab. `secubank-terminal/` is a Rust terminal with
a Text User Interface (TUI) that authenticates its users with Keycloak and
authorizes their vault actions with a Cedar policy. `keycloak/` holds the
Keycloak server, which runs in Docker, and two helper scripts. The terminal runs
on the host with Cargo.

The handout describes the work to do. This README describes how to set up the
lab environment and lists the commands used while working on it.

## Prerequisites

- Docker with Docker Compose 2.20.3 or newer (check with
  `docker compose version`). Older versions do not support the `include` used by
  the root `compose.yaml`.
- Rust 1.89 or newer, with Clippy. Clippy is part of the default `rustup`
  profile. If `cargo clippy` is missing, install it with
  `rustup component add clippy`.
- `bash`, `curl`, `jq` and `openssl`.

Every command below starts from the lab root (the folder that holds this
README). The terminal reads `.env` from the folder it runs in, and `VAULTS_PATH`
is relative to that folder, so `cargo` always runs in `secubank-terminal/`.

## Setup

The following steps set up the lab environment. They are done once only, except
for the last step, which must be repeated after changes to the realm.

### 1. Create the configuration files

Create both `.env` files from their examples. Do this once only, since copying
again overwrites the values filled in afterwards.

```sh
cp keycloak/.env.example keycloak/.env
cp secubank-terminal/.env.example secubank-terminal/.env
```

Then set the two secrets that do not depend on the realm:

- In `keycloak/.env`, set `KC_BOOTSTRAP_ADMIN_PASSWORD` to the output of
  `openssl rand -hex 16`. Keycloak only creates its admin account on the first
  start, while its database is empty. Set the password before step 2, since a
  later change has no effect until the next `docker compose down -v`.
- In `secubank-terminal/.env`, set `DIAL_CODE_PEPPER` to the output of
  `openssl rand -base64 32`. Changing it later invalidates every dial code
  stored in `vaults.toml`.

Keep the other provided values of `secubank-terminal/.env` as they are.
`KEYCLOAK_URL`, `KEYCLOAK_REALM`, the two client IDs and `VAULTS_PATH` already
match the names that Part A requires. `KEYCLOAK_SA_CLIENT_SECRET`,
`KEYCLOAK_REALM_KID` and `KEYCLOAK_REALM_PUBLIC_KEY` stay empty until step 3.

### 2. Start Keycloak and build the realm

```sh
docker compose up -d --wait
```

The first start downloads the Keycloak 26.7.3 image. The command returns once
Keycloak passes its health check, which can take a minute.

Log in to the admin console at <http://localhost:7080/admin> as `admin`, with
the password set in step 1. The console warns that this is a temporary admin
account. This is expected, since Keycloak creates the account again from
`keycloak/.env` after each `docker compose down -v`.

Always reach Keycloak through `http://localhost:7080` and never through
`127.0.0.1`, since tokens obtained through `127.0.0.1` carry another issuer
(`iss`).

Then create and configure the `secubank` realm in the admin console, as Part A
of the handout asks, with your own test users. Give them test passwords only,
since the realm export contains the users. Each user can change their password
in the account console of the realm, at
<http://localhost:7080/realms/secubank/account>.

### 3. Connect the terminal to the realm

Three values of `secubank-terminal/.env` come from the realm:

1. `KEYCLOAK_SA_CLIENT_SECRET` is the secret of the service account client. In
   the admin console, it is under Clients >
   `secubank-terminal-service-account` > Credentials > Client secret.
2. `KEYCLOAK_REALM_KID` and `KEYCLOAK_REALM_PUBLIC_KEY` are the signing key of
   the realm, which the terminal uses to verify the access tokens. The terminal
   reads this key from `.env` and never fetches it at runtime. Print it with:

   ```sh
   keycloak/print-realm-key.sh
   ```

   The script prints a comment line followed by `KEYCLOAK_REALM_KID=...` and
   `KEYCLOAK_REALM_PUBLIC_KEY=...`. Paste these lines over the two lines of the
   same name in `secubank-terminal/.env` (the comment can be pasted too). If the
   script answers that the realm must have exactly one RS256 signing key, copy
   the `Kid` and the `Public key` of the RS256 row by hand from Realm settings >
   Keys.

The realm gets a new signing key after each `docker compose down -v`, so the key
is printed and pasted again every time. The service account secret is part of
the realm export and stays the same.

### 4. Create the vault file, then test and run the terminal

```sh
cd secubank-terminal
cp vaults.example.toml vaults.toml
cargo test
cargo run
```

- `cp` creates `vaults.toml`, and the same command later resets every vault.
  `vaults.example.toml` documents the format of the file. The terminal rewrites
  `vaults.toml` after each change, which drops its comments.
- `cargo test` runs the unit tests. Until the `todo!()` functions are written,
  the tests that reach them fail with `not yet implemented`.
- `cargo run` starts the terminal. It reads `.env` once at startup, so quit and
  start it again after any change to `.env`. It does not start while a value is
  missing or invalid (see [Troubleshooting](#troubleshooting)). In the menu, `q`
  or `Esc` quits. In a form, `Esc` goes back to the menu. The bottom line of the
  screen lists the keys.

## Keycloak data and realm export

The realm, its users and every change made in the admin console are stored in
the Docker volume `secubank_keycloak-data`. This volume survives
`docker compose stop`, `docker compose down` and restarts. Only
`docker compose down -v` deletes it.

| Action                          | Command, from the lab root                                               |
| ------------------------------- | ------------------------------------------------------------------------ |
| Stop Keycloak and keep its data | `docker compose stop`                                                    |
| Start Keycloak again            | `docker compose up -d --wait`                                            |
| Follow the Keycloak logs        | `docker compose logs -f keycloak`                                        |
| Export the realm and its users  | `keycloak/export-realm.sh`                                               |
| Delete the Keycloak data        | `docker compose down -v`                                                 |
| Reset the vaults                | `cp secubank-terminal/vaults.example.toml secubank-terminal/vaults.toml` |

`keycloak/export-realm.sh` writes the realm and its users to
`keycloak/realm/secubank-realm.json`, without the realm keys. It stops Keycloak
during the export, starts it again afterwards, and asks before overwriting a
previous export. This export is handed in, so run the script again after each
change to the realm.

After `docker compose down -v`, the next `docker compose up -d --wait` imports
`keycloak/realm/secubank-realm.json` if it exists. Without an export, Keycloak
starts with no `secubank` realm, so export the realm before deleting the data.
After the import:

- The admin account is created again from `keycloak/.env`.
- The realm has a new signing key. Run `keycloak/print-realm-key.sh` again,
  update `secubank-terminal/.env` and restart the terminal.

Deleting the data and starting Keycloak again is also how to check that the
export brings the realm and its users back, as Part A requires.

A change of `DIAL_CODE_PEPPER` makes the stored dial codes unusable. Reset the
vaults afterwards, or remove the `dial_code_hash` of each vault in
`vaults.toml`.

## Hand in

The last section of the handout lists what is handed in, including the
documentation of the test users in `keycloak/`, in a form of your choice. Both
of these commands must pass:

```sh
(cd secubank-terminal && cargo test && cargo clippy --all-targets -- -D warnings)
```

Clippy fails on the unused parameters of the `todo!()` functions until they are
written. Once both commands pass, export the realm a last time and remove the
build folder before creating the archive:

```sh
keycloak/export-realm.sh
(cd secubank-terminal && cargo clean)
```

## Troubleshooting

The terminal prints its startup errors as `secubank-terminal: <message>`. The
messages below come from the terminal unless stated otherwise:

- `cannot read .env in the current directory`: `cargo run` was started outside
  `secubank-terminal/`, or `secubank-terminal/.env` does not exist (step 1).
- `missing variable <NAME>`: `<NAME>` is empty in `secubank-terminal/.env`
  (steps 1 and 3).
- `invalid value for KEYCLOAK_URL`: the URL must start with `http://` and have
  no trailing `/`. Keep `http://localhost:7080`.
- `invalid value for DIAL_CODE_PEPPER`: the pepper must be padded base64 of 32
  to 96 bytes. Generate it with `openssl rand -base64 32`.
- `invalid value for KEYCLOAK_REALM_PUBLIC_KEY`: the value is not an RSA public
  key. Paste the output of `keycloak/print-realm-key.sh` again, on a single
  line.
- `invalid Cedar policies` or `Cedar policies fail validation`:
  `policy/secubank.cedar` does not parse, or does not validate against the
  schema (Part E).
- `not yet implemented`, and the terminal stops: the action reached a `todo!()`
  function.
- `Access denied.` for every action: the username or password is wrong, the
  account is locked out by brute force detection after failed logins (even
  with the right password, until the lockout ends or the admin unlocks it in
  the user's details), Keycloak is stopped, the realm key in `.env` is outdated
  (after `docker compose down -v`), `vaults.toml` is broken, or the policy
  denies the action (the empty policy denies everything). The terminal does not
  say which step failed.
- `Registration unavailable.`: Keycloak is stopped, `KEYCLOAK_SA_CLIENT_SECRET`
  is wrong, or the service account client is not allowed to create users.
- `Registration refused.`: Keycloak refused the new user, for instance because
  of its password policy.
- `Cannot reach http://localhost:7080/realms/secubank`, from
  `keycloak/print-realm-key.sh`: Keycloak is not running, or the `secubank`
  realm does not exist yet.
- An error about `include`, from `docker compose`: Docker Compose is older than
  2.20.3.
