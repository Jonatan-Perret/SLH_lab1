# SecuBank test users

Test users of the `secubank` realm, one per case of the handout table (Part A,
requirement 7). They are part of the realm export
(`keycloak/realm/secubank-realm.json`). The passwords are test passwords only.

## Users

| Username | Password | Enabled | Groups | Direct roles | Effective app roles | Logs in as | As a new owner |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `test-client-standard` | `dQsFVRjVlnoyZw3JiQrTNA==` | yes | `standard-clients` | `default-roles-secubank` | `client`, `clearance-standard` | Client | Allowed |
| `test-client-elite` | `dQsFVRjVlnoyZw3JiQrTNA==` | yes | `elite-clients` | `default-roles-secubank` | `client`, `clearance-elite` | Client | Allowed |
| `test-client-premium` | `dQsFVRjVlnoyZw3JiQrTNA==` | yes | `premium-clients` | `default-roles-secubank` | `client`, `clearance-premium` | Client | Allowed |
| `user-officer` | `dQsFVRjVlnoyZw3JiQrTNA==` | yes | `officers` | `account`: `view-profile`, `manage-account` | `bank-security-officer` | Officer | Refused |
| `test-no-roles` | `dQsFVRjVlnoyZw3JiQrTNA==` | yes | none | none | none | Denied | Refused |
| `test-client-no-clearance` | `dQsFVRjVlnoyZw3JiQrTNA==` | yes | none | `default-roles-secubank` | `client` | Denied | Allowed, but cannot use the vault |
| `test-clearance-standard-no-client` | `dQsFVRjVlnoyZw3JiQrTNA==` | yes | `standard-clients` | `account`: `view-profile`, `manage-account` | `clearance-standard` | Denied | Refused |
| `test-client-clearance-standard-clearance-elite` | `dQsFVRjVlnoyZw3JiQrTNA==` | yes | `standard-clients`, `elite-clients` | `default-roles-secubank` | `client`, `clearance-standard`, `clearance-elite` | Denied | Allowed, but cannot use the vault |
| `test-client-bank-security-officer-clearance-standard` | `dQsFVRjVlnoyZw3JiQrTNA==` | yes | `officers`, `standard-clients` | `default-roles-secubank` | `client`, `bank-security-officer`, `clearance-standard` | Denied | Refused |
| `test-bank-security-officer-clearance-standard` | `dQsFVRjVlnoyZw3JiQrTNA==` | yes | `officers`, `standard-clients` | `account`: `view-profile`, `manage-account` | `bank-security-officer`, `clearance-standard` | Denied | Refused |
| `test-disabled` | `dQsFVRjVlnoyZw3JiQrTNA==` | **no** | `standard-clients` | `default-roles-secubank` | `client`, `clearance-standard` | Denied | Refused |
| `test-disabled-officer` | `dQsFVRjVlnoyZw3JiQrTNA==` | **no** | `officers` | `account`: `view-profile`, `manage-account` | `bank-security-officer` | Denied | Not applicable |

## Realm building blocks

- **Default roles** (`default-roles-secubank`): `client`, `offline_access`,
  `uma_authorization`, `account` → `view-profile` and `manage-account`.
- **Default group**: `standard-clients`.
- **Groups**, each giving exactly one role:

  | Group | Realm role |
  | --- | --- |
  | `standard-clients` | `clearance-standard` |
  | `elite-clients` | `clearance-elite` |
  | `premium-clients` | `clearance-premium` |
  | `officers` | `bank-security-officer` |

## Manual procedures (Section 2)

All of these are done in the admin console of the `secubank` realm.

- **Raise a client to Elite or Premium**: Users → user → Groups → leave
  `standard-clients`, join `elite-clients` or `premium-clients`.
- **Bring a client back to Standard**: leave `elite-clients` or `premium-clients`,
  join `standard-clients`.
- **Make an account an officer**: Users → user → Groups → leave every clearance
  group, join `officers`. Role mapping → unassign `default-roles-secubank`,
  assign the `account` client roles `view-profile` and `manage-account`.
- **Disable an account**: Users → user → Details → turn **Enabled** off.
- **Unlock an account** locked by brute force detection: Users → user → Details
  → unlock.
- **Change a password**: the user changes it in the account console at
  <http://localhost:7080/realms/secubank/account>.

## AI use

An AI assistant (Claude, in Claude Code) was used during Part A, as the handout
allows, to explain how to perform tasks and to check the result, not to build
the realm. It explained how to create the `secubank-terminal-service-account`
client, which Keycloak password policies match the password rules of the
terminal, and how to set up the test users of the table. It read the realm
export and the running realm (read only, through the Admin API) and pointed out
mistakes, such as `client` missing from the default roles and groups giving
several clearances. Every change to the realm was made by hand in the admin
console. The assistant was also used to format this file and correct for 
orthographic errors.
