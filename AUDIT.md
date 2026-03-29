# prb-signer — Security Audit

Date: 2026-03-29

## Network operations

| Line | Operation | Binding |
|------|-----------|---------|
| 345 | `websockets.serve(host, port, ssl=ctx)` | WSS server 127.0.0.1:38383 |
| 326 | `websocket.send(signed_xml)` | response to client |
| 331 | `websocket.send(f"ERROR: {e}")` | error to client |
| 296 | `websocket.send("who are you?")` | unknown message response |

Слуша **само на localhost** (127.0.0.1). Не прави outbound connections.

## PIN handling

| Line | Operation | Risk |
|------|-----------|------|
| 373 | `getpass.getpass("Smart card PIN: ")` | OK — interactive |
| 360 | `--pin` CLI argument | **HIGH** — видим в `ps aux` |
| 50 | `self.pin = pin` | PIN в паметта за целия живот на сървъра |
| 72 | `session.login(self.pin)` | PIN в PKCS#11 |

**FIX needed**: Премахни `--pin` от CLI. Само interactive prompt или env var `PDFSIGN_PIN`.

## File I/O

| Line | Operation | Risk |
|------|-----------|------|
| 274 | `open(key_path, "wb")` — TLS private key | **HIGH** — unencrypted, no chmod |
| 276 | `open(cert_path, "wb")` — TLS self-signed cert | OK |

**FIX needed**: `os.chmod(key_path, 0o600)` след запис.

## Authentication

**NONE.** Всеки локален процес може да се свърже и поиска подписване.
Браузър с trusted cert може да бъде exploit-нат от malicious website
(JS connect to `wss://127.0.0.1:38383`).

Оригиналната SIRMA Java аплет СЪЩО няма auth — ние сме compatible.
Бъдещо подобрение: Origin header проверка.

## Error message leak

Line 331: `f"ERROR: {e}"` — пълен Python exception text се праща на клиента.
Може да съдържа file paths, PKCS#11 грешки, internal state.

**FIX**: Заменй с generic `"ERROR: signing failed"`, логвай детайлите локално.

## Crypto

- SHA-1 digest + RSA-SHA1 signature (lines 143, 195) — **слаб** но SIRMA-compatible
- TLS: самоподписан cert, генериран при старт

## Hardcoded paths

| Line | Path |
|------|------|
| 33 | `/usr/lib64/pkcs11/onepin-opensc-pkcs11.so` |
| 37-39 | Alternative PKCS#11 lib paths |

## Import bug

Line 269: `ipaddress.IPv4Address` — модулът се import-ва на line 392 (в `__main__`).
Ще fail-не ако `_generate_self_signed_cert` се вика от друг модул.

## Summary

| Severity | Line | Issue |
|----------|------|-------|
| HIGH | 360 | `--pin` видим в process list |
| HIGH | 274 | TLS private key без encryption и chmod |
| HIGH | 345 | Без authentication на WebSocket |
| MEDIUM | 331 | Exception leak към client |
| MEDIUM | 143 | SHA-1 (SIRMA compatibility) |
| LOW | 50 | PIN в паметта за целия uptime |
| LOW | 269 | `ipaddress` import location |

**Localhost only. No outbound connections. PIN never logged or sent over network.**
**Smart card private key never leaves the card (PKCS#11).**
