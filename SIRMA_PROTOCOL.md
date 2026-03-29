# SIRMA DigitalSignServer — Protocol Analysis

Reverse-engineered from `digital-sign-server-1.0-SNAPSHOT.jar` (e-services.prb.bg)

## Architecture

```
Browser (e-services.prb.bg)
    |
    | WebSocket (wss://127.0.0.1:38383/sign/)
    |
Local HTTPS Server (Jetty 9.2.7, self-signed cert)
    |
    | PKCS#11 (IAIK wrapper)
    |
Smart Card (B-Trust QES)
```

## Server

- HTTPS on `127.0.0.1:38383` (SSL, self-signed cert `DigitalSignServer.jks`)
- Also tries ports: 39383, 40383, 41383, 42383, 43383, 44383, 45383, 46383, 47383, 48383
- WebSocket endpoint: `/sign/`
- Servlet: `com.sirma.digitalsign.DigitalSignServlet`
- Handler: `com.sirma.digitalsign.DigitalSignWebSocket`

## WebSocket Protocol

### Incoming (browser → server)

JSON message:
```json
{"type":"XmlString","xml":"<UserService><id>7736</id>...</UserService>","stampToken":"2026-03-29T05:37:35.749"}
```

Fields:
- `type`: always `"XmlString"`
- `xml`: XML document to sign (Java-escaped)
- `stampToken`: ISO timestamp for the signature

### Outgoing (server → browser)

On success: signed XML as UTF-8 string (the original XML with `<Signature>` element appended)

On error: `"ERROR: <message>"`

### Control messages

- `STOP_MESSAGE` — shutdown
- `PIGN_MESSAGE` — ping
- `SHOW_UP_MESSAGE` — show dialog
- `POGN_MESSAGE` — pong
- Unknown message → responds `"who are you?"`

## XML Signing Details

Source: `com.sirma.digitalsign.signer.XmlStringSigner`

### Algorithm
- Digest: **SHA-1** (`http://www.w3.org/2000/09/xmldsig#sha1`)
- Transform: **enveloped-signature** (`http://www.w3.org/2000/09/xmldsig#enveloped-signature`)
- Canonicalization: **C14N with comments** (`http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments`)
- Signature method: **RSA-SHA1** or **DSA-SHA1** (auto-detected from key algorithm)

### KeyInfo
- KeyValue (public key)
- X509Data (certificate)

### Signing flow
1. Parse JSON, extract `xml` and `stampToken`
2. `StringEscapeUtils.unescapeJava(xml)` — unescape Java string
3. Prepend `<?xml version="1.0" encoding="UTF-8"?>` if missing
4. Parse XML → DOM Document
5. Get X509Certificate + PrivateKey from smart card (PKCS#11 via IAIK)
6. Create DOMSignContext with private key
7. Create enveloped XMLSignature (SHA-1 digest, RSA/DSA-SHA1)
8. Sign and canonicalize
9. Return signed XML bytes as UTF-8 string

## PKCS#11 / Smart Card

Source: `com.sirma.digitalsign.card.IaikWrapper`

- Uses IAIK PKCS#11 wrapper (`iaikPkcs11Wrapper.jar`)
- Loads PKCS#11 native library (platform-dependent DLL/SO)
- Opens module, gets token, finds certificate + private key
- GUI dialogs for: library selection, PIN entry, certificate selection

## Certificate (self-signed, for local HTTPS)

```
Subject: C=BG, ST=Sofia, L=Sofia, O=Sirma, OU=Sirma Solutions, CN=127.0.0.1
Valid: 2016-02-26 to 2026-02-23 (EXPIRED!)
```

Embedded in JAR as `DigitalSignServer.jks` (Java KeyStore)

## Known Issues

- Java 8 (EOL) required
- Java Web Start (JNLP) deprecated since Java 9, removed since Java 11
- Self-signed certificate expired 2026-02-23
- Jetty 9.2.7 from 2015 — known vulnerabilities
- SHA-1 digest — deprecated, weak
- JNLP requests `<all-permissions/>`
- Browser must add security exception for https://127.0.0.1:38383

## Python Replacement Plan

Replace Java applet with Python WebSocket server:
1. `websockets` or `aiohttp` — WSS server on 127.0.0.1:38383
2. Same self-signed cert (or generate new)
3. `signxml` — XML digital signature (enveloped, SHA-256 upgrade)
4. `PyKCS11` or `python-pkcs11` — smart card access
5. Parse same JSON protocol, return signed XML
6. No Java needed!
