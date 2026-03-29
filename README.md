# prb-signer

Python replacement for SIRMA DigitalSignServer Java applet.
Signs XML documents for e-services.prb.bg using B-Trust QES smart card.

## Problem

e-services.prb.bg (Prokuratura) requires a Java Web Start applet
for digital signing. The applet:
- Requires Java 8 (EOL)
- Uses deprecated JNLP (removed from Java 11+)
- Has expired SSL certificate (2026-02-23)
- Uses Jetty 9.2.7 from 2015
- Takes days to set up on Linux

## Solution

Python WebSocket server that speaks the same protocol.
Drop-in replacement — the browser doesn't know the difference.

## How it works

```
Browser (e-services.prb.bg)
    |
    | WebSocket JSON: {"type":"XmlString","xml":"...","stampToken":"..."}
    |
prb_signer.py (wss://127.0.0.1:38383/sign/)
    |
    | PKCS#11 (PyKCS11 + OpenSC)
    |
B-Trust Smart Card → signed XML → browser
```

## Setup

```bash
# Uses the same venv as pdfsign
./go.sh
```

First run installs: `websockets`, `signxml`, `PyKCS11`, `lxml`

## Usage

```bash
# Interactive PIN prompt:
./go.sh

# With PIN on command line:
./go.sh --pin 1234

# Custom port:
./go.sh --port 39383

# Custom PKCS#11 library:
./go.sh --pkcs11-lib /path/to/opensc-pkcs11.so
```

Then open Firefox, go to e-services.prb.bg, sign as usual.

## Firefox setup

Add security exception for `https://127.0.0.1:38383`:
1. Open `https://127.0.0.1:38383` in Firefox
2. Accept the self-signed certificate warning
3. Done — browser will now connect to prb_signer

## Files

- `prb_signer.py` — main server
- `go.sh` — launcher (venv + deps + run)
- `SIRMA_PROTOCOL.md` — reverse-engineered protocol docs
- `digital-sign-server.jar` — original SIRMA JAR (reference)
- `DigitalSignServer.cer` — original SIRMA certificate
- `DigitalSignLocal.jnlp` — original JNLP launcher

## Requirements

- Python 3.10+
- OpenSC (`emerge opensc`)
- B-Trust smart card reader (pcscd running)
- Firefox

## Status

DRAFT — needs testing with live e-services.prb.bg session.
PKCS#11 ↔ signxml integration may need adjustments.

## SECURITY AUDIT

**See [AUDIT.md](AUDIT.md) for full security analysis.**

## Original Java applet analysis

See `SIRMA_PROTOCOL.md` for full protocol details including
the legendary PIGN/POGN messages (not PING/PONG).

---

# NO MORE PIGN/POGN. 😄

*SCteam, 2026-03-29*
