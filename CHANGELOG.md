# Changelog

## 2026-03-29 11:07 — PRODUCTION!

First real document signed successfully!
- XML: 3016 bytes, преписка 39240, serviceType=3
- Signed in 0.25 seconds
- Portal accepted it
- The Java applet FAILED this morning. prb-signer SUCCEEDED.

## 2026-03-29

### Initial release
- WebSocket server (WSS) on 127.0.0.1:38383
- PKCS#11 XML signing via PyKCS11 + signxml
- SIRMA protocol compatible (JSON: type/xml/stampToken)
- Self-signed TLS cert generation
- go.sh launcher with venv + deps

### Smart card UX
- Interactive PIN prompt (getpass, no echo)
- Smart card presence check before PIN prompt
- pcscd running check
- Certificate listing with subject, SN, validity
- Interactive certificate selection when multiple found

### Documentation
- SIRMA_PROTOCOL.md — reverse-engineered from JAR decompilation
- AUDIT.md — security analysis (PIN handling, network, file I/O)
- README.md with setup + usage instructions
