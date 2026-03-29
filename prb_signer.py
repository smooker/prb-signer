#!/usr/bin/env python3
"""
prb_signer.py — Python replacement for SIRMA DigitalSignServer

WebSocket server on wss://127.0.0.1:38383/sign/ that signs XML documents
using a PKCS#11 smart card (B-Trust QES), compatible with e-services.prb.bg.

Usage:
    pip install websockets signxml PyKCS11 lxml cryptography
    python3 prb_signer.py [--port 38383] [--pin PIN]

Replaces the Java Web Start applet (DigitalSignLocal.jnlp) entirely.
"""

import asyncio
import json
import ssl
import sys
import os
import argparse
import logging
from pathlib import Path
from datetime import datetime

import websockets
from lxml import etree
from signxml import XMLSigner, methods
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import load_der_x509_certificate
import PyKCS11

# PKCS#11 library path (OpenSC)
PKCS11_LIB = "/usr/lib64/pkcs11/onepin-opensc-pkcs11.so"
if not os.path.exists(PKCS11_LIB):
    # Try alternative paths
    for alt in ["/usr/lib/pkcs11/onepin-opensc-pkcs11.so",
                "/usr/lib64/opensc-pkcs11.so",
                "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"]:
        if os.path.exists(alt):
            PKCS11_LIB = alt
            break

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("prb_signer")


class SmartCardSigner:
    """PKCS#11 smart card access for XML signing."""

    def __init__(self, pin=None):
        self.pin = pin
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(PKCS11_LIB)
        self.session = None
        self.cert = None
        self.cert_der = None
        self.privkey_handle = None

    def open(self):
        """Open PKCS#11 session and find certificate + private key."""
        slots = self.pkcs11.getSlotList(tokenPresent=True)
        if not slots:
            raise RuntimeError("No smart card found")

        slot = slots[0]
        token_info = self.pkcs11.getTokenInfo(slot)
        log.info("Token: %s (slot %d)", token_info.label.strip(), slot)

        self.session = self.pkcs11.openSession(slot, PyKCS11.CKF_SERIAL_SESSION)

        if self.pin:
            self.session.login(self.pin)

        # Find all certificates
        certs = self.session.findObjects([
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
            (PyKCS11.CKA_CERTIFICATE_TYPE, PyKCS11.CKC_X_509),
        ])

        if not certs:
            raise RuntimeError("No certificate found on smart card")

        # Collect non-CA certificates with matching private keys
        candidates = []
        for cert_obj in certs:
            attrs = self.session.getAttributeValue(cert_obj, [
                PyKCS11.CKA_VALUE, PyKCS11.CKA_LABEL, PyKCS11.CKA_ID
            ])
            cert_der = bytes(attrs[0])
            cert_label = bytes(attrs[1]).decode('utf-8', errors='replace').strip()
            cert_id = bytes(attrs[2])

            x509 = load_der_x509_certificate(cert_der)

            # Skip CA certs
            try:
                from cryptography.x509 import ExtensionOID
                basic = x509.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
                if basic.value.ca:
                    continue
            except Exception:
                pass

            # Check for matching private key
            privkeys = self.session.findObjects([
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                (PyKCS11.CKA_ID, cert_id),
            ])
            if privkeys:
                candidates.append((cert_label, cert_id, cert_der, x509, privkeys[0]))

        if not candidates:
            raise RuntimeError("No suitable signing certificate found")

        # If multiple — let user choose
        if len(candidates) == 1:
            choice = 0
        else:
            print("\nAvailable signing certificates:")
            for i, (label, _, _, x509, _) in enumerate(candidates):
                subj = x509.subject.rfc4514_string()
                sn = x509.serial_number
                valid = x509.not_valid_after_utc.strftime("%Y-%m-%d")
                print(f"  [{i+1}] {subj}")
                print(f"       Label: {label}  SN: {sn:X}  Valid until: {valid}")
            while True:
                try:
                    choice = int(input(f"\nSelect certificate [1-{len(candidates)}]: ")) - 1
                    if 0 <= choice < len(candidates):
                        break
                except (ValueError, EOFError):
                    pass
                print("Invalid choice.")

        cert_label, cert_id, self.cert_der, self.cert, self.privkey_handle = candidates[choice]
        log.info("Using certificate: %s (SN: %s)", cert_label, self.cert.serial_number)

    def sign_xml(self, xml_str, stamp_token=None):
        """Sign XML document using smart card.

        Args:
            xml_str: XML document as string
            stamp_token: timestamp token (included in signed properties)

        Returns:
            Signed XML as string
        """
        if not self.session or not self.privkey_handle:
            raise RuntimeError("Smart card not opened")

        # Parse XML
        if not xml_str.strip().startswith("<?xml"):
            xml_str = '<?xml version="1.0" encoding="UTF-8"?>' + xml_str

        root = etree.fromstring(xml_str.encode('utf-8'))

        # Sign using signxml with PKCS#11
        # signxml needs a key — we'll use the PKCS#11 session for raw signing
        signer = XMLSigner(
            method=methods.enveloped,
            digest_algorithm="sha1",       # Match SIRMA (SHA-1, unfortunately)
            signature_algorithm="rsa-sha1", # Match SIRMA
            c14n_algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
        )

        # We need to provide the private key for signing
        # signxml can use a PKCS#11 callback or we sign with PyKCS11 directly
        # For now, use the PyKCS11 raw sign approach

        signed_root = self._sign_with_pkcs11(root)

        # Serialize
        result = etree.tostring(signed_root, xml_declaration=True,
                                encoding='UTF-8', pretty_print=False)
        return result.decode('utf-8')

    def _sign_with_pkcs11(self, root):
        """Sign XML using PKCS#11 private key and signxml."""
        from signxml import XMLSigner
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes

        # Create a custom signer that uses PKCS#11 for the actual signing
        # signxml needs a key object — we create a wrapper

        class PKCS11Key:
            """Wrapper to make PyKCS11 private key work with signxml."""
            def __init__(self, session, key_handle, algorithm):
                self.session = session
                self.key_handle = key_handle
                self.algorithm = algorithm

            def sign(self, data, padding_obj, hash_algo):
                """Sign data using PKCS#11."""
                if isinstance(hash_algo, hashes.SHA1):
                    mechanism = PyKCS11.CKM_SHA1_RSA_PKCS
                elif isinstance(hash_algo, hashes.SHA256):
                    mechanism = PyKCS11.CKM_SHA256_RSA_PKCS
                else:
                    mechanism = PyKCS11.CKM_SHA1_RSA_PKCS

                sig = self.session.sign(self.key_handle, data, PyKCS11.Mechanism(mechanism))
                return bytes(sig)

            @property
            def key_size(self):
                return 2048  # Common for B-Trust

        pk11_key = PKCS11Key(self.session, self.privkey_handle, "RSA")

        signer = XMLSigner(
            method=methods.enveloped,
            digest_algorithm="sha1",
            signature_algorithm="rsa-sha1",
            c14n_algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
        )

        signed = signer.sign(root, key=pk11_key, cert=[self.cert_der])
        return signed

    def close(self):
        """Close PKCS#11 session."""
        if self.session:
            try:
                self.session.logout()
            except Exception:
                pass
            self.session.closeSession()
            self.session = None


class PRBSignerServer:
    """WebSocket server compatible with SIRMA DigitalSignServer protocol."""

    def __init__(self, host="127.0.0.1", port=38383, certfile=None, keyfile=None, pin=None):
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.pin = pin
        self.signer = None

    def _get_ssl_context(self):
        """Create SSL context with self-signed cert."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if self.certfile and self.keyfile:
            ctx.load_cert_chain(self.certfile, self.keyfile)
        else:
            # Generate self-signed cert on the fly
            self._generate_self_signed_cert()
            ctx.load_cert_chain(self._cert_path, self._key_path)
        return ctx

    def _generate_self_signed_cert(self):
        """Generate self-signed cert for 127.0.0.1."""
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
        import datetime

        cert_dir = Path(__file__).parent / "certs"
        cert_dir.mkdir(exist_ok=True)
        self._cert_path = str(cert_dir / "server.pem")
        self._key_path = str(cert_dir / "server.key")

        if os.path.exists(self._cert_path):
            return

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        today = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d")
        name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "BG"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Sofia"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Sofia"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SCteam"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "IT@SCteam"),
            x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
        ])
        cert = (x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.now(datetime.UTC))
                .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=3650))
                .add_extension(
                    x509.SubjectAlternativeName([
                        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                        x509.DNSName("localhost"),
                        x509.DNSName("127.0.0.1"),
                        x509.RFC822Name("sc@smooker.org"),
                        x509.DirectoryName(x509.Name([
                            x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
                        ])),
                    ]),
                    critical=False,
                )
                .sign(key, hashes.SHA256()))

        with open(self._key_path, "wb") as f:
            f.write(key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))
        with open(self._cert_path, "wb") as f:
            f.write(cert.public_bytes(Encoding.PEM))

        log.info("Generated self-signed cert: %s", self._cert_path)

    async def handle_websocket(self, websocket, path=None):
        """Handle WebSocket connection."""
        log.info("Socket Connected: %s", websocket.remote_address)

        try:
            async for message in websocket:
                log.info("Received: %.80s...", message)

                # Control messages
                if message in ("STOP", "stop"):
                    log.info("Stop requested")
                    await websocket.close()
                    return

                if not message.startswith('{"type"'):
                    await websocket.send("who are you?")
                    continue

                try:
                    data = json.loads(message)
                except json.JSONDecodeError:
                    await websocket.send("ERROR: Invalid JSON")
                    continue

                msg_type = data.get("type", "")
                if msg_type != "XmlString":
                    await websocket.send("ERROR: Unknown type: " + msg_type)
                    continue

                xml_str = data.get("xml", "")
                stamp_token = data.get("stampToken", "")

                # Unescape Java-style escapes (the original uses StringEscapeUtils.unescapeJava)
                xml_str = xml_str.encode().decode('unicode_escape')

                log.info("Signing [%.60s...] with stampToken [%s]", xml_str, stamp_token)

                try:
                    # Initialize signer on first sign request
                    if not self.signer:
                        pin = self.pin
                        if not pin:
                            import getpass
                            print()  # newline after log output
                            pin = getpass.getpass("Smart card PIN (first sign request): ")
                        self.signer = SmartCardSigner(pin=pin)
                        self.signer.open()

                    signed_xml = self.signer.sign_xml(xml_str, stamp_token)
                    log.info("XML is signed.")
                    await websocket.send(signed_xml)

                except Exception as e:
                    error_msg = f"ERROR: {e}"
                    log.error(error_msg)
                    await websocket.send(error_msg)

        except websockets.exceptions.ConnectionClosed as e:
            log.info("Socket Closed: [%s] %s", e.code, e.reason)
        except Exception as e:
            log.error("WebSocket error: %s", e)

    async def run(self):
        """Start the WebSocket server."""
        ssl_ctx = self._get_ssl_context()

        log.info("Starting PRB Signer on wss://%s:%d/sign/", self.host, self.port)
        log.info("PKCS#11 lib: %s", PKCS11_LIB)

        async with websockets.serve(
            self.handle_websocket,
            self.host,
            self.port,
            ssl=ssl_ctx,
            subprotocols=None,
        ):
            log.info("Server ready. Listening for browser requests...")
            print()
            print("FIRST TIME?")
            print("  1. Open https://127.0.0.1:38383 in Firefox")
            print("  2. Accept the self-signed certificate warning")
            print("  3. Go to https://e-services.prb.bg")
            print("  4. Sign your document — PIN will be asked here")
            print()
            await asyncio.Future()  # run forever


def main():
    parser = argparse.ArgumentParser(description="PRB Digital Signer — SIRMA replacement")
    parser.add_argument("--port", type=int, default=38383, help="Listen port (default: 38383)")
    parser.add_argument("--host", default="127.0.0.1", help="Listen address")
    parser.add_argument("--pin", help="Smart card PIN (interactive prompt if not given)")
    parser.add_argument("--cert", help="SSL certificate PEM file")
    parser.add_argument("--key", help="SSL private key PEM file")
    parser.add_argument("--pkcs11-lib", help="PKCS#11 library path")
    args = parser.parse_args()

    if args.pkcs11_lib:
        global PKCS11_LIB
        PKCS11_LIB = args.pkcs11_lib

    server = PRBSignerServer(
        host=args.host,
        port=args.port,
        certfile=args.cert,
        keyfile=args.key,
        pin=args.pin,  # None = will prompt on first sign request
    )

    try:
        asyncio.run(server.run())
    except KeyboardInterrupt:
        log.info("Shutting down...")
        if server.signer:
            server.signer.close()


if __name__ == "__main__":
    import ipaddress  # needed for cert generation
    main()
