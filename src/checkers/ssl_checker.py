"""
ssl_checker.py — Analiza el certificado SSL/TLS y versiones de protocolo soportadas.

Errores de red (timeout, conexión rechazada) → se omite el módulo sin generar hallazgos.
Solo se reportan hallazgos cuando la conexión TLS fue exitosa.
"""

import ssl
import socket
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from ..parser import Finding, Instance


_RISK_CODE = {"Critical": "4", "High": "3", "Medium": "2", "Low": "1", "Informational": "0"}


def _finding(name, risk, desc, solution, cwe="327", evidence="") -> Finding:
    inst = [Instance(uri="", method="", param="", attack="", evidence=evidence)] if evidence else []
    return Finding(
        plugin_id="", name=name, risk=risk, risk_code=_RISK_CODE[risk],
        confidence="3", description=desc, solution=solution,
        reference="", cwe_id=cwe, wasc_id="4", count=1, instances=inst, source="ssl",
    )


def _connect_tls(hostname: str, port: int, timeout: int,
                 verify: bool = True) -> Tuple[dict, str]:
    """
    Intenta un handshake TLS. Devuelve (cert_dict, protocol_version).
    Lanza ssl.SSLCertVerificationError si el cert no es válido (esperado).
    Lanza socket.timeout / OSError si hay problema de red (no es hallazgo SSL).
    """
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
            cert = tls.getpeercert(binary_form=False) or {}
            proto = tls.version() or ""
    return cert, proto


def _try_tls_version(hostname: str, port: int,
                     min_ver: ssl.TLSVersion, max_ver: ssl.TLSVersion,
                     timeout: int = 10) -> bool:
    """
    Retorna True si el servidor acepta una conexión con esa versión exacta de TLS.
    Silencia todos los errores (timeout, SSL error, etc.) — devuelve False si falla.
    """
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = min_ver
        ctx.maximum_version = max_ver
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname):
                return True
    except Exception:
        return False


class SSLChecker:
    """Analiza el certificado y configuración TLS del servidor."""

    # Errores de red que no son vulnerabilidades SSL — se omiten silenciosamente
    _NETWORK_ERRORS = (socket.timeout, TimeoutError, ConnectionRefusedError,
                       ConnectionResetError, OSError)

    def check(self, url: str) -> List[Finding]:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = parsed.hostname or parsed.netloc
        port     = parsed.port or 443

        if not hostname:
            return []

        # ── Intentar conexión TLS (con retry en timeout) ──────────────────────
        cert: dict = {}
        cert_error: Optional[str] = None
        self_signed: bool = False
        connected: bool = False

        for attempt, timeout in enumerate([15, 30], 1):
            try:
                cert, _ = _connect_tls(hostname, port, timeout=timeout, verify=True)
                connected = True
                break

            except ssl.SSLCertVerificationError as e:
                # Error SSL real — intentar sin verificación para analizar el cert
                cert_error = str(e)
                try:
                    cert, _ = _connect_tls(hostname, port, timeout=timeout, verify=False)
                    connected = True
                except self._NETWORK_ERRORS as net_e:
                    if attempt == 1:
                        print(f"   ↩️  SSL: timeout sin verificación, reintentando...", flush=True)
                        continue
                    print(f"   ⚠️  SSL: no se pudo conectar ({net_e}) — módulo omitido", flush=True)
                    return []
                except Exception:
                    connected = True  # cert_error ya está seteado; continuar análisis
                # Auto-firmado si el error menciona "self" en alguna forma
                self_signed = any(k in cert_error.lower()
                                  for k in ("self", "self_signed", "self-signed",
                                            "unable to get local issuer"))
                break  # No reintentar en errores SSL

            except self._NETWORK_ERRORS as e:
                if attempt == 1:
                    print(f"   ↩️  SSL: timeout (intento 1), reintentando con 30s...", flush=True)
                    continue
                # Segundo intento también falló — NO es un hallazgo, solo un problema de red
                print(f"   ⚠️  SSL: no se pudo conectar con {hostname}:{port} ({type(e).__name__}) "
                      f"— módulo SSL omitido", flush=True)
                return []

            except Exception as e:
                # Error inesperado (DNS, protocolo, etc.) — no es hallazgo SSL
                print(f"   ⚠️  SSL: error inesperado ({type(e).__name__}: {e}) "
                      f"— módulo SSL omitido", flush=True)
                return []

        if not connected:
            return []

        # ── Analizar resultados ───────────────────────────────────────────────
        findings: List[Finding] = []

        if self_signed:
            findings.append(_finding(
                "Certificado SSL auto-firmado",
                "Medium",
                f"The server at {hostname} presents a self-signed SSL certificate. "
                "Self-signed certificates are not trusted by browsers or operating systems "
                "because they cannot be validated by a trusted Certificate Authority (CA). "
                "This exposes users to man-in-the-middle attacks without any warning from "
                "their browser in automation/API contexts.",
                "Replace the self-signed certificate with one issued by a trusted CA. "
                "Free certificates are available from Let's Encrypt (certbot). "
                "Ensure automated renewal is configured to prevent expiry.",
                "295",
            ))
        elif cert_error and not self_signed:
            findings.append(_finding(
                "Error de validación del certificado SSL",
                "High",
                f"The SSL certificate for {hostname} could not be validated: {cert_error}. "
                "Possible causes include a hostname mismatch, expired certificate, or an "
                "untrusted certificate chain. Users will see browser security warnings.",
                "Verify the certificate is issued by a trusted CA, matches the server hostname "
                "in its Subject Alternative Names, has not expired, and that the full chain "
                "(including intermediates) is correctly served.",
                "297",
                evidence=cert_error[:300],
            ))

        if cert:
            findings += self._check_expiry(cert, hostname)
            findings += self._check_hostname(cert, hostname, cert_error)

        findings += self._check_tls_versions(hostname, port)

        return findings

    def _check_expiry(self, cert: dict, hostname: str) -> List[Finding]:
        not_after = cert.get("notAfter", "")
        if not not_after:
            return []
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expiry - datetime.now(timezone.utc)).days
        except ValueError:
            return []

        issuer_pairs = cert.get("issuer", ())
        issuer = next(
            (v for pair in issuer_pairs for k, v in pair if k == "organizationName"),
            "Unknown CA"
        )

        if days_left < 0:
            return [_finding(
                "Certificado SSL expirado",
                "Critical",
                f"The SSL certificate for {hostname} expired {abs(days_left)} day(s) ago "
                f"(expiry date: {expiry.strftime('%Y-%m-%d')}). Browsers will block access with "
                f"a hard security error that cannot be bypassed. Issuer: {issuer}.",
                "Renew the certificate immediately. If using Let's Encrypt, run: certbot renew. "
                "Configure automated renewal to prevent future outages.",
                "298", evidence=f"Not After: {not_after}",
            )]
        elif days_left <= 14:
            return [_finding(
                f"Certificado SSL expira en {days_left} días — renovación urgente",
                "High",
                f"The SSL certificate for {hostname} expires in {days_left} day(s) "
                f"(on {expiry.strftime('%Y-%m-%d')}). Immediate renewal is required to prevent "
                f"service disruption. Issuer: {issuer}.",
                "Renew the certificate before it expires. Set up automated renewal if not already done.",
                "298", evidence=f"Not After: {not_after}",
            )]
        elif days_left <= 30:
            return [_finding(
                f"Certificado SSL expira pronto ({days_left} días)",
                "Medium",
                f"The SSL certificate for {hostname} will expire in {days_left} day(s) "
                f"(on {expiry.strftime('%Y-%m-%d')}). Plan renewal to avoid downtime. Issuer: {issuer}.",
                "Schedule certificate renewal. Configure automated renewal (e.g., certbot --deploy-hook).",
                "298", evidence=f"Not After: {not_after}",
            )]
        return []

    def _check_hostname(self, cert: dict, hostname: str,
                        cert_error: Optional[str]) -> List[Finding]:
        if not cert_error:
            return []
        err = cert_error.lower()
        if "hostname" not in err and "mismatch" not in err and "match" not in err:
            return []
        san = cert.get("subjectAltName", ())
        san_names = [v for _, v in san]
        return [_finding(
            "Mismatch entre hostname y certificado SSL",
            "Critical",
            f"The SSL certificate does not match the hostname '{hostname}'. "
            f"Certificate covers: {', '.join(san_names) or 'unknown'}. "
            "Attackers can exploit this for undetected man-in-the-middle attacks.",
            f"Obtain a certificate that includes '{hostname}' in its Subject Alternative Names.",
            "297", evidence=cert_error[:300],
        )]

    def _check_tls_versions(self, hostname: str, port: int) -> List[Finding]:
        findings = []

        tls10 = False
        try:
            tls10 = _try_tls_version(hostname, port,
                                     ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1)
        except AttributeError:
            pass  # Python build without TLS 1.0 support

        tls11 = False
        try:
            tls11 = _try_tls_version(hostname, port,
                                     ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1)
        except AttributeError:
            pass

        if tls10:
            findings.append(_finding(
                "TLS 1.0 habilitado en el servidor",
                "High",
                f"The server at {hostname} accepts TLS 1.0 connections. TLS 1.0 was deprecated "
                "in RFC 8996 (2021) and is vulnerable to POODLE, BEAST, and downgrade attacks. "
                "PCI DSS, HIPAA and most compliance frameworks explicitly require disabling it.",
                "Disable TLS 1.0 in the server TLS configuration. Set minimum version to TLS 1.2. "
                "Example (nginx): ssl_protocols TLSv1.2 TLSv1.3;",
                "327", evidence=f"Server accepted TLS 1.0 handshake on {hostname}:{port}",
            ))

        if tls11:
            sev = "Low" if tls10 else "Medium"
            findings.append(_finding(
                "TLS 1.1 habilitado en el servidor",
                sev,
                f"The server at {hostname} accepts TLS 1.1 connections. TLS 1.1 was deprecated "
                "in RFC 8996 (2021). While less vulnerable than TLS 1.0, it lacks support for "
                "authenticated encryption (AEAD) cipher suites available in TLS 1.2+.",
                "Disable TLS 1.1. Set minimum TLS version to 1.2. "
                "Example (nginx): ssl_protocols TLSv1.2 TLSv1.3;",
                "327", evidence=f"Server accepted TLS 1.1 handshake on {hostname}:{port}",
            ))

        return findings
