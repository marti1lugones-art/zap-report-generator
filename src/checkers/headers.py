"""
headers.py — Verifica la presencia y configuración de headers HTTP de seguridad.
"""

from typing import List
import urllib.request
import urllib.error
import ssl

from ..parser import Finding, Instance


# CWE IDs de referencia
_CWE = {
    "csp":         "693",
    "hsts":        "319",
    "xfo":         "1021",
    "xcto":        "116",
    "rp":          "200",
    "pp":          "284",
}


def _get_headers(url: str) -> dict:
    """Hace GET al sitio y devuelve los headers de respuesta (lowercase keys)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (Security-Audit-Bot/1.0)"},
    )
    handler = urllib.request.HTTPSHandler(context=ctx)
    opener = urllib.request.build_opener(handler)
    with opener.open(req, timeout=15) as resp:
        return {k.lower(): v for k, v in resp.headers.items()}


def _finding(name, risk, desc, solution, cwe, evidence="") -> Finding:
    inst = [Instance(uri="", method="GET", param="", attack="", evidence=evidence)] if evidence else []
    return Finding(
        plugin_id="",
        name=name,
        risk=risk,
        risk_code={"Critical": "4", "High": "3", "Medium": "2", "Low": "1", "Informational": "0"}[risk],
        confidence="3",
        description=desc,
        solution=solution,
        reference="",
        cwe_id=cwe,
        wasc_id="",
        count=1,
        instances=inst,
        source="headers",
    )


class HeadersChecker:
    """Verifica headers HTTP de seguridad en la respuesta del servidor."""

    def check(self, url: str) -> List[Finding]:
        try:
            headers = _get_headers(url)
        except Exception as e:
            return [_finding(
                "Error al conectar con el servidor",
                "Informational",
                f"No se pudo obtener los headers HTTP del sitio: {e}",
                "Verificar que el sitio esté disponible y accesible.",
                "",
            )]

        findings: List[Finding] = []
        findings += self._check_csp(headers)
        findings += self._check_hsts(headers, url)
        findings += self._check_xfo(headers)
        findings += self._check_xcto(headers)
        findings += self._check_referrer(headers)
        findings += self._check_permissions(headers)
        return findings

    def _check_csp(self, h: dict) -> List[Finding]:
        val = h.get("content-security-policy", "")
        if not val:
            return [_finding(
                "Content-Security-Policy ausente",
                "High",
                "The Content-Security-Policy (CSP) header is not present in the HTTP response. "
                "Without CSP, the browser has no instructions to restrict the sources from which "
                "scripts, styles, images and other resources can be loaded, leaving the application "
                "highly exposed to Cross-Site Scripting (XSS) and data injection attacks.",
                "Implement a Content-Security-Policy header with at minimum a restrictive "
                "default-src directive. Example: Content-Security-Policy: default-src 'self'; "
                "script-src 'self'; object-src 'none'. Avoid using 'unsafe-inline' or 'unsafe-eval'.",
                _CWE["csp"],
            )]
        issues = []
        if "unsafe-inline" in val:
            issues.append("'unsafe-inline' allows inline scripts/styles")
        if "unsafe-eval" in val:
            issues.append("'unsafe-eval' allows eval() execution")
        if "*" in val and "default-src" in val:
            issues.append("wildcard (*) in default-src negates protection")
        if issues:
            return [_finding(
                "Content-Security-Policy con configuración débil",
                "Medium",
                f"The Content-Security-Policy header is present but contains directives that reduce "
                f"its effectiveness: {'; '.join(issues)}.",
                "Review and harden the CSP policy. Remove 'unsafe-inline', 'unsafe-eval' and "
                "wildcard sources. Use nonces or hashes for inline scripts if needed.",
                _CWE["csp"],
                evidence=val[:200],
            )]
        return []

    def _check_hsts(self, h: dict, url: str) -> List[Finding]:
        if not url.startswith("https"):
            return []
        val = h.get("strict-transport-security", "")
        if not val:
            return [_finding(
                "Strict-Transport-Security (HSTS) ausente",
                "High",
                "The Strict-Transport-Security header is absent. Without HSTS, browsers may connect "
                "via HTTP even when HTTPS is available, making the site vulnerable to SSL-stripping "
                "attacks that silently downgrade the connection.",
                "Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload. "
                "A max-age of at least 6 months (15768000 seconds) is recommended.",
                _CWE["hsts"],
            )]
        # Check max-age value
        max_age = 0
        for part in val.split(";"):
            part = part.strip()
            if part.lower().startswith("max-age="):
                try:
                    max_age = int(part.split("=")[1].strip())
                except ValueError:
                    pass
        if max_age < 15768000:
            return [_finding(
                "HSTS con max-age insuficiente",
                "Low",
                f"The Strict-Transport-Security header is present but has a max-age value of "
                f"{max_age} seconds, which is below the recommended minimum of 15,768,000 seconds "
                f"(approximately 6 months). A low max-age reduces the protection window.",
                "Increase max-age to at least 31,536,000 seconds (1 year) and add includeSubDomains.",
                _CWE["hsts"],
                evidence=val,
            )]
        return []

    def _check_xfo(self, h: dict) -> List[Finding]:
        val = h.get("x-frame-options", "")
        csp = h.get("content-security-policy", "")
        # CSP frame-ancestors is a modern replacement
        if "frame-ancestors" in csp:
            return []
        if not val:
            return [_finding(
                "X-Frame-Options ausente",
                "Medium",
                "The X-Frame-Options header is not set. Without this header, the application can be "
                "embedded in an iframe by a malicious third-party site, enabling Clickjacking attacks "
                "that trick users into interacting with hidden UI elements.",
                "Add the header: X-Frame-Options: DENY (recommended) or X-Frame-Options: SAMEORIGIN. "
                "Alternatively, use Content-Security-Policy: frame-ancestors 'none'.",
                _CWE["xfo"],
            )]
        if val.upper() not in ("DENY", "SAMEORIGIN"):
            return [_finding(
                "X-Frame-Options con valor no estándar",
                "Low",
                f"The X-Frame-Options header is set to '{val}', which is not a standard value. "
                "Only DENY and SAMEORIGIN are defined in the RFC. Invalid values may be ignored by browsers.",
                "Change X-Frame-Options to DENY or SAMEORIGIN.",
                _CWE["xfo"],
                evidence=val,
            )]
        return []

    def _check_xcto(self, h: dict) -> List[Finding]:
        val = h.get("x-content-type-options", "")
        if not val:
            return [_finding(
                "X-Content-Type-Options ausente",
                "Low",
                "The X-Content-Type-Options header is missing. Without it, browsers may try to "
                "guess the MIME type of responses (MIME-sniffing), potentially executing malicious "
                "content as a different type than intended (e.g., interpreting a text file as a script).",
                "Add the header: X-Content-Type-Options: nosniff",
                _CWE["xcto"],
            )]
        return []

    def _check_referrer(self, h: dict) -> List[Finding]:
        val = h.get("referrer-policy", "")
        if not val:
            return [_finding(
                "Referrer-Policy ausente",
                "Low",
                "The Referrer-Policy header is not set. By default, browsers may send the full URL "
                "of the current page as the Referer header to third-party sites, potentially leaking "
                "sensitive information present in URLs (session tokens, user IDs, etc.).",
                "Add the header: Referrer-Policy: strict-origin-when-cross-origin (recommended) "
                "or no-referrer for maximum privacy.",
                _CWE["rp"],
            )]
        unsafe = {"unsafe-url", "no-referrer-when-downgrade", "origin-when-cross-origin"}
        if val.lower() in unsafe:
            return [_finding(
                "Referrer-Policy con política permisiva",
                "Low",
                f"Referrer-Policy is set to '{val}', which may send the full URL including path "
                "and query string to third parties. This can leak sensitive URL parameters.",
                "Use Referrer-Policy: strict-origin-when-cross-origin or no-referrer.",
                _CWE["rp"],
                evidence=val,
            )]
        return []

    def _check_permissions(self, h: dict) -> List[Finding]:
        # Also accept Feature-Policy (legacy name)
        val = h.get("permissions-policy", "") or h.get("feature-policy", "")
        if not val:
            return [_finding(
                "Permissions-Policy ausente",
                "Informational",
                "The Permissions-Policy header (formerly Feature-Policy) is not set. This header "
                "controls which browser features and APIs the page can use. Without it, features "
                "like camera, microphone, geolocation and payment handlers are unrestricted.",
                "Add a Permissions-Policy header restricting unused browser features. Example: "
                "Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()",
                _CWE["pp"],
            )]
        return []
