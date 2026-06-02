"""
email_security.py — Verifica SPF, DMARC y DKIM en los registros DNS del dominio.
"""

from typing import List, Optional
from ..parser import Finding, Instance


_RISK_CODE = {"Critical": "4", "High": "3", "Medium": "2", "Low": "1", "Informational": "0"}

DKIM_SELECTORS = ["google", "selector1", "selector2", "default", "mail", "dkim", "k1"]


def _finding(name, risk, desc, solution, cwe="345", evidence="") -> Finding:
    inst = [Instance(uri="", method="DNS", param="", attack="", evidence=evidence)] if evidence else []
    return Finding(
        plugin_id="",
        name=name,
        risk=risk,
        risk_code=_RISK_CODE[risk],
        confidence="3",
        description=desc,
        solution=solution,
        reference="",
        cwe_id=cwe,
        wasc_id="",
        count=1,
        instances=inst,
        source="email",
    )


def _dns_txt(domain: str) -> List[str]:
    import dns.resolver
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=10)
        return [b.decode() if isinstance(b, bytes) else str(b)
                for rdata in answers
                for b in (rdata.strings if hasattr(rdata, "strings") else [str(rdata)])]
    except Exception:
        return []


class EmailSecurityChecker:
    """Verifica la configuración de seguridad de email del dominio."""

    def check(self, url: str) -> List[Finding]:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.hostname or parsed.netloc
        if not domain:
            return []

        findings: List[Finding] = []
        findings += self._check_spf(domain)
        findings += self._check_dmarc(domain)
        findings += self._check_dkim(domain)
        return findings

    # ── SPF ───────────────────────────────────────────────────────────────
    def _check_spf(self, domain: str) -> List[Finding]:
        records = _dns_txt(domain)
        spf_records = [r for r in records if r.startswith("v=spf1")]

        if not spf_records:
            return [_finding(
                "Registro SPF ausente",
                "High",
                f"The domain '{domain}' has no SPF (Sender Policy Framework) DNS record. "
                "SPF specifies which mail servers are authorized to send email on behalf of the "
                "domain. Without SPF, any server can send email claiming to be from this domain, "
                "making it trivial to spoof the sender address in phishing attacks.",
                f"Add a TXT record to '{domain}' with the form: v=spf1 include:mail-provider.com ~all. "
                "List all authorized sending sources and use -all (hard fail) to reject unauthorized senders.",
                "345",
            )]

        if len(spf_records) > 1:
            return [_finding(
                "Múltiples registros SPF detectados",
                "Medium",
                f"The domain '{domain}' has {len(spf_records)} SPF records. RFC 7208 requires "
                "exactly one SPF record per domain. Multiple records cause evaluation failures "
                "in mail receivers, effectively disabling SPF protection.",
                "Merge all SPF directives into a single TXT record.",
                "345",
                evidence=" | ".join(spf_records),
            )]

        spf = spf_records[0]
        findings = []

        if "+all" in spf:
            findings.append(_finding(
                "SPF con mecanismo +all (pass all) — crítico",
                "Critical",
                f"The SPF record for '{domain}' ends with '+all', which explicitly authorizes ANY "
                "server in the world to send email as this domain. This completely defeats the "
                "purpose of SPF and makes the domain trivially spoofable. "
                f"Record: {spf}",
                "Replace '+all' with '-all' (hard fail) to reject all unauthorized senders. "
                "Update the record to list only legitimate sending sources before applying -all.",
                "345",
                evidence=spf,
            ))
        elif "?all" in spf:
            findings.append(_finding(
                "SPF con mecanismo ?all (neutral)",
                "Medium",
                f"The SPF record for '{domain}' ends with '?all' (neutral), which means mail "
                "receivers take no action on unauthorized senders. This provides no spoofing "
                "protection. Record: {spf}",
                "Replace '?all' with '-all' (hard fail) or at minimum '~all' (soft fail).",
                "345",
                evidence=spf,
            ))
        elif "~all" in spf:
            findings.append(_finding(
                "SPF con softfail (~all) en lugar de hardfail (-all)",
                "Low",
                f"The SPF record uses '~all' (softfail), which marks unauthorized emails as "
                "suspicious but does not reject them. Depending on the receiver's policy, "
                "spoofed emails may still be delivered. Record: {spf}",
                "Consider upgrading to '-all' (hardfail) once all legitimate sending sources are "
                "documented in the SPF record. Ensure no authorized senders are missing first.",
                "345",
                evidence=spf,
            ))

        return findings

    # ── DMARC ─────────────────────────────────────────────────────────────
    def _check_dmarc(self, domain: str) -> List[Finding]:
        dmarc_domain = f"_dmarc.{domain}"
        records = _dns_txt(dmarc_domain)
        dmarc_records = [r for r in records if "v=DMARC1" in r]

        if not dmarc_records:
            return [_finding(
                "Registro DMARC ausente",
                "High",
                f"The domain '{domain}' has no DMARC (Domain-based Message Authentication, "
                "Reporting and Conformance) policy. Without DMARC, even if SPF and DKIM pass, "
                "there is no policy instructing receivers what to do with failing messages. "
                "The domain is vulnerable to email spoofing and phishing impersonation.",
                f"Add a DMARC TXT record at '_dmarc.{domain}'. Start with monitoring mode: "
                "v=DMARC1; p=none; rua=mailto:dmarc-reports@yourdomain.com. "
                "Progress to p=quarantine and then p=reject as confidence grows.",
                "345",
            )]

        dmarc = dmarc_records[0]
        policy = ""
        for part in dmarc.split(";"):
            part = part.strip()
            if part.startswith("p="):
                policy = part[2:].strip().lower()
                break

        if policy == "none":
            return [_finding(
                "DMARC con política p=none (solo monitoreo)",
                "Medium",
                f"The DMARC record for '{domain}' has policy p=none, which only monitors email "
                "flows and sends reports but does not quarantine or reject unauthorized emails. "
                "Spoofed emails are still delivered to recipients. Record: {dmarc}",
                "Analyze DMARC aggregate reports to identify all legitimate email sources. "
                "Once confident, upgrade to p=quarantine and eventually p=reject.",
                "345",
                evidence=dmarc,
            )]
        elif policy == "quarantine":
            return [_finding(
                "DMARC con política p=quarantine (protección parcial)",
                "Low",
                f"The DMARC record uses p=quarantine, which marks unauthorized emails as spam "
                "rather than rejecting them outright. Spoofed emails may still reach users' "
                "spam folders. Record: {dmarc}",
                "Once all legitimate sending sources are covered by SPF/DKIM, upgrade to "
                "p=reject to fully block unauthorized use of the domain.",
                "345",
                evidence=dmarc,
            )]
        elif policy == "reject":
            return []  # Good configuration
        else:
            return [_finding(
                "Política DMARC no reconocida",
                "Low",
                f"The DMARC record has an unrecognized or missing policy value: '{policy}'. "
                f"Record: {dmarc}",
                "Ensure the DMARC record contains a valid p= value: none, quarantine, or reject.",
                "345",
                evidence=dmarc,
            )]

    # ── DKIM ─────────────────────────────────────────────────────────────
    def _check_dkim(self, domain: str) -> List[Finding]:
        found_selector: Optional[str] = None
        found_record: Optional[str] = None

        for selector in DKIM_SELECTORS:
            dkim_domain = f"{selector}._domainkey.{domain}"
            records = _dns_txt(dkim_domain)
            dkim_records = [r for r in records if "v=DKIM1" in r or "p=" in r]
            if dkim_records:
                found_selector = selector
                found_record = dkim_records[0]
                break

        if found_selector:
            # DKIM found — check if key is revoked (p= empty)
            if 'p=""' in (found_record or "") or "p=;" in (found_record or ""):
                return [_finding(
                    f"DKIM encontrado pero clave revocada (selector: {found_selector})",
                    "Medium",
                    f"A DKIM record was found for selector '{found_selector}' at "
                    f"'{found_selector}._domainkey.{domain}', but the public key (p=) is empty, "
                    "indicating the key has been explicitly revoked. Emails signed with this "
                    "selector will fail DKIM validation.",
                    "Generate a new DKIM key pair, publish the new public key in DNS, and "
                    "configure your mail server to sign with the new private key.",
                    "345",
                    evidence=found_record[:200] if found_record else "",
                )]
            return []  # Good — DKIM is configured

        # Not found in common selectors
        return [_finding(
            "DKIM no encontrado en selectores comunes",
            "Medium",
            f"DKIM (DomainKeys Identified Mail) was not found in any of the commonly used "
            f"selectors checked: {', '.join(DKIM_SELECTORS)}. "
            "Note: this does not confirm that DKIM is absent — the domain may be using a "
            "custom selector not included in this scan. However, if DKIM is not configured, "
            "emails from this domain cannot be cryptographically verified by recipients, "
            "reducing protection against email forgery.",
            f"Verify whether DKIM is configured with a non-standard selector by checking your "
            "email provider's documentation. If DKIM is not set up, generate a key pair and "
            "add the public key as a TXT record at SELECTOR._domainkey." + domain,
            "345",
        )]
