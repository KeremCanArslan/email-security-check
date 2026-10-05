"""Email security check for a domain: MX, SPF, DMARC, DKIM and MTA-STS.

Usage:
    python emailsec.py example.com
    python emailsec.py example.com --lang tr
    python emailsec.py example.com --json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field, asdict

import dns.exception
import dns.resolver

COMMON_DKIM_SELECTORS = (
    "default", "google", "selector1", "selector2", "k1", "k2", "s1", "s2",
    "mail", "dkim", "smtp", "mandrill", "mxvault", "zoho",
)
SPF_LOOKUP_LIMIT = 10  # RFC 7208, section 4.6.4
SPF_LOOKUP_TERMS = re.compile(r"^[+\-~?]?(include:|a\b|a:|a/|mx\b|mx:|mx/|ptr|exists:|redirect=)", re.I)


class DnsClient:
    """Thin wrapper around dnspython that returns empty lists instead of raising."""

    def __init__(self, timeout: float = 5.0):
        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = timeout

    def _query(self, name: str, rtype: str):
        try:
            return self.resolver.resolve(name, rtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
                dns.exception.Timeout, dns.name.EmptyLabel):
            return []

    def txt(self, name: str) -> list[str]:
        return [b"".join(r.strings).decode("utf-8", "replace") for r in self._query(name, "TXT")]

    def mx(self, name: str) -> list[str]:
        records = sorted(self._query(name, "MX"), key=lambda r: r.preference)
        return [str(r.exchange).rstrip(".") for r in records]


@dataclass
class Finding:
    check: str
    status: str  # "ok", "warn", "fail", "info"
    key: str     # message key, rendered per language
    detail: str = ""
    penalty: int = 0


@dataclass
class Report:
    domain: str
    mx: list[str] = field(default_factory=list)
    spf: str | None = None
    spf_lookups: int = 0
    dmarc: str | None = None
    dkim_selectors: list[str] = field(default_factory=list)
    mta_sts: bool = False
    findings: list[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        return max(0, 100 - sum(f.penalty for f in self.findings))

    @property
    def grade(self) -> str:
        s = self.score
        return "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else "D" if s >= 40 else "F"


def spf_records(txts: list[str]) -> list[str]:
    return [t for t in txts if t.lower().startswith("v=spf1")]


def count_spf_lookups(record: str, dns_client: DnsClient, seen: set[str] | None = None, depth: int = 0) -> int:
    """Count DNS-querying SPF terms, following include: and redirect= recursively."""
    seen = seen if seen is not None else set()
    total = 0
    for term in record.split()[1:]:
        if not SPF_LOOKUP_TERMS.match(term):
            continue
        total += 1
        target = None
        low = term.lower().lstrip("+-~?")
        if low.startswith("include:"):
            target = term.split(":", 1)[1]
        elif low.startswith("redirect="):
            target = term.split("=", 1)[1]
        if target and target not in seen and depth < 10:
            seen.add(target)
            nested = spf_records(dns_client.txt(target))
            if nested:
                total += count_spf_lookups(nested[0], dns_client, seen, depth + 1)
    return total


def parse_tags(record: str) -> dict[str, str]:
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def check_domain(domain: str, dns_client: DnsClient | None = None,
                 selectors: tuple[str, ...] = COMMON_DKIM_SELECTORS) -> Report:
    dns_client = dns_client or DnsClient()
    domain = domain.strip().lower().rstrip(".")
    rep = Report(domain=domain)
    add = rep.findings.append

    # MX
    rep.mx = dns_client.mx(domain)
    if rep.mx:
        add(Finding("MX", "ok", "mx_ok", ", ".join(rep.mx[:3])))
    else:
        add(Finding("MX", "info", "mx_none"))

    # SPF
    spfs = spf_records(dns_client.txt(domain))
    if not spfs:
        add(Finding("SPF", "fail", "spf_missing", penalty=30))
    else:
        rep.spf = spfs[0]
        if len(spfs) > 1:
            add(Finding("SPF", "fail", "spf_multiple", str(len(spfs)), penalty=20))
        last = rep.spf.split()[-1].lower()
        if last == "+all" or last == "all":
            add(Finding("SPF", "fail", "spf_plus_all", penalty=30))
        elif last == "?all":
            add(Finding("SPF", "warn", "spf_neutral_all", penalty=15))
        elif last in ("~all", "-all"):
            add(Finding("SPF", "ok", "spf_ok", last))
        elif not last.startswith("redirect="):
            add(Finding("SPF", "warn", "spf_no_all", penalty=10))
        rep.spf_lookups = count_spf_lookups(rep.spf, dns_client)
        if rep.spf_lookups > SPF_LOOKUP_LIMIT:
            add(Finding("SPF", "fail", "spf_too_many_lookups", str(rep.spf_lookups), penalty=20))

    # DMARC
    dmarcs = [t for t in dns_client.txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    if not dmarcs:
        add(Finding("DMARC", "fail", "dmarc_missing", penalty=30))
    else:
        rep.dmarc = dmarcs[0]
        tags = parse_tags(rep.dmarc)
        policy = tags.get("p", "").lower()
        if policy == "none":
            add(Finding("DMARC", "warn", "dmarc_none", penalty=15))
        elif policy in ("quarantine", "reject"):
            add(Finding("DMARC", "ok", "dmarc_ok", policy))
        else:
            add(Finding("DMARC", "fail", "dmarc_invalid", policy or "-", penalty=20))
        if tags.get("pct", "100") != "100":
            add(Finding("DMARC", "warn", "dmarc_pct", tags["pct"], penalty=5))
        if "rua" not in tags:
            add(Finding("DMARC", "warn", "dmarc_no_rua", penalty=5))

    # DKIM (selectors cannot be listed through DNS, so only common ones are probed)
    for sel in selectors:
        if any("p=" in t for t in dns_client.txt(f"{sel}._domainkey.{domain}")):
            rep.dkim_selectors.append(sel)
    if rep.dkim_selectors:
        add(Finding("DKIM", "ok", "dkim_ok", ", ".join(rep.dkim_selectors)))
    else:
        add(Finding("DKIM", "warn", "dkim_not_found", penalty=10))

    # MTA-STS
    rep.mta_sts = any(t.lower().startswith("v=stsv1") for t in dns_client.txt(f"_mta-sts.{domain}"))
    add(Finding("MTA-STS", "ok" if rep.mta_sts else "info",
                "mta_sts_ok" if rep.mta_sts else "mta_sts_missing", penalty=0 if rep.mta_sts else 5))
    return rep


MESSAGES = {
    "en": {
        "title": "Email security report", "score": "Score", "check": "Check", "status": "Status", "result": "Result",
        "mx_ok": "Mail servers found: {d}",
        "mx_none": "No MX record. The domain does not receive email; SPF and DMARC still protect it from spoofing.",
        "spf_missing": "No SPF record. Anyone can send email that claims to come from this domain.",
        "spf_multiple": "{d} SPF records found. Only one is allowed; receivers treat this as an error.",
        "spf_plus_all": "SPF ends with +all, which authorises every server on the internet.",
        "spf_neutral_all": "SPF ends with ?all, which gives no protection.",
        "spf_ok": "SPF record is valid and ends with {d}.",
        "spf_no_all": "SPF record has no 'all' mechanism at the end.",
        "spf_too_many_lookups": "SPF needs {d} DNS lookups; the limit is 10, so validation fails.",
        "dmarc_missing": "No DMARC record. Spoofed email is not rejected and no reports are received.",
        "dmarc_none": "DMARC policy is p=none (monitoring only). Spoofed email is still delivered.",
        "dmarc_ok": "DMARC policy is p={d}.",
        "dmarc_invalid": "DMARC policy value is invalid: {d}",
        "dmarc_pct": "DMARC applies to only {d}% of messages.",
        "dmarc_no_rua": "DMARC has no rua address, so aggregate reports are not collected.",
        "dkim_ok": "DKIM key found for selector(s): {d}",
        "dkim_not_found": "No DKIM key found for common selectors. Verify with the email provider.",
        "mta_sts_ok": "MTA-STS is published.",
        "mta_sts_missing": "MTA-STS is not published (recommended, not required).",
    },
    "tr": {
        "title": "E-posta güvenlik raporu", "score": "Puan", "check": "Kontrol", "status": "Durum", "result": "Sonuç",
        "mx_ok": "Posta sunucuları bulundu: {d}",
        "mx_none": "MX kaydı yok. Alan adı e-posta almıyor; SPF ve DMARC yine de sahte gönderime karşı korur.",
        "spf_missing": "SPF kaydı yok. Herkes bu alan adı adına e-posta gönderebilir.",
        "spf_multiple": "{d} adet SPF kaydı var. Yalnız bir kayıt olabilir; alıcı sunucular bunu hata sayar.",
        "spf_plus_all": "SPF +all ile bitiyor; internetteki tüm sunuculara gönderim izni veriyor.",
        "spf_neutral_all": "SPF ?all ile bitiyor; koruma sağlamıyor.",
        "spf_ok": "SPF kaydı geçerli ve {d} ile bitiyor.",
        "spf_no_all": "SPF kaydının sonunda 'all' tanımı yok.",
        "spf_too_many_lookups": "SPF {d} DNS sorgusu gerektiriyor; sınır 10 olduğu için doğrulama başarısız olur.",
        "dmarc_missing": "DMARC kaydı yok. Sahte e-postalar reddedilmiyor ve rapor alınmıyor.",
        "dmarc_none": "DMARC politikası p=none (yalnız izleme). Sahte e-postalar yine teslim ediliyor.",
        "dmarc_ok": "DMARC politikası p={d}.",
        "dmarc_invalid": "DMARC politika değeri geçersiz: {d}",
        "dmarc_pct": "DMARC iletilerin yalnız %{d} kadarına uygulanıyor.",
        "dmarc_no_rua": "DMARC kaydında rua adresi yok; toplu raporlar alınmıyor.",
        "dkim_ok": "DKIM anahtarı bulunan seçiciler: {d}",
        "dkim_not_found": "Yaygın seçicilerde DKIM anahtarı bulunamadı. E-posta sağlayıcısıyla doğrulanmalı.",
        "mta_sts_ok": "MTA-STS yayımlanmış.",
        "mta_sts_missing": "MTA-STS yayımlanmamış (önerilir, zorunlu değil).",
    },
}
STATUS_LABEL = {
    "en": {"ok": "OK", "warn": "Warning", "fail": "Fail", "info": "Info"},
    "tr": {"ok": "Uygun", "warn": "Uyarı", "fail": "Eksik", "info": "Bilgi"},
}


def render_markdown(rep: Report, lang: str = "en") -> str:
    m, s = MESSAGES[lang], STATUS_LABEL[lang]
    lines = [f"# {m['title']}: {rep.domain}", "", f"**{m['score']}: {rep.score}/100 ({rep.grade})**", "",
             f"| {m['check']} | {m['status']} | {m['result']} |", "|---|---|---|"]
    for f in rep.findings:
        lines.append(f"| {f.check} | {s[f.status]} | {m[f.key].format(d=f.detail)} |")
    if rep.spf:
        lines += ["", f"SPF: `{rep.spf}`"]
    if rep.dmarc:
        lines += ["", f"DMARC: `{rep.dmarc}`"]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Check SPF, DKIM, DMARC, MX and MTA-STS for a domain.")
    ap.add_argument("domains", nargs="+")
    ap.add_argument("--lang", choices=("en", "tr"), default="en")
    ap.add_argument("--json", action="store_true", help="print machine-readable output")
    args = ap.parse_args(argv)
    client = DnsClient()
    reports = [check_domain(d, client) for d in args.domains]
    if args.json:
        print(json.dumps([{**asdict(r), "score": r.score, "grade": r.grade} for r in reports],
                         ensure_ascii=False, indent=2))
    else:
        print("\n".join(render_markdown(r, args.lang) for r in reports))
    return 0 if all(r.score >= 60 for r in reports) else 1


if __name__ == "__main__":
    sys.exit(main())
