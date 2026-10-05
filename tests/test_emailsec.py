import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from emailsec import check_domain, count_spf_lookups, render_markdown  # noqa: E402


class FakeDns:
    def __init__(self, txt=None, mx=None):
        self._txt = txt or {}
        self._mx = mx or {}

    def txt(self, name):
        return self._txt.get(name, [])

    def mx(self, name):
        return self._mx.get(name, [])


def keys(rep):
    return {f.key for f in rep.findings}


def test_well_configured_domain_scores_a():
    dns = FakeDns(
        txt={
            "good.com": ["v=spf1 include:_spf.google.com -all"],
            "_spf.google.com": ["v=spf1 ip4:1.2.3.0/24 ~all"],
            "_dmarc.good.com": ["v=DMARC1; p=reject; rua=mailto:d@good.com"],
            "google._domainkey.good.com": ["v=DKIM1; k=rsa; p=MIIB"],
            "_mta-sts.good.com": ["v=STSv1; id=1"],
        },
        mx={"good.com": ["aspmx.l.google.com"]},
    )
    rep = check_domain("Good.com.", dns)
    assert rep.domain == "good.com"
    assert rep.score == 100 and rep.grade == "A"
    assert rep.dkim_selectors == ["google"]
    assert rep.spf_lookups == 1


def test_missing_records_fail():
    rep = check_domain("empty.com", FakeDns())
    assert {"spf_missing", "dmarc_missing", "dkim_not_found", "mx_none"} <= keys(rep)
    assert rep.score == 100 - 30 - 30 - 10 - 5
    assert rep.grade == "F"


def test_spf_plus_all_and_dmarc_none():
    dns = FakeDns(txt={
        "weak.com": ["v=spf1 +all"],
        "_dmarc.weak.com": ["v=DMARC1; p=none; pct=50"],
    })
    rep = check_domain("weak.com", dns)
    assert {"spf_plus_all", "dmarc_none", "dmarc_pct", "dmarc_no_rua"} <= keys(rep)


def test_multiple_spf_records_flagged():
    dns = FakeDns(txt={"two.com": ["v=spf1 -all", "v=spf1 mx -all"]})
    assert "spf_multiple" in keys(check_domain("two.com", dns))


def test_spf_lookup_count_is_recursive_and_flags_over_limit():
    txt = {"big.com": ["v=spf1 " + " ".join(f"include:i{n}.com" for n in range(6)) + " -all"]}
    for n in range(6):
        txt[f"i{n}.com"] = ["v=spf1 a mx ip4:10.0.0.1 ~all"]
    dns = FakeDns(txt=txt)
    assert count_spf_lookups(txt["big.com"][0], dns) == 6 + 6 * 2
    assert "spf_too_many_lookups" in keys(check_domain("big.com", dns))


def test_spf_include_loop_terminates():
    dns = FakeDns(txt={"a.com": ["v=spf1 include:b.com -all"], "b.com": ["v=spf1 include:a.com -all"]})
    assert count_spf_lookups(dns.txt("a.com")[0], dns) == 3


def test_turkish_rendering():
    out = render_markdown(check_domain("empty.com", FakeDns()), "tr")
    assert "E-posta güvenlik raporu" in out and "SPF kaydı yok" in out
