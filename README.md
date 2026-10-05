# email-security-check

Checks whether a domain is protected against email spoofing and produces a short graded report in English or Turkish.

| Check | What is verified |
|---|---|
| MX | Mail servers exist |
| SPF | One record only, safe `all` qualifier, DNS lookup count within the RFC 7208 limit of 10 (includes are followed recursively) |
| DMARC | Record exists, policy is `quarantine` or `reject`, applies to 100% of mail, aggregate reports (`rua`) are collected |
| DKIM | Public key published for common selectors (Google Workspace, Microsoft 365, Zoho, Mailchimp and others) |
| MTA-STS | Policy record published |

## Usage

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python emailsec.py example.com
.venv/bin/python emailsec.py example.com --lang tr
.venv/bin/python emailsec.py a.com b.com --json
```

The exit code is `1` when any domain scores below 60, so the tool can run in CI or a scheduled job.

## Example (github.com, October 2026)

```
# Email security report: github.com

Score: 95/100 (A)

| Check   | Status  | Result                                                   |
|---------|---------|----------------------------------------------------------|
| MX      | OK      | Mail servers found: github-com.mail.protection.outlook.com |
| SPF     | OK      | SPF record is valid and ends with ~all.                  |
| DMARC   | OK      | DMARC policy is p=quarantine.                            |
| DKIM    | OK      | DKIM key found for selector(s): google, selector1, k1, k2, s1, s2 |
| MTA-STS | Info    | MTA-STS is not published (recommended, not required).    |
```

## Limitations

- DKIM selectors cannot be listed through DNS. The tool probes common selectors only; "not found" means the key should be confirmed with the email provider.
- Only public DNS records are read. No email is sent and no server is scanned.

## Tests

```bash
.venv/bin/python -m pytest -q
```

DNS is replaced with a fake client in tests, so they run offline.

## Türkçe

Bir alan adının sahte e-posta gönderimine karşı korunup korunmadığını denetler: MX, SPF, DMARC, DKIM ve MTA-STS kayıtlarını okur, puanlar ve Türkçe veya İngilizce rapor üretir (`--lang tr`). Yalnız herkese açık DNS kayıtlarını okur.

## License

MIT
