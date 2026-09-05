"""
forensics/main.py — Email header & auth forensics.

Public contract:
    parse_email(eml_path: str) -> dict

Return shape:
{
    "message_id":       str,          # e.g. "<abc123@mail.example.com>"
    "subject":          str,
    "from_addr":        str,          # full RFC 5322 address
    "sender_domain":    str,          # just the domain part of from_addr, lowercased
    "body_text":        str,
    "spf_result":       "pass" | "fail" | "softfail" | "none",
    "dkim_result":      "pass" | "fail" | "none",
    "dmarc_result":     "pass" | "fail" | "none",
    "sender_anomalies": [str],        # e.g. ["from_returnpath_mismatch", "reply_to_mismatch"]
    "received_chain":   [
        {
            "hop_index": int,
            "from_host": str,
            "by_host":   str,
            "ip":        str,
            "timestamp": str,         # ISO-8601 or raw header value
        },
        ...
    ],
    "origin_ip":        str,          # earliest reliable IP in the received chain
}

Rules (from master context):
- Never raise an exception. On any failure, return the same shape with
  empty strings / "none" / [] rather than crashing.
- Do NOT change field names — other modules key into this dict by name.

Milestone status:
  [x] 1.1  Basic field extraction (message_id, subject, from_addr,
           sender_domain, body_text)
  [x] 1.2  SPF/DKIM/DMARC verification (dual-path)
  [x] 1.3  Received-chain reconstruction
  [x] 1.4  Sender anomaly detection
  [x] 1.5  Full fixture pass + real test assertions
"""

import email
import email.policy
import email.utils
import re


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _strip_html(html: str) -> str:
    """Very lightweight tag stripper — stdlib only, no BeautifulSoup dep yet."""
    # Replace block-level tags with newlines so we don't smash words together.
    html = re.sub(r"<(br|p|div|tr|li)[^>]*>", "\n", html, flags=re.IGNORECASE)
    # Drop all remaining tags.
    html = re.sub(r"<[^>]+>", "", html)
    # Collapse excessive blank lines.
    html = re.sub(r"\n{3,}", "\n\n", html)
    return html.strip()


def _extract_body(msg) -> str:
    """Walk *msg* parts; prefer first text/plain, fall back to text/html."""
    plain = None
    html = None
    for part in msg.walk():
        ct = part.get_content_type()
        # Skip multipart containers — their children are visited by walk().
        if part.get_content_maintype() == "multipart":
            continue
        if ct == "text/plain" and plain is None:
            try:
                plain = part.get_content()
            except Exception:  # noqa: BLE001
                plain = ""
        elif ct == "text/html" and html is None:
            try:
                html = part.get_content()
            except Exception:  # noqa: BLE001
                html = ""
    if plain is not None:
        return plain.strip()
    if html is not None:
        return _strip_html(html)
    return ""


def _sender_domain(from_addr: str) -> str:
    """Extract the lowercased domain from a raw From header value."""
    try:
        _, addr = email.utils.parseaddr(from_addr)
        if "@" in addr:
            return addr.split("@", 1)[1].lower().strip()
    except Exception:  # noqa: BLE001
        pass
    return ""


# ---------------------------------------------------------------------------
# Auth helpers — Milestone 1.2
# ---------------------------------------------------------------------------

# SPF result values the contract accepts.
_VALID_SPF   = {"pass", "fail", "softfail", "none"}
# Map uncommon header tokens → our contract vocabulary.
_NORMALISE   = {
    "neutral":    "none",
    "temperror":  "none",
    "permerror":  "fail",
    "policy":     "none",
}


def _parse_auth_results_header(msg) -> dict:
    """Step 1 — parse an ``Authentication-Results`` header when present.

    Gmail, Outlook, and most large providers stamp every delivered message
    with one; it records the results at the time of actual delivery.  For
    archived mail (e.g. old corpus emails where the DKIM key is long gone)
    this is often the *only* reliable source.

    Returns dict with keys ``spf``, ``dkim``, ``dmarc`` — each ``"none"``
    when the header is absent or the value is unrecognised.
    """
    out = {"spf": "none", "dkim": "none", "dmarc": "none"}
    header = msg.get("Authentication-Results", "") or ""
    if not header:
        return out
    for key in ("spf", "dkim", "dmarc"):
        m = re.search(rf'\b{key}=(\S+)', header, re.IGNORECASE)
        if not m:
            continue
        val = m.group(1).rstrip(";, ").lower()
        val = _NORMALISE.get(val, val)
        # Enforce contract vocabulary — drop anything we don't recognise.
        valid = _VALID_SPF if key == "spf" else {"pass", "fail", "none"}
        if val in valid:
            out[key] = val
    return out


def _live_dkim_verify(raw_bytes: bytes) -> str:
    """Step 2 — cryptographic DKIM verification via ``dkimpy``.

    Only called when a ``DKIM-Signature`` header is actually present;
    otherwise there is nothing to verify and we skip straight to
    ``"none"``.

    Returns ``"pass"``, ``"fail"``, or ``"none"`` on any error.
    """
    try:
        import dkim  # dkimpy package
        return "pass" if dkim.verify(raw_bytes) else "fail"
    except Exception:  # noqa: BLE001  — DNS timeout, key not found, etc.
        return "none"


def _checkdmarc_lookup(domain: str) -> dict:
    """Step 3 — DNS record-level SPF/DMARC check via ``checkdmarc``.

    Validates whether the *sending domain itself* publishes valid SPF and
    DMARC records, independent of what the individual email headers say.
    This is the purely DNS-based signal — it tells us whether the domain
    is configured to reject spoofed mail, not whether *this* email passed.

    Returns dict with keys ``spf``, ``dmarc`` — each ``"none"`` on any
    failure (DNS timeout, domain doesn't exist, etc.).
    """
    out = {"spf": "none", "dmarc": "none"}
    if not domain:
        return out
    try:
        import checkdmarc as cd  # noqa: PLC0415
        results = cd.check_domains([domain], timeout=5)
        # check_domains may return a list or a single dict depending on version.
        r = results[0] if isinstance(results, list) and results else results
        if not isinstance(r, dict):
            return out
        # --- SPF ---
        spf_data = r.get("spf") or {}
        if spf_data.get("valid") is True:
            # Check the actual record for softfail (~all) vs hard fail (-all).
            record = spf_data.get("record", "") or ""
            out["spf"] = "softfail" if "~all" in record else "pass"
        elif spf_data.get("valid") is False:
            out["spf"] = "fail"
        # --- DMARC ---
        dmarc_data = r.get("dmarc") or {}
        if dmarc_data.get("valid") is True:
            out["dmarc"] = "pass"
        elif dmarc_data.get("valid") is False:
            out["dmarc"] = "fail"
    except Exception:  # noqa: BLE001  — never raise
        pass
    return out


def _get_auth_results(
    msg,
    raw_bytes: bytes,
    sender_domain: str,
) -> tuple:
    """Orchestrate the dual-path auth verification.

    Priority order (mirrors the build guide rationale):
      1. ``Authentication-Results`` header  — most reliable for archived mail.
      2. Live ``dkimpy`` verification       — real crypto, only when a
         DKIM-Signature header is actually present.
      3. ``checkdmarc`` DNS lookup          — fills gaps for SPF/DMARC.
      4. ``"none"``                         — honest answer when nothing resolves.

    Returns ``(spf_result, dkim_result, dmarc_result)``.
    """
    auth = _parse_auth_results_header(msg)
    spf, dkim, dmarc = auth["spf"], auth["dkim"], auth["dmarc"]

    # Path 2: live DKIM only when the signature header is present and
    # path 1 didn't already give us a definitive answer.
    if dkim == "none" and msg.get("DKIM-Signature"):
        dkim = _live_dkim_verify(raw_bytes)

    # Path 3: DNS lookup to fill any remaining "none" values.
    if spf == "none" or dmarc == "none":
        dns = _checkdmarc_lookup(sender_domain)
        if spf == "none":
            spf = dns["spf"]
        if dmarc == "none":
            dmarc = dns["dmarc"]

    return spf, dkim, dmarc


# ---------------------------------------------------------------------------
# Received-chain helper — Milestone 1.3
# ---------------------------------------------------------------------------

# IPv4: optionally bracketed, e.g. 1.2.3.4 or [1.2.3.4]
_RE_IPV4 = re.compile(
    r'\[?(\d{1,3}(?:\.\d{1,3}){3})\]?'
)
# IPv6: bracketed form is common in Received headers, e.g. [2001:db8::1]
_RE_IPV6 = re.compile(
    r'\[?([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7})\]?'
)
# "from host" and "by host" tokens at the start of a Received header value.
_RE_FROM_HOST = re.compile(r'\bfrom\s+(\S+)', re.IGNORECASE)
_RE_BY_HOST   = re.compile(r'\bby\s+(\S+)',   re.IGNORECASE)


def _parse_received_chain(msg) -> tuple:
    """Turn raw ``Received`` headers into an ordered hop list + origin IP.

    ``msg.get_all('Received')`` returns headers **most-recent hop first**
    (each server prepends its own Received header at the top of the
    message).  We reverse so ``hop_index 0`` is the true origin — the
    first server that touched the message.

    Per-hop extraction:
    - ``from_host`` / ``by_host`` via regex on ``from <token>`` / ``by <token>``.
    - IP via IPv4 pattern first, then IPv6 pattern as fallback.
    - ``timestamp``: split on the last ``;`` in the header value, parse the
      remainder with ``email.utils.parsedate_to_datetime()``, serialise to
      ISO-8601.  Falls back to the raw string if parsing fails.

    ``origin_ip`` is the IP of hop 0, or the first hop with a non-empty IP
    if hop 0 has none (some mail relays omit the IP on the first hop).

    Returns ``(received_chain: list, origin_ip: str)``.
    """
    raw_headers = msg.get_all("Received") or []
    # Reverse: index 0 = earliest (origin), last = most recent.
    raw_headers = list(reversed(raw_headers))

    chain = []
    for idx, header in enumerate(raw_headers):
        # ---- hosts --------------------------------------------------------
        m_from = _RE_FROM_HOST.search(header)
        m_by   = _RE_BY_HOST.search(header)
        from_host = m_from.group(1) if m_from else ""
        by_host   = m_by.group(1)   if m_by   else ""

        # ---- IP -----------------------------------------------------------
        # Prefer IPv4; fall back to IPv6.
        ip = ""
        m4 = _RE_IPV4.search(header)
        if m4:
            ip = m4.group(1)
        else:
            m6 = _RE_IPV6.search(header)
            if m6:
                ip = m6.group(1)

        # ---- timestamp ----------------------------------------------------
        # Received headers end with "; <datetime>"
        timestamp = ""
        if ";" in header:
            raw_ts = header.rsplit(";", 1)[-1].strip()
            try:
                dt = email.utils.parsedate_to_datetime(raw_ts)
                timestamp = dt.isoformat()
            except Exception:  # noqa: BLE001
                timestamp = raw_ts  # keep raw rather than silently drop

        chain.append({
            "hop_index": idx,
            "from_host": from_host,
            "by_host":   by_host,
            "ip":        ip,
            "timestamp": timestamp,
        })

    # origin_ip: IP of hop 0, else first hop that has one.
    origin_ip = ""
    for hop in chain:
        if hop["ip"]:
            origin_ip = hop["ip"]
            break

    return chain, origin_ip


# ---------------------------------------------------------------------------
# Sender anomaly helper — Milestone 1.4
# ---------------------------------------------------------------------------

# Basic shape check for a well-formed Message-ID: <local@domain>
_RE_MSGID = re.compile(r'^\s*<[^@>\s]+@[^@>\s]+>\s*$')


def _detect_sender_anomalies(msg, sender_domain: str, message_id: str) -> list:
    """Compare From / Return-Path / Reply-To domains; inspect Message-ID.

    Flags appended to the returned list:

    ``from_returnpath_mismatch``
        The domain in ``Return-Path`` differs from ``sender_domain``.
        Note: legitimate bulk mailers (newsletters, ticketing systems) use a
        dedicated bounce domain for Return-Path, so this alone is not
        damning — it is one +10 signal among several.

    ``reply_to_mismatch``
        The domain in ``Reply-To`` differs from ``sender_domain``.
        A classic phishing tell: replies are harvested by an attacker-
        controlled address while the visible From looks plausible.

    ``missing_message_id``
        ``Message-ID`` header is absent or empty.  Real mail servers
        always generate one; absence often indicates a hand-crafted
        phishing message.

    ``suspicious_message_id``
        Present but either fails the ``<local@domain>`` shape check or
        its domain does not match ``sender_domain``.
    """
    anomalies = []

    def _domain_of(header_val: str) -> str:
        """Return lowercased domain from an RFC 5322 address value, or ''."""
        try:
            _, addr = email.utils.parseaddr(header_val or "")
            if "@" in addr:
                return addr.split("@", 1)[1].lower().strip()
        except Exception:  # noqa: BLE001
            pass
        return ""

    # ---- Return-Path vs From ---------------------------------------------
    return_path_raw = msg.get("Return-Path", "") or ""
    rp_domain = _domain_of(return_path_raw)
    if rp_domain and rp_domain != sender_domain:
        anomalies.append("from_returnpath_mismatch")

    # ---- Reply-To vs From ------------------------------------------------
    reply_to_raw = msg.get("Reply-To", "") or ""
    rt_domain = _domain_of(reply_to_raw)
    if rt_domain and rt_domain != sender_domain:
        anomalies.append("reply_to_mismatch")

    # ---- Message-ID sanity -----------------------------------------------
    if not message_id:
        anomalies.append("missing_message_id")
    else:
        # Flag if it doesn't match <local@domain> shape ...
        if not _RE_MSGID.match(message_id):
            anomalies.append("suspicious_message_id")
        else:
            # ... or if its domain doesn't match sender_domain.
            msgid_domain = _domain_of(message_id.strip("<>"))
            if msgid_domain and msgid_domain != sender_domain:
                anomalies.append("suspicious_message_id")

    return anomalies


# ---------------------------------------------------------------------------
# Public contract
# ---------------------------------------------------------------------------

def parse_email(eml_path: str) -> dict:
    """Parse *eml_path* and return a ParsedEmail dict.

    Milestones 1.1–1.4 implemented:
      message_id, subject, from_addr, sender_domain, body_text,
      spf/dkim/dmarc (dual-path), received_chain, origin_ip,
      sender_anomalies.

    Never raises — all exceptions are caught and the shape is returned with
    empty / "none" values.

    Args:
        eml_path: Filesystem path to a .eml file.

    Returns:
        ParsedEmail dict (see module docstring for full shape).
    """
    # ------------------------------------------------------------------
    # Safe open — read raw bytes first so dkimpy gets the exact original
    # bytes; text mode can silently alter CRLF line endings and break
    # signature verification.
    # ------------------------------------------------------------------
    try:
        with open(eml_path, "rb") as fh:
            raw_bytes = fh.read()
        msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
    except Exception as exc:  # noqa: BLE001
        # File not found, permission denied, etc. — never raise.
        return {
            "message_id": "",
            "subject": "",
            "from_addr": "",
            "sender_domain": "",
            "body_text": "",
            "spf_result": "none",
            "dkim_result": "none",
            "dmarc_result": "none",
            "sender_anomalies": [],
            "received_chain": [],
            "origin_ip": "",
            "error": str(exc),
        }

    # ------------------------------------------------------------------
    # Milestone 1.1 — basic field extraction
    # ------------------------------------------------------------------
    message_id = msg.get("Message-ID", "") or ""
    subject    = msg.get("Subject",    "") or ""
    from_addr  = msg.get("From",       "") or ""

    sender_domain = _sender_domain(from_addr)
    body_text     = _extract_body(msg)

    # ------------------------------------------------------------------
    # Milestone 1.2 — SPF/DKIM/DMARC dual-path verification
    # ------------------------------------------------------------------
    spf_result, dkim_result, dmarc_result = _get_auth_results(
        msg, raw_bytes, sender_domain
    )

    # ------------------------------------------------------------------
    # Milestone 1.3 — received-chain reconstruction
    # ------------------------------------------------------------------
    received_chain, origin_ip = _parse_received_chain(msg)

    # ------------------------------------------------------------------
    # Milestone 1.4 — sender anomaly detection
    # ------------------------------------------------------------------
    sender_anomalies = _detect_sender_anomalies(msg, sender_domain, message_id)

    return {
        "message_id":       message_id,
        "subject":          subject,
        "from_addr":        from_addr,
        "sender_domain":    sender_domain,
        "body_text":        body_text,
        "spf_result":       spf_result,
        "dkim_result":      dkim_result,
        "dmarc_result":     dmarc_result,
        "sender_anomalies": sender_anomalies,
        "received_chain":   received_chain,
        "origin_ip":        origin_ip,
    }
