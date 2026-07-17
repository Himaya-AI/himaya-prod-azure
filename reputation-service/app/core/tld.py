from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass

import tldextract


HOST_RE = re.compile(r"^[a-z0-9.-]+$", re.IGNORECASE)


@dataclass(frozen=True)
class TldResult:
    valid_format: bool
    domain: str | None
    root_domain: str | None
    subdomain: str | None
    tld: str | None
    valid_tld: bool
    public_domain: bool


class TldService:
    def __init__(self) -> None:
        self._extractor = tldextract.TLDExtract(suffix_list_urls=())

    def analyze(self, value: str) -> TldResult:
        host = self._extract_host(value)
        if not host:
            return TldResult(
                valid_format=False,
                domain=None,
                root_domain=None,
                subdomain=None,
                tld=None,
                valid_tld=False,
                public_domain=False,
            )

        extracted = self._extractor(host)
        root_domain = self._join_parts(extracted.domain, extracted.suffix)
        subdomain = extracted.subdomain or None
        tld = extracted.suffix or None
        valid_tld = bool(tld)
        public_domain = bool(root_domain and valid_tld)

        return TldResult(
            valid_format=bool(root_domain and valid_tld),
            domain=host,
            root_domain=root_domain,
            subdomain=subdomain,
            tld=tld,
            valid_tld=valid_tld,
            public_domain=public_domain,
        )

    @staticmethod
    def _extract_host(value: str) -> str | None:
        raw = value.strip().lower().rstrip(".")
        if not raw:
            return None

        if "@" in raw:
            raw = raw.rsplit("@", 1)[-1]

        if "://" in raw:
            parsed = urllib.parse.urlparse(raw)
            raw = parsed.hostname or ""

        if not raw:
            return None

        try:
            raw = raw.encode("idna").decode("ascii")
        except UnicodeError:
            pass

        if not HOST_RE.match(raw):
            return None
        return raw

    @staticmethod
    def _join_parts(domain: str, suffix: str) -> str | None:
        if not domain or not suffix:
            return None
        return f"{domain}.{suffix}"