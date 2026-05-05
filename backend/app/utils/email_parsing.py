"""Safe email parsing helpers."""

from dataclasses import dataclass
from email.utils import parseaddr


@dataclass(frozen=True)
class ParsedEmail:
    """Safely parsed email field parts."""

    display_name: str
    address: str
    domain: str | None


def normalize_email_address(value: str | None) -> str | None:
    """Normalize an email address string without trusting it as valid."""
    if value is None:
        return None
    return value.strip()


def normalize_domain(value: str | None) -> str | None:
    """Normalize a domain-like value for comparison."""
    if not value:
        return None
    domain = value.strip().lower().strip("<>[]()")
    if "@" in domain:
        domain = domain.rsplit("@", 1)[-1]
    if ":" in domain and not domain.count(":") > 1:
        domain = domain.split(":", 1)[0]
    domain = domain.rstrip(".")
    return domain or None


def parse_email_field(value: str | None) -> ParsedEmail:
    """Parse an email field without assuming it is well-formed."""
    raw_value = value or ""
    display_name, address = parseaddr(raw_value)
    if not address and "@" in raw_value:
        address = raw_value.strip()
    domain = normalize_domain(address.rsplit("@", 1)[-1] if "@" in address else None)
    return ParsedEmail(
        display_name=display_name.strip(),
        address=address.strip().lower(),
        domain=domain,
    )


def get_header(headers: dict[str, str], name: str) -> str | None:
    """Return a header value using case-insensitive lookup."""
    target = name.lower()
    for header_name, value in headers.items():
        if header_name.lower() == target:
            return value
    return None
