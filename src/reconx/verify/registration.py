"""Self-registration that crosses an authentication boundary.

Some applications are meant to be reachable only through an identity provider —
a staff portal behind Entra ID, a partner console behind Okta — and still ship an
enabled local ``/register`` endpoint. Anyone on the internet can then create an
account, receive a session, and land inside the application without ever holding
an identity the organisation issued. The SSO boundary is still there; it simply
is not the only door.

The whole difficulty is telling that apart from a shop that lets customers sign
up, because at the HTTP level the two look identical: a registration form that
answers unauthenticated. Reporting every ``/register`` as an authentication
bypass would be worse than useless. So the check is built around one specific
contradiction, which is cheap to observe and hard to explain away:

1. **The login surface offers no local credentials.** The application's own
   sign-in page hands off to an identity provider and has no password form, or
   a protected area redirects anonymous visitors straight to that provider.
   This is what makes SSO the *intended* authentication rather than one option
   among several.
2. **A local registration form exists anyway**, posts to the same origin, and
   creates a password-backed account rather than being a dressed-up link to the
   identity provider.
3. **There is a boundary to cross.** Some area rejects anonymous access — a
   redirect to login, a 401 or a 403 — which is both proof that the application
   expects authentication and the control half of the comparison in step 4.

Those three, reproduced, are reported as **Probable**. They are observable
without writing anything to the target, and they are what a researcher needs in
order to look.

**Confirmed requires actually registering**, because nothing short of a session
proves the endpoint accepts a stranger. That writes a row somebody then has to
delete, so it happens only when the scope file grants ``account_creation`` and
names a mailbox to create the account under, and only once per host. The proof
is differential: the protected area that refused us anonymously must answer the
new session with application content. One account, recorded in the finding by
address so it can be named in the report and removed.

Anything found on that authenticated page is scanned for customer data, and
**only ever stored redacted** — a count and a masked sample. Reading a page you
were not supposed to reach is the finding; copying strangers' phone numbers into
a local database is not part of it. Values that also appear on the anonymous
version of the page are subtracted first, so a support address in the footer
does not become a breach.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from reconx.db.models import FindingTier, Severity
from reconx.verify.reproduce import reproduce
from reconx.verify.waf import WafState, classify_response

__all__ = [
    "FormField",
    "HtmlForm",
    "parse_forms",
    "RegistrationForm",
    "classify_registration",
    "IdpSignature",
    "IDP_SIGNATURES",
    "detect_identity_providers",
    "LoginSurface",
    "ProtectedArea",
    "SensitiveCategory",
    "SensitiveDataScan",
    "scan_sensitive_data",
    "redact",
    "RegistrationVerdict",
    "RegistrationVerifier",
    "REGISTRATION_PATHS",
    "LOGIN_PATHS",
    "PROTECTED_PATHS",
]


# Paths worth asking about. Short on purpose: content discovery has usually
# already found the real one, and this list is the fallback for when it has not.
REGISTRATION_PATHS: tuple[str, ...] = (
    "/register",
    "/signup",
    "/sign-up",
    "/registration",
    "/users/register",
    "/user/register",
    "/account/register",
    "/auth/register",
    "/create-account",
)

LOGIN_PATHS: tuple[str, ...] = (
    "/login",
    "/signin",
    "/sign-in",
    "/auth/login",
    "/users/login",
    "/account/login",
    "/",
)

PROTECTED_PATHS: tuple[str, ...] = (
    "/dashboard",
    "/home",
    "/account",
    "/profile",
    "/admin",
    "/portal",
    "/orders",
)


# ---------------------------------------------------------------------------
# forms
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FormField:
    """One input in a form."""

    name: str
    type: str = "text"
    value: str = ""
    required: bool = False
    options: tuple[str, ...] = ()

    @property
    def hidden(self) -> bool:
        return self.type == "hidden"


@dataclass
class HtmlForm:
    """A form, resolved against the page it was served on."""

    source_url: str
    action: str
    method: str = "POST"
    fields: list[FormField] = field(default_factory=list)
    submit_labels: list[str] = field(default_factory=list)

    @property
    def names(self) -> set[str]:
        return {f.name.lower() for f in self.fields if f.name}

    @property
    def same_origin(self) -> bool:
        here, there = urlsplit(self.source_url), urlsplit(self.action)
        return (here.scheme, here.hostname, here.port) == (
            there.scheme,
            there.hostname,
            there.port,
        )

    @property
    def action_host(self) -> str:
        return urlsplit(self.action).hostname or ""

    def of_type(self, kind: str) -> list[FormField]:
        return [f for f in self.fields if f.type == kind]

    def matching(self, *fragments: str) -> list[FormField]:
        """Fields whose name contains any of ``fragments`` (case-insensitive)."""
        return [
            f
            for f in self.fields
            if f.name and any(fragment in f.name.lower() for fragment in fragments)
        ]


def parse_forms(body: str, page_url: str) -> list[HtmlForm]:
    """Extract every form on a page, with actions resolved to absolute URLs."""
    try:
        soup = BeautifulSoup(body, "lxml")
    except Exception:  # pragma: no cover - parser fallback
        soup = BeautifulSoup(body, "html.parser")

    forms: list[HtmlForm] = []
    for element in soup.find_all("form"):
        action = str(element.get("action") or "").strip()
        form = HtmlForm(
            source_url=page_url,
            action=urljoin(page_url, action) if action else page_url,
            method=str(element.get("method") or "GET").strip().upper() or "GET",
        )

        for node in element.find_all(["input", "select", "textarea"]):
            tag = node.name
            kind = str(node.get("type") or "text").strip().lower() if tag == "input" else tag
            name = str(node.get("name") or "").strip()
            if kind == "submit":
                label = str(node.get("value") or "").strip()
                if label:
                    form.submit_labels.append(label)
                if not name:
                    continue
            options: tuple[str, ...] = ()
            if tag == "select":
                options = tuple(
                    str(option.get("value") or option.get_text(strip=True))
                    for option in node.find_all("option")
                )
            form.fields.append(
                FormField(
                    name=name,
                    type=kind,
                    value=str(node.get("value") or ""),
                    required=node.has_attr("required"),
                    options=options,
                )
            )

        for node in element.find_all("button"):
            kind = str(node.get("type") or "submit").strip().lower()
            if kind == "submit":
                label = node.get_text(strip=True)
                if label:
                    form.submit_labels.append(label)
        forms.append(form)
    return forms


# Names that mean "type the password again", which is the single most reliable
# way to tell a registration form from a login form.
_CONFIRM_NAMES = (
    "password_confirmation",
    "passwordconfirmation",
    "confirm_password",
    "confirmpassword",
    "password_confirm",
    "passwordconfirm",
    "password2",
    "repeat_password",
    "retype_password",
    "verify_password",
    "password_again",
)

_EMAIL_NAMES = ("email", "e-mail", "mail", "username", "user_name", "login")
_PERSON_NAMES = (
    "name",
    "firstname",
    "first_name",
    "lastname",
    "last_name",
    "fullname",
    "full_name",
    "given_name",
    "surname",
    "company",
    "organisation",
    "organization",
    "phone",
    "mobile",
)

# Provisioning gates. An invitation or activation code means accounts are not
# open to the public, whatever the form looks like.
_INVITE_NAMES = (
    "invit",
    "access_code",
    "accesscode",
    "activation_code",
    "activationcode",
    "registration_code",
    "registrationcode",
    "signup_code",
    "enrol",
    "enroll",
    "voucher",
    "employee_id",
    "employeeid",
    "staff_id",
    "staffid",
)
_INVITE_WORDING = (
    "invitation code",
    "invite code",
    "invitation link",
    "by invitation",
    "you need an invitation",
    "access code",
    "activation code",
    "registration code",
    "ask your administrator",
    "contact your administrator",
)
_APPROVAL_WORDING = (
    "pending approval",
    "await approval",
    "awaiting approval",
    "will be reviewed",
    "subject to approval",
    "must be approved",
    "once approved",
    "after approval",
)
_CAPTCHA_MARKERS = (
    "g-recaptcha",
    "recaptcha/api.js",
    "hcaptcha.com",
    "h-captcha",
    "cf-turnstile",
    "turnstile/v0/api.js",
    "data-sitekey",
    "friendlycaptcha",
)
_REGISTER_WORDING = (
    "register",
    "sign up",
    "signup",
    "create account",
    "create an account",
    "create your account",
    "new account",
    "daftar",  # Indonesian: these portals are not all in English
    "buat akun",
)


@dataclass
class RegistrationForm:
    """A form judged to create a local, password-backed account."""

    form: HtmlForm
    url: str
    password_field: str
    confirm_field: str | None = None
    identity_field: str | None = None
    csrf_field: str | None = None
    csrf_value: str | None = None
    invite_fields: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    captcha: bool = False
    approval_required: bool = False

    @property
    def gated(self) -> bool:
        """True when something other than the form itself controls provisioning."""
        return bool(self.invite_fields) or self.approval_required


def _first_name(
    form: HtmlForm, fragments: Sequence[str], *, exclude: Sequence[str] = ()
) -> str | None:
    skip = {name.lower() for name in exclude}
    for candidate in form.fields:
        lowered = candidate.name.lower()
        if not lowered or lowered in skip:
            continue
        if any(fragment in lowered for fragment in fragments):
            return candidate.name
    return None


def classify_registration(
    form: HtmlForm, body: str = ""
) -> tuple[RegistrationForm | None, str]:
    """Decide whether a form creates a local account.

    Returns ``(registration, reason)``. When the form is not one, the reason
    says why — which is what a discarded candidate is reported with, because
    "there was a form at /register and we ignored it" is not an auditable claim.
    """
    lowered_body = body.lower()

    if form.method != "POST":
        return None, (
            f"the form at {form.source_url} submits with {form.method}, which is not "
            "how an account is created"
        )

    passwords = [f for f in form.of_type("password") if f.name]
    if not passwords:
        return None, (
            f"the form at {form.source_url} has no password field, so it does not set "
            "local credentials"
        )

    if not form.same_origin:
        return None, (
            f"the form at {form.source_url} posts to {form.action_host}, a different "
            "origin, so it hands off to that service rather than registering locally"
        )

    confirm = next(
        (f.name for f in passwords[1:] if f.name),
        None,
    ) or _first_name(form, _CONFIRM_NAMES)
    identifiers = [
        f.name
        for f in form.fields
        if f.name
        and (f.type == "email" or any(word in f.name.lower() for word in _EMAIL_NAMES))
    ]
    identity = next(iter(identifiers), None)
    # Profile fields are what a registration form asks for *beyond* an
    # identifier. Without excluding the identifiers, "username" matches "name"
    # and every login form in the world looks like a sign-up.
    person = _first_name(form, _PERSON_NAMES, exclude=identifiers)
    labels = " ".join(form.submit_labels).lower()
    says_register = any(word in labels for word in _REGISTER_WORDING)

    reasons: list[str] = []
    if confirm:
        reasons.append(f"a password confirmation field ({confirm})")
    if identity and person:
        reasons.append(f"an identity field ({identity}) alongside profile fields ({person})")
    if says_register:
        reasons.append(f"a submit control labelled {' / '.join(form.submit_labels)!r}")

    # A login form is password plus one identity field and nothing else. Demand
    # at least one positive signal beyond that shape.
    if not reasons:
        return None, (
            f"the form at {form.source_url} has the shape of a login form (a password "
            "and an identity field, no confirmation and no profile fields), so it was "
            "not treated as registration"
        )

    csrf = next(
        (
            f
            for f in form.fields
            if f.hidden
            and f.name
            and any(
                token in f.name.lower()
                for token in ("csrf", "token", "authenticity", "nonce", "state")
            )
        ),
        None,
    )
    invites = [f.name for f in form.matching(*_INVITE_NAMES) if not f.hidden]
    registration = RegistrationForm(
        form=form,
        url=form.source_url,
        password_field=passwords[0].name,
        confirm_field=confirm,
        identity_field=identity,
        csrf_field=csrf.name if csrf else None,
        csrf_value=csrf.value if csrf else None,
        invite_fields=invites,
        reasons=reasons,
        captcha=any(marker in lowered_body for marker in _CAPTCHA_MARKERS),
        approval_required=any(word in lowered_body for word in _APPROVAL_WORDING),
    )
    if not invites and any(word in lowered_body for word in _INVITE_WORDING):
        registration.invite_fields = ["(wording only)"]
    return registration, "registration form"


# ---------------------------------------------------------------------------
# identity providers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IdpSignature:
    """How to recognise one identity provider in a page or a redirect."""

    provider: str
    # Substrings, lower-cased, specific enough not to match prose. A bare
    # "saml" or "google" would match half the web, so they are not here.
    markers: tuple[str, ...]


IDP_SIGNATURES: tuple[IdpSignature, ...] = (
    IdpSignature(
        provider="Microsoft Entra ID (Azure AD)",
        markers=(
            "login.microsoftonline.com",
            "login.windows.net",
            "login.microsoft.com",
            "sts.windows.net",
            "/adfs/ls",
            "msal.min.js",
            "sign in with microsoft",
            "sign in with azure",
            "azure ad",
            "azuread",
            "entra id",
            "office 365",
            "microsoft 365",
        ),
    ),
    IdpSignature(
        provider="Okta",
        markers=("okta.com", "oktapreview.com", "okta-signin-widget", "sign in with okta"),
    ),
    IdpSignature(provider="Auth0", markers=("auth0.com", "auth0-lock", "auth0.js")),
    IdpSignature(provider="OneLogin", markers=("onelogin.com",)),
    IdpSignature(provider="Ping Identity", markers=("pingone.com", "pingidentity.com")),
    IdpSignature(
        provider="Google Workspace",
        markers=("accounts.google.com", "sign in with google", "gsi/client"),
    ),
    IdpSignature(
        provider="Keycloak",
        markers=("/auth/realms/", "/realms/", "keycloak.js"),
    ),
    IdpSignature(
        provider="SAML",
        markers=(
            "samlrequest=",
            "/saml2/",
            "/sso/saml",
            "urn:oasis:names:tc:saml",
            "shibboleth",
        ),
    ),
    IdpSignature(
        provider="OpenID Connect",
        markers=(
            "/oauth2/authorize",
            "/oauth2/v2.0/authorize",
            "/connect/authorize",
            "/.well-known/openid-configuration",
            "response_type=code",
        ),
    ),
)


def detect_identity_providers(*haystacks: str) -> list[tuple[str, str]]:
    """Which identity providers are named, and by which marker.

    Returns ``(provider, marker)`` pairs, one per provider, so a verdict can say
    what it saw rather than asserting "SSO" and leaving it there.
    """
    blob = " ".join(part.lower() for part in haystacks if part)
    found: list[tuple[str, str]] = []
    for signature in IDP_SIGNATURES:
        for marker in signature.markers:
            if marker in blob:
                found.append((signature.provider, marker))
                break
    return found


@dataclass
class LoginSurface:
    """What the application's own sign-in looks like."""

    url: str | None = None
    status: int | None = None
    providers: list[tuple[str, str]] = field(default_factory=list)
    local_password_form: bool = False
    redirected_to: str | None = None
    checked: list[str] = field(default_factory=list)

    @property
    def sso_only(self) -> bool:
        """The intended way in is an identity provider, with no local password."""
        return bool(self.providers) and not self.local_password_form

    def explain(self) -> str:
        if not self.providers:
            return "no identity provider was named on the sign-in surface"
        names = ", ".join(sorted({provider for provider, _ in self.providers}))
        markers = ", ".join(sorted({marker for _, marker in self.providers}))
        if self.local_password_form:
            return (
                f"the sign-in page offers {names} ({markers}) *and* a local password "
                "form, so local accounts appear to be intended"
            )
        return (
            f"the sign-in page at {self.url} hands off to {names} ({markers}) and "
            "carries no local password form"
        )


@dataclass
class ProtectedArea:
    """A path that refuses anonymous visitors, and how it refuses them."""

    url: str
    status: int
    how: str
    location: str | None = None
    body_sample: str = ""

    def explain(self) -> str:
        return f"{self.url} refuses an anonymous request ({self.how})"


# ---------------------------------------------------------------------------
# sensitive data, redacted
# ---------------------------------------------------------------------------


def redact(value: str, *, keep: int = 2) -> str:
    """Mask the middle of a value, keeping just enough to recognise its shape."""
    text = value.strip()
    if len(text) <= keep * 2:
        return "*" * len(text)
    masked = min(len(text) - keep * 2, 8)
    return f"{text[:keep]}{'*' * masked}{text[-keep:]}"


def _redact_email(value: str) -> str:
    local, _, domain = value.partition("@")
    host, _, tld = domain.rpartition(".")
    return f"{redact(local)}@{redact(host)}.{tld}"


def _redact_amount(value: str) -> str:
    digits = sum(ch.isdigit() for ch in value)
    symbol = value.strip()[:2].strip()
    return f"{symbol} <{digits}-digit amount>"


@dataclass(frozen=True)
class _Pattern:
    label: str
    regex: re.Pattern[str]
    redactor: Callable[[str], str]
    note: str


_SENSITIVE_PATTERNS: tuple[_Pattern, ...] = (
    _Pattern(
        label="email addresses",
        regex=re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
        redactor=_redact_email,
        note="contact details",
    ),
    _Pattern(
        label="telephone numbers",
        # International subscriber numbers, optionally with a + and separators.
        # The trailing guard refuses a partial match; the leading one is applied
        # in code, because both are needed to stop the middle twelve digits of a
        # spaced-out card number reading as a phone number.
        regex=re.compile(r"(?<![\d.])\+?\d{2}[\d\s.()-]{7,16}\d(?![\d.\s-]*\d)"),
        redactor=redact,
        note="contact details",
    ),
    _Pattern(
        label="monetary amounts",
        regex=re.compile(
            r"(?:Rp|IDR|USD|EUR|GBP|SGD|MYR|AUD|\$|€|£|₹|¥)\s?\d{1,3}(?:[.,]\d{3})+"
            r"(?:[.,]\d{2})?",
            re.IGNORECASE,
        ),
        redactor=_redact_amount,
        note="order or financial values",
    ),
    _Pattern(
        label="payment card numbers",
        regex=re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"),
        redactor=redact,
        note="card data",
    ),
)


# Dates and timestamps are the phone-number pattern's worst enemy: "28-09-2026"
# is twelve digits with separators, exactly like an international number.
_DATE_LIKE = re.compile(r"\d{1,4}[-/.]\d{1,2}[-/.]\d{2,4}")

# Issuer prefixes for the card lengths that dominate real data. Deliberately
# narrow: a 13-digit mobile number passes Luhn one time in ten, and "we found a
# payment card" is not a claim worth being wrong about.
_CARD_PREFIXES = ("4", "51", "52", "53", "54", "55", "34", "37", "6011", "65")

# "Is this match the tail of a longer number?" A regex lookbehind cannot ask
# that without also rejecting a number that simply follows a space in prose.
_TAIL_OF_A_NUMBER = re.compile(r"\d[\s.()-]?$")


def _luhn(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for index, char in enumerate(digits):
        value = int(char)
        if index % 2 == parity:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


@dataclass
class SensitiveCategory:
    """One class of personal data found on a page, counted and masked."""

    label: str
    note: str
    count: int
    samples: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "label": self.label,
            "note": self.note,
            "count": self.count,
            "redacted_samples": list(self.samples),
        }


@dataclass
class SensitiveDataScan:
    """What a page exposes, described without reproducing any of it."""

    categories: list[SensitiveCategory] = field(default_factory=list)
    rows: int = 0

    @property
    def total(self) -> int:
        return sum(category.count for category in self.categories)

    @property
    def significant(self) -> bool:
        """Enough records that this is a data set rather than a contact footer."""
        if any(category.count >= 5 for category in self.categories):
            return True
        return len([c for c in self.categories if c.count >= 3]) >= 2

    def summary(self) -> str:
        if not self.categories:
            return "no personal data patterns were found on the page"
        parts = [f"{c.count} distinct {c.label}" for c in self.categories]
        tail = f" across {self.rows} table rows" if self.rows else ""
        return ", ".join(parts) + tail

    def as_dict(self) -> dict:
        return {
            "rows": self.rows,
            "total": self.total,
            "significant": self.significant,
            "categories": [category.as_dict() for category in self.categories],
        }


def scan_sensitive_data(
    body: str, *, control_body: str = "", max_samples: int = 3
) -> SensitiveDataScan:
    """Count personal data on a page, keeping only redacted samples.

    ``control_body`` is the same page as an anonymous visitor sees it. Anything
    present there too is subtracted: a support address or a phone number in the
    footer is on every page and is not what an authentication bypass exposed.
    """
    scan = SensitiveDataScan()
    control = control_body or ""
    # A value belongs to one category. Without this an Indonesian mobile number
    # is counted again as a payment card the moment it happens to pass Luhn.
    claimed: set[str] = set()

    for pattern in _SENSITIVE_PATTERNS:
        seen: list[str] = []
        for match in pattern.regex.finditer(body):
            value = match.group(0).strip()
            if not value or value in seen or value in control or value in claimed:
                continue
            digits = re.sub(r"\D", "", value)
            if pattern.label == "payment card numbers" and not (
                13 <= len(digits) <= 19
                and _luhn(digits)
                and digits.startswith(_CARD_PREFIXES)
            ):
                continue
            if pattern.label == "telephone numbers" and (
                not 9 <= len(digits) <= 15
                or _DATE_LIKE.search(value)
                or _TAIL_OF_A_NUMBER.search(body[max(0, match.start() - 2) : match.start()])
            ):
                continue
            seen.append(value)
            claimed.add(value)

        if seen:
            scan.categories.append(
                SensitiveCategory(
                    label=pattern.label,
                    note=pattern.note,
                    count=len(seen),
                    samples=[pattern.redactor(value) for value in seen[:max_samples]],
                )
            )

    rows = len(re.findall(r"<tr[\s>]", body, re.IGNORECASE))
    control_rows = len(re.findall(r"<tr[\s>]", control, re.IGNORECASE))
    scan.rows = max(0, rows - control_rows)
    return scan


# ---------------------------------------------------------------------------
# the verdict
# ---------------------------------------------------------------------------


@dataclass
class RegistrationVerdict:
    """What the check concluded about one host."""

    base_url: str
    tier: FindingTier = FindingTier.DISCARDED
    confidence: int = 0
    severity: Severity = Severity.INFO
    reason: str = ""
    signals: list[str] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)
    obstructed: bool = False

    registration_url: str | None = None
    login_surface: LoginSurface | None = None
    protected_area: ProtectedArea | None = None
    providers: list[str] = field(default_factory=list)

    # Set only when the scope permitted account creation and one was made.
    created_account: str | None = None
    session_confirmed: bool = False
    data_scan: SensitiveDataScan | None = None

    @property
    def host(self) -> str:
        return urlsplit(self.base_url).hostname or ""

    @property
    def vulnerable(self) -> bool:
        return self.tier in (FindingTier.CONFIRMED, FindingTier.PROBABLE)

    @property
    def cleanup_required(self) -> bool:
        return self.created_account is not None

    def as_dict(self) -> dict:
        return {
            "base_url": self.base_url,
            "tier": self.tier.value,
            "confidence": self.confidence,
            "severity": self.severity.value,
            "reason": self.reason,
            "signals": list(self.signals),
            "registration_url": self.registration_url,
            "providers": list(self.providers),
            "protected_area": self.protected_area.url if self.protected_area else None,
            "created_account": self.created_account,
            "session_confirmed": self.session_confirmed,
            "data_scan": self.data_scan.as_dict() if self.data_scan else None,
        }


# ---------------------------------------------------------------------------
# the verifier
# ---------------------------------------------------------------------------


class AccountCreationRefused(RuntimeError):
    """Account creation was requested but the scope does not authorize it."""


_LOGIN_HINTS = ("login", "signin", "sign-in", "sign_in", "auth", "sso", "session")

# Every free-text field gets this, so an account ReconX made is obvious to
# whoever finds it in the users table.
_PROBE_LABEL = "ReconX Authorized Test"


class RegistrationVerifier:
    """Checks whether self-registration crosses an SSO boundary."""

    def __init__(
        self,
        http,
        *,
        baselines=None,
        attempts: int = 3,
        required: int = 3,
        allow_account_creation: bool = False,
        probe_email: str | None = None,
        registration_paths: Sequence[str] = REGISTRATION_PATHS,
        login_paths: Sequence[str] = LOGIN_PATHS,
        protected_paths: Sequence[str] = PROTECTED_PATHS,
    ) -> None:
        if allow_account_creation and not probe_email:
            raise AccountCreationRefused(
                "account creation needs a mailbox to register under so the account is "
                "attributable and can be deleted; set permissions.test_account_email "
                "in the scope file"
            )
        self._http = http
        self._baselines = baselines
        self._attempts = max(1, attempts)
        self._required = max(1, min(required, attempts))
        self._allow_account_creation = allow_account_creation
        self._probe_email = probe_email
        self._registration_paths = tuple(registration_paths)
        self._login_paths = tuple(login_paths)
        self._protected_paths = tuple(protected_paths)

    # -- entry point -------------------------------------------------------

    async def verify(
        self, base_url: str, *, known_urls: Sequence[str] = ()
    ) -> RegistrationVerdict:
        """Run the check against one origin, e.g. ``https://portal.example.com``."""
        root = base_url.rstrip("/")
        verdict = RegistrationVerdict(base_url=root)

        # 1. Is there a local registration form at all? Cheapest question, and
        #    on most hosts the answer ends the check.
        registration, why_not = await self._find_registration(root, known_urls, verdict)
        if registration is None:
            verdict.reason = why_not
            return verdict

        verdict.registration_url = registration.url
        verdict.signals.append("local_registration_form")

        if registration.gated:
            gate = (
                f"an invitation or code field ({', '.join(registration.invite_fields)})"
                if registration.invite_fields
                else "wording that says new accounts are approved by an administrator"
            )
            verdict.tier = FindingTier.DISCARDED
            verdict.reason = (
                f"{registration.url} carries {gate}, so provisioning is not open to "
                "anyone who finds the page"
            )
            return verdict

        # 2. What does the application's own sign-in look like?
        surface = await self._login_surface(root)
        verdict.login_surface = surface
        verdict.providers = sorted({provider for provider, _ in surface.providers})

        if not surface.providers:
            verdict.tier = FindingTier.DISCARDED
            verdict.reason = (
                f"{registration.url} accepts public sign-ups, but no identity provider "
                "was found on the sign-in surface, so there is no authentication "
                "boundary for registration to bypass. This is ordinary behaviour for an "
                f"application with its own accounts. {surface.explain()}"
            )
            return verdict

        verdict.signals.append("identity_provider_present")

        # 3. Is there a boundary at all, and does it hold for anonymous callers?
        protected = await self._protected_area(root)
        verdict.protected_area = protected
        if protected is not None:
            verdict.signals.append("protected_area_refuses_anonymous")

        if not surface.sso_only:
            verdict.tier = FindingTier.NEEDS_REVIEW
            verdict.confidence = 35
            verdict.reason = (
                f"{registration.url} accepts public sign-ups and {surface.explain()}. "
                "Local accounts and an identity provider side by side is a deliberate "
                "design in plenty of applications, so this needs a human to say which "
                "one this is"
            )
            verdict.evidence.append(self._page_evidence(registration))
            return verdict

        if protected is None:
            verdict.tier = FindingTier.NEEDS_REVIEW
            verdict.confidence = 40
            verdict.reason = (
                f"{surface.explain()}, yet {registration.url} creates a local account. "
                "No area was found that refuses anonymous access, so the boundary this "
                "would cross was not established"
            )
            verdict.evidence.append(self._page_evidence(registration))
            return verdict

        # 4. Does the registration page hold still? A form seen once may be a
        #    deploy artefact or a cached page.
        stability = await reproduce(
            self._registration_probe(registration.url),
            attempts=self._attempts,
            required=self._required,
        )
        if not stability.stable:
            verdict.tier = FindingTier.DISCARDED
            verdict.reason = (
                f"the registration form at {registration.url} did not hold still: "
                f"{stability.explain()}"
            )
            return verdict
        verdict.signals.append("reproduced")

        verdict.evidence.append(self._page_evidence(registration))
        verdict.evidence.append(
            {
                "label": "sign-in hands off to the identity provider",
                "request_url": surface.url,
                "response_status": surface.status,
                "note": surface.explain(),
            }
        )
        verdict.evidence.append(
            {
                "label": "protected area refuses an anonymous request",
                "request_url": protected.url,
                "response_status": protected.status,
                "note": protected.explain(),
            }
        )

        provider_names = ", ".join(verdict.providers)
        verdict.tier = FindingTier.PROBABLE
        verdict.confidence = 70
        verdict.severity = Severity.HIGH
        verdict.reason = (
            f"{surface.explain()}, {protected.explain()}, and yet {registration.url} "
            f"serves a local registration form that sets a password ("
            f"{'; '.join(registration.reasons)}). An account created there would hold a "
            f"session the {provider_names} boundary never issued. "
            f"{stability.explain()}. Registering was not attempted, so this is Probable: "
            "the form's presence is proved, its acceptance is not"
        )

        # 5. Proof, if and only if the scope authorized writing to the target.
        if self._allow_account_creation:
            await self._prove_by_registering(verdict, registration, protected)
        elif registration.captcha:
            verdict.reason += (
                ". The page carries a CAPTCHA, which slows automation down but does not "
                "stop one person registering once"
            )

        return verdict

    # -- step 1: find the registration form --------------------------------

    async def _find_registration(
        self, root: str, known_urls: Sequence[str], verdict: RegistrationVerdict
    ) -> tuple[RegistrationForm | None, str]:
        """Look for a local registration form, preferring URLs already discovered."""
        rejections: list[str] = []

        for url in self._registration_candidates(root, known_urls):
            response = await self._get(url)
            if response is None:
                continue
            if response.throttled_host:
                verdict.obstructed = True

            state = classify_response(
                status=response.status, headers=response.headers, body=response.body
            )
            if state.state is not WafState.CLEAN:
                verdict.obstructed = True
                rejections.append(f"{url} was {state.state.value}")
                continue
            if response.status >= 400:
                continue
            if await self._is_missing(root, response):
                continue

            body = response.text
            final_url = response.url or url
            for form in parse_forms(body, final_url):
                registration, reason = classify_registration(form, body)
                if registration is not None:
                    return registration, reason
                rejections.append(reason)

        detail = f" ({rejections[0]})" if rejections else ""
        return None, (
            f"no local registration form was found under {root}{detail}"
        )

    def _registration_candidates(
        self, root: str, known_urls: Sequence[str]
    ) -> list[str]:
        """Discovered registration URLs first, then the fallback path list."""
        candidates: list[str] = []
        seen: set[str] = set()

        for url in known_urls:
            parts = urlsplit(url)
            path = (parts.path or "/").rstrip("/").lower() or "/"
            if not any(
                path.endswith(candidate.rstrip("/"))
                for candidate in self._registration_paths
            ):
                continue
            normalized = f"{root}{parts.path}"
            if normalized not in seen:
                seen.add(normalized)
                candidates.append(normalized)

        for path in self._registration_paths:
            url = f"{root}{path}"
            if url not in seen:
                seen.add(url)
                candidates.append(url)
        return candidates

    def _registration_probe(self, url: str):
        async def probe(_index: int) -> tuple[bool, str | None]:
            response = await self._get(url)
            if response is None or response.status >= 400:
                return False, "the registration page stopped answering"
            forms = parse_forms(response.text, response.url or url)
            for form in forms:
                registration, _ = classify_registration(form, response.text)
                if registration is not None:
                    return True, None
            return False, "the registration form was no longer on the page"

        return probe

    # -- step 2: the login surface -----------------------------------------

    async def _login_surface(self, root: str) -> LoginSurface:
        surface = LoginSurface()

        for path in self._login_paths:
            url = f"{root}{path}" if path != "/" else f"{root}/"
            response = await self._get(url)
            if response is None:
                continue
            surface.checked.append(url)
            if response.status >= 400 or await self._is_missing(root, response):
                continue

            body = response.text
            final_url = response.url or url
            providers = detect_identity_providers(
                body, final_url, *(hop_url for _, hop_url in response.redirect_chain)
            )
            has_local = any(
                form.method == "POST" and form.of_type("password") and form.same_origin
                for form in parse_forms(body, final_url)
            )

            # The root page counts only when it is itself the sign-in surface:
            # a marketing home page that links to an IdP is not a login page.
            if path == "/" and not providers and not has_local:
                continue

            if surface.url is None or providers:
                surface.url = final_url
                surface.status = response.status
                surface.providers = providers or surface.providers
                surface.local_password_form = has_local or surface.local_password_form
                if response.redirect_chain:
                    surface.redirected_to = final_url
            if providers:
                break

        if surface.url is None:
            surface.url = f"{root}/"
        return surface

    # -- step 3: a boundary to cross ---------------------------------------

    async def _protected_area(self, root: str) -> ProtectedArea | None:
        for path in self._protected_paths:
            url = f"{root}{path}"
            response = await self._get(url, follow_redirects=False)
            if response is None:
                continue

            location = response.header("location")
            if response.status in (301, 302, 303, 307, 308) and location:
                target = urljoin(url, location).lower()
                if any(hint in target for hint in _LOGIN_HINTS) or detect_identity_providers(
                    target
                ):
                    return ProtectedArea(
                        url=url,
                        status=response.status,
                        how=f"HTTP {response.status} to {urljoin(url, location)}",
                        location=urljoin(url, location),
                        body_sample=response.text[:400],
                    )
                continue
            if response.status in (401, 403):
                return ProtectedArea(
                    url=url,
                    status=response.status,
                    how=f"HTTP {response.status}",
                    body_sample=response.text[:400],
                )
        return None

    # -- step 5: proof, when the scope allows it ---------------------------

    async def _prove_by_registering(
        self,
        verdict: RegistrationVerdict,
        registration: RegistrationForm,
        protected: ProtectedArea,
    ) -> None:
        """Create one account and see whether its session crosses the boundary.

        This is the only part of ReconX that writes to a target, so it is
        deliberately narrow: one account, from a mailbox the scope named, with
        every value recorded. It is never retried and never repeated for
        reproducibility — the read-only signals carry that burden, because
        "it reproduced" is not worth a second unwanted account.
        """
        if registration.captcha:
            verdict.reason += (
                ". Registration was not attempted because the page carries a CAPTCHA, "
                "which an automated submission would fail for reasons that say nothing "
                "about whether the endpoint is open. Submit the form by hand to confirm"
            )
            return

        email = self._unique_email()
        password = self._probe_password()
        payload = self._fill(registration, email, password)

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": f"{urlsplit(registration.url).scheme}://{urlsplit(registration.url).netloc}",
            "Referer": registration.url,
        }
        if registration.csrf_field and registration.csrf_value:
            headers["X-CSRF-TOKEN"] = registration.csrf_value

        # Contain the session: without this the rest of the scan would quietly
        # run as the account we just made.
        with self._http.isolated_cookies():
            before = self._http.cookies
            try:
                response = await self._http.post(
                    registration.form.action,
                    data=payload,
                    headers=headers,
                    follow_redirects=False,
                )
            except Exception as exc:
                verdict.reason += (
                    f". Registration was attempted and the request failed "
                    f"({type(exc).__name__}), so acceptance is still unproved"
                )
                return

            session = {
                name: value
                for name, value in self._http.cookies.items()
                if before.get(name) != value
            }
            location = response.header("location")

            if not session:
                verdict.reason += (
                    f". Registration was attempted: the endpoint answered HTTP "
                    f"{response.status} and set no session cookie, so it did not create "
                    "a usable account"
                )
                verdict.evidence.append(
                    {
                        "label": "registration attempt rejected",
                        "request_url": registration.form.action,
                        "response_status": response.status,
                        "note": "no session cookie was returned",
                    }
                )
                return

            # The account exists from here on, whatever the session turns out to
            # do, so record it before anything else can go wrong.
            verdict.created_account = email
            verdict.signals.append("registration_accepted")

            authenticated = await self._get(protected.url, cookies=session)

        if authenticated is None:
            verdict.reason += (
                f". An account ({email}) was created and the protected area could not "
                "then be fetched, so the session was not tested"
            )
            return

        crossed = authenticated.status == 200 and not self._looks_like_login(authenticated)
        verdict.evidence.append(
            {
                "label": "registration accepted",
                "request_url": registration.form.action,
                "response_status": response.status,
                "note": (
                    f"created {email}; the response set {len(session)} session cookie(s)"
                    + (f" and redirected to {urljoin(registration.url, location)}" if location else "")
                ),
            }
        )

        if not crossed:
            verdict.confidence = max(verdict.confidence, 75)
            verdict.reason += (
                f". An account ({email}) was created, but its session did not reach "
                f"{protected.url} (HTTP {authenticated.status}), so the account exists "
                "without having crossed the boundary. Delete it and check by hand what "
                "the account can see"
            )
            return

        verdict.session_confirmed = True
        verdict.signals.append("session_crossed_boundary")
        verdict.tier = FindingTier.CONFIRMED
        verdict.confidence = 95
        verdict.severity = Severity.CRITICAL
        verdict.evidence.append(
            {
                "label": "the new session reaches the protected area",
                "request_url": protected.url,
                "response_status": authenticated.status,
                "note": (
                    f"the same URL answered an anonymous request with {protected.how}; "
                    f"with the registered session it returns HTTP {authenticated.status}"
                ),
            }
        )

        providers = ", ".join(verdict.providers)
        verdict.reason = (
            f"An unauthenticated request to {registration.url} created a local account "
            f"({email}), which was issued a session that reaches {protected.url} — the "
            f"same URL that refuses anonymous callers with {protected.how}. The "
            f"application's sign-in hands off to {providers}, so this account holds "
            "access that the identity provider never granted and no administrator "
            f"invited. Delete {email} once the report is filed"
        )

        # What did that account get to see?
        scan = scan_sensitive_data(
            authenticated.text, control_body=protected.body_sample
        )
        verdict.data_scan = scan
        if scan.significant:
            verdict.signals.append("sensitive_data_exposed")
            verdict.evidence.append(
                {
                    "label": "personal data on the page the account reached",
                    "request_url": protected.url,
                    "response_status": authenticated.status,
                    "note": (
                        f"{scan.summary()}. Samples are redacted deliberately: "
                        + "; ".join(
                            f"{c.label}: {', '.join(c.samples)}" for c in scan.categories
                        )
                    ),
                }
            )
            verdict.reason += (
                f". The page it reached carries {scan.summary()}, so the bypass exposes "
                "records as well as access"
            )

    # -- payload construction ----------------------------------------------

    def _unique_email(self) -> str:
        """A plus-addressed, obviously-synthetic address under the named mailbox."""
        local, _, domain = (self._probe_email or "").partition("@")
        return f"{local}+reconx-{secrets.token_hex(4)}@{domain}"

    @staticmethod
    def _probe_password() -> str:
        """Random, and shaped to pass the usual complexity rules on the first try."""
        return f"Rx{secrets.token_urlsafe(12)}9!aZ"

    def _fill(
        self, registration: RegistrationForm, email: str, password: str
    ) -> dict[str, str]:
        """Build the form body, keeping every hidden value the server sent us."""
        payload: dict[str, str] = {}
        for item in registration.form.fields:
            if not item.name:
                continue
            lowered = item.name.lower()

            if item.hidden:
                payload[item.name] = item.value
            elif item.type == "password":
                payload[item.name] = password
            elif item.type == "email" or any(
                fragment in lowered for fragment in ("email", "e-mail", "mail")
            ):
                payload[item.name] = email
            elif item.type == "checkbox":
                # Terms and conditions: a registration form that requires one
                # and does not get it is rejected for the wrong reason.
                payload[item.name] = item.value or "on"
            elif item.type == "select" and item.options:
                payload[item.name] = next(
                    (option for option in item.options if option), ""
                )
            elif any(fragment in lowered for fragment in ("phone", "mobile", "tel")):
                # A documentation-reserved number, so nothing real is dialled.
                payload[item.name] = "+15550100"
            elif item.type in ("text", "textarea", "url", "number", "date", "") or any(
                fragment in lowered for fragment in _PERSON_NAMES
            ):
                payload[item.name] = _PROBE_LABEL

        payload[registration.password_field] = password
        if registration.confirm_field:
            payload[registration.confirm_field] = password
        if registration.identity_field:
            payload[registration.identity_field] = email
        if registration.csrf_field:
            payload[registration.csrf_field] = registration.csrf_value or ""
        return payload

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _looks_like_login(response) -> bool:
        """Did we get the sign-in page back instead of the protected page?

        An application that answers an unauthenticated request by rendering its
        login page with HTTP 200 is common, and reading that as "the session
        worked" is how an authentication check fools itself.
        """
        path = (urlsplit(response.url).path or "").lower()
        if any(hint in path for hint in _LOGIN_HINTS):
            return True
        forms = parse_forms(response.text, response.url)
        return any(form.of_type("password") for form in forms)

    def _page_evidence(self, registration: RegistrationForm) -> dict:
        return {
            "label": "unauthenticated registration form",
            "request_url": registration.url,
            "response_status": 200,
            "note": (
                f"posts to {registration.form.action}; recognised by "
                f"{'; '.join(registration.reasons)}"
            ),
        }

    async def _is_missing(self, root: str, response) -> bool:
        """Is this the host's not-found page wearing a 200?"""
        if self._baselines is None:
            return False
        path = urlsplit(response.url).path or "/"
        missing, _ = await self._baselines.is_not_found(root, path, response.fingerprint)
        return missing

    async def _get(self, url: str, **kwargs):
        try:
            return await self._http.get(url, **kwargs)
        except Exception:
            return None
