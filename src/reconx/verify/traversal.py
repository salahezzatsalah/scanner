"""Path traversal verification.

The naive check is to send ``../../etc/passwd`` and grep the response for
``root:``. That fires on documentation pages, on tutorials, on error messages
that quote the requested path, and on any application that echoes its input —
which is why traversal reports are so often closed as invalid.

Two things make a claim here checkable:

* **The signature has to be a record, not a word.** ``root:x:0:0`` in the shape
  a real ``/etc/passwd`` line takes, anchored and with the right field count, not
  the substring ``root``.
* **The control has to fail.** The same filename without the traversal sequence
  must not produce the signature. If it does, the file was already reachable and
  the ``../`` changed nothing.

The two independent oracles are **two different files**, not two encodings of the
same one. Reaching ``/etc/passwd`` and ``/etc/group`` means two unrelated record
formats appeared where a benign filename produces neither, and no page that
happens to quote one of them can account for that. Two encodings of one payload
would be two views of a single observation, which is the mistake the two-oracle
rule exists to prevent.

Within each oracle, several forms are tried, because applications normalise one
and not another: the plain ``../``, a percent-encoded ``..%2f`` sent without
re-encoding, and a deeper climb. Those are filter bypasses, not extra evidence,
so finding the file by any of them counts once.

Each oracle's control is the same filename with no climb: if the file is
reachable without traversal, the traversal proved nothing.

**This reads only enough to prove reachability.** It requests a small number of
well-known paths whose content is a recognisable *format*, and it records the
matched line and nothing else. It does not enumerate the filesystem, walk
directories, fetch application source or configuration, or copy file contents
into the report. Proving the boundary is crossed is the finding; reading what is
behind it is the program owner's data.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from reconx.verify.base import (
    FetchResult,
    OracleResult,
    OracleStrength,
    ParameterVerdict,
    ParameterVerifier,
    ParamTarget,
    decide_from_oracles,
)
from reconx.verify.differential import Detection, DifferentialOracle

__all__ = [
    "FILE_SIGNATURES",
    "TraversalVerdict",
    "TraversalVerifier",
    "find_file_signature",
]


@dataclass(frozen=True)
class FileSignature:
    """A well-known file, and the shape that proves we are looking at it."""

    label: str
    #: Path relative to whatever the parameter's base directory is.
    target: str
    #: Matches the file's *format*, not a word that appears in it.
    pattern: re.Pattern[str]
    note: str


# Deliberately short. Each entry has a machine-checkable record format, which is
# what separates "this is the file" from "this page mentions the file".
FILE_SIGNATURES: tuple[FileSignature, ...] = (
    FileSignature(
        label="unix account database",
        target="etc/passwd",
        # Seven colon-separated fields with uid and gid 0. Bounded by a line
        # edge or an HTML tag edge, so a file rendered inside <pre> still
        # matches while the bare word "root" in a sentence does not.
        pattern=re.compile(
            r"(?:^|>)root:[^:\n<]*:0:0:[^:\n<]*:[^:\n<]*:[^:\n<]*(?:$|<)",
            re.MULTILINE,
        ),
        note="an /etc/passwd record for uid 0 with all seven fields",
    ),
    FileSignature(
        label="unix group database",
        target="etc/group",
        pattern=re.compile(
            r"(?:^|>)root:[^:\n<]*:0:[^:\n<]*(?:$|<)", re.MULTILINE
        ),
        note="an /etc/group record for gid 0",
    ),
    FileSignature(
        label="windows hosts file",
        target="windows/win.ini",
        pattern=re.compile(
            r"(?:^|>)\[(?:fonts|extensions|mci extensions)\]",
            re.MULTILINE | re.IGNORECASE,
        ),
        note="a win.ini section header",
    ),
)

# The forms tried for each file. A filter bypass, not independent evidence: the
# first one that reaches the file ends the search. ``raw`` means the value is not
# percent-encoded on the way out, without which ``..%2f`` would arrive as the
# literal text rather than as an encoded separator.
_FORMS: tuple[tuple[str, str, int, bool], ...] = (
    ("../", "a traversal sequence", 3, False),
    ("../", "a deeper traversal sequence", 6, False),
    ("..%2f", "a percent-encoded traversal sequence", 3, True),
    ("....//", "a doubled traversal sequence", 3, False),
)


def find_file_signature(body: str) -> tuple[FileSignature, str] | None:
    """Return the signature and the matched line, if a known file is present."""
    window = body[:200_000]
    for signature in FILE_SIGNATURES:
        match = signature.pattern.search(window)
        if match:
            return signature, match.group(0)[:200]
    return None


@dataclass
class TraversalVerdict(ParameterVerdict):
    """The verification outcome for one file-path parameter."""

    file_label: str = ""
    matched_line: str = ""

    def as_dict(self) -> dict:
        return {
            **super().as_dict(),
            "file_label": self.file_label,
            # The matched record is kept because it is the proof. Nothing beyond
            # the one matching line is ever stored.
            "matched_line": self.matched_line,
        }


class TraversalVerifier(ParameterVerifier):
    """Verifies that a parameter can reach a file outside its intended directory."""

    vuln_class = "path_traversal"
    title = "Path traversal"
    verdict_class = TraversalVerdict

    async def verify(
        self, target: ParamTarget | str, parameter: str | None = None
    ) -> TraversalVerdict:
        target = self.target_of(target, parameter)
        verdict: TraversalVerdict = self.new_verdict(target)  # type: ignore[assignment]

        original = await self.fetch(target.apply(target.current_value))
        if not original.ok:
            verdict.reason = (
                f"the original request could not be completed ({original.error})"
            )
            return verdict
        if self.gate_obstruction(verdict, original):
            return verdict

        # The signature already on the unmodified page makes the oracle
        # meaningless, exactly as a pre-existing SQL error does. This is the
        # /docs/passwd case: a page about /etc/passwd contains the record shape.
        pre_existing = find_file_signature(original.text)
        if pre_existing is not None:
            signature, line = pre_existing
            verdict.file_label = signature.label
            verdict.oracles.append(
                OracleResult(
                    name="file_signature",
                    agreed=False,
                    reason=(
                        f"the unmodified page already contains {signature.note} "
                        f"({line[:80]!r}), so its appearance under a traversal payload "
                        "says nothing about what the parameter can reach"
                    ),
                    strength=OracleStrength.DECISIVE,
                )
            )
            verdict.apply(decide_from_oracles(verdict.oracles))
            return verdict

        def detect(result: FetchResult) -> Detection:
            found = find_file_signature(result.text)
            if found is None:
                return Detection(present=False)
            signature, line = found
            return Detection(present=True, detail=f"{signature.note}: {line[:80]!r}")

        # One oracle per file. The first two that are reachable decide it; there
        # is no value in walking the rest of the list once the bar is met.
        for index, signature in enumerate(FILE_SIGNATURES):
            result = await self._probe_file(target, signature, index, detect, verdict)
            verdict.oracles.append(result)
            if len([o for o in verdict.oracles if o.agreed]) >= 2:
                break

        verdict.apply(
            decide_from_oracles(
                verdict.oracles,
                fallback_reason=(
                    "no traversal payload reached a file outside the parameter's "
                    "intended directory"
                ),
            )
        )
        return verdict

    async def _probe_file(
        self,
        target: ParamTarget,
        signature: FileSignature,
        index: int,
        detect,
        verdict: TraversalVerdict,
    ) -> OracleResult:
        """Try to reach one well-known file, in each form, against a control."""
        name = f"reached_{signature.target.replace('/', '_')}"
        last: OracleResult | None = None

        for separator, label, depth, raw in _FORMS:
            payload = separator * depth + signature.target
            # The control is the same filename with no climb.
            oracle = DifferentialOracle(
                self.fetch,
                name=name,
                signal=f"{signature.label} record format",
                detect=detect,
                payload_label=label,
                strength=(
                    OracleStrength.DECISIVE if index == 0 else OracleStrength.STRONG
                ),
                attempts=self._attempts,
                required=self._required,
                lone_reason=(
                    f"the parameter reaches {signature.label} outside its intended "
                    "directory, which is a real boundary crossing, but no second file "
                    "was reachable to corroborate it; confirm by hand before reporting"
                ),
            )
            result = await oracle.run(
                target.apply(payload, raw=raw),
                target.apply(signature.target),
                evidence_label=f"{label} to {signature.target}",
                collect=verdict.evidence,
            )
            if result.agreed:
                verdict.file_label = verdict.file_label or signature.label
                verdict.matched_line = verdict.matched_line or str(
                    result.detail.get("observed") or ""
                )
                result.detail.update(
                    {"file": signature.target, "form": separator, "depth": depth}
                )
                return result
            last = result

        return last or OracleResult(
            name=name,
            agreed=False,
            reason=f"no form of traversal reached {signature.target}",
            strength=OracleStrength.DECISIVE,
        )
