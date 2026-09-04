# Person 5 Typosquat Module Process Log

## Scope and constraints

- Own only the `typosquat/` module and its tests/watchlist.
- Preserve the pinned `check_domain(domain: str) -> dict` signature.
- Preserve the pinned return keys: `domain`, `is_suspicious`,
  `closest_match`, `distance`, and `match_type`.
- Never raise for empty, malformed, or unexpected domain input.
- Do not modify files owned by other team members.

## Current implementation understood

- `typosquat/main.py` loads `watchlist.json` on each call.
- `normalize_domain()` trims and lowercases input, removes a scheme,
  path, port, and leading `www.`.
- `levenshtein()` implements ordinary Levenshtein distance with dynamic
  programming; it does not handle adjacent transpositions as one edit.
- `check_domain()` compares the normalized input with every watchlist entry,
  selects the closest entry, and flags a non-exact match at distance <= 2.
- Homoglyph detection is not implemented.
- The function echoes the original input in the `domain` result field, but a
  non-string value can currently fail during normalization.
- `test_typosquat.py` checks output shape, exact trusted-domain behavior,
  digit substitutions, common typos, and an unrelated domain. It does not yet
  cover all shared `.eml` fixtures or malformed inputs.
- `watchlist.json` contains ten domains, including `bankofamerica.com`.
- The shared phishing fixture uses `micros0ft-support.com`; the current
  whole-domain distance threshold may miss it because the `-support` suffix
  adds more than two edits relative to `microsoft.com`.

## Roadmap / independently testable targets

### Target 1: Contract-safe input and fixture baseline

- Make empty and malformed inputs return the required safe result shape
  without raising.
- Verify normalization behavior with focused unit tests.
- Capture a baseline for fixture domains without changing valid-domain
  matching policy in this input-safety target.
- Defer resolution of the known legitimate-fixture mismatch between
  `bank-of-america.com` and the current `bankofamerica.com` watchlist entry.
- Test: `pytest typosquat/test_typosquat.py -q` plus focused new cases.

### Target 2: Damerau-Levenshtein matching

- Replace ordinary Levenshtein comparison with Damerau-Levenshtein so an
  adjacent transposition such as `mircosoft.com` costs one edit.
- Keep exact watchlist domains safe and retain a justified threshold.
- Test: unit cases for insertion, deletion, substitution, transposition,
  exact matches, and unrelated domains.

### Target 3: Homoglyph detection

- Add a constrained, explicit homoglyph mapping for relevant Latin/Cyrillic
  lookalikes and detect mapped equivalents against the watchlist.
- Return `match_type: "homoglyph"` for this path while preserving all pinned
  fields and safe behavior for unsupported Unicode.
- Test: representative Cyrillic substitutions, mixed-script inputs, and
  ordinary ASCII domains.

### Target 4: Watchlist and fixture coverage

- Review the watchlist for fixture coverage, sorted/validated entries, and
  false-positive cases.
- Expand focused tests to all shared phishing and legitimate fixtures using
  their sender domains.
- Test: the module suite against the shared fixture set and malformed values.

### Target 5: Integration readiness and regression pass

- Confirm the result is directly consumable by dashboard scoring and campaign
  correlation without changing the contract.
- Run the complete repository test suite and record unrelated failures without
  changing other owners' files.
- Test: typosquat suite first, then repository-wide `pytest`.

## Decisions made

- Target 1 is complete; Target 2 is the next target.
- Target 2 is now complete; Target 3 is the next target.
- The pinned public API and return field names are frozen.
- The detector will remain self-contained and will not add live DNS or
  external API calls.
- Matching should be conservative enough to avoid false positives on trusted
  domains while still catching one- and two-edit impersonations.
- Target 1 intentionally preserves existing valid-domain matching behavior;
  Damerau-Levenshtein, homoglyph detection, and broader fixture matching are
  deferred to later targets.
- Invalid input is defined here as a non-string value or a string that becomes
  empty after the existing normalization steps. These inputs return the safe
  contract result without attempting watchlist matching.
- The existing `distance <= 2` suspicion threshold is retained. Damerau-
  Levenshtein changes transposition costs while keeping the established
  sensitivity for one- and two-edit substitutions, insertions, and deletions.
- The distance helper uses the standard dynamic-programming matrix with last
  matching-character positions, supporting adjacent transposition as one
  edit without adding dependencies.

## Files changed

- `typosquat/main.py` — reject non-string and empty normalized inputs before
  matching; calculate Damerau-Levenshtein distance for watchlist matching.
- `typosquat/test_typosquat.py` — add parameterized exact-result tests for
  malformed and empty inputs plus edit-operation and transposition tests.
- `process.md` — update the execution log and mark Target 2 complete.

No files outside the Person 5 module and its process log were changed.

## Tests run and results

- `py -3.12 -m pytest typosquat\\test_typosquat.py -q` — passed, 16 tests.
- `py -3.12 -m pytest typosquat\\test_typosquat.py -q` — passed, 21 tests
  after Target 2.
- `py -3.12 -m pytest -q` — passed, 44 tests.
- Fixture header inspection — completed; sender domains found were
  `bank-of-america.com`, `paypa1.com`, and `micros0ft-support.com`.
- `git diff --check` — passed.

## Problems encountered

- The current watchlist contains `bankofamerica.com`, while the legitimate
  fixture uses `bank-of-america.com`; this needs an explicit false-positive
  decision in a later fixture-coverage target.
- The current whole-domain comparison may miss the required
  `micros0ft-support.com` phishing fixture; brand-label comparison or a
  carefully scoped suffix policy needs to be decided in a later target.
- No new problems were found during Target 2 validation.

## Next target

Target 3: implement constrained homoglyph detection and add focused
Unicode/mixed-script tests.