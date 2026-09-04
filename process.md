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
- `check_domain()` first checks whether a supported homoglyph-normalized
  domain exactly matches a watchlist entry, then uses ordinary matching for
  all other inputs.
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

- Target 1 is complete.
- Target 2 is complete.
- Target 3 is complete.
- Target 4 is complete.
- Target 5 is now complete; all planned Person 5 targets are complete.
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
- Homoglyph handling uses a small explicit Cyrillic-to-Latin mapping for
  common lookalikes (`а`, `е`, `о`, `р`, `с`, `х`, and `у`). It is applied only
  when a mapped domain exactly matches a watchlist entry, limiting false
  positives and avoiding an external dependency.
- A supported homoglyph match takes precedence over the ordinary distance
  result and reports the raw domain distance plus `match_type: "homoglyph"`.
  Unsupported Unicode remains on the existing safe distance path.
- The watchlist now includes the legitimate fixture domain
  `bank-of-america.com` alongside `bankofamerica.com`, preventing a false
  positive for the shared legitimate fixture. It retains the required brands,
  multiple bank domains, and `sbi.co.in`; no separate institution domain is
  named in the project context.
- Hyphenated first-label domains are checked for a close typo in the prefix
  before the suffix (for example, `micros0ft-support.com`). This is a narrow
  brand-impersonation rule and does not increase the ordinary distance
  threshold or treat arbitrary suffixes as trusted.
- Integration remains contract-only: the pipeline receives the unchanged
  five-field typosquat result, scoring can read `is_suspicious`, and
  correlation can read `closest_match`. No scoring or correlation behavior
  was changed for Target 5.

## Files changed

- `typosquat/main.py` — reject non-string and empty normalized inputs before
  matching; calculate Damerau-Levenshtein distance and detect supported
  homoglyph matches; detect close brand typos followed by a hyphenated label
  suffix.
- `typosquat/test_typosquat.py` — add parameterized exact-result tests for
  malformed and empty inputs plus edit-operation, transposition, homoglyph,
  ASCII, Unicode edge-case, and shared-fixture sender-domain tests.
- `typosquat/watchlist.json` — add `bank-of-america.com` and keep the starter
  domains sorted.
- `process.md` — record final integration and regression results; mark Target
  5 complete.

No files outside the Person 5 module and its process log were changed.

## Tests run and results

- `py -3.12 -m pytest typosquat\\test_typosquat.py -q` — passed, 16 tests.
- `py -3.12 -m pytest typosquat\\test_typosquat.py -q` — passed, 21 tests
  after Target 2.
- `py -3.12 -m pytest typosquat\\test_typosquat.py -q` — passed, 26 tests
  after Target 3.
- `py -3.12 -m pytest typosquat\\test_typosquat.py -q` — passed, 32 tests
  after Target 4.
- `py -3.12 -m pytest -q` — passed, 44 tests.
- `py -3.12 -m pytest -q` — passed, 49 tests after Target 3.
- `py -3.12 -m pytest -q` — passed, 55 tests after Target 4.
- `py -3.12 -m pytest typosquat\\test_typosquat.py -q` — passed, 32 tests in
  final Target 5 validation.
- `py -3.12 -m pytest -q` — passed, 55 tests in final Target 5 validation.
- `py -3.12 run_demo.py` — passed; the phishing fixture produced a suspicious
  typosquat result with `closest_match: "paypal.com"`, and the combined
  record included scoring and correlation outputs.
- Python 3.12 integration assertion with a malformed sender domain — passed;
  the pipeline returned the exact five-field safe typosquat result without an
  exception.
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
- The explicit mapping intentionally covers common Cyrillic lookalikes only;
  broader Unicode confusable coverage is outside this target.
- The first Target 4 run failed because of a missing comma in the updated JSON
  watchlist; the syntax was corrected and the focused suite then passed.
- No integration or regression problems were found during Target 5.

## Next target

All planned Person 5 targets are complete. No further module target is
scheduled; future changes should be coordinated with the owning integration
team members and preserve the pinned contract.