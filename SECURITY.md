# Security policy

## Reporting a vulnerability in this repository

Open a [security advisory](https://github.com/Zaidzyy/ai-llm-security-research/security/advisories/new),
or a public issue if the impact is low. Expect a response within 7 days.

The detector is the most likely place for a real bug — a normalisation gap that lets a
payload through, or a false-positive pattern that would break a production pipeline. Both are
worth reporting.

## Research conduct

Findings in this repository were produced under the following constraints:

- Personal accounts and vendor-provided interfaces only
- Ordinary interactive rates — no automation against production endpoints, no load testing
- No access to other users' data or sessions
- No testing against vendor infrastructure — no scanning, no authentication testing, no DoS
- Findings reported to the vendor before publication
- 90 days or vendor resolution, whichever comes first, before publishing a write-up

## What is never published here

- Working payloads that circumvent a production model's safeguards
- Model output in categories the vendor's own policy withholds
- Vulnerabilities in third-party software, which carry their own disclosure obligation
- Personal or account identifiers

Payload withholding is **permanent**, not disclosure-timed. The 90-day convention exists so a
vendor cannot bury a fix indefinitely; it does not create an obligation to publish a
weaponised string once the window closes. Publishing the finding discharges the duty to the
community. Publishing the payload serves no additional defensive purpose.

Full rationale: [`docs/redaction-policy.md`](docs/redaction-policy.md).

## Intended use of the tooling

The harness and detector are defensive instruments — for regression-testing your own system
prompts, and for filtering untrusted content ahead of an LLM call.

The published probe suite contains no working jailbreaks. Its probes target a benign canary
token and carry no harmful objective, by design and by test
(`tests/test_runner.py::TestSuite::test_templates_carry_no_harmful_objective` fails the build
if that changes).

Do not use this tooling against systems you are not authorised to test. Vendor terms of
service govern model testing regardless of research intent; authorisation is your
responsibility to establish, not to assume.
