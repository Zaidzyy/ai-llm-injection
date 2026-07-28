# Redaction policy

What never gets committed to this repository, and why. Written as a standing rule rather
than a case-by-case judgement, because case-by-case judgement is how payloads end up in
public repos.

## Never published

### 1. Working payloads
Any prompt, persona directive, or configuration string that reliably circumvents a
production model's safeguards.

**Why:** a repository whose README claims responsible disclosure while shipping the payload
contradicts itself in public. The claim is the artifact — breaking it costs more than the
screenshot is worth.

This applies **permanently**, not on a disclosure timer. Standard 90-day windows exist so a
vendor cannot bury a fix indefinitely; they do not create an obligation to publish a
weaponised string once the window closes. Publishing the *finding* discharges the duty.
Publishing the *payload* serves no additional defensive purpose.

### 2. Model output in prohibited categories
Anything the model produced that falls in a category the vendor's own policy withholds —
exploit code, malware, weapons or drug synthesis, and so on.

**Why:** the output is the harm. Republishing it causes exactly the damage the safeguard
existed to prevent, and does so at greater scale than the original session. That the model
generated it rather than the researcher changes nothing about its effect.

### 3. Vulnerabilities in third-party software
Anything affecting a product other than the one under test — including vulnerabilities the
model surfaced or generated exploit code for.

**Why:** a separate vendor means a **separate disclosure obligation**. Publishing a working
exploit for a third party's product under an "AI safety research" heading is dropping an
unreported vulnerability with extra steps. Those findings go through their own disclosure
process or not at all.

### 4. Personal and account identifiers
Email addresses, account names, conversation URLs, sidebar chat history, browser profile
details, session tokens, anything in a screenshot's periphery.

**Why:** conversation URLs are frequently shareable links. Sidebar history is an unintended
profile of the researcher. Both are trivially avoided by cropping and trivially permanent
once pushed.

---

## Published

- Technique classes and mechanisms, described at concept level
- Screenshots showing **stated policy**, refusals, and UI surfaces — cropped and redacted
- Harness output, scores, and technique-level results
- Mitigations, detection heuristics, defensive tooling
- Disclosure timelines including outcomes that went against the researcher

## Screenshot procedure

1. **Crop** browser chrome, address bar, sidebar, and OS taskbar. Keep only the content pane.
2. **Redact** any payload text with an opaque box — a visible marked box, not a blur. Blurs
   have been reversed; opaque fills have not.
3. **Verify** the periphery: account email, conversation URL, notification badges, window
   titles, file paths.
4. **Re-open the exported file** and read it as a stranger would. Redaction applied to a copy
   is not redaction applied to the committed file.

Committed images in `images/` were processed this way. `03-configuration-surface-redacted.png`
retains the settings UI to evidence the delivery channel, with the payload removed — the
channel is the finding; the string is not.

## Report hygiene

`redteam.report.to_json()` **strips prompts and responses by default.** Recovering them
requires `--include-responses`, whose help text says not to commit the output.

Real payloads used in live testing belong in `harness/probes/private.yaml`, which is
gitignored and loaded only with `--include-private`. That run prints a warning to stderr.

Safe-by-default beats a policy document nobody reads. This document exists for the cases
defaults cannot cover.
