# Redaction policy

What never gets committed to this repository, and why. Written as a standing rule rather
than a case-by-case judgement, because case-by-case judgement is how payloads end up in
public repos.

## Never published

### 1. Vulnerabilities in third-party software
Anything affecting a product other than the one under test — including vulnerabilities the
model surfaced or generated exploit code for.

**Why:** a separate vendor means a **separate disclosure obligation**. Publishing a working
exploit for a third party's product under an "AI safety research" heading is dropping an
unreported vulnerability with extra steps. Those findings go through their own disclosure
process or not at all.

### 2. Personal and account identifiers
Email addresses, account names, conversation URLs, sidebar chat history, browser profile
details, session tokens, anything in a screenshot's periphery.

**Why:** conversation URLs are frequently shareable links. Sidebar history is an unintended
profile of the researcher. Both are trivially avoided by cropping and trivially permanent
once pushed.

### 3. Anything not needed to make the point
Evidence exists to support a specific claim. Material beyond that claim adds risk without
adding proof.

---

## Published

- Technique classes and mechanisms, described at concept level
- Screenshots evidencing **stated policy**, refusals, and the UI surfaces involved
- Harness output, scores, and technique-level results
- Mitigations, detection heuristics, defensive tooling
- Disclosure timelines including outcomes that went against the researcher

## Screenshot procedure

1. **Crop** browser chrome, address bar, sidebar, and OS taskbar. Keep only the content pane.
2. **Verify** the periphery: account email, conversation URL, notification badges, window
   titles, file paths.
3. **Re-open the exported file** and read it as a stranger would. Redaction applied to a copy
   is not redaction applied to the committed file.

Committed images in `images/` were processed this way. `jailbreak.jpeg` retains the settings UI
to evidence the delivery channel — the channel is what the finding rests on, not the string.

## Report hygiene

`redteam.report.to_json()` **strips prompts and responses by default.** Recovering them
requires `--include-responses`, whose help text says not to commit the output.

Real payloads used in live testing belong in `harness/probes/private.yaml`, which is
gitignored and loaded only with `--include-private`. That run prints a warning to stderr.

Safe-by-default beats a policy document nobody reads. This document exists for the cases
defaults cannot cover.
