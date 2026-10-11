# Genuine notepad.exe is judged malicious

## Symptom

`C:\Windows\System32\notepad.exe` is a Microsoft-signed system binary (catalog-signed:
`Get-AuthenticodeSignature` reports Valid, Catalog, CN=Microsoft Windows). The static
investigator should call it benign. Across 11 benchmark runs it never did:

| Version | Commit | Runs | Verdicts |
|---|---|---|---|
| Before the retrieval work | `c6a0379` | 3 | malicious ×3 |
| U9: imports collected | `34a27a6` | 3 | malicious ×2, inconclusive ×1 |
| U10: all lists collected | `dc2c661` | 3 | malicious ×3 |
| Fix 1: capa grading, density signal | `fb9ccf8` | 1 | inconclusive ×1 |
| Fix 2: section names, debugger imports | `39455d2` | 1 | malicious ×1 |

Objective in every run: "Identify suspicious behavior". Rows are in
`runs/benchmarks/*_notepad.jsonl`, traces in `runs/benchmarks/traces/`. The last two
versions have one run each, so their verdicts are single data points.

Dashboard of all runs, findings and evidence: https://claude.ai/artifact/WGtJMtHi1jjLFcWY1kycm2

## Why it happened

Every piece of evidence the model cited is something ordinary Windows programs have.

| Evidence | What it actually is | Owner |
|---|---|---|
| "Only 1 function discovered in a 360 KB file; may be packed" | `list_functions` only reads the PE entry point, so the density check fired on every file over 64 KiB. | MIRA (fixed) |
| 35 capa capabilities (create process, delete file, registry, mutex, XOR, geolocation) at 0.9 confidence each | capa describes what code can do, not intent. Every hit counted as a strong rule match. | MIRA (fixed) |
| Section `fothk` "not from a standard toolchain" | `fothk` is in 81% of System32 binaries. | MIRA (fixed) |
| `IsDebuggerPresent`, `OutputDebugStringW` as anti-debugging | The C runtime imports them: 60% and 52% of System32 binaries. | MIRA (fixed) |
| `GetProcAddress`, 5 ordinal-only imports | Near-universal (GetProcAddress in 67% of System32 binaries). Already weak evidence. | MIRA (wording added) |
| `go.microsoft.com` URLs and `Software\Microsoft\Notepad` registry paths read as "masquerading" | Exactly what real Notepad contains. | Model reasoning |
| `.rsrc` entropy 6.97 | Below MIRA's own 7.2 threshold; icons and images look like that. | Model reasoning |

Survey basis: 2,111 PE files in `C:\Windows\System32`, October 2026.

## What was fixed

All in `mira/agents/static/evidence.py`, each with tests.

1. **`fb9ccf8`, function density:** no density signal when every discovered function came
   from the PE entry point.
2. **`fb9ccf8`, capa grading:** each hit is graded by capa-rules' top-level namespace.
   - anti-analysis, persistence, impact, malware-family: strong (0.9);
   - communication, collection, targeting: moderate (0.6);
   - everything else: weak (0.4), and its sentence says "benign software commonly has this
     capability too".
   - Strongest hits are named first, so the 20-hit cap never hides them.
3. **`39455d2`, section names:** `fothk`, `.imrsiv`, `gfids`, `.00cfg` and `init` count as
   standard sections.
4. **`39455d2`, debugger imports:** `IsDebuggerPresent` and `OutputDebugString` became weak
   evidence and say the C runtime imports them. `CheckRemoteDebuggerPresent`,
   `NtSetInformationThread`, `NtQueryInformationProcess` and `DebugActiveProcess` stay strong.
   `GetProcAddress` evidence now says most Windows programs import it.

Note: the prompt shows the model only each evidence sentence, never its confidence number,
so a weak grade reaches the model only through the sentence's wording.

## What still drives the malicious verdict

From the single run on `39455d2`:

1. **The model flags `fothk` itself.** It read the section name from the raw `analyze_pe`
   output. It argued that the section's near-zero entropy suggests encrypted data, which is
   backwards: encrypted data has high entropy, and near-zero means padding. It also cited a
   URL evidence item (E4) as support. Report validation checks only that cited ids exist,
   not that they fit the claim.
2. **Two capa hits are anti-analysis and stay strong by design:** "execute anti-debugging
   instructions" and "reference analysis tools strings". Two more are moderate: "get
   geographical location" and "identify system language".
3. **No rule requires strong evidence for a malicious verdict.** The objective wording also
   primes the model to find something suspicious.

## Options not yet taken

- **Prompt guidance:** tell the model MIRA already flags unusual section names and entropy,
  so it should not re-judge raw values, and that low entropy means padding, not encryption.
- **Verdict rule:** a non-benign verdict must cite at least one strong piece of evidence.
  This is the plan's deferred "verdict-set validation" item.
- **Labeled samples first:** measure on benign, malicious, ambiguous and malformed samples
  before tuning further, so the changes are not fitted to notepad alone.
- **Signature check (deferred by decision):** System32 binaries carry no embedded signature.
  An embedded-only check would call them unsigned and worsen this. Catalog verification
  needs WinVerifyTrust through `ctypes`, which is Windows-only (CI runs on Linux) and trusts
  the analysis host's catalogs.

## Other open items from this work

- **Uncommitted endpoint change:** `mira/reasoning/model/adapter.py` hardcodes the Azure
  resource `shareablepublicproject-resource` and the model `DeepSeek-V4-Flash`, and sends
  `MODEL_API_KEY` to that host. All benchmarks above ran with it. Review before committing.
- **Review findings skipped on purpose:**
  - Runs that stop making progress get no final report turn. That is the existing rule from
    `bba8900`.
  - A partial page walk (one that hit `fetch_error`) refuses an identical retry; the rest of
    the list is fetched with `offset=next_offset`.
  - Pages are fetched one after another (plan KTD1).
- **Not reviewed:** the U10 change (`dc2c661`: collection table and pass-through of pages
  without paging counters). The code review ran before it.
- **Labeled-sample comparison not run:** the plan's real gate for U9 and U10.
