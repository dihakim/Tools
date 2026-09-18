# ComplianceCheck (Go rewrite)

Single static binary, no runtime dependencies, cross-compiled for every OS
from one dev machine. No internet access required or used anywhere.

## Run it

    ./compliancecheck-linux-amd64 --target /path/to/scan --output report.json
    # or on Windows:
    compliancecheck-windows-amd64.exe --target C:\path\to\scan --output report.json

    # or, for a point-and-click local web UI instead of the CLI:
    ./compliancecheck-linux-amd64 --serve
    # opens a browser at http://127.0.0.1:8642 automatically (use --no-browser
    # to skip that on a headless machine and just get the printed URL)

Flags:
  --target        file or folder to scan (required unless --serve)
  --output        write JSON report here (default: prints to stdout)
  --min-severity  info|low|medium|high|critical - only include findings at/above this
  --flagged-only  shortcut for --min-severity low
  --serve         start the local web UI instead of a one-shot scan
  --port          port for --serve (default 8642, 0 = pick any free port)
  --no-browser    with --serve, don't try to auto-open a browser

## Build all platforms yourself

    ./build_all.sh

Produces dist/ with binaries for linux-amd64, linux-arm64, macos-amd64,
macos-arm64, windows-amd64. No target OS or VM needed - Go cross-compiles
natively.

## What's implemented

- Storage/file scanning: see previous section - PII, language detection,
  file signature mismatch, entropy, PDF/DOCX/XLSX/PPTX text extraction.
- Cipher/encoding engine (`internal/cipher`) - each of the following has
  encode, decode, and pattern-detection support, and is wired into the
  storage scanner's content checks:
  - Common encodings: base64, hex, base32, binary (8-bit groups), URL
    (percent) encoding - detected as substrings within larger text (e.g.
    a base64 token pasted into a config file), decoded automatically,
    and - if the decoded bytes look like real text rather than binary
    data (validated at the byte level, not naively with unicode.IsPrint,
    which was a real bug caught during testing: invalid UTF-8 decodes
    as the printable replacement character, so raw binary was initially
    slipping through as "meaningful text") - the decoded plaintext is
    itself run back through the PII scanner. A base64-encoded password
    or API key pasted into a README is exactly the case this catches.
  - Classical ciphers: Caesar/ROT13 (all 25 shifts brute-forced),
    Atbash, and Vigenère (key length recovered via Index-of-Coincidence,
    including correcting for the well-known ambiguity where multiples of
    the true key length also show elevated IC - verified during testing
    against a 6-letter key that was initially mis-detected as 12), each
    with the key recovered via chi-squared frequency analysis. This is
    the "auto-decode when there's a key" capability: when a file's text
    doesn't match any known language, the scanner automatically attempts
    all of these before giving up and reporting it as merely
    "unrecognized." A successful crack's plaintext is validated against
    real language detection before being trusted (not just "some shift
    produced fewer weird characters") and is itself re-scanned for PII -
    verified end-to-end: a synthetic Caesar-shifted memo containing a
    fake SSN and phone number was correctly cracked, decoded, and had
    both PII items correctly flagged from the decoded text.
  - Not yet added: general polyalphabetic/homophonic substitution beyond
    Vigenère, and modern encryption formats (AES/PGP-encrypted blobs) -
    those aren't crackable without a key at all, so the entropy check is
    what surfaces them today (high entropy, not attributed to a specific
    cipher).
- Network scanning: see previous section - interfaces, hosts file,
  DNS resolvers, listening ports (Linux tested; other OSes partial/honest gaps).
- Network IP/DNS enrichment (`internal/netinfo`), all offline/static data:
  - Every IP address surfaced anywhere (interfaces, hosts file, DNS
    resolvers, listening ports) is classified as public / private
    (RFC 1918/4193) / loopback / link-local / multicast / CGNAT
    (RFC 6598) / documentation range (RFC 5737/3849) / broadcast /
    unspecified - exact stdlib logic against the defined ranges, not a
    heuristic. Verified against this machine's own interface, which
    turned out to be in the RFC 5737 documentation range - correctly
    classified rather than mistaken for a real address.
  - Known public DNS resolver database (Google, Cloudflare, Quad9,
    OpenDNS, AdGuard, CleanBrowsing, and others) - "who owns/operates
    this DNS server" for well-known providers, from a small embedded
    table, NOT a live WHOIS/RDAP lookup (which would require internet
    access this tool intentionally doesn't use). General IP ownership
    lookup (arbitrary IP -> registrant) is out of scope for the same
    reason - that fundamentally needs a live registry query.
- Software scanning:
  - OS identity (all OSes; Linux also reads /etc/os-release for the
    human-readable distro name)
  - Local user accounts - Linux/macOS via /etc/passwd (pure stdlib, no
    exec), flags non-root UID-0 accounts (critical - classic backdoor
    pattern) and system accounts with unexpected interactive shells (low).
    This is the "who else uses this device" capability from the original
    ask. Windows: not yet implemented (needs NetUserEnum or `net user`)
  - Running processes - Linux via /proc directly (no `ps` dependency),
    flags processes running from a deleted/replaced binary (medium -
    common fileless-persistence pattern) and unexplainable root processes.
    Correctly does NOT flag kernel threads (kworker, ksoftirqd, etc.) for
    having no resolvable exe path, since that's normal for them - only
    flags root processes that have a real command line AND an
    unresolvable exe. macOS/Windows: not yet implemented
  - Installed-software inventory - Debian/Ubuntu via dpkg's status file
    (pure stdlib parse, no exec), RedHat/Fedora/SUSE via `rpm -qa` if
    the rpm binary is already present (using an existing system tool,
    not installing anything new). Reports as one inventory summary
    (full package list in evidence, since 500-2000+ base-OS packages
    aren't individually "suspicious") plus a separate Finding for any
    package stuck in a broken/partial install state. macOS/Windows: not
    yet implemented
- Local web UI (`--serve`): a single embedded HTML/CSS/JS file (no
  external resources, no CDN - works with zero internet access), served
  from a plain net/http server bound to 127.0.0.1 only. It's a thin
  layer over the exact same scanner code the CLI uses - point-and-click
  target entry, severity/category/text filtering, expandable findings
  with full evidence, all client-side after the one scan request.
  - Native file/folder picker: a "Browse..." button (with a Folder/File(s)
    toggle) triggers the OS's own picker instead of requiring a typed
    path - browsers can't hand a webpage a real filesystem path for
    security reasons, so this works by having the *server* (which is
    just a local process, not a remote web app) shell out to whatever
    picker the OS already has: PowerShell's WinForms dialogs on Windows,
    `osascript`/Finder on macOS, `zenity` or `kdialog` on Linux
    (whichever the desktop environment provides - confirmed this
    correctly reports a clear "no picker found, type the path manually"
    error on a minimal Linux box with neither installed, rather than
    failing silently). Multi-file selection is supported end-to-end -
    verified scanning two separate files in one request and merging
    their findings into a single report.
  - Per-category check selection: each category (Storage/Network/
    Software/Hardware) expands to show its individual checks (e.g.
    Storage: file signature / PII / encoded content / cipher / entropy /
    extraction) so a person can pick exactly what to search for and
    include in the report, not just the whole category. This is a
    post-scan filter (every check still runs; only what's returned is
    restricted) - verified: restricting Storage to only "PII" correctly
    dropped an unrelated high-entropy finding while keeping the PII one.
    One disclosed trade-off: a file's "clean" marker reflects the full
    scan, not the filtered check set.
  - PII type picker: within Storage, choose specific PII types to search
    for (e.g. only email addresses, not phone numbers) - verified:
    restricting to EMAIL only on a file containing both an email and a
    phone number correctly returned just the email finding.
  - Cipher Tools tab: paste text and Analyze to auto-detect + decode
    (language detection first, then classical cipher cracking if
    unrecognized, then embedded-encoding detection - the "likely cipher
    and most likely meaning" workflow); or Decode with a specific cipher
    selected (key optional for Caesar/Vigenère - triggers automatic key
    recovery when left blank, exactly the "select the cipher, don't know
    the key" case); or Encode plaintext with any supported cipher.
    Backed by the same internal/cipher engine as the automated scanner.
  - Forensic Tools tab: File Hash Calculator (MD5/SHA-1/SHA-256/SHA-512
    in one pass), Hash Identifier (guesses likely algorithm from a bare
    hash string's length/format - e.g. correctly identifies a 32-hex-char
    string as possibly MD5/NTLM/MD4), and a JWT Decoder (decodes header/
    payload for inspection without verifying the signature, since this
    tool never has the signing secret - flags `alg: none` and expired/
    not-yet-valid tokens; verified against a real expired test token).
- Hardware scanning (Linux only so far - macOS/Windows are an honest
  "not implemented" rather than a guess):
  - CPU model/core count, memory total/available (/proc)
  - Storage volumes with usage %, skipping virtual/pseudo filesystems so
    the report isn't dominated by cgroup/tmpfs noise
  - USB devices (/sys/bus/usb) - vendor/product/manufacturer/serial
  - Disk encryption presence heuristic (device-mapper/LUKS detection +
    /etc/crypttab) - explicitly labeled as heuristic, not authoritative

## Hardware/software intelligence (internal/hwintel), from real reference data

Diana supplied a hardware/software intelligence export - static reference
data, not a live feed. Wired in:

  - MAC OUI vendor lookup (~11,000 prefixes) - every network interface's
    MAC address gets a vendor name where recognized.
  - USB vendor/product ID registry (~10,000 entries) - fills in a device
    name when the hardware itself doesn't report a friendly string.
    Notably also flags devices whose registry entry is itself marked
    suspicious (e.g. a "Counterfeit flash drive" product-name match) at
    MEDIUM instead of just displaying it inertly.
  - PCI device scanner (NEW capability) - enumerates /sys/bus/pci/devices
    directly (no lspci/exec needed) and cross-references the ~10,000-row
    PCI registry for vendor/device names.
  - CPU vulnerability scanner (NEW capability) - reads Linux's own
    /sys/devices/system/cpu/vulnerabilities/* (the kernel's authoritative,
    current mitigation status - always more accurate than matching CPU
    model strings against a static list) and cross-references bundled
    Spectre/Meltdown/Foreshadow CVE data for context. Verified catching a
    real partially-unmitigated status (a composite "Mitigation: ..."
    string that contained "BHI: Vulnerable" as a sub-component) that a
    naive "starts with Mitigation = fine" check would have missed.
  - Software blacklist/whitelist/CVE cross-referencing - installed
    packages get checked against bundled known-bad publisher/tool names,
    trusted-publisher whitelist, and a small CVE reference set. Verified
    matching correctly (e.g. "UltraSurf" -> blacklist hit, "Microsoft" ->
    whitelist hit, "Chrome" -> CVE hits). This is explicitly a small
    SAMPLE dataset (~15-85 entries per table), not a live threat-intel
    feed - a match is meaningful, a miss proves nothing.

All registries are coverage snapshots (the hardware export was itself
capped at 10,000 rows per table out of larger source tables), not
exhaustive - a lookup miss just means "not in this snapshot," not
"verified clean."

## Bigram-based cipher-crack validation (internal/ngram), from real corpus data

Real English (~5,000 entries) and French (~10,000 entries) bigram
frequency data, sourced from corpus frequency exports. This exists
specifically to hardstop a recurring class of bug: the classical-cipher
auto-crack validation (Caesar/Vigenère/XOR) originally relied only on a
naive "fraction of tokens matching a stopword list" score, which proved
exploitable twice during testing - garbled, wrong-key decode output could
rack up enough coincidental single-word matches to outscore the correct
decode. Real bigrams are a much harder target to hit by chance (two
specific consecutive words matching, not one), so for English/French
specifically, a crack candidate now also has to clear a minimum
real-bigram-pair ratio before being trusted. Spanish/German don't have
bigram data yet and still rely on the lighter stopword-only check - a
real, disclosed asymmetry, not a hidden gap.

## Additional PII types (from Diana's pii_categories/components/templates data)

Three new PII rules, modeled directly on the supplied category/template
spec: Date of Birth (ISO format, context-boosted by "date of birth"/"dob"
keywords), Street Address (US-style, requires a real street-suffix word -
verified catching "742 Evergreen Terrace" only after expanding the
suffix list past the original spec's set, which was missing common ones
like Terrace/Circle/Way), and Driver's License (US-style state+number).
Deliberately left as LOW severity without a nearby context keyword (raw
ISO dates and letter+digit codes are common in non-PII contexts - version
strings, invoice numbers, timestamps) and boosted to MEDIUM when context
confirms it, the same pattern already used for phone numbers.

## Saved WiFi profile extraction (Linux)

Reads NetworkManager's connection files directly (plain INI text under
/etc/NetworkManager/system-connections, pure stdlib parsing, no nmcli
needed). A saved profile with a plaintext password is flagged MEDIUM -
that's real signal the original spec called out specifically ("a
significant security vulnerability" when discovered). These files need
root to read, which is the OS correctly protecting the credentials, not
a bug here - running without it just reports "permission denied" rather
than fabricating a result. This sandbox has no NetworkManager at all, so
the "not present" path is verified end-to-end; the actual INI-parsing
logic (SSID/security-type/password extraction) was verified separately
against a synthetic connection file and correctly extracted all three
fields. macOS (Keychain) and Windows (WLAN AutoConfig store) are an
honest "not yet implemented" rather than a guess.

## TPM / Secure Boot (Linux)

- TPM presence: checked via /sys/class/tpm existence - pure file-existence
  check, no ioctl/exec.
- Secure Boot: reads the well-known SecureBoot EFI variable directly under
  /sys/firmware/efi/efivars (the same thing `mokutil --sb-state` reads).
  Correctly reports "not UEFI" (not "disabled") on legacy-BIOS systems and
  most VMs/containers, verified against this project's own sandbox (no
  TPM, no UEFI at all) - the "not present" paths are confirmed working;
  the positive-detection paths (TPM found, Secure Boot enabled) are
  straightforward existence/byte checks but have not been run against
  real hardware with those features active, for lack of a test machine.

## Person-name PII detection (internal/pii/names.go), from real name data

Sourced from an international forename/surname frequency dataset
(~1,240 forenames, ~1,500 surnames, Latin-script/romanized entries only).
Detects "First Last" pairs where BOTH words are recognized in their
respective dictionaries - not either list alone, which would fire
constantly on ordinary prose (a common first name or surname appears
in text far too often to be a useful signal by itself). Requiring the
adjacent pair is a much sharper filter: verified correctly catching real
names ("Maria Garcia", "John Smith and Sarah Johnson") while correctly
NOT flagging plausible-looking capitalized phrases like "New York" or
"Random Capitalized Words." Also correctly surfaced "Robert Aragon" in
the project's own sample PII test document - a name that was invisible
to every other check, since it's not a regex-matchable pattern.
Coverage is necessarily partial (~1,200-1,500 most internationally
common names, not exhaustive, Latin-script only) - a miss doesn't mean
"no name is there."

## Language data architecture (internal/langdata)

Answers the "how do I organize words/bigrams/sentences per language,
where bigrams reference words and sentences reference both" design
question directly.

**The design: a `Language` struct per language (words, bigrams, sentences
as three flat slices) - but the three datasets are independent and
cross-referenced by lookup, not nested into each other.** A `Bigram`
doesn't contain two `Word` structs; it has a `FirstWord(lang)` method
that looks its halves up in the same `Language`. A `Sentence` doesn't
contain its words/bigrams; `sentence.Words(lang)` and
`sentence.Bigrams(lang)` resolve them on demand.

Why not nest them: the three datasets arrive from different sources at
different times (today: bigrams only, for en/fr; word lists and sentence
lists are coming later, per language, separately). If a bigram embedded
full word objects, every bigram would need updating whenever the word
list changes. With lookup-based references instead:
  - Each dataset can be added/updated/regenerated independently.
  - A language can exist with only bigrams today (the actual current
    state) and gain words/sentences later with zero code changes - just
    drop a CSV file in, matching exactly the "bigrams now, words and
    sentences later" rollout plan.
  - No duplicated data (a word's popularity/risk lives in exactly one
    place).

**File layout - this is also the answer to "keep it organized":**

    internal/langdata/data/<code>/words.csv       text,popularity,risk
    internal/langdata/data/<code>/bigrams.csv     text,popularity
    internal/langdata/data/<code>/sentences.csv   text,popularity

Adding a new language: create `internal/langdata/data/<code>/` with
whichever of the three CSVs you have (all three optional - a language
can exist with just one). Adding a dataset to an existing language: drop
the missing CSV into its existing directory. Neither requires touching
any Go source - `internal/langdata/loader.go` auto-discovers every
subdirectory of `data/` at build time via `go:embed`, and each language
only registers if it has at least one non-empty dataset.

**Ergonomics** (the "Word("Doll", popularity: 2901, risk: 0.1)" ask):

    lang, _ := langdata.Get("en")
    w, ok := lang.Word("doll")               // Word{Text, Popularity, Risk}
    b, ok := lang.Bigram("of the")           // Bigram{Text, First, Second, Popularity}
    fw, ok := b.FirstWord(lang)              // resolves "of" back to its Word
    s, ok := lang.Sentence("the cat sat")
    words := s.Words(lang)                   // []Word, resolved on demand
    score := lang.BigramPlausibility(text)   // used by cipher-crack validation

**Migration note:** the bigram data added earlier this session (English
~5,000 entries, French ~10,000) has been moved into this structure with
real popularity numbers preserved from the original frequency exports
(e.g. "of the" carries its real corpus count, not a placeholder).
`internal/ngram` (the package cipher-crack validation calls) is now a
thin compatibility wrapper delegating to `internal/langdata`, so nothing
in `internal/cipher` needed to change - verified via full regression
before/after (English and French Vigenère cracks both still recover the
exact correct key, and the whole-system scan produces byte-identical
finding counts).

`internal/langdetect`'s stopword-list-based language detection is a
separate, older system and hasn't been folded into this yet - a natural
next step once real word-frequency lists arrive per language, but not
forced prematurely while only bigram data exists.

**Update - words and sentences have since arrived** (real data, not
placeholders): English now has 4,350 words (real corpus frequency, e.g.
"the" = 22,038,615) and 10,000 sentences; French now has 9,999 words and
242 sentences. Both languages now have all three datasets. One real bug
caught and fixed while wiring this in: case-insensitive lookup was
silently letting whichever case-variant of a word/sentence happened to
appear LATER in the source file win, discarding an earlier and far more
popular one (a lowercase "oh." at frequency 5,162 was overwriting the
real "Oh." at frequency 1,146,885, purely because of file order) - fixed
so a collision now keeps whichever variant has the higher popularity,
verified against that exact case.

Deferred/not wired in yet: 3/4/5-gram frequency data (English and
French, supplied) - the current schema only models words/bigrams/
sentences, so trigram+ data would need a schema extension (straightforward
- same pattern, one more flat collection - but not done since nothing
currently consumes it; bigram-level validation is already a large
accuracy improvement over the plain stopword check it replaced). A
messier print-layout French word-frequency file was also skipped since a
cleaner source for the same data was already used.

## Rough dictionary translation ("decode" a language like a cipher)

Real bilingual dictionary data wired in: CC-CEDICT for Chinese (115,570
entries, filtered to words ≤4 characters - longer CEDICT entries are
almost always idioms/proper nouns rather than everyday vocabulary), a
Wiktionary extract for Spanish (97,993 single-word entries), and the
official Jōyō kanji list for Japanese (2,136 characters - single-kanji
meanings only, no compound-word dictionary was supplied for Japanese).

`internal/translate` ties this together: tokenize (Chinese uses the
`SegmentCJK` dictionary-segmentation built earlier; Japanese falls back
to per-character since there's no compound-word dictionary for it;
everything else splits on whitespace), look each token up, and produce
a word-by-word breakdown plus a crude literal "rough translation" (first
short definition of each token, in original word order). This is framed
deliberately as decoding, not translating - same conceptual family as
the classical-cipher tools elsewhere in this project: given a known
"key" (dictionary data instead of a Vigenère key), decode token-by-token
and show your work, with zero claim to fluent output.

Verified against the exact example given: "我们的朋友是你的朋友"
("our friend is your friend") glossed at 100% dictionary coverage, with
我们 → "we; us; ourselves; our" and 朋友 → "friend" matching almost
verbatim. Also verified for Spanish ("gracias amigo" → "thank you
friend").

Available via the Cipher Tools tab's new "Translate" panel, or the
`/api/translate` and `/api/translate/languages` endpoints.

## Scan tab reorganized: one dropdown per category, checkbox in the header

Restructured per request: the four categories (Storage/Files, Network,
Software, Hardware) are now each a single collapsible dropdown with its
enable/disable checkbox built into the header row, instead of a separate
checkbox strip above a separate accordion list. Storage/Files' dropdown
now contains, in order: a "General" section (hidden files, file
signature mismatch, cipher detection, encoded content, entropy,
extraction issues, SSH/SUID/credential-file checks), a "PII detections"
section (the PII type picker), and the "Custom search" panel (specific-
person and exact-text/regex search) nested inside it, per request,
rather than sitting as a separate block below everything else.

Also added a real gap the reorganization surfaced: hidden-file/folder
detection didn't exist before (Unix dot-prefix convention, or the
Windows hidden-file attribute via a proper syscall check) - now a
"General" check under Storage/Files. LOW severity, visibility-only
(dotfiles are common and mostly benign) - verified against a real
`.secret_config` test file (correctly flagged) alongside a normal file
(correctly left clean).

The whole restructured UI was verified for real, not just by reading the
code: extracted the page's JavaScript and ran it in Node with jsdom (a
real DOM implementation, not a browser, but real DOM APIs and real
execution) against mocked API responses, confirming all four category
dropdowns render, the checkbox lives inside each summary row, the PII
grid and Custom Search panel are nested inside Storage/Files specifically
(and correctly absent from the other three), unchecking a sub-item
correctly changes what `collectChecks()` sends, and adding a name/term
query correctly renders in the list. One real bug caught during this
process turned out to be a test-harness timing issue, not an actual page
bug (a mocked `fetch` assigned after the page's own script had already
run) - worth naming so it isn't mistaken for a fixed product bug.

## Spanish + Chinese added (5 languages now: en/fr/es/de*/zh)

Spanish: 10,000 words with real frequency data, same architecture as
English/French (space-delimited, no changes needed). German still only
has the original stopword-based langdetect support, not full langdata
words/bigrams/sentences yet - marked with `*` above pending that data.

**Chinese is a genuinely different case, worth being precise about.**
Chinese text has no spaces between words - every other part of this
codebase (langdetect's scoring, bigram plausibility, cipher-crack
validation) assumes whitespace-delimited tokenization, which is simply
wrong for Chinese and would silently fail on it (a whole sentence would
tokenize as one giant "word" that matches nothing).

What's actually done: 10,000 Chinese words loaded with real frequency
data, plus a new `Language.SegmentCJK()` - dictionary-based forward
maximum-matching segmentation (the standard lightweight technique for
CJK tokenization without a full NLP library/model: at each position,
greedily take the longest known dictionary word starting there, fall
back to one character if nothing matches). This is genuinely tested, not
just plausible-looking: segmenting "我们的朋友是你的朋友" ("our friend
is your friend") correctly produced `[我们 的 朋友 是 你 的 朋友]` -
exactly the real word boundaries a Chinese speaker would draw, correctly
keeping "我们" (we) and "朋友" (friend) as single 2-character words
rather than splitting them into individual characters.

What's NOT done: `SegmentCJK` isn't wired into langdetect or the
cipher-crack validation pipeline yet - those packages still assume
Latin-script space-tokenization throughout, and connecting Chinese
detection all the way through would mean touching both of them
non-trivially (langdetect's whole scoring model, cipher/crack.go's
`looksLikeRealSentence` word-cleanliness check, the bigram
plausibility scorer). Simple dictionary maximum-matching also has real,
known limitations even for its intended job - no ambiguity resolution,
no recognition of genuinely novel multi-character words outside the
10,000-word dictionary. The data and the segmenter are real and tested;
full language-detection integration for Chinese is a deliberately
separate, not-yet-done next step, not something quietly assumed to work.



## File signature database rebuilt from structured reference data

Replaced the earlier hand-maintained ~31-entry signature list with a
structured 84-entry export, with two real upgrades:

- **Multi-checkpoint matching.** A signature can now require several
  (offset, bytes) pairs to ALL match, not just one - this is what makes
  it possible to tell WAV/AVI/WEBP apart even though they all share the
  same 4-byte "RIFF" prefix at offset 0 (the real disambiguator is a
  second 4-byte tag 8 bytes in). Verified against synthetic files built
  to the real format spec: a "RIFF...AVI " file saved as `.wav` was
  correctly identified as "avi", not just a generic RIFF match - the old
  single-checkpoint scheme couldn't have made that distinction. Also
  verified a genuine `.wav` and a genuine `.mp4` both correctly pass as
  clean. Offsets were independently checked against known real format
  specs during import (TAR's "ustar" at byte 257, ISO 9660's "CD001" at
  byte 32769, MP4's "ftyp" at byte 4 - all textbook-correct) after
  catching and fixing two of my own bugs in the offset-parsing math.
- **Reliable vs. heuristic signatures.** Only genuine format-guaranteed
  binary magic numbers (PE headers, ZIP/OOXML, images, audio/video,
  archives, SQLite, etc.) can trigger a "signature mismatch" verdict.
  Text-based formats whose first bytes aren't actually guaranteed by
  spec (a shebang line, a JSON brace, an XML declaration, a comment
  character) are marked heuristic-only: they can still positively
  confirm a match, but never cause a mismatch flag on their own, since
  plenty of legitimate files of those types don't start that way (a
  sourced shell script often has no shebang; JSON/XML commonly have
  leading whitespace or a BOM). Getting this wrong would have turned
  ordinary text files into false "signature mismatch" reports - the
  opposite of what this check is for.

## Custom search: specific people and exact strings/regex

Two new user-directed search types, on top of the general PII engine:

- **Name search**: give any combination of first/middle/last name and it
  generates realistic real-world format variants automatically - "Mike
  Brown", "Mike H. Brown", "Brown, Mike Hawk", "M. Brown", etc. - rather
  than only matching the exact spelling typed in. Each variant carries a
  confidence tier (full first+last = high, bare initials = low) so
  abbreviated/ambiguous forms are still surfaced but clearly labeled as
  less certain. Verified: correctly found "Mike Brown", "Mike H. Brown",
  and "Brown, Mike Hawk" in test text while correctly NOT matching an
  unrelated "Mike Bishop" or "Sarah Brown" also present in the same text.
  Overlapping matches at the same position (a short variant matching
  inside a longer one) are deduplicated to keep only the more specific hit.
- **Exact string/regex search**: arbitrary user-supplied text or regex
  pattern, case-sensitive or not. Non-regex input is escaped so it's
  never accidentally interpreted as regex syntax.

Available via `--serve`'s "Custom search" panel on the Scan tab, or the
API's `custom_names`/`custom_terms` fields.

## New: persistence, SSH audit, SUID scan, credential-file scan, firewall

Five more checks, all verified against real data in this project's own
sandbox:

- **Persistence/autostart scanning** (Linux) - cron (`/etc/crontab`,
  `/etc/cron.d/*`, the periodic script dirs), systemd enabled units (read
  directly from `/etc/systemd/system/*.wants/` symlinks - NOT via
  `systemctl`, which needs a running bus connection that isn't always
  available; confirmed in this sandbox, where `systemctl list-timers`
  failed with "Failed to connect to bus" while the same data was still
  readable straight from disk), XDG autostart `.desktop` entries, and
  `/etc/rc.local`. Verified against this sandbox's real cron.d entry and
  every one of its real enabled systemd units.
- **SSH key security audit** (Linux/macOS) - flags an overly-permissive
  `~/.ssh` directory, a group/other-readable private key, or a
  group/other-writable `authorized_keys`/config (each defeats SSH's trust
  model). Never reads or reports actual key material. Verified against a
  synthetic profile with a deliberately misconfigured 644 private key and
  755 `.ssh` dir - both correctly flagged (HIGH and MEDIUM respectively).
- **SUID/SGID binary scan** (Linux/macOS) - the classic Unix
  privilege-escalation hardening check. A small known-common set
  (passwd, sudo, ping, mount, etc.) reports at INFO; anything else at LOW
  for a closer look. Verified against this sandbox's real `/usr/bin/passwd`
  (genuinely SUID) and every other real SUID/SGID binary on the system.
- **Credential-file scanning** - checks well-known PLAINTEXT-BY-DESIGN
  credential locations (`.aws/credentials`, `.netrc`, `.git-credentials`,
  `.npmrc`, `.pypirc`, Docker/kube configs). These are a fundamentally
  different category from browser-saved-password decryption (see below):
  nothing here is OS-encrypted, they're just config files a tool reads as
  plain text, same sensitivity as any other file this tool reads.
  Verified against synthetic AWS credentials and a `.netrc` - both
  correctly flagged HIGH with the actual secret material never quoted in
  the finding, only its presence.
- **Firewall rules** (Linux) - `nft list ruleset` or `iptables-save`
  fallback, both already-installed system tools invoked read-only.
  Neither is installed in this project's sandbox, so only the graceful
  "tool not found" path is verified end-to-end; the parsing logic itself
  is a straightforward line count/passthrough, not complex enough to need
  separate verification.

## What's NOT ported/finished yet


- macOS/Windows: local user accounts (Windows only), running processes,
  installed-software inventory, and essentially all of hardware
  (CPU/memory/storage/USB/encryption) - each needs a platform-specific
  implementation (WMI on Windows, sysctl/IOKit/system_profiler/pkgutil
  on macOS) not yet built
- BIOS/TPM/secure boot/firmware integrity/temperature/fan-speed/
  benchmark hardware checks from the Python version - not ported;
  these mostly need vendor tools (dmidecode, smartctl) which conflicts
  with the "no install required" goal and needs more thought
- PDF text extraction only handles standard font encodings (see earlier
  section)
- Android/iOS on-device execution (linux-arm64 binary runs under Termux
  as-is; iOS needs a jailbreak or host-side backup analysis)
- Saved/decrypted browser passwords - deliberately excluded, see below

## Browser history & bookmarks forensics (NOT saved passwords)

Reads Firefox's places.sqlite and Chrome/Edge's History file directly, via
a purpose-built pure-Go SQLite reader (`internal/sqlitemin` - see below).
Emits one summary Finding per browser profile (entry/domain counts, top
domains, a capped sample) rather than one Finding per URL, which would
flood the report; every visited domain is also cross-checked against the
small bundled website-reputation reference data (`internal/hwintel`) -
verified catching a synthetic visit to a domain flagged "critical" risk
in that data, correctly raised to HIGH severity.

**Deliberately excluded: saved/decrypted browser passwords.** Reading
history and bookmarks is the same sensitivity as everything else this
tool reads (local files, no protection to bypass). Decrypting saved
login credentials is a different kind of capability - Chrome's "Login
Data" and Firefox's key4.db/logins.json are specifically OS/browser-
encrypted to keep other processes from reading them, and a generic
"decrypt every saved password in one pass" function is also the
signature core feature of commodity credential-stealing malware
(RedLine, Vidar, LummaC2, and similar infostealers all implement exactly
this). That's true of the artifact regardless of the intent behind
building it, so it isn't included here.

### internal/sqlitemin - a minimal pure-Go SQLite reader, built from scratch

A real pure-Go SQLite driver (github.com/glebarez/go-sqlite) was
attempted first, to avoid reinventing this - but its transitive
dependencies (golang.org/x/sys, modernc.org/libc, modernc.org/sqlite)
turned out to be unreachable from this project's sandboxed build
environment (only github.com is allowlisted; golang.org and modernc.org
are not), so a CGO-free dependency wasn't obtainable here. Rather than
fall back to a CGO-based driver (which would break this project's
"cross-compile from one Linux box to 5 platforms with zero extra
tooling" architecture - the entire reason this got rewritten out of
Python), this is a from-scratch reader implementing just enough of the
public SQLite file format to read a named table's rows: file header
parsing, table B-tree traversal (both interior and leaf pages), SQLite's
varint and record/serial-type encoding, and overflow-page following for
values too large to fit in one page. Column names/order are read
dynamically from each table's own CREATE TABLE statement (via
sqlite_master) rather than hardcoded, since real Firefox/Chrome schemas
vary across versions.

This was verified rigorously against REAL SQLite files (written by
Python's standard sqlite3 module, which uses the actual reference
SQLite C library - not a synthetic mock of the format):
  - A small table with a deliberately oversized field (a 5,020-character
    URL) - correctly read back byte-for-byte, confirming overflow-page
    handling works.
  - A 3,000-row table spanning ~68 pages - every row read back with the
    correct primary-key value (`id`), zero duplicates, zero missing rows,
    in strictly ascending key order, confirming interior-page B-tree
    traversal works correctly across many pages.
  - Along the way, caught and fixed a real SQLite format subtlety: an
    `INTEGER PRIMARY KEY` column is stored as a rowid alias and is NEVER
    present in the record body (it decodes as NULL) - the first version
    of this reader returned `nil` for every `id` column until this was
    special-cased, which would have silently broken the bookmark-to-URL
    join (Firefox's moz_bookmarks.fk references moz_places.id).
  - A realistic Firefox profile (moz_places + moz_bookmarks, with a
    bookmark referencing a place by fk) was read end-to-end through the
    actual browser scanner - both the history summary and the bookmark
    title-to-URL join produced correct results.

## Adding a language

Drop a new stopword JSON file in internal/langdetect/ (see en.json for
the shape) - no code change needed. To add context keywords for a
language to an existing PII rule, edit internal/pii/rules.json.
