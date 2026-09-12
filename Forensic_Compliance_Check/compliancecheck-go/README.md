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
- Browser history/bookmarks/saved-credentials forensics - not started;
  saved-credential decryption specifically needs OS-specific credential
  APIs (DPAPI/Keychain/gnome-keyring) and deserves real care before
  being added, not a rushed pass

## Adding a language

Drop a new stopword JSON file in internal/langdetect/ (see en.json for
the shape) - no code change needed. To add context keywords for a
language to an existing PII rule, edit internal/pii/rules.json.
