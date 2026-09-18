#!/usr/bin/env python3
# internal/langdata/tools/generate_langdata.py
#
# Regenerates internal/langdata/data/<code>/{words,bigrams,sentences}.csv for
# every supported language, all eight (en, fr, es, de, it, pt, zh, ja), from
# coherent, reproducible sources. Run from anywhere; passes --cache and
# --data to point at the download cache and the repo data directory.
#
# Output CSV schema (header is the source of truth; the Go loader parses by
# header name):
#
#   words.csv:     text,popularity,risk,meaning1..meaning5,pinyin,readings
#   bigrams.csv:   text,popularity,meaning1,meaning2
#   sentences.csv: text,popularity,risk,meaning1,meaning2
#
# The meaningN columns are English glosses for the word (words/bigrams) or a
# curated English translation (sentences, only the top ~500 per language).
# dictionary.json is no longer written; its contents migrate into the
# meaning columns instead (see README for the full provenance story).
#
# Sources, all cached under --cache once downloaded:
#   * orgtre/top-open-subtitles-sentences  -> word + sentence frequency lists
#     (top_words/{code}_top_words.csv, top_sentences/{code}_top_sentences.csv)
#   * orgtre/google-books-ngram-frequency  -> bigrams for en/fr/es/de/it/zh
#     (2grams_{english,french,spanish,german,italian,chinese_simplified}.csv)
#   * kaikki.org per-language Wiktionary post-processed JSONL (fr/de/it/pt),
#     gzip variant when available - source of word meanings (senses[].glosses)
#   * fluhus/wordnet-to-json wordnet.json.gz - English word meanings
#   * the in-repo dictionary.json files (es/zh/ja) are converted to meaning
#     columns and then deleted
#   * pt/ja bigrams are derived from the orgtre sentence corpus (no
#     google-books 2gram source exists for them): word pairs for pt,
#     character pairs for ja (subtitles are unsegmented there)
#
# Meaning order follows zodict file order; dictionary-only words are appended
# as popularity-0 rows to preserve translate() coverage.
import argparse
import csv
import gzip
import json
import os
import re
import sys
import unicodedata
import urllib.request
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except AttributeError:  # pragma: no cover - <3.7 fallback
    pass

LANGS = ["en", "fr", "es", "de", "it", "pt", "zh", "ja"]

# Language name on kaikki.org for the per-language post-processed dictionary.
KAIIKKI_LANG_NAMES = {"fr": "French", "de": "German", "it": "Italian", "pt": "Portuguese"}

# google-books ngram file slugs for languages that have them.
GB_BIGRAM_SLUG = {
    "en": "english",
    "fr": "french",
    "es": "spanish",
    "de": "german",
    "it": "italian",
    "zh": "chinese_simplified",
}

ORG_BASE = "https://raw.githubusercontent.com/orgtre/top-open-subtitles-sentences/main/bld"
GB_BASE = "https://raw.githubusercontent.com/orgtre/google-books-ngram-frequency/main/ngrams"
KAIIKKI_BASE = "https://kaikki.org/dictionary"
WORDNET_URL = (
    "https://raw.githubusercontent.com/fluhus/wordnet-to-json/v1.0/wordnet.json.gz"
)

TOP_WORDS_N = 10_000          # orgtre words kept per language
TOP_SENT_N = 10_000           # orgtre sentences kept per language
MAX_MEANINGS = 5              # meaning1..meaning5 columns
MAX_TOTAL_WORDS = 100_000     # words.csv row cap (only kaikki/WordNet langs)
MAX_BIGRAM_N = 5_000          # rows in bigrams.csv per language
MIN_BIGRAM_COUNT = 2          # derived bigrams must occur at least this often

# es/zh/ja dictionaries come from the in-repo dictionary.json files and stay
# intact; the cap exists only for the externally-sourced (kaikki/WordNet)
# glossaries that are far larger.
FULL_DICT_LANGS = ("es", "zh", "ja")

SENTENCE_TRANSLATIONS_PATH = Path(__file__).resolve().parent / "sentence_translations.py"


def info(msg):
    print(f"[generate-langdata] {msg}")


def warn(msg):
    print(f"[generate-langdata] WARNING: {msg}", file=sys.stderr)


# --------------------------------------------------------------------------
# Download/cache helpers
# --------------------------------------------------------------------------

NO_DOWNLOAD = False


def download(url, dest):
    """Stream-download url to dest unless it already exists."""
    dest = Path(dest)
    if dest.exists() and dest.stat().st_size > 0:
        return True
    if NO_DOWNLOAD:
        sys.exit(f"cache file missing but --no-download is set: {dest}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "generate-langdata/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp, open(tmp, "wb") as out:
            total = int(resp.headers.get("Content-Length") or 0)
            got = 0
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                out.write(chunk)
                got += len(chunk)
                if total:
                    info(f"  {dest.parent.name}/{dest.name}: {got / 1e6:.1f}/{total / 1e6:.1f} MB")
        os.replace(tmp, dest)
        return True
    except Exception as e:
        try:
            tmp.unlink()
        except OSError:
            pass
        warn(f"failed to download {url}: {e}")
        return False


def need(cache_dir, rel, url):
    dest = cache_dir / rel
    if not dest.exists():
        info(f"downloading {url}")
        if not download(url, dest):
            sys.exit(f"missing required cache file {dest}; supply it or fix the download")
    return dest


# --------------------------------------------------------------------------
# Word validation
# --------------------------------------------------------------------------

def is_valid_word(tok):
    """Letters (any script) plus a small set of intra-word punctuation."""
    if not tok or len(tok) > 40:
        return False
    has_letter = False
    for ch in tok:
        if ch in "'-\u2019\u00b4":
            continue
        cat = unicodedata.category(ch)
        if cat.startswith("L"):
            has_letter = True
            continue
        if ch == "\u30fc":  # katakana prolonged-sound mark
            continue
        return False
    return has_letter


# --------------------------------------------------------------------------
# Glossary (word -> english meanings) loading per language
# --------------------------------------------------------------------------

def parse_kaikki(path):
    """kaikki.org post-processed JSONL -> {word: [up to 5 glosses]}."""
    openfn = gzip.open if str(path).endswith(".gz") else open
    glosses = {}
    with openfn(path, "rt", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            w = entry.get("word")
            if not w:
                continue
            seen = glosses.get(w)
            for sense in entry.get("senses") or ():
                gl = sense.get("glosses") or ()
                if not gl:
                    continue
                g = gl[0]
                if seen is None:
                    seen = glosses[w] = []
                if len(seen) >= MAX_MEANINGS:
                    break
                if g not in seen:
                    seen.append(g)
    return glosses


def parse_wordnet(path):
    """fluhus wordnet-to-json -> {word: [up to 5 glosses]}."""
    with gzip.open(path, "rt", encoding="utf-8") as f:
        data = json.load(f)
    glosses = {}
    for syn in data.get("synset", {}).values():
        g = syn.get("gloss")
        if not g:
            continue
        for w in syn.get("word") or ():
            seen = glosses.get(w)
            if seen is None:
                glosses[w] = [g]
            elif g not in seen:
                if len(seen) < MAX_MEANINGS:
                    seen.append(g)
    return glosses


def parse_repo_dict(path):
    """In-repo dictionary.json (es/zh/ja) -> (glosses, extra)."""
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    glosses, extra = {}, {}
    for k, v in raw.items():
        defs = v.get("definitions") or ()
        if defs:
            glosses[k] = list(defs)[:MAX_MEANINGS]
        extra[k] = (v.get("pinyin", ""), v.get("readings", ""))
    return glosses, extra


def load_glossary(lang, cache_dir, data_dir):
    """Return (ci_gloss, ci_extra): lowercase-keyed meaning maps."""
    gloss = {}
    extra = {}
    if lang == "en":
        wp = need(cache_dir, "wordnet.json.gz", WORDNET_URL)
        info(f"loading WordNet meanings for en")
        gloss = parse_wordnet(wp)
    elif lang in KAIIKKI_LANG_NAMES:
        name = KAIIKKI_LANG_NAMES[lang]
        rel = Path("kaikki") / f"kaikki.org-dictionary-{name}.jsonl.gz"
        url = f"{KAIIKKI_BASE}/{name}/{rel.name}"
        if not download(url, cache_dir / rel):
            # some languages only publish the plain .jsonl
            rel = Path("kaikki") / f"kaikki.org-dictionary-{name}.jsonl"
            url = f"{KAIIKKI_BASE}/{name}/{rel.name}"
            need(cache_dir, rel, url)
        info(f"loading kaikki meanings for {lang} ({rel.name})")
        gloss = parse_kaikki(cache_dir / rel)
    elif lang in ("es", "zh", "ja"):
        path = data_dir / lang / "dictionary.json"
        if not path.exists():
            warn(f"no in-repo dictionary.json for {lang}; meanings will be empty")
        else:
            info(f"converting {path.name} meanings for {lang}")
            gloss, extra = parse_repo_dict(path)
    else:  # pragma: no cover
        warn(f"no glossary source for {lang}")

    ci_gloss = {}
    ci_extra = {}
    for w, m in gloss.items():
        ci_gloss.setdefault(w.lower(), m)
    for w, (p, r) in extra.items():
        ci_extra.setdefault(w.lower(), (p, r))
    info(f"  {lang}: {len(gloss):,} glossed words, {len(ci_gloss):,} case-insensitive")
    return ci_gloss, ci_extra


# --------------------------------------------------------------------------
# Frequency word / sentence / bigram loading
# --------------------------------------------------------------------------

def load_freq_words(path):
    rows = []
    seen = set()
    with open(path, encoding="utf-8", newline="") as f:
        reader = csv.reader(f)
        next(reader, None)  # header: word,count
        for rec in reader:
            if len(rec) < 2:
                continue
            w, cnt = rec[0], rec[1]
            if not is_valid_word(w):
                continue
            key = w.lower()
            if key in seen:
                continue
            seen.add(key)
            rows.append((w, cnt))
            if len(rows) >= TOP_WORDS_N:
                break
    return rows


def load_freq_sentences(path):
    rows = []
    with open(path, encoding="utf-8", newline="") as f:
        reader = csv.reader(f)
        next(reader, None)  # header: sentence,count
        for rec in reader:
            if len(rec) < 2 or not rec[0]:
                continue
            rows.append((rec[0], rec[1]))
            if len(rows) >= TOP_SENT_N:
                break
    return rows


def load_google_bigrams(path):
    rows = []
    with open(path, encoding="utf-8", newline="") as f:
        reader = csv.reader(f)
        next(reader, None)  # header: ngram,freq
        for rec in reader:
            if len(rec) < 2 or not rec[0]:
                continue
            rows.append((rec[0], rec[1]))
            if len(rows) >= MAX_BIGRAM_N:
                break
    return rows


def word_tokens(sentence):
    return [t.lower() for t in re.findall(r"[^\W\d_]+", sentence) if is_valid_word(t)]


def derive_bigrams(sentences, lang):
    counts = {}
    for text, _count in sentences:
        if lang == "ja":
            chars = list("".join(word_tokens(text)))
            pairs = zip(chars, chars[1:])
        else:
            toks = word_tokens(text)
            pairs = zip(toks, toks[1:])
        for a, b in pairs:
            key = a + " " + b
            counts[key] = counts.get(key, 0) + 1
    ranked = [(cnt, key) for key, cnt in counts.items() if cnt >= MIN_BIGRAM_COUNT]
    ranked.sort(reverse=True)
    return [(key, str(cnt)) for cnt, key in ranked[:MAX_BIGRAM_N]]


# --------------------------------------------------------------------------
# CSV writers
# --------------------------------------------------------------------------

def write_words(path, base_rows, append_rows, max_total):
    """Write words.csv; max_total=None means uncapped (full in-repo dicts)."""
    with open(path, "w", encoding="utf-8", newline="") as f:
        wtr = csv.writer(f)
        wtr.writerow(
            ["text", "popularity", "risk", "meaning1", "meaning2", "meaning3",
             "meaning4", "meaning5", "pinyin", "readings"]
        )
        written = 0
        for text, pop, meanings, pinyin, readings in base_rows:
            wtr.writerow([text, pop, "", *meanings, pinyin, readings])
            written += 1
        for text, pop, meanings, pinyin, readings in append_rows:
            if max_total is not None and written >= max_total:
                break
            wtr.writerow([text, pop, "", *meanings, pinyin, readings])
            written += 1
    return written


def write_bigrams(path, rows):
    with open(path, "w", encoding="utf-8", newline="") as f:
        wtr = csv.writer(f)
        wtr.writerow(["text", "popularity", "meaning1", "meaning2"])
        for text, pop, m1, m2 in rows:
            wtr.writerow([text, pop, m1, m2])


def write_sentences(path, rows):
    with open(path, "w", encoding="utf-8", newline="") as f:
        wtr = csv.writer(f)
        wtr.writerow(["text", "popularity", "risk", "meaning1", "meaning2"])
        for text, pop, meaning in rows:
            wtr.writerow([text, pop, "", meaning, ""])


# --------------------------------------------------------------------------
# Word row assembly
# --------------------------------------------------------------------------

def build_word_rows(lang, ci_gloss, ci_extra, freq_words):
    base_rows = []
    used = set()
    for text, pop in freq_words:
        key = text.lower()
        meanings = ci_gloss.get(key, [])
        pinyin, readings = ci_extra.get(key, ("", ""))
        base_rows.append((text, pop, meanings, pinyin, readings))
        used.add(key)

    append_rows = []
    for key in ci_gloss:
        if key in used:
            continue
        pinyin, readings = ci_extra.get(key, ("", ""))
        append_rows.append((key, 0, ci_gloss[key], pinyin, readings))
        used.add(key)
    return base_rows, append_rows


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cache", default=os.environ.get(
        "LANGDATA_CACHE", str(Path.home() / ".cache" / "langdata")),
        help="directory for downloaded source files (default: LANGDATA_CACHE or ~/.cache/langdata)")
    ap.add_argument("--data", default=str(Path(__file__).resolve().parent.parent / "data"),
        help="repo internal/langdata/data directory to write (default: alongside this script)")
    ap.add_argument("--langs", nargs="+", default=LANGS, choices=LANGS)
    ap.add_argument("--no-download", action="store_true")
    args = ap.parse_args()

    global NO_DOWNLOAD
    NO_DOWNLOAD = args.no_download
    cache_dir = Path(args.cache)
    data_dir = Path(args.data)

    # Load the curated sentence-translation table once.
    namespace = {}
    with open(SENTENCE_TRANSLATIONS_PATH, encoding="utf-8") as f:
        exec(compile(f.read(), str(SENTENCE_TRANSLATIONS_PATH), "exec"), namespace)
    translations = namespace["SENTENCE_TRANSLATIONS"]

    for lang in args.langs:
        info(f"== {lang} ==")
        out_dir = data_dir / lang
        out_dir.mkdir(parents=True, exist_ok=True)

        freq_words = load_freq_words(
            need(cache_dir, f"orgtre_words/{lang}.csv",
                 f"{ORG_BASE}/top_words/{lang}_top_words.csv"))
        freq_sentences = load_freq_sentences(
            need(cache_dir, f"orgtre_sent/{lang}.csv",
                 f"{ORG_BASE}/top_sentences/{lang}_top_sentences.csv"))
        info(f"  freq: {len(freq_words):,} words, {len(freq_sentences):,} sentences")

        ci_gloss, ci_extra = load_glossary(lang, cache_dir, data_dir)

        base_rows, append_rows = build_word_rows(lang, ci_gloss, ci_extra, freq_words)
        max_total = None if lang in FULL_DICT_LANGS else MAX_TOTAL_WORDS
        written = write_words(out_dir / "words.csv", base_rows, append_rows, max_total)
        info(f"  words.csv: {written:,} rows ({len(base_rows):,} freq + "
             f"{written - len(base_rows):,} dictionary)")

        if lang in GB_BIGRAM_SLUG:
            gb_rows = load_google_bigrams(
                need(cache_dir, f"2grams/{lang}.csv",
                     f"{GB_BASE}/2grams_{GB_BIGRAM_SLUG[lang]}.csv"))
            bigram_rows = []
            for text, pop in gb_rows:
                m1 = m2 = ""
                parts = text.split(" ", 1)
                if len(parts) == 2:
                    m1 = (ci_gloss.get(parts[0].lower()) or [""])[0]
                    m2 = (ci_gloss.get(parts[1].lower()) or [""])[0]
                bigram_rows.append((text, pop, m1, m2))
        else:
            bigram_rows = []
            for text, pop in derive_bigrams(freq_sentences, lang):
                m1 = m2 = ""
                parts = text.split(" ", 1)
                if len(parts) == 2:
                    m1 = (ci_gloss.get(parts[0].lower()) or [""])[0]
                    m2 = (ci_gloss.get(parts[1].lower()) or [""])[0]
                bigram_rows.append((text, pop, m1, m2))
            info(f"  bigrams derived from sentences ({lang})")
        write_bigrams(out_dir / "bigrams.csv", bigram_rows)
        info(f"  bigrams.csv: {len(bigram_rows):,} rows")

        # Sentence meanings: only the top ~500 curated per language.
        table = translations.get(lang, {})
        sentence_rows = []
        translated = 0
        for text, pop in freq_sentences:
            meaning = table.get(text, "")
            if meaning:
                translated += 1
            sentence_rows.append((text, pop, meaning))
        write_sentences(out_dir / "sentences.csv", sentence_rows)
        info(f"  sentences.csv: {len(sentence_rows):,} rows ({translated:,} with meaning)")

        # migrate: dictionary.json is now fully represented in words.csv
        dict_path = out_dir / "dictionary.json"
        if dict_path.exists():
            dict_path.unlink()
            info(f"  removed {dict_path.name}")

    # Stale full-tree backup no longer represents the new schema.
    fr_zip = data_dir / "fr.zip"
    if fr_zip.exists():
        fr_zip.unlink()
        info("removed stale data/fr.zip")


if __name__ == "__main__":
    main()