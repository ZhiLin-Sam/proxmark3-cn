#!/usr/bin/env python3
"""
extract_cn2.py - Extract ALL translatable strings from PM3 client source.
Captures: command_t descriptions, CLIParserInit hints/examples, arg_* help,
           PrintAndLogEx runtime messages, snprintf dynamic strings,
           and colored section headers inside _CYAN_() etc.
"""
import re, json, os, sys

SRC_DIR = os.path.expanduser("~/pm3_cn2/client/src")
OUTPUT = "/tmp/cn2_to_translate.json"

# ── helpers ──────────────────────────────────────────────
def norm(s):
    return re.sub(r'[\t ]+', ' ', s.strip())

def nontrivial(s):
    """True if the string contains actual human-readable content to translate."""
    if len(s) < 2:
        return False
    if s == '\xff':
        return False
    # Pure ANSI
    if re.fullmatch(r'\x1b\[[\d;]*m[\s]*', s):
        return False
    # Pure format-spec only
    if re.fullmatch(r'%[-\+0 #]*[\d.]*[hljztL]*(?:ll|hh)?[diouxXeEfFgGaAcspn%]', s):
        return False
    # Pure separator line
    if re.fullmatch(r'[-=*#_]+', s):
        return False
    # Whitespace only
    if re.fullmatch(r'\s+', s):
        return False
    return True

def unescape_c(s):
    """Resolve \\n \\t \\\" etc. to plain chars so translation API sees clean text."""
    return s.encode().decode('unicode_escape')

# ── extraction ───────────────────────────────────────────
def extract_file(fp):
    with open(fp, encoding='utf-8', errors='replace') as f:
        src = f.read()
    lines = src.split('\n')

    result = {'cmd_desc': set(), 'hint': set(), 'example': set(),
              'arg_help': set(), 'runtime': set(), 'dynamic': set()}

    # ── 1. command_t descriptions ──
    in_table = False
    i = 0
    while i < len(lines):
        line = lines[i]
        # Detect table start
        if re.match(r'^\s*static\s+command_t\s+\w+\s*\[\s*\]\s*=\s*\{', line):
            in_table = True
            i += 1
            continue
        # Detect table end
        if in_table and re.match(r'^\s*\};', line):
            in_table = False
            i += 1
            continue
        if not in_table:
            i += 1
            continue

        # Single-line entry: {"cmd", fn, guard, "desc"}
        m = re.match(r'\s*\{[^"]*"([^"]*)",\s*\w+,\s*\w+,\s*"((?:[^"\\]|\\.)*)"', line)
        if m:
            name, desc = m.group(1), m.group(2)
            if '---' not in name and nontrivial(desc):
                result['cmd_desc'].add(norm(desc))
            i += 1
            continue

        # Multi-line entry: {"cmd", fn, guard,
        #                     "desc part 1"
        #                     "desc part 2"}
        mm = re.match(r'\s*\{[^"]*"([^"]*)",\s*\w+,\s*\w+,\s*$', line)
        if mm:
            name = mm.group(1)
            parts = []
            j = i + 1
            while j < len(lines):
                cm = re.match(r'^\s*"((?:[^"\\]|\\.)*)"', lines[j])
                if cm:
                    parts.append(cm.group(1))
                    j += 1
                else:
                    break
            if parts and nontrivial(' '.join(parts)) and '---' not in name:
                result['cmd_desc'].add(norm(' '.join(parts)))
            i = j
            continue

        # Catch _CYAN_("SectionName") style headers inside table entries
        # These appear as: {"-----------", CmdHelp, AlwaysAvailable,
        #                   "---------------- " _CYAN_("Section") " -------------"}
        mh = re.match(r'\s*\{[^"]*"([^"]*)",\s*\w+,\s*\w+,\s*"(?:[-=]+ )?\s*$', line)
        if mh and '---' in mh.group(1):
            # Look for _XXX_("text") macros on continuation lines
            parts = []
            j = i + 1
            while j < len(lines) and j < i + 5:
                lm = lines[j].strip()
                cm = re.match(r'^"((?:[^"\\]|\\.)*)"', lm)
                if cm:
                    parts.append(cm.group(1))
                    j += 1
                elif re.match(r"^\}\);?", lm):
                    break
                else:
                    break
            txt = ' '.join(parts).strip()
            if nontrivial(txt):
                result['cmd_desc'].add(norm(txt))
            i = j
            continue

        i += 1

    # ── 2. CLIParserInit hints & examples ──
    for m in re.finditer(
        r'CLIParserInit\s*\(\s*\S+\s*,\s*'
        r'"((?:[^"\\]|\\.)*)"\s*,\s*'    # hint (second arg)
        r'"((?:[^"\\]|\\.)*)"',           # example (third arg)
        src
    ):
        hint = norm(m.group(1))
        example = norm(m.group(2))
        if nontrivial(hint):
            result['hint'].add(hint)
        if nontrivial(example):
            result['example'].add(example)

    # ── 3. arg_* help strings ──
    # arg_str0("f","name","<hex>","help text"), arg_lit0("h","help","text"), etc.
    for m in re.finditer(
        r'arg_\w+\d?\s*\(\s*(?:"[^"]*"\s*,\s*){1,3}"((?:[^"\\]|\\.)*)"',
        src
    ):
        txt = norm(m.group(1))
        if nontrivial(txt):
            result['arg_help'].add(txt)

    # ── 4. PrintAndLogEx / PrintAndLog ──
    for m in re.finditer(
        r'PrintAndLog(?:Ex|Options)?\s*\([^,)]*,\s*"((?:[^"\\]|\\.)*)"',
        src
    ):
        txt = norm(m.group(1))
        if nontrivial(txt):
            result['runtime'].add(txt)

    # ── 5. snprintf with translatable content ──
    for m in re.finditer(
        r'snprintf\s*\([^,)]+,\s*[^,)]+,\s*"((?:[^"\\]|\\.)*)"',
        src
    ):
        txt = norm(m.group(1))
        if nontrivial(txt) and '%' in txt:
            result['dynamic'].add(txt)

    return result

# ── main ─────────────────────────────────────────────────
c_files = []
for root, dirs, files in os.walk(SRC_DIR):
    for f in files:
        if f.endswith('.c'):
            c_files.append(os.path.join(root, f))

print(f"Processing {len(c_files)} .c files...")
pool = {k: set() for k in ['cmd_desc', 'hint', 'example', 'arg_help', 'runtime', 'dynamic']}

for i, fp in enumerate(sorted(c_files)):
    if i % 20 == 0:
        print(f"  {i}/{len(c_files)}")
    r = extract_file(fp)
    for k in pool:
        pool[k] |= r[k]

# Deduplicate across categories
seen = set()
all_strs = {}
for cat in ['cmd_desc', 'hint', 'example', 'arg_help', 'runtime', 'dynamic']:
    for s in sorted(pool[cat]):
        if s not in seen:
            seen.add(s)
            all_strs[s] = ""

print(f"\n=== Summary ===")
for k, v in pool.items():
    print(f"  {k:20s}: {len(v):5d}")
print(f"  {'unique dedup':20s}: {len(all_strs):5d}")

with open(OUTPUT, 'w', encoding='utf-8') as f:
    json.dump(all_strs, f, ensure_ascii=False, indent=2)
print(f"\nSaved: {OUTPUT}")
