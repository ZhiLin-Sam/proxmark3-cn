#!/usr/bin/env python3
"""
apply_cn2.py - Apply Chinese translations to PM3 source with precision.
Strategy: Scan C string literals character-by-character, replacing ONLY
inside quoted strings. No BLACKLIST — only filters out C keyword literals
and pure format-spec strings.
"""
import re, os, sys, subprocess, time, shutil

ZH_FILE = "/tmp/zh_trans_cn2.py"
SRC_DIR = os.path.expanduser("~/pm3_cn2/client/src")
BUILD_DIR = os.path.expanduser("~/pm3_cn2")
OUTPUT_BIN = os.path.expanduser("~/pm3_cn2/client/proxmark3")
WIN_DEST = "/mnt/c/Users/Samso/OneDrive/Desktop/Projects/promark3/proxmark3-cn2-4.21611/client/proxmark3_cn2"

# ── C reserved keywords that might appear as string literals ──
# These should NOT be translated even if they match a dict entry.
C_KEYWORDS = {
    "auto", "break", "case", "char", "const", "continue", "default",
    "do", "double", "else", "enum", "extern", "float", "for", "goto",
    "if", "int", "long", "register", "return", "short", "signed",
    "sizeof", "static", "struct", "switch", "typedef", "union",
    "unsigned", "void", "volatile", "while",
    "true", "false", "NULL", "nullptr",
}

# ── format-spec matcher ──
FMT_RE = re.compile(
    r'%(?:[#0\- +]*)(?:\d*\.?\d*)?(?:hh|h|l|ll|j|z|t|L)?'
    r'[diouxXeEfFgGaAcspn%]'
    r'|%%'
    r'|%" PRI[uxXdi]64 "'
)

def fmt_specs(s):
    return set(FMT_RE.findall(s))

# ── load translations ──
def load_trans():
    with open(ZH_FILE, 'r', encoding='utf-8') as f:
        content = f.read()
    ns = {}
    exec(compile(content, ZH_FILE, 'exec'), ns)
    return ns.get('translations', {})

# ── apply to one file ──
def apply_c_file(filepath, trans):
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        src = f.read()

    count = 0
    result = []
    i = 0
    n = len(src)

    while i < n:
        ch = src[i]

        if ch == '"':
            # Start of string literal — extract until closing "
            j = i + 1
            literal = []
            while j < n:
                if src[j] == '\\':
                    literal.append(src[j:j+2])
                    j += 2
                    continue
                if src[j] == '"':
                    break
                literal.append(src[j])
                j += 1

            inner = ''.join(literal)
            close = j  # position of closing "

            # Try to translate
            if inner in trans:
                zh = trans[inner]
                if (
                    zh 
                    and zh != inner 
                    and inner not in C_KEYWORDS
                    and len(inner) >= 2
                ):
                    # verify format specifiers preserved
                    orig_f = fmt_specs(inner)
                    new_f = fmt_specs(zh)
                    if orig_f == new_f:
                        # escape quotes in Chinese text for C string
                        safe_zh = zh.replace('\\', '\\\\').replace('"', '\\"')
                        result.append('"' + safe_zh + '"')
                        count += 1
                        i = close + 1
                        continue

            # Not translated — keep original
            result.append(src[i:close+1])
            i = close + 1

        elif ch == "'":
            # Char literal — skip
            j = i + 1
            while j < n:
                if src[j] == '\\':
                    j += 2
                    continue
                if src[j] == "'":
                    break
                j += 1
            result.append(src[i:j+1])
            i = j + 1

        elif ch == '/' and i + 1 < n and src[i+1] == '/':
            # Line comment
            j = i
            while j < n and src[j] != '\n':
                j += 1
            result.append(src[i:j])
            i = j

        elif ch == '/' and i + 1 < n and src[i+1] == '*':
            # Block comment
            j = src.find('*/', i + 2)
            if j == -1:
                j = n
            else:
                j += 2
            result.append(src[i:j])
            i = j

        elif ch == '#':
            # Preprocessor directive — preserve entire line
            j = i
            while j < n and src[j] != '\n':
                j += 1
            result.append(src[i:j])
            i = j

        else:
            result.append(ch)
            i += 1

    new_src = ''.join(result)

    if count > 0:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_src)

    return count


# ── main ──
def main():
    print("Loading translations...")
    t0 = time.time()
    trans = load_trans()
    print(f"  {len(trans)} entries ({time.time()-t0:.1f}s)")

    # Pre-filter stats
    valid = 0
    for e, zh in trans.items():
        if (
            zh and zh != e 
            and e not in C_KEYWORDS 
            and len(e) >= 2
            and fmt_specs(e) == fmt_specs(zh)
        ):
            valid += 1
    print(f"  Valid translations: {valid}")

    # Build reverse lookup for dedup info
    by_len = sorted([(len(e), e) for e in trans], reverse=True)
    print(f"  Longest: {by_len[0][1][:60]!r}")
    print(f"  Shortest: {by_len[-1][1]!r}")

    print("\nApplying...")
    t0 = time.time()
    total = 0
    changed = 0

    for root, dirs, files in os.walk(SRC_DIR):
        for f in sorted(files):
            if not f.endswith('.c') and not f.endswith('.h'):
                continue
            fp = os.path.join(root, f)
            n = apply_c_file(fp, trans)
            if n > 0:
                changed += 1
                total += n
                if n > 40:
                    print(f"  {f}: {n}")

    print(f"\nTotal: {total} replacements in {changed} files ({time.time()-t0:.1f}s)")

    if "build" in sys.argv:
        print("\n=== Building ===")
        os.chdir(BUILD_DIR)
        r = subprocess.run(
            ["make", "-j4", "client"],
            capture_output=True, text=True, timeout=300
        )
        if r.returncode != 0:
            print("BUILD FAILED")
            lines = (r.stderr or r.stdout).split('\n')
            for line in lines[-30:]:
                if line.strip():
                    print(f"  {line}")
            return 1

        sz = os.path.getsize(OUTPUT_BIN) // 1024
        print(f"Build OK: {OUTPUT_BIN} ({sz} KB)")

        os.makedirs(os.path.dirname(WIN_DEST), exist_ok=True)
        shutil.copy2(OUTPUT_BIN, WIN_DEST)
        print(f"Copied to: {WIN_DEST}")
    else:
        print("(add 'build' to compile)")

    return 0

if __name__ == "__main__":
    sys.exit(main())
