#!/usr/bin/env python3
"""
apply_v2.py - Safe translation application with format specifier preservation.
Key improvements:
1. Verifies translated string preserves all format specifiers
2. Skips short strings (<4 chars unless translatable category)
3. Blacklists C identifiers, keywords, attribute names
"""
import re, sys, os, subprocess, shutil, time

ZH_FILE = "/tmp/zh_trans_cn2.py"
SRC_DIR = os.path.expanduser("~/pm3_cn2/client/src")
BUILD_DIR = os.path.expanduser("~/pm3_cn2")
OUTPUT_BIN = os.path.expanduser("~/pm3_cn2/client/proxmark3")
WIN_DIR = "/mnt/c/Users/Samso/OneDrive/Desktop/Projects/promark3/proxmark3-cn2-4.21611/client/"

# Strings that must NEVER be translated
BLACKLIST = set("""
a b c d e f g h i j k l m n o p q r s t u v w x y z
A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
0 1 2 3 4 5 6 7 8 9
default return break case const continue do else enum extern for goto if
register sizeof static struct switch typedef union volatile while
void int char long short float double unsigned signed auto
true false NULL nullptr OK ok Done ERROR error WARNING warning
INFO DEBUG SUCCESS NORMAL FAILED NOLF END START
hf lf hw mf em sc nd pm csv json xml bin txt hex raw elf
USB UART SPI I2C JTAG SWD ARM MCU FPGA LED ADC DAC
data tag info name type path size date time file
input output stdin stdout stderr argc argv
build host target clean all install
""".split())

# Format specifier patterns to preserve
FMT_RE = re.compile(r'%(?:[0-9.]*)(?:[hljztL]|ll|hh)?[%csdioxXufFeEgGaAspn]|%" PRI[uxXdi]64 "')

def fmt_specs(s):
    """Return set of format specifiers in a string."""
    return set(FMT_RE.findall(s))

def load_translations():
    with open(ZH_FILE, 'r', encoding='utf-8') as f:
        content = f.read()
    ns = {}
    exec(compile(content, ZH_FILE, 'exec'), ns)
    return ns.get('translations', {})

def apply_to_file(filepath, trans):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
    except:
        return 0
    
    count = 0
    
    def replacer(m):
        nonlocal count
        inner = m.group(1)
        
        if inner not in trans:
            return m.group(0)
        if inner in BLACKLIST:
            return m.group(0)
        if len(inner) < 4:
            return m.group(0)
        
        chn = trans[inner]
        if not chn or chn == inner:
            return m.group(0)
        
        # Verify format specifiers are preserved
        orig_fmts = fmt_specs(inner)
        new_fmts = fmt_specs(chn)
        if orig_fmts != new_fmts:
            # Translation broke format specifiers - skip
            return m.group(0)
        
        count += 1
        return '"' + chn + '"'
    
    # Match C string literals, handling \" escapes
    pattern = re.compile(r'"((?:[^"\\]|\\.)*)"')
    new_content = pattern.sub(replacer, content)
    
    if count > 0:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)
    
    return count

def main():
    print("Loading translations...")
    t0 = time.time()
    translations = load_translations()
    print(f"Loaded {len(translations)} entries in {time.time()-t0:.1f}s")
    
    # Count format-specifier-clean translations
    clean = 0
    skipped = 0
    for eng, chn in translations.items():
        if chn == eng: continue
        if len(eng) < 4: skipped += 1; continue
        if eng in BLACKLIST: skipped += 1; continue
        if fmt_specs(eng) != fmt_specs(chn): skipped += 1; continue
        clean += 1
    print(f"Clean translations: {clean}, Skipped: {skipped}")
    
    print("\nApplying...")
    t0 = time.time()
    total = 0
    files_changed = 0
    
    for root, dirs, files in os.walk(SRC_DIR):
        for f in sorted(files):
            if not f.endswith('.c') and not f.endswith('.h'):
                continue
            fp = os.path.join(root, f)
            n = apply_to_file(fp, translations)
            if n > 0:
                files_changed += 1
                total += n
                if n > 40:
                    print(f"  {f}: {n}")
    
    print(f"\nTotal: {total} replacements in {files_changed} files ({time.time()-t0:.1f}s)")
    
    if "build" in sys.argv:
        print("\nBuilding...")
        os.chdir(BUILD_DIR)
        result = subprocess.run(["make", "-j4", "client"], capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            print("BUILD FAILED!")
            err = (result.stderr or result.stdout).split('\n')
            for line in err[-20:]:
                if line.strip():
                    print(f"  {line}")
            return 1
        
        size = os.path.getsize(OUTPUT_BIN) // 1024
        print(f"Build OK: {OUTPUT_BIN} ({size} KB)")
        
        os.makedirs(WIN_DIR, exist_ok=True)
        dest = WIN_DIR + "proxmark3_cn2"
        shutil.copy2(OUTPUT_BIN, dest)
        print(f"Copied to: {dest}")
    else:
        print("Skipping build (add 'build' arg)")

if __name__ == "__main__":
    sys.exit(main() or 0)
