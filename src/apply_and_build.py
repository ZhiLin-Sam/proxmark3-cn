#!/usr/bin/env python3
"""
apply_and_build.py - Apply Chinese translations to Proxmark3 client source.
Safety: Only replaces strings that are at least 3 chars long.
Uses regex with quote boundaries: (?<=")eng(?=").
Excludes: C keywords, GCC attrs, preprocessor directives, single chars.
"""
import re, sys, os, subprocess, shutil, time

TRANS_FILE = "/tmp/zh_trans_cn2.py"
SRC_DIR = os.path.expanduser("~/pm3_cn2/client/src")
BUILD_DIR = os.path.expanduser("~/pm3_cn2")
OUTPUT_BIN = os.path.expanduser("~/pm3_cn2/client/proxmark3")
WIN_OUTPUT = "/mnt/c/Users/Samso/OneDrive/Desktop/Projects/promark3/proxmark3-cn2-4.21611/client/proxmark3_cn2"

# Strings that should NEVER be translated (C keywords, GCC attrs, common identifiers)
BLACKLIST = {
    "default", "return", "break", "case", "const", "continue",
    "do", "else", "enum", "extern", "for", "goto", "if",
    "register", "sizeof", "static", "struct", "switch", "typedef",
    "union", "volatile", "while", "void", "int", "char", "long",
    "short", "float", "double", "unsigned", "signed", "auto",
    "visibility", "deprecated", "format", "scanf", "printf",
    "noreturn", "nonnull", "warn_unused_result", "unused",
    "packed", "aligned", "noinline", "always_inline",
    "PACKED", "RAMFUNC", "WEAK", "NORETURN",
    "true", "false", "NULL", "true", "false",
    "OK", "ok", "ERROR", "error", "WARNING", "warning",
    "INFO", "INFO", "DEBUG", "DEBUG", "SUCCESS",
    "NORMAL", "FAILED",
    "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
    "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
    "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
    "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
    "NOLF", "END", "START",
    "hf", "lf", "hw", "mf", "em", "sc", "nd", "pm",
    "csv", "json", "xml", "bin", "txt", "hex", "raw", "elf",
    "USB", "UART", "SPI", "I2C", "JTAG", "SWD",
    "ARM", "MCU", "FPGA", "LED", "ADC", "DAC",
}

def load_translations():
    trans = {}
    with open(TRANS_FILE, 'r', encoding='utf-8') as f:
        content = f.read()
    exec(compile(content, TRANS_FILE, 'exec'), trans)
    return trans['translations']

def safe_replace(filepath, translations):
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()
    
    original = content
    replaced = 0
    
    # Sort by length (longest first) to avoid partial matches
    sorted_trans = sorted(translations.items(), key=lambda x: len(x[0]), reverse=True)
    
    for eng, chn in sorted_trans:
        if eng == chn:  # Skip untranslated
            continue
        if len(eng) < 3:  # Too short, risky
            continue
        if eng in BLACKLIST:  # C keyword or common identifier
            continue
        if eng.strip() in BLACKLIST:
            continue
        # Skip if translation is identical (failed)
        if chn.strip() == eng.strip():
            continue
            
        # Escape for regex
        escaped = re.escape(eng)
        # Replace only within string literals: (?<=")eng(?=")
        # But need to handle cases where eng appears inside a longer string
        pattern = r'(?<=")' + escaped + r'(?=")'
        
        # Also handle multi-part strings like "text1" "text2" - treat as concatenation
        # Use callback to fix potential issues with \x escapes
        def make_replacer(chn_str):
            def replacer(m):
                return chn_str
            return replacer
        
        try:
            new_content = re.sub(pattern, make_replacer(chn), content)
            if new_content != content:
                replaced += 1
                content = new_content
        except re.error as e:
            print(f"  Regex error for [{eng[:50]}]: {e}")
        except Exception as e:
            print(f"  Error: {eng[:50]} -> {e}")
    
    if replaced > 0:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
    
    return replaced

def fix_common_issues():
    """Fix known C code corruption from translations."""
    fixes = [
        # visibility("default") should NOT be translated
        (r'visibility\("default"\)', 'visibility("default")'),
        # __attribute__ strings
        (r'__attribute__\s*\(\s*\(\s*([^)]+)\s*\)\s*\)', None),  # Don't touch
    ]
    # Walk and fix
    for root, dirs, files in os.walk(SRC_DIR):
        for f in files:
            if not f.endswith('.c') and not f.endswith('.h'):
                continue
            fp = os.path.join(root, f)
            with open(fp, 'r', encoding='utf-8', errors='replace') as fh:
                content = fh.read()
            changed = False
            for pattern, repl in fixes:
                if repl is None:
                    continue
                new_content = re.sub(pattern, repl, content)
                if new_content != content:
                    content = new_content
                    changed = True
            if changed:
                with open(fp, 'w', encoding='utf-8') as fh:
                    fh.write(content)

def build():
    print("\nBuilding...")
    os.chdir(BUILD_DIR)
    result = subprocess.run(["make", "-j4", "client"], capture_output=True, text=True)
    if result.returncode != 0:
        print("BUILD FAILED!")
        # Show last 30 lines of error
        lines = result.stderr.split('\n') if result.stderr else result.stdout.split('\n')
        for line in lines[-30:]:
            print(f"  {line}")
        return False
    
    print("Build successful!")
    
    # Get binary size
    size = os.path.getsize(OUTPUT_BIN)
    print(f"Binary: {OUTPUT_BIN} ({size//1024} KB)")
    
    # Copy to Windows
    os.makedirs(os.path.dirname(WIN_OUTPUT), exist_ok=True)
    shutil.copy2(OUTPUT_BIN, WIN_OUTPUT)
    win_size = os.path.getsize(WIN_OUTPUT)
    print(f"Copied to: {WIN_OUTPUT} ({win_size//1024} KB)")
    
    return True

def main():
    print("Loading translations...")
    translations = load_translations()
    print(f"Loaded {len(translations)} translations")
    
    # Filter translations
    filtered = {}
    for eng, chn in translations.items():
        if eng == chn:
            continue
        if len(eng) < 3:
            continue
        if eng in BLACKLIST:
            continue
        filtered[eng] = chn
    print(f"After filtering: {len(filtered)} translations to apply")
    
    # Walk source files
    total_replaced = 0
    files_changed = 0
    
    for root, dirs, files in os.walk(SRC_DIR):
        for f in files:
            if not f.endswith('.c') and not f.endswith('.h'):
                continue
            fp = os.path.join(root, f)
            r = safe_replace(fp, filtered)
            if r > 0:
                files_changed += 1
                total_replaced += r
                print(f"  {f}: {r} replacements")
    
    print(f"\nTotal: {total_replaced} replacements in {files_changed} files")
    
    # Fix known issues
    fix_common_issues()
    
    if "build" in sys.argv:
        build()

if __name__ == "__main__":
    main()
