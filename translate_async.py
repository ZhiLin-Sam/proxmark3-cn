#!/usr/bin/env python3
"""
translate_async.py - Async DeepSeek translation of all extracted strings.
API: DeepSeek chat, 200 concurrent, batch 30 strings per request.
Input: /tmp/cn2_to_translate.json
Output: /tmp/zh_trans_cn2.py (Python dict)
"""
import json, asyncio, time, os, sys
from openai import AsyncOpenAI

INPUT = "/tmp/cn2_to_translate.json"
OUTPUT = "/tmp/zh_trans_cn2.py"
API_KEY = os.environ.get("DEEPSEEK_API_KEY", "your-deepseek-api-key")
API_BASE = "https://api.deepseek.com"
BATCH_SIZE = 30
MAX_CONCURRENT = 200
TEMPERATURE = 0.01

client = AsyncOpenAI(api_key=API_KEY, base_url=API_BASE)

SYSTEM_PROMPT = """You are translating Proxmark3 RFID tool interface strings from English to Chinese.
Rules:
1. Translate ALL user-visible text to natural Chinese (Simplified)
2. Keep technical terms unchanged: MIFARE, ISO14443, CRC, FPGA, SPIFFS, ATR, APDU, UID, PICC, PCD, NTAG, DESFire, EV1, EV2, iCLASS, FeliCa, CryptoRF, NACK, etc.
3. Keep format specifiers EXACT: %s, %d, %02X, %x, %u, %i, %c, %f, %02x, %08x, %04X, PRIu64, PRIX64, PRIx64, PRId64, %zu, %p, %.1f, %5.2f
4. Keep ANSI color macros EXACT: _CYAN_(), _RED_(), _YELLOW_(), _GREEN_(), _BLUE_(), _MAGENTA_(), _WHITE_(), etc.
5. Keep backtick-quoted text EXACT: `text`
6. Keep hex values and numbers unchanged
7. Preserve all punctuation structure (brackets, quotes, colons)
8. For short status messages (1-5 words), use concise Chinese
9. For long explanatory text, use clear natural Chinese
10. Do NOT add any explanation - return ONLY the JSON mapping

Return a JSON object mapping each English string to its Chinese translation."""

async def translate_batch(batch_items, sem):
    """Translate a batch of strings."""
    eng_strings = [s for s, _ in batch_items]
    user_msg = json.dumps(eng_strings, ensure_ascii=False)

    async with sem:
        for attempt in range(3):
            try:
                resp = await client.chat.completions.create(
                    model="deepseek-chat",
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": f"Translate these English strings to Chinese. Return a JSON object where keys are English strings and values are Chinese translations:\n\n{user_msg}"}
                    ],
                    temperature=TEMPERATURE,
                    max_tokens=4096,
                    response_format={"type": "json_object"},
                    timeout=60
                )
                result = json.loads(resp.choices[0].message.content)
                # Validate keys match
                translated = {}
                for eng in eng_strings:
                    if eng in result:
                        translated[eng] = result[eng]
                    else:
                        # Try finding a close match
                        found = False
                        for k, v in result.items():
                            if k.strip() == eng.strip():
                                translated[eng] = v
                                found = True
                                break
                        if not found:
                            translated[eng] = eng  # Keep original
                return translated
            except Exception as e:
                if attempt < 2:
                    await asyncio.sleep(1)
                else:
                    print(f"  FAIL after 3 attempts: {e}")
                    return {s: s for s in eng_strings}

async def main():
    with open(INPUT, 'r', encoding='utf-8') as f:
        all_strings = json.load(f)

    items = list(all_strings.items())
    batches = [items[i:i+BATCH_SIZE] for i in range(0, len(items), BATCH_SIZE)]
    total = len(items)
    print(f"Total strings: {total}")
    print(f"Batches: {len(batches)} (batch size: {BATCH_SIZE})")
    print(f"Concurrency: {MAX_CONCURRENT}")
    print()

    sem = asyncio.Semaphore(MAX_CONCURRENT)
    
    t0 = time.time()
    all_translated = {}
    done = 0

    async def process_batch(idx, batch):
        nonlocal done
        result = await translate_batch(batch, sem)
        done += len(batch)
        if done % 200 == 0 or done >= total:
            elapsed = time.time() - t0
            rate = done / elapsed if elapsed > 0 else 0
            print(f"  [{done}/{total}] {rate:.0f} str/s, {elapsed:.1f}s elapsed")
        return result

    tasks = [process_batch(i, b) for i, b in enumerate(batches)]
    results = await asyncio.gather(*tasks)

    for r in results:
        all_translated.update(r)

    elapsed = time.time() - t0
    print(f"\nTranslated {len(all_translated)}/{total} in {elapsed:.1f}s ({total/elapsed:.0f} str/s)")

    # Write output as Python file
    with open(OUTPUT, 'w', encoding='utf-8') as f:
        f.write("# Auto-generated Chinese translations for Proxmark3 client\n")
        f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Total entries: {len(all_translated)}\n\n")
        f.write("translations = {\n")
        for eng, chn in sorted(all_translated.items()):
            # Escape backslashes and quotes
            eng_esc = eng.replace('\\', '\\\\').replace("'", "\\'")
            chn_esc = chn.replace('\\', '\\\\').replace("'", "\\'")
            f.write(f"    '{eng_esc}': '{chn_esc}',\n")
        f.write("}\n")

    print(f"Saved to {OUTPUT}")

if __name__ == "__main__":
    asyncio.run(main())
