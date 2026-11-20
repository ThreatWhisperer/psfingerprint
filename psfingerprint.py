#!/usr/bin/env python3
"""
psfingerprint.py - static PowerShell obfuscation fingerprinter.

Reads a script as text (never executes it), reports:
  * which obfuscation TECHNIQUES are present (with evidence + counts)
  * which known OBFUSCATOR / builder profiles best match
  * every likely EXECUTION SINK (line numbers) so you know what to defang
  * blobs / decoding hints (base64, byte arrays, Base85, XOR keys, compression)
  * DECODED content: Base64, -enc, hex, decimal/byte arrays, [char] chains and
    Base85, peeled recursively through UTF-16, GZip/Deflate and XOR (including
    repeating-key recovery), plus IoCs, and an optional cleaned copy

Usage:
  python -I psfingerprint.py sample.txt            full report
  python -I psfingerprint.py --help | --guide      help / how to read the report

Heuristic, not proof: treat the profile match as a lead, and confirm by
comparing with output from the tool itself.
"""
import argparse, base64, collections, json, math, re, sys

MAXLINE_SHOW = 140

# --------------------------------------------------------------------------
# Technique detectors: name -> (regex, flags, description)
# --------------------------------------------------------------------------
T = {
    # --- Invoke-Obfuscation TOKEN family
    "tick_marks":        (r"[A-Za-z]`[A-Za-z]", 0, "Backtick escapes inside identifiers (Ie`X, N`ew-Obj`ect)"),
    "format_reorder":    (r"\(\s*[\"']\{\d+\}\{\d+\}[^\"']*[\"']\s*-f\s*", re.I, "-f format-operator string reordering (\"{1}{0}\" -f ...)"),
    "string_concat":     (r"[\"'][^\"'\r\n]{1,6}[\"']\s*\+\s*[\"'][^\"'\r\n]{1,6}[\"']\s*\+", 0, "Short string-fragment concatenation"),
    "random_case":       (r"\b(?!(?:iex|IEX|Iex|New-Object|new-object|Invoke-Expression|invoke-expression|Write-Host|write-host)\b)(?:[iI][Ee][xX]|[nN][eE][wW]-[oO][bB][jJ][eE][cC][tT]|[iI][nN][vV][oO][kK][eE]-[eE][xX][pP][rR][eE][sS][sS][iI][oO][nN]|[wW][rR][iI][tT][eE]-[hH][oO][sS][tT])\b", 0, "RaNdOm CaSe cmdlet names"),
    "var_curly":         (r"\$\{[^}]*`[^}]*\}", 0, "${v`a`r} curly-brace variable obfuscation"),
    # --- Invoke-Obfuscation STRING family
    "string_reverse":    (r"\[(?:array|Array)\]::Reverse|-join\s*\(?\s*[\"'][^\"']+[\"']\s*\[\s*-1\s*\.\.|\[-1\.\.-\d+\]|RightToLeft", re.I, "String reversal"),
    "replace_chain":     (r"(?:-replace|\.replace\()\s*\(?\s*[\"'][^\"']{1,8}[\"']\s*,\s*[\"'][^\"']?[\"']", re.I, "Replace-chain decoding (junk-char stripping)"),
    # --- Invoke-Obfuscation ENCODING family
    "char_cast":         (r"\[char\]\s*\(?\s*\[?(?:int)?\]?\s*\d{2,3}", re.I, "[char]NN character casting"),
    "char_array_join":   (r"\[char\[\]\]\s*\(\s*\d+\s*,\s*\d+", re.I, "[char[]](n,n,...) arrays"),
    "hex_encoding":      (r"\[convert\]::ToInt\d+\(\s*\$?_?[^,]*,\s*16\s*\)|0x[0-9a-f]{2}\s*,\s*0x[0-9a-f]{2}\s*,", re.I, "Hex encoding"),
    "octal_encoding":    (r"\[convert\]::ToInt\d+\([^,]+,\s*8\s*\)", re.I, "Octal encoding"),
    "binary_encoding":   (r"\[convert\]::ToInt\d+\([^,]+,\s*2\s*\)", re.I, "Binary encoding"),
    "bxor_encoding":     (r"-bxor\s*(?:0x[0-9a-f]+|\d+|\$\w+)", re.I, "-bxor single/repeating key"),
    "xor_identity":      (r"\(\s*\(?\$\w+\)?\s*-bor\s*\(?\$\w+\)?\s*\)\s*-\s*\(\s*\$\w+\s*-band", re.I, "(a -bor b) - (a -band b)  == XOR (disguised)"),
    "securestring":      (r"ConvertTo-SecureString|SecureStringToBSTR|PtrToStringAuto", re.I, "SecureString encoding/encryption"),
    "whitespace_enc":    (r"[\t ]{40,}[\"']\s*-split", 0, "Whitespace encoding"),
    "special_char_enc":  (r"\$\{[;=+()\[\]!@#%^&*~]+\}\s*=", 0, "Special-character-only variable encoding"),
    # --- encodings / containers
    "base64_call":       (r"FromBase64String", re.I, "Base64 decoding"),
    "encodedcommand":    (r"-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedcommand)\s+[A-Za-z0-9+/=]{40,}", re.I, "-EncodedCommand launcher"),
    "compression":       (r"IO\.Compression\.(?:Deflate|GZip)Stream|DeflateStream|GZipStream", re.I, "Deflate/GZip compression layer"),
    "aes_crypto":        (r"(?:Aes|Rijndael)(?:Managed|CryptoServiceProvider)?|CreateDecryptor", re.I, "AES encryption layer"),
    "base85_alphabet":   (r"52200625|614125\b", 0, "Base85 (85^4 / 85^3 constants)"),
    "byte_array_blob":   (r"\[byte\[\]\]\s*@?\(\s*(?:\d{1,3}\s*,\s*){200,}", re.I, "Large inline [byte[]] array"),
    "big_b64_string":    (r"[\"'][A-Za-z0-9+/]{400,}={0,2}[\"']", 0, "Large inline base64 string"),
    # --- junk / control-flow
    "arith_noise":       (r"\$\w+\s*=\s*\(+\s*\d+\s*[+-]\s*\d+\s*[+-]\s*\d+\s*\)?\s*[+-]\s*\d+\s*[+-]\s*\d+", 0, "Constant-arithmetic junk assignments"),
    "array_index_pick":  (r"=\s*@\(\s*@\(\s*\d+(?:\s*,\s*\d+)+\s*\)\s*,\s*@\(", 0, "2-D array char-code picking (@(@(..),@(..))[i][j])"),
    "opaque_predicate":  (r"if\s*\(\s*\d{6,}\s*-(?:gt|lt|eq|ne)\s*\d{6,}\s*\)", re.I, "Opaque predicates (if(123456 -gt 654321))"),
    "bigint_math":       (r"\[System\.Numerics\.BigInteger\]::", re.I, "BigInteger string decoding"),
    "sleep_evasion":     (r"ManualResetEvent|WaitOne\(|Start-Sleep|Thread\]::Sleep", re.I, "Sleep / timing evasion"),
    # --- launcher-style IEX obfuscation (Invoke-Obfuscation)
    "iex_shellid":       (r"\$ShellId\[\s*1\s*\]\s*\+\s*\$ShellId\[\s*13\s*\]|\$PSHome\[\s*\d+\s*\]\s*\+\s*\$PSHome\[|\$env:ComSpec\[\s*\d+\s*,|\$VerbosePreference\.ToString\(\)\[|\(\s*\[string\]\$VerbosePreference\)\[|\.Name\[\s*3\s*,\s*11\s*,\s*2\s*\]|MDr\(\)", re.I, "Invoke-Obfuscation obfuscated IEX ($ShellId[1]+$ShellId[13], $env:ComSpec[4,15,25] ...)"),
    "gv_gci_varaccess":  (r"\b(?:gv|Get-Variable|gci|Get-ChildItem|ls|dir|item)\s+[\"']?(?:variable:|\*)\S*", re.I, "Variable access via gv/gci variable:"),
    # --- in-memory execution / evasion (post-deobfuscation behaviour)
    "amsi_tamper":       (r"amsiInitFailed|AmsiScanBuffer|AmsiUtils|amsi\.dll", re.I, "AMSI tampering"),
    "etw_tamper":        (r"EtwEventWrite|PSEtwLogProvider|etwProvider", re.I, "ETW tampering"),
    "reflection_emit":   (r"Reflection\.Emit|DefineDynamicAssembly|DefineDynamicModule", re.I, "Reflection.Emit delegate building"),
    "fn_ptr_delegate":   (r"GetDelegateForFunctionPointer", re.I, "Native call via function-pointer delegate"),
    "api_hash_fnv":      (r"2166136261|16777619", 0, "FNV-1a hashing (API hashing)"),
    "api_hash_ror13":    (r"-shr\s*13\b[^\n]{0,60}-bor[^\n]{0,60}-shl\s*19|-shl\s*19\b[^\n]{0,60}-bor[^\n]{0,60}-shr\s*13|0x0?E8E4ABDB|0x726774C", re.I, "ROR13-style API hashing"),
    "pe_parsing":        (r"0x3C\b[^\n]{0,80}ToInt32|0x5A4D|0x4D\b[^\n]{0,30}0x5A\b", re.I, "Manual PE header parsing"),
    "injection_target":  (r"rundll32\.exe|MicrosoftEdgeUpdate|notepad\.exe|svchost\.exe|explorer\.exe|dllhost\.exe|werfault\.exe|RegAsm\.exe|MSBuild\.exe|InstallUtil\.exe|aspnet_compiler\.exe", re.I, "Common injection/sacrificial process name"),
    "assembly_load":     (r"\[(?:System\.)?Reflection\.Assembly\]::(?:Load|LoadFile|LoadFrom)\b|::Load\(\s*\[", re.I, "In-memory .NET Assembly.Load"),
    "download":          (r"DownloadString|DownloadData|DownloadFile|Invoke-WebRequest|\biwr\b|Invoke-RestMethod|\birm\b|Net\.WebClient|HttpClient|BitsTransfer|Start-BitsTransfer", re.I, "Network download"),
}

# --------------------------------------------------------------------------
# Execution sinks (what you must defang)
# --------------------------------------------------------------------------
SINKS = [
    (r"\b(?:iex|Invoke-Expression)\b", "Invoke-Expression / iex"),
    (r"\bInvoke-Command\b|\bicm\b", "Invoke-Command"),
    (r"\[ScriptBlock\]::Create|\.NewScriptBlock\(|\{\s*\}\.Ast", "ScriptBlock creation"),
    (r"\.AddScript\(|\[PowerShell\]::Create|\[runspacefactory\]", "Runspace / PowerShell.Create"),
    (r"(?:^|[;\s(])\.\s*\(\s*\$[\w:]+\s*\)", "Dot-invoke of variable  .($x)"),
    (r"(?:^|[;\s(])&\s*\(?\s*\$[\w:{}]+", "Call operator  & $x"),
    (r"(?:^|[;\s(])[.&]\s*\(\s*[\"'(]", "Invoke of built string  &('i'+'ex')"),
    (r"(?<!param\()(?<!,\s)\[type\]\s*\$\w+\s*(?:\)\s*::|;|$)|-as\s*\[type\]\s*\)\s*::|\$\w+::\(\s*\$\w+\s*\)", "Dynamic type / static call (resolve!)"),
    (r"\$\w+\s*\.\s*\(\s*\$\w+\s*\)\s*\(", "Dynamic method call  $o.($m)(...)"),
    (r"\.Invoke\(|\.InvokeReturnAsIs\(|\.DynamicInvoke\(", ".Invoke() call"),
    (r"\bStart-Process\b|\bsaps\b|Diagnostics\.Process\]::Start|\bcmd(?:\.exe)?\s+/c\b|\bpowershell(?:\.exe)?\s+-", "Child process launch"),
    (r"\bAdd-Type\b", "Add-Type (compiles C#)"),
    (r"\$ExecutionContext\.InvokeCommand|InvokeScript\(", "ExecutionContext.InvokeCommand"),
    (r"\b(?:Set-Alias|sal|New-Alias|nal)\b", "Alias creation (may hide iex)"),
]

# --------------------------------------------------------------------------
# Tool / builder profiles: (name, required-any, supporting, note)
# Score = matched required (x3) + matched supporting (x1); need >=1 required.
# --------------------------------------------------------------------------
PROFILES = [
    ("Invoke-Obfuscation (TOKEN)",
        ["tick_marks", "format_reorder"], ["random_case", "string_concat", "var_curly", "gv_gci_varaccess"],
        "Daniel Bohannon's framework, Token\\All style. Revoke-Obfuscation + Sigma posh_ps_token_obfuscation apply."),
    ("Invoke-Obfuscation (STRING)",
        ["string_reverse", "replace_chain", "format_reorder"], ["string_concat", "iex_shellid"],
        "String\\1-3 (concatenate / reorder / reverse)."),
    ("Invoke-Obfuscation (ENCODING)",
        ["char_array_join", "hex_encoding", "octal_encoding", "binary_encoding", "securestring", "whitespace_enc", "special_char_enc"],
        ["iex_shellid", "bxor_encoding", "random_case"],
        "Encoding\\1-8 (ASCII/Hex/Octal/Binary/SecureString/BXOR/Special chars/Whitespace)."),
    ("Invoke-Obfuscation (COMPRESS / LAUNCHER)",
        ["iex_shellid"], ["compression", "base64_call", "encodedcommand"],
        "Obfuscated IEX invocation is the strongest single Invoke-Obfuscation tell."),
    ("Chimera",
        ["string_concat"], ["base64_call", "random_case", "replace_chain"],
        "tokyoneon's Chimera: string splitting + variable renaming with dictionary words, often AMSI-bypass prefixed. Weak match on its own."),
    ("xencrypt / PSEncrypt-style packer",
        ["aes_crypto"], ["compression", "base64_call", "big_b64_string"],
        "AES+GZip recursive layers; decrypt key/IV are inline."),
    ("Encoded-command launcher (PowerSploit Out-EncodedCommand / C2 stager)",
        ["encodedcommand"], ["compression", "base64_call"],
        "UTF-16LE base64 one-liner; common for Empire/Cobalt Strike/Metasploit stagers."),
    ("Custom arithmetic-noise builder (commodity loader kits)",
        ["arith_noise", "array_index_pick", "opaque_predicate"], ["xor_identity", "bigint_math", "sleep_evasion", "byte_array_blob", "char_cast"],
        "Junk constant math + 2-D array char picking + disguised XOR + IEX from char codes. Not a public tool; matches the 2025-26 ClickFix/loader kits."),
    ("Native-API shellcode injector (post-deobfuscation)",
        ["fn_ptr_delegate", "reflection_emit"], ["api_hash_fnv", "api_hash_ror13", "pe_parsing", "injection_target", "base85_alphabet", "byte_array_blob"],
        "Final-stage loader: resolves APIs, builds delegates, injects a blob. Dump the blob and identify it (Donut: E8 xx xx xx xx)."),
]

# --------------------------------------------------------------------------
def entropy(s: str) -> float:
    if not s: return 0.0
    c = collections.Counter(s); n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())

def scan(text: str):
    lines = text.splitlines()
    res = {"techniques": {}, "sinks": [], "stats": {}, "hints": []}

    # techniques (run per-line with a length cap for speed on huge blob lines)
    for name, (pat, flags, desc) in T.items():
        rx = re.compile(pat, flags | re.M)
        count, first = 0, None
        for i, ln in enumerate(lines, 1):
            chunk = ln if len(ln) < 200000 else ln[:20000] + ln[-20000:]
            m = rx.findall(chunk)
            if m:
                count += len(m)
                if first is None:
                    mm = rx.search(chunk)
                    s = max(0, mm.start() - 30)
                    first = (i, chunk[s:s + MAXLINE_SHOW])
        if count:
            res["techniques"][name] = {"desc": desc, "count": count, "first_line": first[0], "evidence": first[1]}

    # sinks
    for pat, label in SINKS:
        rx = re.compile(pat, re.I | re.M)
        for i, ln in enumerate(lines, 1):
            if len(ln) > 200000:  # skip giant data lines
                continue
            for m in rx.finditer(ln):
                s = max(0, m.start() - 40)
                res["sinks"].append({"line": i, "type": label, "context": ln[s:s + MAXLINE_SHOW]})

    # char-code-built command names: [char]105+[char]101+[char]120 etc.
    for i, ln in enumerate(lines, 1):
        if len(ln) > 200000: continue
        for m in re.finditer(r"((?:\[char\]\s*\d{2,3}\s*\+?\s*){2,})", ln, re.I):
            codes = [int(x) for x in re.findall(r"\d{2,3}", m.group(1))]
            if all(32 <= c < 127 for c in codes):
                word = "".join(chr(c) for c in codes)
                if re.search(r"iex|invoke|expression|downloadstring|frombase64|webclient|amsi|bypass|http", word, re.I):
                    res["hints"].append(f"line {i}: char-codes decode to {word!r}")

    # stats
    var_names = re.findall(r"\$([A-Za-z_][A-Za-z0-9_]{2,})", text[:2_000_000])
    uniq = set(var_names)
    avg_len = sum(map(len, uniq)) / max(1, len(uniq))
    rand_like = sum(1 for v in uniq if re.search(r"[a-z][A-Z0-9][a-z]", v) and len(v) >= 8 and entropy(v) > 3.2)
    wordnum = sum(1 for v in uniq if re.fullmatch(r"(?:[A-Z][a-z]+){2}\d{3}", v))
    longest = max((len(l) for l in lines), default=0)
    res["stats"] = {
        "bytes": len(text), "lines": len(lines), "longest_line": longest,
        "unique_vars": len(uniq), "avg_var_len": round(avg_len, 1),
        "random_looking_vars": rand_like, "WordWordNNN_vars": wordnum,
        "overall_entropy": round(entropy(text[:500000]), 3),
    }
    if rand_like > 50:
        res["hints"].append(f"{rand_like} random-looking variable names (mixed-case alnum) -> automated renamer")
    if wordnum > 20:
        res["hints"].append(f"{wordnum} 'WordWordNNN' variable names (e.g. RouteOffset130) -> dictionary renamer; same kit seen in Base85/Donut injectors")
    if longest > 100000:
        res["hints"].append(f"Payload blob line ~{longest:,} chars -> carve it and decode separately")

    # repeating XOR key heuristic: a printable string var used next to -bxor / disguised XOR
    for m in re.finditer(r"[\"']([A-Za-z0-9_!@#$%^&*]{8,64})[\"']", text[-20000:]):
        if re.search(r"-bxor|-bor[\s\S]{0,80}-band", text[-20000:]):
            res["hints"].append(f"possible XOR key literal near decoder: {m.group(1)!r}")
            break

    # Base64 blob peek
    for m in re.finditer(r"[A-Za-z0-9+/]{200,}={0,2}", text[:3_000_000]):
        try:
            raw = base64.b64decode(m.group(0)[:4000] + "==="[: (4 - len(m.group(0)[:4000]) % 4) % 4])
        except Exception:
            continue
        kind = ("UTF-16LE text (EncodedCommand)" if raw[1:2] == b"\x00" else
                "GZip" if raw[:2] == b"\x1f\x8b" else "PE (MZ)" if raw[:2] == b"MZ" else
                "Donut shellcode?" if raw[:1] == b"\xe8" else "binary/encrypted")
        res["hints"].append(f"base64 blob at offset {m.start():,} ({len(m.group(0)):,} chars) -> {kind}")
        break

    # profiles
    present = set(res["techniques"])
    scored = []
    for name, req, sup, note in PROFILES:
        r = [x for x in req if x in present]
        if not r: continue
        s = [x for x in sup if x in present]
        scored.append({"profile": name, "score": len(r) * 3 + len(s), "matched": r + s, "note": note})
    res["profiles"] = sorted(scored, key=lambda x: -x["score"])
    return res

# --------------------------------------------------------------------------
# Static decoding engine (never executes input)
# --------------------------------------------------------------------------
import binascii, hashlib, os, zlib, gzip as _gzip

MAX_DEPTH = 5
PS_WORDS = re.compile(r"(?i)\b(?:iex|invoke-|new-object|function|param|\$env:|frombase64|downloadstring|start-process|write-host|\[convert\]|\[system\.|http)")
B85_PS = "".join(chr(c) for c in range(33, 123) if c not in (34, 36, 39, 92, 96))  # seen in Donut injectors
B85_ALPHABETS = [
    ("Base85 (RFC1924/Python)", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"),
    ("Base85 (ASCII85)", "".join(chr(c) for c in range(33, 118))),
    ("Base85 (custom: printable minus quotes/$/`)", B85_PS),
]

def _bytes_entropy(b: bytes) -> float:
    if not b: return 0.0
    c = collections.Counter(b); n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())

def _printable_ratio(b: bytes) -> float:
    if not b: return 0.0
    return sum(1 for x in b if x in (9, 10, 13) or 32 <= x < 127) / len(b)

def _utf16_ratio(b: bytes) -> float:
    if len(b) < 4: return 0.0
    hi = b[1::2]
    return sum(1 for x in hi if x == 0) / len(hi)

def _b64(s: str):
    s = re.sub(r"\s+", "", s)
    if len(s) < 16 or len(s) % 4 == 1: return None
    s += "=" * (-len(s) % 4)
    try: return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError): return None

def _b85_custom(s: str, alpha: str):
    idx = {c: i for i, c in enumerate(alpha)}
    s = re.sub(r"\s+", "", s)
    if any(c not in idx for c in s): return None
    out = bytearray(); full, rem = divmod(len(s), 5)
    try:
        for i in range(full):
            v = 0
            for c in s[i*5:i*5+5]: v = v * 85 + idx[c]
            out += v.to_bytes(4, "big")
        if rem:
            if rem == 1: return None
            v = 0
            for c in s[full*5:]: v = v * 85 + idx[c]
            for _ in range(5 - rem): v = v * 85 + 84
            out += v.to_bytes(4, "big")[:rem - 1]
    except OverflowError:
        return None
    return bytes(out)

def _whole(text, rx):
    return re.fullmatch(rx, text.strip()) is not None

def peel(data: bytes, chain=None, depth=0):
    """Recursively decode a byte blob. Returns (chain_list, final_bytes, final_kind, final_text_or_None)."""
    chain = list(chain or [])
    if depth > MAX_DEPTH or not data:
        return chain, data, "empty" if not data else "max-depth", None
    # containers / formats
    if data[:2] == b"\x1f\x8b":
        try: return peel(_gzip.decompress(data), chain + ["GZip"], depth + 1)
        except Exception: pass
    if data[:2] == b"MZ":
        return chain, data, "PE executable (MZ)", None
    if data[:1] == b"\xe8" and len(data) > 1024 and _bytes_entropy(data[5:4096]) > 7.5:
        return chain, data, "Donut shellcode (E8 + encrypted instance)", None
    if data[:4] == b"\x7fELF":
        return chain, data, "ELF executable", None
    if data[:2] == b"PK":
        return chain, data, "ZIP archive", None
    # text?
    text = None
    if _utf16_ratio(data) > 0.85 and len(data) % 2 == 0:
        try: text = data.decode("utf-16le"); chain = chain + ["UTF-16LE text"]
        except UnicodeDecodeError: text = None
    if text is None and _printable_ratio(data) > 0.95:
        text = data.decode("utf-8", errors="replace"); chain = chain + ["text"]
    if text is not None:
        t = text.strip()
        if len(t) >= 16 and _whole(t, r"[A-Za-z0-9+/\s]+={0,2}"):
            b = _b64(t)
            if b: return peel(b, chain + ["Base64"], depth + 1)
        if len(t) >= 16 and _whole(t, r"(?:[0-9A-Fa-f]{2}\s*)+"):
            try: return peel(bytes.fromhex(re.sub(r"\s+", "", t)), chain + ["hex"], depth + 1)
            except ValueError: pass
        if _whole(t, r"(?:\d{1,3}\s*,\s*){7,}\d{1,3}"):
            nums = [int(x) for x in re.findall(r"\d+", t)]
            if all(n < 256 for n in nums): return peel(bytes(nums), chain + ["decimal bytes"], depth + 1)
        return chain, data, "text", text
    # raw deflate (common: IO.Compression.DeflateStream)
    if _bytes_entropy(data[:4096]) > 6.5:
        for wbits, name in ((-15, "raw Deflate"), (15, "zlib")):
            try:
                out = zlib.decompress(data, wbits)
                if out: return peel(out, chain + [name], depth + 1)
            except zlib.error:
                pass
    return chain, data, f"binary (entropy {_bytes_entropy(data[:65536]):.2f}{' - likely encrypted/compressed' if _bytes_entropy(data[:65536]) > 7.2 else ''})", None

def _xor(data: bytes, kb: bytes) -> bytes:
    if len(kb) == 1:
        return data.translate(bytes(b ^ kb[0] for b in range(256)))
    n = len(kb)
    return bytes(b ^ kb[i % n] for i, b in enumerate(data))

def _plausible(out: bytes) -> bool:
    """Decoded result must look like real content, not just printable noise."""
    if out[:2] in (b"MZ", b"\x1f\x8b"): return True
    if _printable_ratio(out) < 0.95: return False
    s = out.decode("latin-1")
    return bool(PS_WORDS.search(s) or re.search(r"(?i)https?://|\\\\[\w.]+\\|\.(?:exe|dll|ps1)\b", s))

_TEXT_SCORE = [0] * 256
for _c in range(256):
    if chr(_c) in " etaoinsrlhdcu$()-.=;'\"{}[]_ETAOINSRLHDC": _TEXT_SCORE[_c] = 3
    elif 32 <= _c < 127 or _c in (9, 10, 13): _TEXT_SCORE[_c] = 1
    else: _TEXT_SCORE[_c] = -8

def _crack_repeating_xor(data: bytes, max_klen=64):
    """Recover a repeating XOR key when the plaintext is text (classic key-length + per-column frequency attack)."""
    sample = data[:16384]
    if len(sample) < 512: return None
    def ham(a, b): return sum(bin(x ^ y).count("1") for x, y in zip(a, b))
    cands = []
    for kl in range(1, max_klen + 1):
        blocks = [sample[i*kl:(i+1)*kl] for i in range(min(24, len(sample) // kl))]
        if len(blocks) < 4: continue
        d = sum(ham(blocks[i], blocks[i+1]) for i in range(len(blocks) - 1)) / ((len(blocks) - 1) * kl)
        cands.append((d, kl))
    for _, kl in sorted(cands)[:6]:
        key = bytearray()
        for col in range(kl):
            colbytes = sample[col::kl]
            key.append(max(range(256), key=lambda k: sum(_TEXT_SCORE[b ^ k] for b in colbytes)))
        for p in range(1, kl + 1):  # shrink to the shortest repeating period
            if kl % p == 0 and key == (key[:p] * (kl // p)):
                key = key[:p]; break
        out = _xor(sample, bytes(key))
        if _plausible(out):
            return bytes(key)
    return None

def _xor_try(data: bytes, keys):
    """Literal keys, then single-byte brute force, then repeating-key cryptanalysis. Returns (desc, plaintext) or None."""
    sample = data[:4096]
    for k in keys:
        kb = k if isinstance(k, bytes) else str(k).encode()
        if kb and _plausible(_xor(sample, kb)):
            return f"XOR key {kb.decode('latin-1')!r} (literal in script)", _xor(data, kb)
    for k in range(1, 256):
        if _plausible(_xor(sample, bytes([k]))):
            return f"XOR single byte 0x{k:02x}", _xor(data, bytes([k]))
    if 4.5 < _bytes_entropy(data[:65536]) < 7.4:   # text XORed with a short key sits in this band
        kb = _crack_repeating_xor(data)
        if kb:
            shown = kb.decode("latin-1") if all(32 <= c < 127 for c in kb) else kb.hex()
            return f"XOR key {shown!r} (recovered by cryptanalysis)", _xor(data, kb)
    return None

def find_candidates(text: str):
    """Yield (line, source_kind, raw_bytes_or_str) for encoded-looking literals."""
    lines = text.splitlines()
    for i, ln in enumerate(lines, 1):
        # -EncodedCommand
        for m in re.finditer(r"(?i)\s-e(?:n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?\s+['\"]?([A-Za-z0-9+/]{20,}={0,2})", ln):
            b = _b64(m.group(1))
            if b: yield i, "-EncodedCommand", b
        # quoted base64
        for m in re.finditer(r"['\"]([A-Za-z0-9+/]{20,}={0,2})['\"]", ln):
            s = m.group(1)
            if not (re.search(r"[A-Z]", s) and re.search(r"[a-z]", s) and re.search(r"\d", s)): continue
            b = _b64(s)
            if b: yield i, "Base64 string", b
        # quoted hex
        for m in re.finditer(r"['\"]((?:[0-9A-Fa-f]{2}){12,})['\"]", ln):
            yield i, "hex string", bytes.fromhex(m.group(1))
        # 0x byte lists
        for m in re.finditer(r"(?:0x[0-9A-Fa-f]{1,2}\s*,\s*){7,}0x[0-9A-Fa-f]{1,2}", ln):
            yield i, "0x byte array", bytes(int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{1,2})", m.group(0)))
        # decimal arrays (bytes or char codes)
        for m in re.finditer(r"(?<![\d.\w])(?:\d{1,5}\s*,\s*){7,}\d{1,5}(?![\d.])", ln):
            nums = [int(x) for x in m.group(0).split(",")]
            if all(n < 256 for n in nums):
                yield i, "decimal byte array", bytes(nums)
            elif all(n < 0x110000 for n in nums):
                yield i, "char-code array", "".join(chr(n) for n in nums).encode("utf-8", "replace")
        # [char]N chains
        for m in re.finditer(r"(?:\[char\]\s*\(?\s*\d{1,5}\s*\)?\s*\+?\s*){3,}", ln, re.I):
            yield i, "[char] chain", "".join(chr(int(x)) for x in re.findall(r"\d+", m.group(0))).encode("utf-8", "replace")
    # here-strings / long quoted blobs that may be Base85
    for m in re.finditer(r"@[\"']\r?\n(.{200,}?)\r?\n[\"']@", text, re.S):
        blob = m.group(1)
        if _b64(blob): continue
        line = text.count("\n", 0, m.start()) + 1
        for name, alpha in B85_ALPHABETS:
            b = _b85_custom(blob, alpha)
            if b:
                yield line, name, b; break

def decode_all(text: str, max_items=200, _depth=0, _prefix="", _seen=None):
    keys = []
    for ln in text.splitlines():
        if len(ln) > 200000 or not re.search(r"(?i)-bxor|-bor", ln): continue
        keys += [int(k, 0) for k in re.findall(r"(?i)-bxor\s*(0x[0-9a-f]+|\d{1,3})\b", ln) if int(k, 0) < 256]
        keys += re.findall(r"['\"]([^'\"\s]{4,64})['\"]", ln)
    keys = [k if isinstance(k, str) else bytes([k]) for k in dict.fromkeys(keys)][:200]

    arts = []
    seen = _seen if _seen is not None else set()
    for line, src, raw in find_candidates(text):
        h = hashlib.sha256(raw).hexdigest()
        if h in seen: continue
        seen.add(h)
        chain, final, kind, ftext = peel(raw, [src])
        if ftext is None and kind.startswith("binary"):
            x = _xor_try(final, keys)
            if x:
                chain2, final2, kind2, ftext2 = peel(x[1], chain + [x[0]])
                chain, final, kind, ftext = chain2, final2, kind2, ftext2
        interesting = (
            (ftext is not None and len(ftext.strip()) >= 4 and len(chain) > 1 and
             (len(chain) > 2 or PS_WORDS.search(ftext) or re.search(r"https?://|\\\\|\.exe|\.dll", ftext, re.I) or len(ftext) >= 24))
            or kind.startswith(("PE", "Donut", "ELF", "ZIP"))
            or len(final) >= 256
        )
        if not interesting: continue
        loc = f"{_prefix}{line}"
        arts.append({
            "line": loc, "chain": chain, "kind": kind, "size": len(final),
            "sha256": hashlib.sha256(final).hexdigest(), "text": ftext, "bytes": final,
        })
        # decoded text can hide further layers: scan it too
        if ftext and len(ftext) > 64 and _depth < 3:
            arts += decode_all(ftext, max_items - len(arts), _depth + 1, f"{loc}>", seen)
        if len(arts) >= max_items: break
    return arts

def extract_iocs(texts):
    iocs = {"urls": set(), "ips": set(), "paths": set()}
    for t in texts:
        if not t: continue
        iocs["urls"].update(m.rstrip(".,;") for m in re.findall(r"(?i)\bhttps?://[^\s'\"<>()`]+", t))
        for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", t):
            if all(int(o) < 256 for o in ip.split(".")) and not ip.startswith(("0.", "127.", "255.")):
                iocs["ips"].add(ip)
        iocs["paths"].update(re.findall(r"(?i)\b[A-Z]:\\(?:[^\\\s'\"<>|]+\\)*[^\\\s'\"<>|]+\.(?:exe|dll|ps1|bat|cmd|vbs|js|hta|lnk|tmp|dat)\b", t))
        iocs["paths"].update(re.findall(r"(?i)\$env:(?:appdata|temp|localappdata|programdata|public|userprofile)[^\s'\";)]*", t))
    return {k: sorted(v) for k, v in iocs.items()}

def defang(s: str) -> str:
    return s.replace("http", "hxxp").replace(".", "[.]")

# --------------------------------------------------------------------------
# Cleaner: resolve simple obfuscation inline -> readable copy (still NOT safe to run)
# --------------------------------------------------------------------------
_SQ = r"'(?:[^']|'')*'"
_DQ = r'"[^"$`]*"'
_LIT = f"(?:{_SQ}|{_DQ})"

def _lit_val(s: str) -> str:
    return s[1:-1].replace("''", "'") if s[0] == "'" else s[1:-1]

def _q(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"

CANON = ["Invoke-Expression", "New-Object", "Invoke-WebRequest", "Invoke-RestMethod", "Start-Process",
         "Set-Variable", "Get-Variable", "Get-ChildItem", "Out-String", "Start-Sleep", "Add-Type",
         "Invoke-Command", "Write-Host", "Net.WebClient", "DownloadString", "DownloadData", "DownloadFile",
         "FromBase64String", "GetString", "IEX"]

def clean_script(text: str):
    counts = collections.Counter()
    out_lines = []
    for ln in text.splitlines():
        if len(ln) > 200000:
            out_lines.append(ln); continue
        for _ in range(6):
            before = ln
            # 1. tick marks inside identifiers (keep real escapes `0 `a `b `e `f `n `r `t `u `v)
            ln, n = re.subn(r"`(?=[A-Za-z])(?![0abefnrtuv])", "", ln); counts["backticks"] += n
            # 2. ([char[]](n,n,..) -join '')  /  -join [char[]](..)
            def cj(m):
                nums = [int(x) for x in re.findall(r"\d+", m.group(1))]
                return _q("".join(chr(x) for x in nums)) if all(x < 0x110000 for x in nums) else m.group(0)
            ln, n = re.subn(r"\(\s*\[char\[\]\]\s*\(([\d\s,]+)\)\s*-join\s*(?:''|\"\")\s*\)", cj, ln, flags=re.I); counts["char arrays"] += n
            ln, n = re.subn(r"-join\s*\(?\s*\[char\[\]\]\s*\(([\d\s,]+)\)\s*\)?", cj, ln, flags=re.I); counts["char arrays"] += n
            # 3. [char]N + [char]N ...
            def cc(m):
                return _q("".join(chr(int(x)) for x in re.findall(r"\d+", m.group(0))))
            ln, n = re.subn(r"\[char\]\s*\(?\s*\d{1,5}\s*\)?(?:\s*\+\s*\[char\]\s*\(?\s*\d{1,5}\s*\)?)*", cc, ln, flags=re.I); counts["[char] casts"] += n
            # 4. "{1}{0}" -f 'a','b'
            def ff(m):
                fmt = _lit_val(m.group("fmt"))
                args = [_lit_val(a) for a in re.findall(_LIT, m.group("args"))]
                try: res = re.sub(r"\{(\d+)\}", lambda k: args[int(k.group(1))], fmt)
                except IndexError: return m.group(0)
                return _q(res)
            ln, n = re.subn(rf"\(?\s*(?P<fmt>{_LIT})\s*-f\s*(?P<args>{_LIT}(?:\s*,\s*{_LIT})*)\s*\)?", ff, ln, flags=re.I); counts["-f format strings"] += n
            # 5. 'a'+'b'+'c'
            def cat(m):
                return _q("".join(_lit_val(x) for x in re.findall(_LIT, m.group(0))))
            ln, n = re.subn(rf"{_LIT}(?:\s*\+\s*{_LIT})+", cat, ln); counts["string concatenations"] += n
            if ln == before: break
        # 6. canonical casing for well-known names
        for w in CANON:
            ln, n = re.subn(rf"(?i)(?<![\w-]){re.escape(w)}(?![\w-])", lambda m, w=w: w, ln)
            # count only real case changes
        out_lines.append(ln)
    cleaned = "\n".join(out_lines)
    case_fixed = sum(1 for a, b in zip(text.split(), cleaned.split()) if a != b and a.lower() == b.lower())
    if case_fixed: counts["case normalised"] = case_fixed
    return cleaned, {k: v for k, v in counts.items() if v}

def build_clean_file(path, text, arts, iocs):
    cleaned, counts = clean_script(text)
    hdr = [
        "<#  psfingerprint cleaned copy - STATIC TRANSFORM, NOT VERIFIED.",
        "    THIS IS STILL MALWARE. DO NOT RUN. Kept as .txt on purpose.",
        f"    source: {os.path.basename(path)}",
        "    resolved: " + (", ".join(f"{k} x{v}" for k, v in counts.items()) or "nothing"),
        "#>", "",
    ]
    ftr = ["", "", "<# ===== DECODED ARTEFACTS (static) ====="]
    for n, a in enumerate(arts, 1):
        ftr.append(f"[{n}] line {a['line']}: {' -> '.join(a['chain'])} => {a['kind']} ({a['size']:,} bytes, sha256 {a['sha256']})")
        if a["text"]:
            ftr.append("    " + a["text"][:2000].replace("#>", "# >").replace("\n", "\n    "))
    if any(iocs.values()):
        ftr.append("\n===== IOCs FROM DECODED CONTENT (defanged) =====")
        for k, vals in iocs.items():
            for v in vals: ftr.append(f"{k[:-1]:<5} {defang(v)}")
    ftr.append("#>")
    return "\n".join(hdr) + cleaned + "\n".join(ftr) + "\n", counts

def save_artefacts(outdir, arts):
    os.makedirs(outdir, exist_ok=True)
    saved = []
    for n, a in enumerate(arts, 1):
        ext = "txt" if a["text"] is not None else "bin"
        slug = re.sub(r"[^a-z0-9]+", "-", a["kind"].lower()).strip("-")[:30]
        loc = re.sub(r"[^0-9]+", "-in-", str(a["line"]))
        fn = os.path.join(outdir, f"artefact_{n:02d}_L{loc}_{slug}.{ext}")
        with open(fn, "wb") as f:
            f.write(a["text"].encode("utf-8") if a["text"] is not None else a["bytes"])
        saved.append(fn)
    return saved

# --------------------------------------------------------------------------
# Presentation
# --------------------------------------------------------------------------
VERSION = "1.2"

CATEGORIES = [
    ("Obfuscation (hides the code's text)", [
        "tick_marks", "format_reorder", "string_concat", "random_case", "var_curly",
        "string_reverse", "replace_chain", "iex_shellid", "gv_gci_varaccess"]),
    ("Encoding / encryption (hides the payload)", [
        "char_cast", "char_array_join", "hex_encoding", "octal_encoding", "binary_encoding",
        "bxor_encoding", "xor_identity", "securestring", "whitespace_enc", "special_char_enc",
        "base64_call", "encodedcommand", "compression", "aes_crypto", "base85_alphabet",
        "byte_array_blob", "big_b64_string", "bigint_math"]),
    ("Junk & anti-analysis (wastes your time)", [
        "arith_noise", "array_index_pick", "opaque_predicate", "sleep_evasion"]),
    ("Behaviour (what the decoded code does - high priority)", [
        "amsi_tamper", "etw_tamper", "reflection_emit", "fn_ptr_delegate", "api_hash_fnv",
        "api_hash_ror13", "pe_parsing", "injection_target", "assembly_load", "download"]),
]
BEHAVIOUR = set(CATEGORIES[3][1])

GUIDE = """\
HOW TO READ THE REPORT
======================

1. VERDICT (top box)
   A one-glance summary: how obfuscated the file is, the best-matching tool,
   how confident that match is, and what to do next.

   Confidence  HIGH   = several tool-specific traits found (score >= 9)
               MEDIUM = some tool-specific traits (score 5-8)
               LOW    = generic traits only (score < 5) - treat as a guess

2. LIKELY OBFUSCATOR / BUILDER
   Known tool profiles ranked by score. Each profile has "required" traits
   (worth 3 points each - at least one must be present) and "supporting"
   traits (1 point each). 'matched' lists the traits that scored.
   Several Invoke-Obfuscation rows together usually means the author stacked
   several of its modes.

3. TECHNIQUES
   Every trick detected, grouped by what it is for:
     Obfuscation        - disguises the PowerShell itself (backticks, -f, concat)
     Encoding           - hides the payload (base64, XOR, char codes, AES, GZip)
     Junk               - filler that exists only to waste analyst time; ignore it
     Behaviour          - what the real code does (injection, AMSI bypass, download)
                          Anything here is a strong signal of malicious intent.
   Format:  name   xCOUNT   description
                   L<line>: first example found

4. HINTS
   Leads worth following: decoded command names, likely XOR keys, where the
   payload blob is and what it looks like (GZip / PE / Donut / UTF-16).

5. DECODED CONTENT
   Encoded literals the tool found and decoded WITHOUT running anything.
     [n] L<line>  chain  =>  result
   The chain shows each step, e.g.
     decimal byte array -> text -> Base64 -> XOR key 'K' (recovered) -> text
   L59275>326 means "line 326 inside the text decoded from line 59275".
   Supported: Base64, -EncodedCommand (UTF-16LE), hex, 0x arrays, decimal
   arrays, [char] chains, Base85 (3 alphabets), GZip, raw Deflate, zlib, XOR
   (literal keys, single-byte brute force, repeating-key cryptanalysis).
   Red results (PE / Donut / ELF / ZIP) are final binaries - save them with
   --outdir and analyse them with the right tool.
   IoCs (URLs, IPs, file paths) found in decoded text are listed, defanged.
   If the verdict shows 'Final stage', you may not need to run anything.

6. EXECUTION SINKS TO DEFANG
   Every place the script can RUN code. Before you execute the sample anywhere,
   replace each of these with a write-to-file, e.g.
       [IO.File]::WriteAllText("layer2.txt", $payload)
   Then run the defanged copy offline and repeat on the output.
   Types marked (resolve!) build a type or method name at runtime - log what
   they resolve to; they can hide a second iex or a runspace.

WORKFLOW
   fingerprint (+ static decode) -> if it reached the final stage, stop here
   otherwise: defang sinks -> run copy offline -> fingerprint layer 2 -> ...
   until the output reads like normal code (behaviour traits appear, junk stops).
"""

class C:
    """ANSI colours; disabled when not a TTY or with --no-color."""
    on = False
    @classmethod
    def w(cls, code, s): return f"\033[{code}m{s}\033[0m" if cls.on else s
    @classmethod
    def b(cls, s): return cls.w("1", s)
    @classmethod
    def dim(cls, s): return cls.w("2", s)
    @classmethod
    def red(cls, s): return cls.w("31;1", s)
    @classmethod
    def yel(cls, s): return cls.w("33;1", s)
    @classmethod
    def grn(cls, s): return cls.w("32;1", s)
    @classmethod
    def cyn(cls, s): return cls.w("36;1", s)

def confidence(score):
    if score >= 9: return "HIGH", C.grn
    if score >= 5: return "MEDIUM", C.yel
    return "LOW", C.red

def obfuscation_level(res):
    t = res["techniques"]
    n = sum(1 for k in t if k not in BEHAVIOUR)
    heavy = any(k in t for k in ("arith_noise", "array_index_pick", "opaque_predicate", "xor_identity", "iex_shellid"))
    if heavy or n >= 7: return "HEAVY", C.red
    if n >= 3: return "MODERATE", C.yel
    if n >= 1: return "LIGHT", C.grn
    return "NONE DETECTED", C.grn

def unique_sinks(res):
    out, seen = [], set()
    for s in res["sinks"]:
        k = (s["line"], s["type"])
        if k not in seen:
            seen.add(k); out.append(s)
    return out

def section(p, title, explain, show_explain):
    p("")
    p(C.cyn(f"-- {title}"))
    if show_explain:
        p(C.dim(f"   {explain}"))

def report(path, res, sinks_only=False, explain=True):
    out = []; p = out.append
    st = res["stats"]
    sinks = unique_sinks(res)
    sink_lines = sorted({s["line"] for s in sinks})
    beh = [k for k in res["techniques"] if k in BEHAVIOUR]

    p(C.b(f"=== {path}"))
    p(C.dim(f"    {st['bytes']:,} bytes | {st['lines']:,} lines | longest line {st['longest_line']:,} chars | "
            f"{st['unique_vars']:,} variables | entropy {st['overall_entropy']}"))

    # ---- verdict box
    lvl, lc = obfuscation_level(res)
    if res["profiles"]:
        top = res["profiles"][0]; conf, cc = confidence(top["score"])
        match = f"{top['profile']}  [score {top['score']}]"
    else:
        conf, cc, match = "-", C.dim, "no known profile matched"
    arts = res.get("decoded", [])
    dbeh = [k for k in res.get("decoded_behaviour", []) if k not in beh]
    final_bin = [a for a in arts if a["kind"].startswith(("PE", "Donut", "ELF", "ZIP"))]
    if final_bin:
        fb = final_bin[-1]
        tool = ("donut-decryptor" if fb["kind"].startswith("Donut") else
                "DIE / capa / dnSpyEx" if fb["kind"].startswith("PE") else "a sandbox")
        nxt = (f"decoded statically down to a {fb['kind'].split(' (')[0]} (L{fb['line']}). "
               f"Save it with --outdir and analyse it with {tool} - no need to run the script")
    elif any(a["text"] and len(a["text"]) > 200 for a in arts):
        nxt = "next layer decoded statically - re-run with --outdir and fingerprint the saved .txt"
    elif beh and lvl != "HEAVY":
        nxt = ("readable layer showing malicious behaviour - DO NOT run it. Analyse it statically"
               + (" and carve/decode the payload blob (see Hints)" if st["longest_line"] > 100000 else ""))
    elif sink_lines:
        nxt = f"defang {len(sinks)} sink(s) on line(s) {', '.join(map(str, sink_lines[:6]))}{' ...' if len(sink_lines) > 6 else ''}, then run the copy offline"
    elif beh:
        nxt = "no exec sinks found - this layer is probably readable; analyse the behaviour"
    else:
        nxt = "no exec sinks found - check whether it is data for another script"
    p("")
    p(C.b("  VERDICT"))
    p(f"    Obfuscation : {lc(lvl)}")
    p(f"    Best match  : {match}")
    p(f"    Confidence  : {cc(conf)}")
    p(f"    Behaviour   : {C.red(', '.join(beh)) if beh else C.dim('none detected at this layer (expected while still encoded)')}")
    if dbeh:
        p(f"    In decoded  : {C.red(', '.join(dbeh))}")
    if final_bin:
        p(f"    Final stage : {C.red(final_bin[-1]['kind'])}  sha256 {final_bin[-1]['sha256']}")
    p(f"    Next step   : {nxt}")

    if not sinks_only:
        section(p, "Likely obfuscator / builder",
                "Ranked tool profiles. 3 pts per tool-specific trait, 1 per supporting trait. A lead, not proof.", explain)
        if res["profiles"]:
            for pr in res["profiles"][:4]:
                conf, cc = confidence(pr["score"])
                p(f"  [{pr['score']:>2}] {C.b(pr['profile'])}  {cc(conf)}")
                p(f"       matched: {', '.join(pr['matched'])}")
                p(C.dim(f"       {pr['note']}"))
        else:
            p("  no profile matched (lightly obfuscated, clean, or a novel builder)")

        section(p, "Techniques",
                "What each trick is for. 'xN' = times seen, 'L<n>' = first line with an example.", explain)
        if not res["techniques"]:
            p("  none")
        for cat, names in CATEGORIES:
            hits = [(k, res["techniques"][k]) for k in names if k in res["techniques"]]
            if not hits: continue
            p("  " + (C.red(cat) if cat.startswith("Behaviour") else C.b(cat)))
            for k, v in sorted(hits, key=lambda kv: -kv[1]["count"]):
                p(f"    {k:<18} x{v['count']:<6} {v['desc']}")
                p(C.dim(f"{'':29}L{v['first_line']}: {v['evidence'].strip()}"))

        if res["hints"]:
            section(p, "Hints", "Leads to follow up: decoded names, keys, and where the payload blob is.", explain)
            for h in dict.fromkeys(res["hints"]):
                p(f"  * {h}")

        if "decoded" in res:
            arts = res["decoded"]
            section(p, f"Decoded content ({len(arts)} artefact(s))",
                    "Encoded literals found and decoded statically. Chain = how each was peeled. "
                    "Repeating XOR keys are recovered by cryptanalysis when the plaintext is text; anything else computed at runtime needs the defang workflow.", explain)
            if not arts:
                p("  nothing decodable found at this layer")
            for n, a in enumerate(arts[:25], 1):
                kc = C.red if a["kind"].startswith(("PE", "Donut", "ELF", "ZIP")) else (C.grn if a["text"] else C.yel)
                p(f"  [{n}] L{a['line']}  {' -> '.join(a['chain'])}  =>  {kc(a['kind'])}  ({a['size']:,} B)")
                if a["text"]:
                    prev = re.sub(r"\s+", " ", a["text"].strip())[:200]
                    p(C.dim(f"       {prev}{' ...' if len(a['text']) > 200 else ''}"))
                else:
                    p(C.dim(f"       sha256 {a['sha256']}  first bytes {a['bytes'][:16].hex(' ')}"))
            if len(arts) > 25:
                p(C.dim(f"  ... {len(arts) - 25} more - use --outdir to save them all"))
            iocs = res.get("iocs", {})
            if any(iocs.values()):
                p("  " + C.red("IoCs in decoded content (defanged):"))
                for k, vals in iocs.items():
                    for v in vals[:30]:
                        p(f"    {k[:-1]:<5} {defang(v)}")
            for line in res.get("saved", []):
                p(C.dim(f"  saved: {line}"))

    section(p, f"Execution sinks to defang ({len(sinks)} on {len(sink_lines)} line(s))",
            "Places the script can RUN code. Replace each with a write-to-file before executing a copy. "
            "(resolve!) = name built at runtime; log what it becomes.", explain)
    if not sinks:
        p("  none found")
    for s in sinks:
        p(f"  L{s['line']:<7} {s['type']:<38} {C.dim(s['context'].strip())}")
    return "\n".join(out)

def list_reference(what):
    if what == "techniques":
        for cat, names in CATEGORIES:
            print(C.b(cat))
            for k in names:
                print(f"  {k:<18} {T[k][2]}")
            print()
    elif what == "profiles":
        for name, req, sup, note in PROFILES:
            print(C.b(name))
            print(f"  required (3 pts, need >=1): {', '.join(req)}")
            print(f"  supporting (1 pt each)    : {', '.join(sup)}")
            print(C.dim(f"  {note}"))
            print()
    elif what == "sinks":
        for _, label in SINKS:
            print(f"  {label}")

HELP_DESC = """\
psfingerprint - identify how a PowerShell script was obfuscated, statically.

It READS the file as text and never executes it. For each file it tells you:
  * VERDICT   how obfuscated it is, the likely tool, confidence, next step
  * PROFILES  which obfuscator/builder it most resembles (Invoke-Obfuscation,
              Chimera, xencrypt, encoded launchers, commodity loader kits...)
  * TECHNIQUES every trick found, grouped by purpose, with line numbers
  * HINTS     decoded command names, XOR keys, payload blob type
  * DECODED   Base64 / -enc / hex / decimal / [char] / Base85 blobs, peeled
              through UTF-16, GZip, Deflate and XOR (keys recovered where
              possible), with URLs, IPs and paths extracted
  * SINKS     every line that can execute code - defang these first
"""

HELP_EPILOG = """\
examples:
  python -I psfingerprint.py sample.ps1.txt
        full report for one file
  python -I psfingerprint.py layer1.txt layer2.txt layer3.txt
        compare every layer you have peeled
  python -I psfingerprint.py sample.txt --sinks-only
        just the lines you must defang before running a copy
  python -I psfingerprint.py sample.txt --json > report.json
        machine-readable output for pipelines / ticket enrichment
  python -I psfingerprint.py sample.txt --outdir out
        save every decoded artefact (.txt text / .bin binary) to out/
  python -I psfingerprint.py sample.txt --clean
        write sample.clean.txt - backticks, concat, -f and [char] resolved,
        decoded artefacts and IoCs appended (still NOT safe to run)
  python -I psfingerprint.py --guide
        explains every section of the report and the scoring
  python -I psfingerprint.py --list techniques
        reference list of everything it can detect

safety:
  * Keep samples with a non-executable extension (.txt) - a double-click on
    .ps1 can run it.
  * Use 'python -I' so Python does not import stray .py files from the
    samples folder.
  * Results are heuristic leads, not attribution proof.
"""

def main():
    ap = argparse.ArgumentParser(
        prog="psfingerprint.py",
        description=HELP_DESC, epilog=HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="*", metavar="FILE",
                    help="script(s) to analyse; UTF-8 or UTF-16 (any extension)")
    g = ap.add_argument_group("output")
    g.add_argument("--sinks-only", action="store_true",
                   help="show only the verdict and execution sinks")
    g.add_argument("--json", action="store_true",
                   help="print raw results as JSON (no colours or explanations)")
    g.add_argument("--quiet", "-q", action="store_true",
                   help="hide the one-line explanations under each section")
    g.add_argument("--no-color", action="store_true",
                   help="disable coloured output (auto-off when piped)")
    d = ap.add_argument_group("decoding")
    d.add_argument("--no-decode", action="store_true",
                   help="skip the static decoder (faster on huge files)")
    d.add_argument("--outdir", metavar="DIR",
                   help="save every decoded artefact to DIR (.txt for text, .bin for binary)")
    d.add_argument("--clean", action="store_true",
                   help="also write <file>.clean.txt: a readable copy with backticks, concat, -f and [char] "
                        "resolved inline, plus decoded artefacts and IoCs appended (still NOT safe to run)")
    r = ap.add_argument_group("reference")
    r.add_argument("--guide", action="store_true",
                   help="explain how to read the report, then exit")
    r.add_argument("--list", choices=["techniques", "profiles", "sinks"],
                   help="list everything the tool can detect, then exit")
    ap.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    a = ap.parse_args()

    if not a.no_color and not a.json and sys.stdout.isatty():
        if sys.platform == "win32":
            os.system("")  # enables ANSI escape handling in Windows consoles
        C.on = True

    if a.guide:
        print(GUIDE); return
    if a.list:
        list_reference(a.list); return
    if not a.files:
        ap.print_help(); return

    allres = {}
    for f in a.files:
        try:
            raw = open(f, "rb").read()
        except OSError as e:
            print(f"error: cannot read {f}: {e}", file=sys.stderr); continue
        text = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") \
            else raw.decode("utf-8", errors="replace").lstrip("﻿")
        res = scan(text)
        if not a.no_decode:
            arts = decode_all(text)
            res["decoded"] = arts
            res["iocs"] = extract_iocs([x["text"] for x in arts])
            dtech = set()
            for x in arts:
                if x["text"] and len(x["text"]) > 64:
                    dtech |= {k for k in scan(x["text"])["techniques"] if k in BEHAVIOUR}
            res["decoded_behaviour"] = sorted(dtech)
            saved = []
            if a.outdir:
                sub = os.path.join(a.outdir, re.sub(r"[^\w.-]", "_", os.path.basename(f)))
                saved += save_artefacts(sub, arts)
            if a.clean:
                body, _ = build_clean_file(f, text, arts, res["iocs"])
                base = os.path.splitext(f)[0] if f.lower().endswith(".txt") else f
                target = (os.path.join(a.outdir, os.path.basename(base) + ".clean.txt")
                          if a.outdir else base + ".clean.txt")
                if a.outdir: os.makedirs(a.outdir, exist_ok=True)
                with open(target, "w", encoding="utf-8") as fh: fh.write(body)
                saved.append(target)
            res["saved"] = saved
        allres[f] = res
        if not a.json:
            print(report(f, res, a.sinks_only, explain=not a.quiet)); print()
    if a.json:
        for r_ in allres.values():
            for x in r_.get("decoded", []):
                x.pop("bytes", None)
                if x["text"] and len(x["text"]) > 5000: x["text"] = x["text"][:5000] + " ...[truncated]"
        print(json.dumps(allres, indent=2))

if __name__ == "__main__":
    main()
