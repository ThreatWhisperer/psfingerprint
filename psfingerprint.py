#!/usr/bin/env python3
"""
psfingerprint.py - static PowerShell obfuscation fingerprinter.

Reads a script as text (never executes it), reports:
  * which obfuscation TECHNIQUES are present (with evidence + counts)
  * which known OBFUSCATOR / builder profiles best match
  * every likely EXECUTION SINK (line numbers) so you know what to defang
  * blobs / decoding hints (base64, byte arrays, Base85, XOR keys, compression)

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
# Presentation
# --------------------------------------------------------------------------
VERSION = "1.1"

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

5. EXECUTION SINKS TO DEFANG
   Every place the script can RUN code. Before you execute the sample anywhere,
   replace each of these with a write-to-file, e.g.
       [IO.File]::WriteAllText("layer2.txt", $payload)
   Then run the defanged copy offline and repeat on the output.
   Types marked (resolve!) build a type or method name at runtime - log what
   they resolve to; they can hide a second iex or a runspace.

WORKFLOW
   fingerprint -> defang sinks -> run copy offline -> fingerprint layer 2 -> ...
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
    if beh and lvl != "HEAVY":
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
    r = ap.add_argument_group("reference")
    r.add_argument("--guide", action="store_true",
                   help="explain how to read the report, then exit")
    r.add_argument("--list", choices=["techniques", "profiles", "sinks"],
                   help="list everything the tool can detect, then exit")
    ap.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    a = ap.parse_args()

    if not a.no_color and not a.json and sys.stdout.isatty():
        if sys.platform == "win32":
            import os; os.system("")  # enables ANSI escape handling in Windows consoles
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
        allres[f] = res
        if not a.json:
            print(report(f, res, a.sinks_only, explain=not a.quiet)); print()
    if a.json:
        print(json.dumps(allres, indent=2))

if __name__ == "__main__":
    main()
