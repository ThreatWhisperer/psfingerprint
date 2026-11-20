# psfingerprint: Static PowerShell Deobfuscator, Decoder and Obfuscator Identifier

**Identify which tool obfuscated a malicious PowerShell script, decode its Base64 / hex / XOR / GZip payloads, find every hidden `iex` and execution point, and get a clear next step. All without running the sample.**

`psfingerprint` is a single-file, zero-dependency Python tool for **malware analysts, SOC analysts, incident responders and threat hunters**. Give it an obfuscated PowerShell script (a dropper, a ClickFix / fake-CAPTCHA payload, a phishing attachment, or an `install.ps1` pulled from a lure site) and it tells you:

- **Which obfuscator or builder made it**: Invoke-Obfuscation (TOKEN / STRING / ENCODING / LAUNCHER), Chimera, xencrypt-style AES+GZip packers, `-EncodedCommand` stagers, commodity loader kits, and native-API shellcode injectors.
- **Every obfuscation technique used**, with counts and line numbers: backticks, `-f` reordering, string concatenation, `[char]` encoding, XOR / `-bxor`, Base64, Base85, GZip/Deflate, AES, junk arithmetic, opaque predicates, and more.
- **Every execution sink** (`iex`, `& $x`, `.($x)`, dynamic `[type]` calls, `.Invoke()`, runspaces) so you can **defang the script** safely before deobfuscating it.
- **Decoded payloads**: Base64, `-EncodedCommand`, hex, decimal and byte arrays, `[char]` chains and Base85, peeled recursively through UTF-16, GZip, Deflate and **XOR, including automatic recovery of repeating XOR keys**. URLs, IPs and file paths are pulled out of the decoded content and defanged.
- **A cleaned copy** of the script, with backticks, string concatenation, `-f` reordering and `[char]` codes resolved inline.
- **What the decoded code does**: AMSI / ETW bypass, process injection, API hashing, `Reflection.Emit`, `Assembly.Load`, downloads.

> **It never executes the input.** The script is read as text and pattern-matched. Nothing is evaluated.

---

## Contents
- [Why](#why)
- [Quick start](#quick-start)
- [Example output](#example-output)
- [How to read the report](#how-to-read-the-report)
- [What it detects](#what-it-detects)
- [Recommended deobfuscation workflow](#recommended-deobfuscation-workflow)
- [Usage](#usage)
- [Safety](#safety)
- [Limitations](#limitations)
- [Related tools](#related-tools)
- [Contributing](#contributing)
- [Licence](#licence)

---

## Why

Existing tools fall into two camps. Some **detect** that PowerShell is obfuscated (Revoke-Obfuscation, Sigma rules, EDR analytics). Others **remove** the obfuscation (PSDecode, PowerDecode, Invoke-Deobfuscation). Neither tells you **which obfuscator or kit** you're looking at, or **where the hidden execution points are** before you start.

That's what you need at the start of triage:

- **Attribution leads:** Invoke-Obfuscation output looks very different from a commodity loader kit or a C2 stager.
- **A defang list:** obfuscated scripts often hide a second `iex`, a runspace, or a dynamically-resolved `[type]::Method()` in the middle of 50,000 lines of junk. Miss one and your "safe" deobfuscation run executes the malware.
- **A next step,** in plain English.

## Quick start

Requires **Python 3.8+**. No packages to install.

```bash
git clone https://github.com/ThreatWhisperer/psfingerprint.git
cd psfingerprint

# Always analyse samples saved with a non-executable extension
python -I psfingerprint.py sample.ps1.txt
```

On Windows / FLARE VM:

```powershell
python -I .\psfingerprint.py .\sample.ps1.txt
```

New to it? Run the built-in guide first:

```bash
python -I psfingerprint.py --guide
```

## Example output

A real 6 MB, 59,000-line PowerShell loader. The payload is XOR-encrypted, buried in junk arithmetic, and runs via an `iex` built from character codes:

```text
=== install.ps1.txt
    6,258,207 bytes | 59,276 lines | longest line 1,930,307 chars | 1,497 variables | entropy 5.774

  VERDICT
    Obfuscation : HEAVY
    Best match  : Custom arithmetic-noise builder (commodity loader kits)  [score 13]
    Confidence  : HIGH
    Behaviour   : none detected at this layer (expected while still encoded)
    In decoded  : api_hash_fnv, fn_ptr_delegate, pe_parsing, reflection_emit
    Final stage : Donut shellcode (E8 + encrypted instance)  sha256 87cfbf82...
    Next step   : decoded statically down to a Donut shellcode (L59275>326). Save it with
                  --outdir and analyse it with donut-decryptor - no need to run the script

-- Likely obfuscator / builder
  [13] Custom arithmetic-noise builder (commodity loader kits)  HIGH
       matched: arith_noise, array_index_pick, opaque_predicate, xor_identity, bigint_math, byte_array_blob, char_cast

-- Techniques
  Encoding / encryption (hides the payload)
    bxor_encoding      x7282   -bxor single/repeating key
    char_cast          x106    [char]NN character casting
    xor_identity       x1      (a -bor b) - (a -band b)  == XOR (disguised)
    byte_array_blob    x1      Large inline [byte[]] array
  Junk & anti-analysis (wastes your time)
    arith_noise        x6457   Constant-arithmetic junk assignments
    opaque_predicate   x207    Opaque predicates (if(123456 -gt 654321))
    array_index_pick   x42     2-D array char-code picking (@(@(..),@(..))[i][j])

-- Decoded content (2 artefact(s))
  [1] L59275  decimal byte array -> text -> Base64 -> XOR key 'AMSI_RESULT_NOT_DETECTED'
              (recovered by cryptanalysis) -> text  =>  text  (434,857 B)
       function NormalizeSet941 { $RouteOffset130 = 34, 36, 39, 92, 96 ...
  [2] L59275>326  Base85 (custom: printable minus quotes/$/`)  =>  Donut shellcode  (331,047 B)

-- Execution sinks to defang (5 on 2 line(s))
  L59276   Dot-invoke of variable  .($x)          ...;.($Oz7gsw1fjzBadKTg3kuKes)($z1aSA0UD3gl)
  L59243   Dynamic type / static call (resolve!)  ...{$t=[type]$IG6E5jZWuqrcKBTxQUGcXAHj;$LKF9VNLvu=$t::(...
  ...
```

In one 5-second static run it:
- **broke the XOR encryption without being given the key**. The key is computed at runtime by the malware, but psfingerprint recovered it by cryptanalysis.
- **decoded the hidden second stage**, byte-identical to what a sandbox detonation produces.
- **found and decoded the Donut shellcode** inside that second stage, using a custom Base85 alphabet.
- **flagged a hidden sink on line 59243**: a dynamically-resolved type call buried in the junk that is easy to miss by eye.

## How to read the report

| Section | What it tells you |
|---|---|
| **Verdict** | How obfuscated the file is (NONE / LIGHT / MODERATE / HEAVY), the best-matching tool, how confident that match is, any malicious behaviour, and what to do next. |
| **Likely obfuscator / builder** | Known tool profiles ranked by score: 3 points per tool-specific trait, 1 per supporting trait. **HIGH** ≥ 9, **MEDIUM** 5–8, **LOW** < 5. |
| **Techniques** | Every trick found, grouped as **Obfuscation** (hides the code), **Encoding** (hides the payload), **Junk** (ignore it) and **Behaviour** (what the code really does; high priority). |
| **Decoded content** | Every encoded literal found and decoded, with the chain of steps (e.g. `decimal -> Base64 -> XOR key 'K' -> text`). `L59275>326` means line 326 inside the text decoded from line 59275. Red results (PE, Donut, ELF, ZIP) are final binaries. Also lists IoCs found in the decoded content, defanged. |
| **Hints** | Command names decoded from char codes, likely XOR keys, where the payload blob is and whether it looks like GZip, a PE, Donut shellcode or UTF-16 `-EncodedCommand` text. |
| **Execution sinks** | Every line that can run code. Replace each one with a write-to-file before running a copy. `(resolve!)` means the name is built at runtime, so log what it becomes. |

Full explanation: `python -I psfingerprint.py --guide`

## What it detects

**41 techniques** across four groups. Run `--list techniques` for the full list and `--list profiles` for exactly how each tool is scored.

**Obfuscator / builder profiles**
- Invoke-Obfuscation: TOKEN, STRING, ENCODING, COMPRESS/LAUNCHER (including the `$ShellId[1]+$ShellId[13]` and `$env:ComSpec[4,15,25]` IEX tricks)
- Chimera
- xencrypt / AES+GZip recursive packers
- `-EncodedCommand` launchers (PowerSploit `Out-EncodedCommand`, Empire, Cobalt Strike, Metasploit-style stagers)
- Custom arithmetic-noise builders (commodity loader / ClickFix kits)
- Native-API shellcode injectors (final stages using `GetDelegateForFunctionPointer`, API hashing and manual PE parsing)

**Obfuscation:** backtick escapes · `-f` format reordering · string concatenation · rAnDoM cAsE · `${v`a`r}` · string reversal · replace chains · obfuscated IEX · `gv`/`gci variable:` access

**Encoding / encryption:** `[char]` casting · `[char[]]` arrays · hex / octal / binary · `-bxor` · disguised XOR `(a -bor b)-(a -band b)` · SecureString · whitespace and special-character encoding · Base64 · `-EncodedCommand` · GZip / Deflate · AES · Base85 · large `[byte[]]` and Base64 blobs · BigInteger decoding

**Junk & anti-analysis:** constant-arithmetic noise · 2-D array char picking · opaque predicates · sleep / timing evasion

**Behaviour:** AMSI tampering · ETW tampering · `Reflection.Emit` · function-pointer delegates · FNV-1a and ROR13 API hashing · manual PE parsing · common injection targets (rundll32, MicrosoftEdgeUpdate, RegAsm, MSBuild…) · `Assembly.Load` · downloads (`WebClient`, `iwr`, `irm`, BITS)

**Decoding:** Base64 · `-EncodedCommand` (UTF-16LE) · hex strings · `0x` arrays · decimal and char-code arrays · `[char]` chains · Base85 (RFC1924, ASCII85 and the custom alphabet used by Donut injectors) · GZip · raw Deflate · zlib · XOR (literal keys from the script, single-byte brute force, **repeating-key cryptanalysis**) · nested layers (up to five deep, and decoded text is rescanned) · IoC extraction (URLs, IPs, Windows paths, `$env:` paths)

**Cleaned copy (`--clean`):** removes backticks · joins string concatenation · resolves `-f` format reordering · converts `[char]` codes and `[char[]]` arrays to text · normalises rAnDoM cAsE · appends decoded artefacts and IoCs

**Execution sinks:** `iex` / `Invoke-Expression` · `Invoke-Command` · `[ScriptBlock]::Create` · runspaces / `AddScript` · `.($x)` · `& $x` · `&('i'+'ex')` · dynamic `[type]` / `-as [type]` calls · `$o.($m)()` · `.Invoke()` · `Start-Process` · `Add-Type` · `$ExecutionContext.InvokeCommand` · alias creation

## Recommended deobfuscation workflow

```
fingerprint  ->  defang every sink  ->  run the COPY offline  ->  fingerprint the output  ->  repeat
```

1. `python -I psfingerprint.py sample.txt --outdir out --clean`. **If the verdict shows a `Final stage`, the static decoder has already reached the payload, so stop here** and analyse the saved file. Otherwise note the profile and **every** sink.
2. In a copy, replace each sink with a write-to-file:
   ```powershell
   [IO.File]::WriteAllText("layer2.txt", $decodedPayload)
   ```
3. Run the defanged copy in an **isolated VM with no network**, for example `unshare -rn pwsh -File harness.ps1` on Linux, or a snapshotted Windows VM with the NIC disabled.
4. Fingerprint `layer2.txt`. Repeat until the verdict shows **Behaviour** and the advice says *do not run*.
5. For embedded binaries, check the Hints: `MZ` → PE (use DIE, capa or dnSpyEx); `E8 xx xx xx xx` → Donut shellcode (use donut-decryptor).

If you can read the decoder, reproduce it in **CyberChef** or Python instead and never execute the sample at all.

## Usage

```
python -I psfingerprint.py [options] FILE [FILE ...]

decoding:
  --outdir DIR     save every decoded artefact (.txt for text, .bin for binary)
  --clean          write <file>.clean.txt: readable copy plus decoded artefacts and IoCs
  --no-decode      skip the static decoder

output:
  --sinks-only     show only the verdict and execution sinks
  --json           machine-readable JSON (for pipelines, SOAR, ticket enrichment)
  -q, --quiet      hide the one-line explanations under each section
  --no-color       disable colour (automatic when piped)

reference:
  --guide          explain how to read the report
  --list {techniques,profiles,sinks}
                   list everything the tool can detect
  --version
```

Examples:

```bash
python -I psfingerprint.py layer1.txt layer2.txt layer3.txt     # compare peeled layers
python -I psfingerprint.py sample.txt --outdir out --clean      # decode everything, save it
python -I psfingerprint.py sample.txt --sinks-only              # just what to defang
python -I psfingerprint.py sample.txt --json > report.json      # automation
```

Input can be UTF-8 or UTF-16 (BOM detected), with any file extension.

## Safety

- The tool **does not execute** anything from the input.
- **Store samples as `.txt`.** On Windows, double-clicking or choosing *Run with PowerShell* on a `.ps1` can detonate it.
- **Decoded `.bin` artefacts can be live payloads** (PE files, shellcode). Keep `--outdir` inside your analysis VM, and never commit or share it unencrypted.
- The **`.clean.txt` copy is still malware**. It is a readable view, not a defanged script.
- Use **`python -I`** (isolated mode) so Python can't import a stray `.py` file planted in your samples folder.
- Don't re-download samples from live attacker infrastructure. Use copies from your EDR, proxy or sandbox.
- Results are **heuristic leads, not proof of attribution**.

## Limitations

- Pattern-based: a determined author can avoid any single signature. Profiles reward several traits together to reduce this.
- The Chimera profile is weak on its own because Chimera mostly renames variables.
- Static decoding recovers literal and repeating-XOR keys, but not keys derived from the environment (hostname, date, a downloaded value). For those, use the defang-and-run workflow.
- The cleaner is regex-based. It is meant for reading, and it can occasionally mis-join unusual quoting.
- Very long single lines (multi-MB blobs) are sampled at the start and end for speed.

## Related tools

| Tool | Purpose |
|---|---|
| [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation) | The obfuscation framework. Generate samples to tune profiles |
| [Revoke-Obfuscation](https://github.com/danielbohannon/Revoke-Obfuscation) | Detects obfuscated PowerShell (yes/no) |
| [PSDecode](https://github.com/R3MRUM/PSDecode) | Dynamic deobfuscation by overriding `iex` |
| [PowerDecode](https://github.com/Malandrone/PowerDecode) | Multi-layer PowerShell deobfuscator |
| [Invoke-Deobfuscation](https://github.com/snowroll/Invoke-Deobfuscation) | AST-based deobfuscation |
| [CyberChef](https://github.com/gchq/CyberChef) | Manual decoding recipes |
| [donut-decryptor](https://github.com/volexity/donut-decryptor) | Unpacks Donut shellcode |

## Contributing

New profiles and detections are welcome. Both are plain data at the top of `psfingerprint.py`:

- **Techniques** live in the `T` dictionary: `name: (regex, flags, description)`. Add the name to a group in `CATEGORIES`.
- **Profiles** live in `PROFILES`: `(name, required_traits, supporting_traits, note)`.
- **Sinks** live in `SINKS`: `(regex, label)`.

When opening a PR, please include a **benign** test snippet that triggers the new detection. **Do not submit live malware.** Reference hashes are fine.

## Licence

MIT. See [LICENSE](LICENSE).

---

<sub>Keywords: PowerShell deobfuscation, PowerShell decoder, Base64 decoder, XOR key recovery, PowerShell obfuscation detection, identify PowerShell obfuscator, Invoke-Obfuscation detection, malicious PowerShell analysis, malware analysis tool, SOC triage, incident response, threat hunting, DFIR, ClickFix, fake CAPTCHA, PowerShell dropper, PowerShell loader, AMSI bypass detection, process injection detection, Donut shellcode, iex, Invoke-Expression, EncodedCommand decoder, static analysis, FLARE VM, REMnux.</sub>
