# Cytadel Exposure Assessment

A Windows desktop tool for **authorized defensive CTI / breach-notification**. It
ingests infostealer-log archives, matches a **client's own email domain**, and
produces a branded Cytadel PDF (and CSV) that reports *exposure for remediation*.

## No plaintext, by design (the whole point)

This tool **never** writes plaintext credentials to the PDF, the CSV, the UI
results grid, or any log/temp file it keeps. It reports *which accounts are
exposed*, not the secrets. Concretely:

- A credential is **in scope only when the username/email is at a client
  domain** (`user@client-domain.com`). URL matches are deliberately *not* used
  for inclusion — that would pull in unrelated individuals.
- As soon as a password is parsed, it is converted by `redact.py` into
  **non-reversible signals only**:
  - length,
  - which character classes are present (lower / upper / digit / symbol),
  - an optional "weak password" flag,
  - a **salted** SHA-256 *reuse key* used only to group identical passwords
    across services (random per-run salt, discarded on exit, never displayed or
    exported).
- No substring, no masked preview, no first-N characters. The plaintext never
  leaves `parser.py`.

This is what keeps the tool lawful under **GDPR data-minimization** and safe to
hand to a client.

## Authorized-use notice

This is a **defensive** CTI tool. Run it **only** against logs for clients who
have authorized you to check their exposure, and **only for their domains**. It
processes third-party breach/stealer data that contains real people's
credentials — handle it lawfully (GDPR). The tool makes **no network calls**,
stores nothing outside the folders you choose, and by design cannot emit raw
credentials. Do not redistribute raw stealer data.

## Requirements

- Python 3.11+ (developed/tested on 3.12)
- See `requirements.txt`. `.7z` (`py7zr`) and `.rar` (`rarfile` + an `unrar`
  binary) are **optional** — the app degrades gracefully with a clear message if
  a format's library is unavailable.

## Run from source

```bat
python -m pip install -r requirements.txt
python main.py
```

## Build the single-file .exe

```bat
build.bat
```

This installs dependencies, runs the test suite, and produces
`dist\CytadelExposure.exe` via PyInstaller (`--onefile --windowed`). Branding is
bundled from the `assets/` folder (`--icon assets\app.ico` for the executable
icon and `--add-data "assets;assets"` for the logos), so no loose files need to
sit next to the `.exe`.

### Branding assets

The `assets/` folder holds:

- `app.ico` — the executable / taskbar icon,
- `logo_white.png` — shown at the top of the app window (dark theme) and used as
  the window icon,
- `logo_dark.png` — drawn on the white PDF cover page.

Paths resolve via `cytadel/resources.py` (`resource_path`), which uses
`sys._MEIPASS` when frozen and the project directory when run from source.
Replace these files to re-brand; keep the same names.

## Linux build (Kali / Debian / Ubuntu)

The Windows `.exe` does not run on Linux — build the native Linux binary from
source. PyInstaller is not a cross-compiler, so a Linux binary must be built on
Linux (locally, or by the CI workflow below).

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip libxcb-cursor0 unrar
bash build_linux.sh          # -> dist/CytadelExposure
./dist/CytadelExposure
```

`libxcb-cursor0` is required by Qt6 for the GUI; `unrar` is only needed for
`.rar` archives (`.7z` uses the bundled `py7zr`).

## Prebuilt binaries via GitHub Releases

`.github/workflows/release.yml` builds the Linux binary (on `ubuntu-22.04`, whose
older glibc keeps it compatible with newer Kali/Debian) and the Windows `.exe`,
then attaches both to a GitHub Release. Trigger it by pushing a version tag:

```bash
git tag v1.0.0
git push origin v1.0.0
```

Install the latest Linux binary on Kali (private repo — uses your `gh` login):

```bash
gh release download --repo <owner>/<repo> --pattern 'CytadelExposure-linux-*' -O CytadelExposure
chmod +x CytadelExposure
sudo apt install -y libxcb-cursor0
./CytadelExposure
```

> **Never commit generated reports.** `Cytadel_Raport_*.pdf` and `*.csv` outputs
> are git-ignored because they can contain real exposed-account data. Keep them
> out of the repository.

## Using the app

1. **Source** — pick a `.zip` / `.7z` / `.rar` archive, or a folder of already
   extracted logs.
2. **Scope** — enter the client domain(s), comma-separated (e.g.
   `client.com, client.net`).
3. **Metadata** — client name, report ID, date, prepared-by, classification
   (all pre-filled and editable).
4. **Options** — password-strength hint, reuse flagging, and "include the
   client's service accounts on any provider" (all redacted-only).
5. **Run** — watch progress and the live log, then review the exposure summary
   and redacted grid.
6. **Save PDF** / **Export CSV** — both contain redacted status only.

### Supported log formats

The parser auto-detects, in a single pass:

- **Block format** — `SOFT:` / `URL:` (or `Host:`) / `USER:` (or `Login:`) /
  `PASS:` (or `Password:`) blocks, delimited by a **blank line**, a run of
  `- _ ~ =`, or simply the next block's `URL:` line.
- **Line format** — `url:username:password` (one credential per line, incl.
  `https://site.com:email@provider.com:password` and `android://…` entries).
- **Combolist / ANTIPUBLIC** — `email:password` lines.

### Scope is intentional — why a scan can return "0 accounts"

A record is included **only** when it belongs to a client domain you entered:
either the **email domain** (`user@client.com`) or, when the third option is
enabled, the **service URL host** (an account on the client's own site, on any
email provider). This scope limit is the GDPR-data-minimization safeguard — the
tool reports **your client's** exposure, not everyone else's in the log.

So a scan of a large dump can legitimately return **0** if none of the entries
belong to the domain you typed. When testing, enter a domain that actually
appears in the data.

## Përdorimi (Shqip)

Mjet **mbrojtës** CTI për njoftim shkeljesh — vetëm për klientë të autorizuar
dhe vetëm për domenet e tyre. Nuk shkruan kurrë fjalëkalime në tekst të thjeshtë
(GDPR).

**Hapat:**

1. **Burimi** — zgjidh një arkiv `.zip` / `.7z` / `.rar`, ose një dosje me loge
   të shpaketuara.
2. **Domeni(et) e klientit** — shkruaji të ndara me presje (p.sh.
   `client.com, client.net`).
3. **Metadata e raportit** — emri i klientit, ID, data, përgatitur nga,
   klasifikimi (të parambushura, të ndryshueshme).
4. **Opsionet** — sinjali i fuqisë, ripërdorimi, dhe **"Përfshi llogaritë e
   shërbimit me çdo provider"** (mbaje të ndezur që të përfshihen llogaritë
   gmail/outlook/yahoo të përdorura në shërbimin e klientit).
5. **Ekzekuto vlerësimin** — ndiq progresin, pastaj shiko përmbledhjen dhe
   tabelën e redaktuar.
6. **Ruaj PDF** / **Eksporto CSV** — të dyja përmbajnë vetëm status të redaktuar.

**Formatet e mbështetura:** blloqe `SOFT/URL/USER/PASS` (të ndara me rresht bosh,
me vija `- _ ~ =`, ose pa ndarës); rreshta `url:user:password`; combolista
`email:password`.

**Pse mund të dalë "0 llogari":** rekordi përfshihet **vetëm** nëse i përket
domenit të klientit që fute (email `@domeni` ose hosti i URL-së). Ky është
kufizimi mbrojtës (GDPR). Nëse asnjë hyrje s'i përket domenit tënd, rezultati
është 0 — normale. Për test, fut një domen që ekziston vërtet në loge.

**Nëse dritarja del më e madhe se ekrani (VM):** përmbajtja tani ka scroll dhe
madhësia kufizohet sipas ekranit; nëse fontet dalin keq, provo
`QT_SCALE_FACTOR=1 python main.py`.

## Safe extraction

Archives are hostile input. The extractor:

- extracts to an OS temp dir and cleans up on exit (your source archive is never
  deleted);
- **zip-slip guard** — skips any entry whose resolved path escapes the root;
- **decompression-bomb caps** — total uncompressed bytes (default 5 GB),
  per-file size, entry count, each checked against both the declared size and
  the bytes actually streamed;
- **nested archives** — extracted recursively up to depth 10;
- never executes archive contents; the optional `.rar` path uses fixed
  arguments and never shell-interpolates filenames.

## Project layout

```
main.py                 # GUI entry point
cytadel/
  extractor.py          # safe archive extraction (zip-slip / bomb / nesting guards)
  parser.py             # stealer-log parsing; redacts before records leave the module
  redact.py             # plaintext -> non-reversible exposure signals
  search.py             # scope match, dedup, reuse flag, sort, CSV export
  pdf_report.py         # branded Cytadel PDF (remediation-driven)
  ui.py                 # PySide6 dark-theme GUI
tests/                  # pytest: parser, redact, extractor, search, end-to-end
build.bat               # PyInstaller build
requirements.txt
```

## Tests

```bat
python -m pytest -q
```

The end-to-end test builds a synthetic zip, runs the full pipeline, and asserts
that an in-scope account appears in the PDF/CSV while **no plaintext password
appears anywhere in the generated bytes** (the PDF is built uncompressed for
that check so it is meaningful).
