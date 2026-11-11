# TypeosquattingDetector

Find registered look-alike domains (typosquatting) of a domain you want to protect, using [dnstwist](https://github.com/elceef/dnstwist).

The scanner generates look-alike variants (typos, homoglyphs, TLD swaps, bit flips, ...), keeps the ones that have a DNS record, and can compare each one with your site:

- `--lsh tlsh|ssdeep`: fuzzy-hash the HTML of each look-alike and compare it with the original.
- `--phash`: take a screenshot of each look-alike and compare it with the original.

## Approach

We do not write our own permutation engine. dnstwist already generates the variants and checks which ones resolve in DNS, so the project focuses on what happens after that:

1. **Generate** look-alikes of the protected domain with dnstwist's 15+ techniques. `--combo` / `--dictionary` add names built from the brand plus a word (`example-login.com`), and `--ct` adds names found in certificate logs, which permutations cannot guess.
2. **Filter** to the variants that have a DNS record (A, AAAA, MX or NS). Most generated names are not registered, so this step removes most of the noise. An allowlist removes your own legitimate domains.
3. **Judge** each registered variant:
   - `--lsh` fetches the HTML and compares it with a fuzzy hash (TLSH or ssdeep). It finds pages that copy the original's layout or text even when the bytes differ.
   - `--phash` renders each page in a headless browser and compares screenshots. It finds clones that look identical to a visitor even when the HTML is different.
   - `--enrich` looks up when the domain was registered. A domain registered last week is more suspicious than one registered ten years ago.
   - A risk score combines these signals with the presence of a mail server, and says why.
4. **Alert** on what changed: with `--state`, only new look-alikes are reported, by text, JSON or e-mail.

### Techniques covered

- **Typing mistakes**: addition, omission, repetition, transposition, replacement, insertion (`gooogle.com`, `gogle.com`, `googel.com`).
- **Visual tricks**: homoglyphs and Cyrillic characters that look like Latin ones (`οpenai.com` with a Greek omicron).
- **Structure**: hyphenation, subdomain tricks (`secure.paypal-verify.com`), TLD swaps (`.com` → `.net`, `.co`).
- **Advanced**: bitsquatting (one flipped bit in memory), vowel swaps, singular/plural, dictionary words.

### Things worth knowing

- **Content comparison is what separates a parked domain from a clone.** A registered look-alike with no similar content is usually a parked or unrelated domain. A high TLSH, ssdeep or pHash score is the signal to investigate.
- **`--phash` needs a real browser and a lot of memory.** It renders one page per registered variant, and dnstwist starts one browser per thread. Our first run with dnstwist's default thread count was killed by Docker's memory limit; `--threads 2` completed. Tested in the Docker image on `example.com`: 107 registered look-alikes, 76 with a pHash score and 54 with a TLSH score.
- **Dependencies are the hard part.** TLSH and ssdeep need native libraries, and pHash needs Chromium and a matching driver. Installing them on a laptop was error-prone, so the Docker image packages all of them.
- **Scores are not comparable across metrics.** TLSH, ssdeep and pHash all report a 0–100 similarity, but they measure different things (text structure, fuzzy bytes, visual layout); compare within one metric, not across them.

## Installation

### With Python

```bash
python3 -m venv venv
source venv/bin/activate
pip install .                            # dnstwist only: permutations and DNS checks
pip install ".[full]"                    # adds Selenium, Pillow, TLSH and ppdeep for --lsh and --phash
```

This installs a `typosquatting` command; `python3 -m typosquatting` works too.

`--phash` also needs Chromium and a matching `chromedriver` on the `PATH`. If they are missing, dnstwist exits with a message from argparse and the CLI reports it as an error.

### With Docker (recommended for `--lsh` and `--phash`)

```bash
docker build -t typosquatting .
docker run --rm -v "$PWD:/out" typosquatting example.com --lsh tlsh --phash --threads 2 -o /out/results.json
```

## Usage

```bash
# List registered look-alikes of example.com
python3 -m typosquatting example.com

# Compare the HTML of each look-alike with the original (TLSH or ssdeep)
python3 -m typosquatting example.com --lsh tlsh

# Save all results to JSON, keeping the 10 closest per metric in the text report
python3 -m typosquatting example.com --lsh tlsh -o results.json --limit 10

# Scan several domains in one run (a failing domain does not stop the others)
python3 -m typosquatting example.com example.org

# Rank by risk: registration dates, brand-plus-word names, certificate logs, own domains ignored
python3 -m typosquatting example.com --enrich --combo --ct --allow example.org --allow-file mine.txt
```

| Option | What it does |
| --- | --- |
| `--combo` | also tries the domain combined with common words (`login`, `secure`, `support`, ...); the list is in `typosquatting/data/combo-words.txt` |
| `--dictionary FILE` | same, with your own word list (one word per line) |
| `--ct` | adds names that got a TLS certificate and contain the brand, from [crt.sh](https://crt.sh) |
| `--allow DOMAIN` | ignores a legitimate domain and its subdomains (repeatable) |
| `--allow-file FILE` | same, one domain per line; `#` starts a comment |
| `--enrich` | looks up each look-alike's registration date through RDAP |
| `--lsh tlsh\|ssdeep`, `--phash` | compares content or screenshots with the original |
| `--threads N` | parallel workers; lower it with `--phash` to save memory |
| `--limit N` | entries per section of the report (default 5) |

### Watching for new look-alikes

A one-off scan lists every registered look-alike, which is a long list that rarely changes. To be alerted only when a **new** one appears, give the scan a state file:

```bash
python3 -m typosquatting example.com example.org --state state.json --email-to security@example.com
```

- The first run only records a baseline in `state.json`; it reports nothing as new and sends no e-mail.
- Later runs list the look-alikes not seen before, and an e-mail is sent only when there are some.
- A look-alike that disappears and comes back is not reported twice: the state keeps every name ever seen.

Run it on a schedule, for example every day with cron (`0 7 * * * cd /path/to/project && python3 -m typosquatting example.com --state state.json --email-to ...`).

### Sending the report by e-mail

Add `--email-to` to send the report. The SMTP server is configured with environment variables, so no password is stored in the code:

```bash
export TYPOSQUAT_SMTP_HOST=smtp.gmail.com
export TYPOSQUAT_SMTP_PORT=587                 # optional, default 587 (STARTTLS)
export TYPOSQUAT_SMTP_USER=you@gmail.com
export TYPOSQUAT_SMTP_PASSWORD=...             # use an app password
export TYPOSQUAT_SMTP_FROM=you@gmail.com

python3 -m typosquatting example.com --email-to security@example.com
```

The e-mail contains the text report in the body and the full results as a JSON attachment. With `--state`, the subject reads `Typosquatting alert: N new look-alike(s) of <domain>`.

## Output

Each registered variant has the fields returned by dnstwist (`domain`, `fuzzer`, `dns_a`, `dns_aaaa`, `dns_mx`, `dns_ns`, and `tlsh` / `ssdeep` / `phash` when requested). The text report shows:

- the number of registered look-alikes and how many come from each technique;
- with `--state`, the look-alikes that are new since the last scan;
- the look-alikes with the highest risk score, each with the reasons for its score;
- the closest look-alikes for each similarity metric that was measured.

The JSON file written by `-o` is a list with one summary per scanned domain. Every variant carries its `risk_score` and `risk_reasons`, and `registered` / `age_days` when `--enrich` was used.

Similarity scores: `tlsh`, `ssdeep` and `phash` are percentages from 0 (no similarity) to 100 (identical). Higher is closer; variants scoring 0 are not listed.

### Risk score

The score is a sum of points, each with a stated reason. The weights are judgement calls, not measured values: they have not been checked against a set of confirmed phishing domains, so treat the score as a way to sort a long list, not as a verdict.

| Signal | Points |
| --- | --- |
| Registered less than 30 / 90 / 365 days ago (`--enrich`) | 3 / 2 / 1 |
| Has an MX record (can send and receive e-mail) | 2 |
| Best content similarity of 70% or more / 40% or more / above 0 (`--lsh`, `--phash`) | 3 / 2 / 1 |
| Homoglyph or Cyrillic characters | 1 |
| Found in certificate logs (`--ct`) | 2 |

## Limitations

- **Registered does not mean malicious.** Many look-alikes are parked or bought defensively by the brand owner. The score helps to sort them; a person still decides.
- **`--ct` depends on crt.sh**, a free service that is often slow or unavailable and that times out on very common brand names (for example `paypal`). When it fails, the scan continues without it and logs a warning. It only keeps names whose own domain contains the brand: a phishing page hosted as `login.example.evil.com` is not found.
- **`--enrich` depends on the public RDAP gateway**, which refuses fast queries and has no record for some extensions. On a test scan of 129 look-alikes it dated about half of them in under two minutes. Undated domains simply get no age points.
- **The permutation approach only finds names it can generate.** Certificate logs and word lists widen the search, but a look-alike unrelated to the brand's spelling (a different word, a translation) is out of reach.

## Tests

```bash
pip install -e ".[test]"
python3 -m pytest
```

The tests replace dnstwist and SMTP with fakes, so they run offline. The same suite runs on every push and pull request through GitHub Actions.

## Project layout

```
typosquatting/
  scanner.py   # dnstwist wrapper and registered-domain filter
  ct.py        # look-alikes found in certificate logs (crt.sh)
  filters.py   # allowlist of legitimate domains
  enrich.py    # registration dates through RDAP
  risk.py      # risk score with reasons
  metrics.py   # counts per technique, closest and riskiest look-alikes
  report.py    # text report, e-mail message and SMTP sending
  state.py     # known look-alikes, to report only new ones
  cli.py       # command-line interface
  data/        # word list for --combo
tests/         # unit tests (offline)
Dockerfile     # image with Chromium, TLSH and ssdeep support
pyproject.toml # packaging and the `typosquatting` command
```

## Authors

- **Badr El Habbassi**: [@badrelh](https://github.com/badrelh)
- **Aymane Bouyghf**: [@aymane-03-cs](https://github.com/aymane-03-cs)
