# VulnScan — a VirusTotal-style vulnerability assessment tool

A web app that checks URLs, files, IP addresses, domains and file hashes against
70+ antivirus engines and threat-intelligence feeds, using the VirusTotal API v3.

Bootstrap 5 frontend, Flask backend, SQLite for caching and scan history.

---

## Read this first: your API key

**Regenerate the key you were given.** It was pasted into a chat, so treat it as
public. On virustotal.com: your avatar → **API key** → **Regenerate**.

**Never put a VirusTotal key in frontend JavaScript.** Two reasons:

1. Anyone can press F12 and read it, then spend your quota or attribute their
   lookups to your account.
2. It would not work anyway — VirusTotal does not send CORS headers, so a browser
   refuses the response.

This is why the app has a backend. The request path is:

```
Browser  ──▶  this Flask app  ──▶  VirusTotal API
             (holds the key)
```

The key is read from the `VT_API_KEY` environment variable and never rendered
into a page or returned by any endpoint. There is a test that asserts this.

---

## Run it locally

```bash
git clone <your-repo-url> && cd vulnscan

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env               # Windows: copy .env.example .env
python app.py
```

Then open `.env` and paste your key on the `VT_API_KEY=` line:

```
VT_API_KEY=your_actual_key_here
```

The app loads `.env` automatically on start, so restart it after editing. Open
<http://localhost:5000>.

Quotes, spaces around the `=`, a trailing `# comment` and an `export` prefix are
all tolerated. What does *not* work: editing `.env.example` instead of `.env`,
leaving the line commented out with a `#`, or Windows silently saving the file as
`.env.txt`. If the key is missing, the terminal prints which of these it is.

`.env` is listed in `.gitignore`, so it never reaches GitHub. Real environment
variables take priority over the file, which is how Render and Docker supply the
key in production without a `.env` existing at all.

### Demo mode (no API key, no quota used)

```bash
python tests/demo_server.py        # http://localhost:5001
```

This runs the whole interface against fixed sample data. Use it to rehearse a
presentation without burning your 500 lookups for the day.

---

## Deploy to Render (free tier)

1. Push this folder to a GitHub repository. `.gitignore` already excludes `.env`
   — confirm your key is not in the commit before you push.
2. On [render.com](https://render.com) → **New** → **Web Service** → connect the repo.
3. Render reads `render.yaml`, so build and start commands are filled in already.
   If you prefer to set them by hand:
   - Build command: `pip install -r requirements.txt`
   - Start command: `gunicorn --bind 0.0.0.0:$PORT --workers 2 --threads 4 --timeout 120 app:app`
4. Under **Environment**, add `VT_API_KEY` with your key. This is the only
   required variable.
5. Deploy. You get a public `https://your-app.onrender.com` URL that anyone can use.

**Railway** is the same shape: connect the repo, add `VT_API_KEY` as a variable,
and it detects the `Procfile`.

**Docker**, if your internship prefers containers:

```bash
docker build -t vulnscan .
docker run -p 8000:8000 -e VT_API_KEY=your_key_here vulnscan
```

> Free hosting tiers use an ephemeral filesystem, so the SQLite cache and history
> reset whenever the service restarts or sleeps. Scanning is unaffected. To make
> history permanent, attach a persistent disk and point `DB_PATH` at it.

---

## What it does

| Tab | What it checks | VirusTotal endpoint |
|---|---|---|
| URL | Phishing, malware distribution, blocklisting | `GET /urls/{id}`, `POST /urls` |
| File | Upload up to 32 MB, scanned by every engine | `GET /files/{sha256}`, `POST /files` |
| IP | Reputation, ASN, network owner, country | `GET /ip_addresses/{ip}` |
| Domain | Reputation, registrar, DNS records, categories | `GET /domains/{domain}` |
| Hash | Look up a known MD5 / SHA-1 / SHA-256 | `GET /files/{hash}` |

Every result shows the detection ratio, a per-vendor breakdown you can filter and
search, the underlying metadata, and a link to the full VirusTotal report.

### Two quota optimisations worth understanding

These are the parts most worth explaining if you present this work:

**Files are hashed before they are uploaded.** The app computes the SHA-256
locally and asks `GET /files/{sha256}` first. If VirusTotal has already analysed
that exact file — true for most known malware — you get the complete report from
one request, with no upload and no waiting. Only a genuinely new file is uploaded.

**URLs are read before they are submitted.** `GET /urls/{id}` returns an existing
report immediately. Submitting for a fresh scan costs a POST plus repeated polling
until the engines finish, so it happens only when the report is missing or you tick
*Force a fresh scan*.

---

## Rate limits

The free public API allows **4 lookups per minute, 500 per day, 15,500 per month**.
That budget is shared by everyone using your deployment, so the app defends it in
three layers:

| Layer | Default | Variable |
|---|---|---|
| Token bucket in front of every VirusTotal call | 4/min | `VT_RATE_LIMIT_PER_MIN` |
| Response cache, so repeat lookups cost nothing | 6 hours | `CACHE_TTL_SECONDS` |
| Per-visitor throttle | 20 per 5 min | `VISITOR_LIMIT_PER_WINDOW`, `VISITOR_WINDOW_SECONDS` |

Polling a fresh submission is deliberately slow (16-second intervals) for the same
reason. If you upgrade to a paid key, raise `VT_RATE_LIMIT_PER_MIN` to match it.

---

## Configuration

All optional except the first.

| Variable | Default | Purpose |
|---|---|---|
| `VT_API_KEY` | — | **Required.** Your VirusTotal API key. |
| `VT_RATE_LIMIT_PER_MIN` | `4` | Calls allowed per minute. |
| `CACHE_TTL_SECONDS` | `21600` | How long a result is reused. |
| `VISITOR_LIMIT_PER_WINDOW` | `20` | Requests one visitor may make per window. |
| `VISITOR_WINDOW_SECONDS` | `300` | Length of that window. |
| `DB_PATH` | `data/scans.db` | SQLite file for cache and history. |
| `PORT` | `5000` | Port to bind. |

---

## Project layout

```
vulnscan/
├── app.py                  Flask routes, validation, per-visitor throttle
├── vt_client.py            VirusTotal wrapper, rate limiter, response normaliser
├── store.py                SQLite cache and scan history
├── templates/index.html    The Bootstrap interface
├── static/
│   ├── css/style.css       Verdict colours, dropzone, tables
│   ├── js/app.js           Scan flow, polling, rendering, theme
│   └── vendor/             Bootstrap 5.3.3 + icons, served locally
├── tests/
│   ├── test_app.py         57 checks, VirusTotal mocked
│   └── demo_server.py      Runs the UI with mocked data
├── Dockerfile  render.yaml  Procfile  requirements.txt  .env.example
```

Bootstrap is served from `static/vendor/` rather than a CDN, so the tool still
works on a restricted network or with no internet beyond the VirusTotal call.

---

## Tests

```bash
python tests/test_app.py
```

57 checks covering input validation, verdict calculation, the cache path, file
hashing, analysis polling, history, error shapes and the rate limiter — all with
VirusTotal mocked, so running them costs no quota.

Worth knowing: the validation tests caught a real bug during development.
`javascript:alert(1)` contains no `://`, so the "add http:// if missing"
convenience turned it into `http://javascript:alert(1)`, which Python's
`urlparse` accepts — reading `javascript` as the hostname and `alert(1)` as the
port. `valid_url()` in `vt_client.py` is strict as a result: it requires an
http/https scheme, a numeric port if one is given, and a host that is either
dotted or an IP literal.

---

## Security notes

- The API key stays server-side and is never sent to the browser.
- All input is validated before any network call is made.
- Vendor names and detection strings come from third parties and are HTML-escaped
  before rendering (see `esc()` in `app.js`), so a malicious page title in a
  VirusTotal report cannot inject script into your page.
- Uploads are capped at 32 MB at both the Flask and application layers.
- `X-Content-Type-Options`, `X-Frame-Options` and `Referrer-Policy` are set on
  every response.

### Honest limitations

Worth stating plainly rather than overselling the tool:

- This is a **threat-intelligence lookup tool**, not a vulnerability scanner. It
  tells you whether a file or address is *known bad*. It does not find CVEs, test
  for misconfiguration, or probe a host — that is what Nessus, OpenVAS and Nmap do.
- A clean result means no vendor has flagged it *yet*. Novel malware routinely
  scores 0/70 on first submission.
- **Uploading a file sends it to VirusTotal, where it can be downloaded by paying
  subscribers.** Never upload confidential documents. Look up the hash instead —
  that reveals nothing about the file's contents.
- Detection names are vendor opinions and often disagree with each other.

---

Built on the [VirusTotal API v3](https://docs.virustotal.com/reference/overview).
