# SIH26106 — Sentinel Mail

An email forensics platform that takes a raw `.eml` file and produces a
fraud verdict backed by four independent signals: **cryptographic header
authentication** (SPF/DKIM/DMARC), **lookalike-domain detection**, **IP relay
geolocation**, and an **NLP phishing classifier** — then correlates related
emails into likely attack campaigns using a graph, and surfaces everything on
an interactive Streamlit dashboard. The project's thesis: an LLM asked "is
this phishing?" cannot verify a DKIM signature, reconstruct an SMTP relay
chain, compute domain edit-distance, geolocate an IP, or hold state across
multiple emails to spot a campaign. This system does all five.

## Folder structure

```
repo-root/
  README.md
  requirements.txt
  .gitignore
  .env.example
  run_demo.py                         ← smoke-test entry point
  docs/                               ← 8 context .md files live here
  contracts/
    fixtures/                         ← shared sample .eml files
      sample_legit_1.eml
      sample_phish_1.eml
      sample_phish_2_campaign_a.eml
      sample_phish_3_campaign_a.eml
  forensics/          main.py         ← Person 1: SPF/DKIM/DMARC
  typosquat/          main.py         ← Person 5: lookalike-domain detection
  geolocation/        main.py         ← Person 6: IP relay geolocation
  nlp_classifier/     main.py         ← Person 2: phishing text classifier
  correlation_graph/  main.py         ← Person 3: campaign correlation graph
  dashboard/          app.py          ← Person 4: Streamlit UI + pipeline
                      pipeline.py
                      scoring.py
  data/                               ← generated at runtime (gitignored)
```

## How to run

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

> **Tip:** use a virtual environment to keep things tidy:
> ```bash
> python -m venv .venv
> # Windows
> .venv\Scripts\activate
> # macOS / Linux
> source .venv/bin/activate
> pip install -r requirements.txt
> ```

### 2. Set up environment variables

```bash
cp .env.example .env
# then edit .env and fill in GEO_API_KEY (free key from ip-api.com or ipinfo.io)
```

### 3. Smoke-test the stub pipeline

```bash
python run_demo.py
```

If this exits with `✅ Smoke test passed.` the entire plumbing works — even
before anyone has written real logic. This is the Day 1 sanity check.

### 4. Run the Streamlit dashboard

```bash
streamlit run dashboard/app.py
```

Upload any `.eml` file from `contracts/fixtures/` to see the full pipeline
output in the browser.

### 5. Run all tests

```bash
pytest
```

## Scope

**In scope:** processing pre-collected `.eml` files through the five signals
above.

**Out of scope (roadmap only):** live inbox / OAuth integration with Gmail or
Outlook, chain-of-custody evidentiary logging, production-grade case
management.

## Team & branches

| Person | Module | Branch |
|--------|--------|--------|
| 1 | `forensics/` — SPF/DKIM/DMARC | `feature/forensics` |
| 2 | `nlp_classifier/` — text classifier | `feature/nlp-classifier` |
| 3 | `correlation_graph/` — campaign graph | `feature/correlation-graph` |
| 4 | `dashboard/` — UI + pipeline + fraud score | `feature/dashboard` |
| 5 | `typosquat/` — domain detection | `feature/typosquat` |
| 6 | `geolocation/` — IP relay map | `feature/geolocation` |

> **Contract rule:** Do not rename a public function or change a return field
> name without telling the whole team first. Other modules import your
> function directly and read specific keys from your return dict.
