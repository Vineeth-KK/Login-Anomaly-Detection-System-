# SENTINEL IDS v4 — Complete Project Documentation

> A Flask-based AI-powered Intrusion Detection System with real-time anomaly detection, honeypot deception, live event streaming, snapshot capture, and a full analytics dashboard. Pure Python ML — no scikit-learn or NumPy required.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [File & Folder Structure](#2-file--folder-structure)
3. [Setup & Installation](#3-setup--installation)
4. [Credentials Reference](#4-credentials-reference)
5. [Pages & Routes](#5-pages--routes)
6. [REST API Reference](#6-rest-api-reference)
7. [Core Pipeline — How a Login Is Processed](#7-core-pipeline--how-a-login-is-processed)
8. [Feature Extraction](#8-feature-extraction)
9. [ML Models — Deep Dive](#9-ml-models--deep-dive)
10. [Threat Engine](#10-threat-engine)
11. [Security Logger](#11-security-logger)
12. [Camera Capture System](#12-camera-capture-system)
13. [Voice Alert](#13-voice-alert)
14. [Mobile Notifications (Pushover)](#14-mobile-notifications-pushover)
15. [Honeypot Design](#15-honeypot-design)
16. [Live Event Stream (SSE)](#16-live-event-stream-sse)
17. [Dataset & Synthetic Data](#17-dataset--synthetic-data)
18. [Frontend Templates](#18-frontend-templates)
19. [Attack Simulation](#19-attack-simulation)
20. [Output Files](#20-output-files)
21. [Dependencies](#21-dependencies)
22. [Configuration & Environment Variables](#22-configuration--environment-variables)
23. [Known Design Decisions & Caveats](#23-known-design-decisions--caveats)
24. [Full Threat Processing Diagram](#24-full-threat-processing-diagram)

---

## 1. Project Overview

SENTINEL IDS v4 is a self-contained intrusion detection demo application. It monitors login attempts, scores them in real time using an ensemble of three ML models, and reacts with snapshots, voice warnings, and push notifications. It doubles as an educational honeypot: a fake corporate portal (`/portal`) is used to lure and fingerprint attackers — any credentials entered there trigger the full threat pipeline.

**Key characteristics:**

- **No login required** to access the dashboard (open by design for demo purposes)
- **Dashboard-first** architecture — everything is visible immediately on `/`
- **Pure-Python ML** — Isolation Forest, DBSCAN, and LOF are all hand-implemented without NumPy or scikit-learn
- **Online retraining** — the Isolation Forest and LOF models retrain every 30 events on a rolling 600-event buffer
- **Zero hard dependencies** — fallback chains ensure the app runs with only Flask installed

---

## 2. File & Folder Structure

```
login-anomaly-project/
│
├── app.py                          # Flask app, all routes, global state
├── requirements.txt                # pip dependencies
├── README.md                       # Quick-start reference
│
├── model/
│   ├── __init__.py
│   ├── anomaly_detector.py         # AnomalyDetector — Isolation Forest + DBSCAN + LOF
│   └── preprocess.py               # FeatureExtractor — raw login → 10-dim vector
│
├── security/
│   ├── __init__.py
│   ├── threat_engine.py            # ThreatEngine — composite risk score + classification
│   ├── logger.py                   # SecurityLogger — JSONL + CSV persistence
│   ├── camera.py                   # CameraCapture — webcam/PIL/PNG/SVG fallback chain
│   └── voice_alert.py              # VoiceAlert — async pyttsx3 TTS
│
├── notifications/
│   ├── __init__.py
│   └── notifier.py                 # MobileNotifier — Pushover push notifications
│
├── data/
│   ├── login_events.csv            # 1,000-row labeled training dataset
│   ├── attack_patterns.json        # Dataset statistics + known attack IPs/usernames
│   └── generate_dataset.py         # Script to regenerate the training dataset
│
├── templates/
│   ├── dashboard.html              # Main dashboard (stats, live feed, snapshots, demo)
│   ├── analytics.html              # ML analytics and cluster visualisation
│   ├── alert.html                  # Threat response page (shown after honeypot trigger)
│   ├── index.html                  # Landing / splash page
│   └── decoy.html                  # Honeypot — fake Nexora Corp employee portal
│
├── static/
│   ├── css/
│   │   └── global.css              # Shared dark-theme stylesheet
│   └── js/
│       └── liquid.js               # Ambient liquid-animation background effect
│
└── outputs/                        # Runtime-generated files (gitignore this)
    ├── threat_logs.jsonl           # Append-only event log (one JSON object per line)
    ├── suspicious_logins.csv       # Same events as CSV for spreadsheet analysis
    └── snap_YYYYMMDD_HHMMSS_*.{jpg,png,svg,json}   # Intruder snapshots + metadata
```

---

## 3. Setup & Installation

### Minimum install (Flask only)

```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# macOS / Linux:
source venv/bin/activate

pip install flask
python data/generate_dataset.py   # builds login_events.csv
python app.py                     # → http://localhost:5000
```

### Recommended install (richer snapshots)

```bash
pip install flask Pillow
```

### Full install (real webcam + voice)

```bash
pip install flask Pillow opencv-python pyttsx3
```

### What each optional package adds

| Package | Effect if absent | Effect if present |
|---|---|---|
| `Pillow` | PNG placeholder via pure Python | Richer PIL-rendered JPEG snapshots |
| `opencv-python` | Falls through to PIL/PNG | Real webcam frame captured on each intrusion |
| `pyttsx3` | Voice alert silently skipped | "Warning. Unauthorized access detected." spoken aloud |

---

## 4. Credentials Reference

### Demo Login (`/api/demo-login`)

Used on the **Demo tab** of the dashboard. Maximum 3 attempts before lockout.

| Username | Password | Effect |
|---|---|---|
| `demo` | `Demo@2026` | ✅ Successful login, no snapshot |
| `guest` | `Guest#123` | ✅ Successful login, no snapshot |
| *anything else* | *anything* | ❌ Failed — snapshot captured, risk scored |

### Honeypot Portal (`/portal/login`)

Used on the fake **Nexora Corp Employee Portal** at `/portal`. All traffic here triggers the full threat pipeline regardless of credentials. The two valid credentials below additionally return a success response (added in v4 update).

| Username | Password | Effect |
|---|---|---|
| `admin` | `Admin@2026` | ✅ Success response + threat pipeline runs |
| `sysop` | `Sysop#123` | ✅ Success response + threat pipeline runs |
| *anything else* | *anything* | 🚨 Threat response → redirect to `/alert` |

> **Note:** Even "valid" honeypot logins still run through `_process()`, meaning the ML models score them, a snapshot is captured, and the event is logged. The "success" is a frontend-only reassurance; the backend always treats the honeypot as hostile.

---

## 5. Pages & Routes

### GET Routes (rendered pages)

| URL | Template | Purpose |
|---|---|---|
| `/` | `dashboard.html` | Main admin dashboard — live feed, stats, snapshots, demo login |
| `/analytics` | `analytics.html` | ML performance metrics, DBSCAN cluster chart, feature importance |
| `/alert` | `alert.html` | Full-screen threat alert (reached after honeypot trigger) |
| `/portal` | `decoy.html` | Honeypot — fake Nexora Corp employee sign-in page |

### App secret key

```python
app.secret_key = "sentinel-open-v4"
```

Used for Flask session signing. Not currently used for session-based authentication (the dashboard is open).

---

## 6. REST API Reference

All endpoints return JSON unless noted.

### `POST /api/demo-login`

Processes a login attempt from the Dashboard Demo tab.

**Request body:**
```json
{ "username": "demo", "password": "Demo@2026", "attempt": 1 }
```

**Success response:**
```json
{ "status": "success", "username": "demo", "risk": 12, "threat": "LOW" }
```

**Failure response:**
```json
{
  "status": "fail",
  "locked": false,
  "attempt": 1,
  "risk": 47,
  "threat": "MEDIUM",
  "origin": "Moscow, Russia",
  "ml_label": "ANOMALY",
  "ml_score": 73.2,
  "snapshot": "outputs/snap_20260513_142301_admin.svg",
  "username": "admin"
}
```

When `locked: true` (attempt ≥ 3), a voice alert fires asynchronously.

---

### `POST /portal/login`

Processes a login attempt from the honeypot portal.

**Request body:**
```json
{ "username": "admin", "password": "wrongpass" }
```

**Threat response** (all non-valid credentials):
```json
{
  "status": "threat",
  "redirect": "/alert",
  "risk_score": 85,
  "ml_score": 91.4,
  "ml_label": "ANOMALY",
  "threat": "CRITICAL",
  "origin": "Dark Web Exit Node",
  "username": "admin",
  "timestamp": "2026-05-13 14:23:01",
  "snapshot": "outputs/snap_20260513_142301_admin.svg",
  "source": "HONEYPOT PORTAL"
}
```

**Success response** (valid honeypot credentials — `admin`/`Admin@2026` or `sysop`/`Sysop#123`):
```json
{ "status": "success", "username": "admin", "timestamp": "2026-05-13 14:23:01" }
```

Side effects on any call: snapshot captured, event logged, voice alert fired, Pushover notification sent (if configured).

---

### `POST /api/simulate`

Generates and processes one synthetic attack event using a random known-bad username and IP.

**Randomly chosen usernames:** `admin`, `root`, `test`, `oracle`, `sa`, `pi`, `postgres`, `mysql`

**Randomly chosen IPs:** `185.220.101.45`, `94.102.49.180`, `45.33.32.156`, `92.118.160.10`

**Response:**
```json
{ "ok": true, "username": "root", "ip": "185.220.101.45", "risk": 78, "threat": "CRITICAL", "origin": "Beijing, China", "snapshot": "..." }
```

---

### `GET /api/stats`

Returns aggregate statistics across all logged events.

```json
{
  "total_events": 142,
  "failed_logins": 138,
  "anomalies": 91,
  "critical_threats": 44,
  "honeypot_hits": 23,
  "simulated_attacks": 55,
  "success_rate": 2.8,
  "threat_distribution": { "CRITICAL": 44, "HIGH": 31, "MEDIUM": 47, "LOW": 20 },
  "source_distribution": { "demo": 64, "decoy": 23, "simulated": 55 },
  "top_origins": [{ "origin": "Moscow, Russia", "count": 18 }, ...]
}
```

---

### `GET /api/recent-events`

Returns the 40 most recent events in reverse-chronological order. Each event object mirrors the full logged structure including `timestamp`, `username`, `ip`, `source`, `valid`, `risk_score`, `ml_score`, `ml_label`, `threat`, `origin`, `ua`, and `snapshot`.

---

### `GET /api/ml-analytics`

Returns comprehensive ML performance data for the analytics dashboard.

Key fields:

| Field | Description |
|---|---|
| `total_samples` | Events in the rolling buffer |
| `anomaly_rate` | % of buffer scored as anomalous |
| `mean_score` | Mean Isolation Forest score across buffer |
| `threshold` | Current IF decision boundary |
| `precision`, `recall`, `f1_score`, `accuracy` | Evaluated against labeled dataset sample |
| `tp`, `tn`, `fp`, `fn` | Confusion matrix counts |
| `lof_anomaly_rate` | LOF anomaly rate on a 50-point sample |
| `model_agreement` | % agreement between IF and LOF |
| `dbscan_clusters` | Number of clusters found |
| `dbscan_silhouette` | Silhouette score (cluster quality, −1 to +1) |
| `dbscan_noise_ratio` | % of points classified as noise |
| `feature_importance` | 10-element array (variance-based, sums to 100%) |
| `score_histogram` | 10-bin histogram of IF scores |

---

### `GET /api/threat-timeline`

Returns hourly event counts for the past 24 hours.

```json
[{ "hour": "09:00", "count": 7 }, { "hour": "10:00", "count": 3 }, ...]
```

---

### `GET /api/cluster-data`

Returns up to 200 sampled buffer points with their DBSCAN cluster assignments and cluster centroids. Used to render the scatter plot on the analytics page.

---

### `GET /api/snapshots`

Returns metadata for up to 30 snapshots (most recent first), each containing `timestamp`, `username`, `risk`, `file`, and `url`.

---

### `DELETE /api/snapshots/<filename>`

Deletes a snapshot and all associated files (`.jpg`, `.png`, `.svg`, `.json`) for the given base filename stem.

---

### `GET /outputs/<filename>`

Static file server for snapshot images and JSON metadata stored in the `outputs/` directory.

---

### `GET /api/live`

Server-Sent Events stream. Emits a `data:` frame every 2 seconds with new events and updated stats. Heartbeats (`: hb`) are sent when no new events exist to keep the connection alive.

```
data: {"events": [...], "stats": {...}}

: hb

: hb
```

---

## 7. Core Pipeline — How a Login Is Processed

Every login attempt — demo, honeypot, or simulated — passes through the same internal `_process()` function:

```
Input: username, password, IP address, User-Agent, source label
         │
         ▼
1. FeatureExtractor.extract()
   → 10-dimensional float vector
         │
         ▼
2. AnomalyDetector.predict(features)
   → ml_score (0.0–1.0), ml_label ("NORMAL" | "ANOMALY")
         │
         ▼
3. ThreatEngine.compute_risk(username, ip, is_valid, ml_score)
   → risk score (0–100)
         │
         ▼
4. ThreatEngine.get_attack_origin(ip)
   → origin string (geo/network label)
         │
         ▼
5. ThreatEngine.classify_threat(risk)
   → "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
         │
         ▼
6. SecurityLogger.log(event)
   → appends to JSONL + CSV
         │
         ▼
7. AnomalyDetector.update(features)
   → updates Welford scaler + rolling buffer
   → triggers retrain every 30 events
         │
         ▼
Return: (event, is_valid, risk, threat, origin, ml_score, ml_label)
```

After `_process()`, each route handler decides whether to additionally call `camera.capture()`, `voice.warn_async()`, and `notifier.send()`.

---

## 8. Feature Extraction

**File:** `model/preprocess.py` — `class FeatureExtractor`

Converts one raw login attempt into a 10-dimensional float vector, all values normalised to approximately [0, 1].

| Index | Feature | Computation |
|---|---|---|
| 0 | `hour_sin` | `sin(2π × hour / 24)` — cyclical time encoding |
| 1 | `hour_cos` | `cos(2π × hour / 24)` — cyclical time encoding |
| 2 | `username_len` | `min(len(username) / 32, 1.0)` |
| 3 | `password_len` | `min(len(password) / 64, 1.0)` |
| 4 | `pwd_entropy` | Shannon entropy / 6.0, capped at 1.0 |
| 5 | `username_risk` | 1.0 if username is in the known-bad set, else 0.0 |
| 6 | `sql_flag` | 1.0 if `'`, `"`, `;`, `--`, `/*`, `*/`, `drop`, `select`, or `union` found in `username+password` |
| 7 | `ip_octet_var` | Variance of the four IP octets / 16384 |
| 8 | `ua_len_norm` | `min(len(user_agent) / 500, 1.0)` |
| 9 | `weekend_flag` | 1.0 if `weekday() >= 5` (Saturday/Sunday) |

**Suspicious username set:** `root`, `admin`, `administrator`, `test`, `guest`, `oracle`, `postgres`, `mysql`, `ubuntu`, `pi`, `user`

**Why cyclical encoding for time?** A linear hour feature (0–23) creates a false discontinuity between 23:00 and 00:00. Encoding hour as sine + cosine preserves the true circular continuity — midnight attacks look similar to 23:00 attacks in feature space.

---

## 9. ML Models — Deep Dive

**File:** `model/anomaly_detector.py` — `class AnomalyDetector`

All three models are hand-implemented in pure Python using only the standard library (`math`, `random`, `csv`, `collections`).

### 9.1 Welford Online Scaler

Before any model sees features, they pass through `_WelfordScaler`. This implements Welford's online algorithm to compute running mean and variance without storing all past values.

```
For each new sample x_i:
  n += 1
  delta = x_i - mean
  mean += delta / n
  M2 += delta × (x_i - mean)
  std = sqrt(M2 / n)
  scaled = (x_i - mean) / (std + ε)
```

This allows the scaler to handle unbounded, drifting data streams without memory proportional to dataset size. The small constant `ε = 1e-8` prevents division by zero on constant features.

---

### 9.2 Isolation Forest

**Parameters:** 80 trees (`n_trees`), 128 samples per tree (`max_samples`), 15% contamination

Isolation Forest works by randomly partitioning data and measuring how quickly a point gets isolated. Anomalies are isolated in fewer splits; normal points require more.

**Tree construction (`_IsoTree`):**
- Randomly picks a feature `f`
- Picks a random split value `v` between min and max of that feature in the current subset
- Recurses on left (`< v`) and right (`>= v`) subsets
- Stops when depth exceeds `ceil(log₂(n_samples))` or only 1 point remains

**Anomaly score:**

```
path_length(x) = average depth across all 80 trees
score(x) = 2^( -mean_path_length / c(max_samples) )
```

Where `c(n) = 2(ln(n-1) + 0.5772) - 2(n-1)/n` is the expected path length of an unsuccessful BST search, used to normalise scores to [0, 1].

**Threshold:** After fitting, all training samples are scored and the threshold is set at the `(1 - contamination)` percentile — the top 15% of scores are considered anomalous.

**Online retraining:** Every 30 new events (`RETRAIN_FREQ`), the forest is fully rebuilt using all samples in the 600-event rolling buffer. This adapts the model to evolving attack patterns.

---

### 9.3 DBSCAN

**Parameters:** ε = 1.5, min_pts = 4

Used for cluster analysis (visualised on the analytics page) rather than per-event scoring. DBSCAN groups together densely connected points and labels sparse outliers as noise (label `-1`).

**Algorithm:**
1. For each unvisited point, find its ε-neighbourhood
2. If `|neighbourhood| ≥ min_pts`, start a new cluster and expand it by adding all density-reachable points
3. Otherwise, mark the point as noise

**Silhouette score:** After clustering, a random sample of up to 100 clustered points is used to compute the silhouette score — a measure of how well-separated the clusters are, ranging from −1 (worst) to +1 (best).

DBSCAN refreshes every 30 events alongside the Isolation Forest retrain.

---

### 9.4 Local Outlier Factor (LOF)

**Parameters:** k = 8 neighbours, 15% contamination

LOF measures how isolated a point is relative to its local neighbourhood density. A point in a sparse region surrounded by dense clusters gets a high LOF score.

**Algorithm:**
1. For each point `x`, find its k nearest neighbours
2. Compute the k-distance (distance to the k-th nearest neighbour)
3. Compute reachability distance: `reach(x, y) = max(dist(x, y), k-dist(y))`
4. Compute local reachability density (lrd): `1 / mean(reach distances to k neighbours)`
5. LOF score = mean of neighbours' lrd / own lrd

A LOF of ~1.0 means the point is as dense as its neighbours (normal). LOF >> 1 means the point is in a sparser region than its neighbourhood (anomalous).

LOF is used as a **cross-validation check** against Isolation Forest. The `model_agreement` metric on the analytics page shows how often both models agree on their classification.

---

### 9.5 Bootstrap Training

On startup, `AnomalyDetector._bootstrap()`:

1. Tries to load `data/login_events.csv` (1,000 labelled rows)
2. Falls back to `_synth()` if the file doesn't exist — generates 300 normal + 60 attack samples synthetically
3. Updates the Welford scaler with every row
4. Fits the Isolation Forest and LOF on the full buffer
5. Runs an initial DBSCAN pass

Training data is **never wiped at runtime** — new events are added to the rolling buffer, which slides to discard the oldest entries once it exceeds 600.

---

### 9.6 Model Output

`AnomalyDetector.predict(features)` returns:

- `ml_score` — raw Isolation Forest score (0.0–1.0, higher = more anomalous)
- `ml_label` — `"ANOMALY"` if score ≥ threshold, else `"NORMAL"`

The `ml_score` is also fed into `ThreatEngine.compute_risk()` where it contributes up to 35 points to the final risk score.

---

## 10. Threat Engine

**File:** `security/threat_engine.py` — `class ThreatEngine`

Computes a composite risk score (0–100) from four signals:

| Signal | Weight | Detail |
|---|---|---|
| Failed login history | Up to 45 pts | `min(fail_count × 15, 45)` — tracked per `username:ip` pair in memory |
| Suspicious username | 20 pts | Fixed bonus if username is in the known-bad set |
| ML anomaly score | Up to 35 pts | `int(ml_score × 35)` |
| Intelligence noise | ±5 pts | `random.randint(-5, 5)` — simulates real-world score variability |
| Valid + anomalous | +15 pts | Extra penalty for a correct password used in an anomalous pattern |

Final score is clamped: `max(5, min(score, 100))`

**Threat classification:**

| Risk Score | Level |
|---|---|
| ≥ 75 | `CRITICAL` |
| 50–74 | `HIGH` |
| 25–49 | `MEDIUM` |
| < 25 | `LOW` |

**Attack origin:** For non-local IPs, a random label is picked from a pool of 12 geopolitical/network strings (e.g. `"Moscow, Russia"`, `"Dark Web Exit Node"`, `"Anonymous Proxy — TOR"`). Local IPs (`127.0.0.1`, `192.168.x.x`, `10.x.x.x`) return `"Local Network"` / `"Corporate Intranet"` / `"Localhost"`.

> The origin labels are illustrative — they are not based on real GeoIP lookup.

**Failed login tracking** is stored in a module-level `defaultdict` (`_FAILED_LOGIN_TRACKER`). It is in-memory only and resets on server restart. It is shared across all routes.

---

## 11. Security Logger

**File:** `security/logger.py` — `class SecurityLogger`

Handles persistent storage of all events in two formats simultaneously.

### Storage files

| File | Format | Purpose |
|---|---|---|
| `outputs/threat_logs.jsonl` | JSON Lines (one object per line) | Primary log, easy to stream and parse |
| `outputs/suspicious_logins.csv` | CSV with header row | Spreadsheet-friendly export |

The `outputs/` directory is created automatically on first run.

### In-memory buffer

All events are also kept in `self._events` (a plain Python list). This list is rebuilt on startup by reading `threat_logs.jsonl`. It is used for all live queries (`get_recent`, `get_stats`, `get_timeline`) to avoid hitting disk on every API call.

### Event schema

```json
{
  "timestamp": "2026-05-13T14:23:01.543210",
  "username":  "admin",
  "ip":        "185.220.101.45",
  "source":    "decoy",
  "valid":     false,
  "risk_score": 85,
  "ml_score":  0.731,
  "ml_label":  "ANOMALY",
  "threat":    "CRITICAL",
  "origin":    "Dark Web Exit Node",
  "ua":        "python-requests/2.28",
  "snapshot":  "outputs/snap_20260513_142301_admin.svg"
}
```

`source` values: `"demo"` (dashboard), `"decoy"` (honeypot), `"simulated"` (attack simulator)

### Snapshot linking

The `snapshot` field is initially `null` in the logged event. After the camera captures a file, `logger.update_last_snapshot(path)` patches the in-memory record (the last event). The JSONL file is **not** retroactively updated — only the in-memory copy is patched for the current session.

---

## 12. Camera Capture System

**File:** `security/camera.py` — `class CameraCapture`

On every intrusion event, a snapshot is generated. The system tries four methods in order, using the first that succeeds:

### Priority chain

**1. OpenCV webcam (`_try_webcam`)**
Opens camera index 0, discards 5 warm-up frames, reads one frame, saves as `.jpg`.
Fails silently if `cv2` is not installed or no webcam is present.

**2. PIL placeholder (`_try_pil`)**
Draws a styled 640×480 `"INTRUDER CAPTURED"` frame with:
- Dark scanline background
- Red radial vignette (intensity scales with risk score)
- Corner L-brackets
- Crosshair with concentric circles
- Alert banner
- Metadata overlay (username, risk %, timestamp)

Saves as `.jpg`. Fails silently if `Pillow` is not installed.

**3. Pure-Python PNG (`_png_placeholder`)**
Generates a valid 640×480 PNG entirely from scratch using only `zlib` and `struct`. Implements the same visual design as the PIL version but with raw pixel manipulation. Produces a `.png` file. No external dependencies.

**4. SVG fallback (`_svg_placeholder`)**
Generates an SVG string. This always succeeds (no dependencies). Produces a `.svg` file displayed natively in browsers.

### File naming

```
outputs/snap_{YYYYMMDD}_{HHMMSS}_{username}.{ext}
outputs/snap_{YYYYMMDD}_{HHMMSS}_{username}.json   ← metadata sidecar
```

Username is sanitised: only alphanumerics, `-`, `_` are kept, truncated to 20 characters.

### Metadata sidecar (`.json`)

Each snapshot has a companion JSON file:
```json
{ "timestamp": "...", "username": "admin", "risk": 85, "file": "outputs/snap_....jpg", "url": "/outputs/snap_....jpg" }
```

### Snapshot listing

`CameraCapture.list_snapshots()` scans `outputs/` for `.json` files starting with `snap_`, loads each, verifies the image file exists, and returns the 30 most recent entries (sorted by filename, which is chronological).

---

## 13. Voice Alert

**File:** `security/voice_alert.py` — `class VoiceAlert`

Fires a non-blocking text-to-speech warning on intrusion events.

```python
voice.warn_async()  # starts a daemon thread; returns immediately
```

The thread calls `pyttsx3.init()`, sets rate 160 wpm and volume 0.9, then speaks:

> *"Warning. Unauthorized access detected. Security team has been notified."*

If `pyttsx3` is not installed or the TTS engine fails for any reason, the exception is caught and silently discarded. Voice is treated as non-critical enhancement.

**Triggered by:** demo login lockout (3rd failed attempt) and all honeypot logins with invalid credentials.

---

## 14. Mobile Notifications (Pushover)

**File:** `notifications/notifier.py` — `class MobileNotifier`

Sends a push notification to a Pushover-configured device when the honeypot is hit.

### Configuration

Set two environment variables before running:

```bash
export PUSHOVER_USER="your_pushover_user_key"
export PUSHOVER_TOKEN="your_app_api_token"
```

If either is empty (the default), `notifier.send()` returns immediately without making any network request.

### Notification format

- **Title:** `🚨 CRITICAL THREAT DETECTED` (or HIGH/MEDIUM/LOW)
- **Body:** Username, risk %, threat level, origin
- **Priority:** 1 (high) for CRITICAL, 0 (normal) for all others
- **Sound:** `siren`

The push is fired in a daemon thread to avoid blocking the request. Uses only `urllib.request` — no third-party HTTP library needed.

---

## 15. Honeypot Design

The honeypot at `/portal` is a deliberately convincing fake corporate login portal styled as **"Nexora Corp — Employee Self-Service Portal"**. Design choices that make it convincing:

- Corporate navy colour scheme (`#1E3A5F`)
- Official-looking topbar with company logo placeholder, department label, live clock
- "Corporate Email / Username" field placeholder (`firstname.lastname@nexora.com`)
- Security notice: *"This portal is monitored by the IT Security team..."*
- Animated loading sequence with fake identity verification steps
- Footer showing encryption and session status indicators

### What happens when someone logs in

1. A simulated two-step verification animation plays (750ms + 550ms delays)
2. A POST is sent to `/portal/login` with the credentials
3. The full `_process()` pipeline runs (ML scoring, risk computation, logging)
4. A snapshot is captured regardless of credentials
5. Voice alert fires and Pushover notification sends (for invalid credentials)
6. **Invalid credentials:** `sl2` shows "⚠ Authentication failed — account may be locked", then redirects to `/alert` with threat data stored in `sessionStorage`
7. **Valid credentials** (`admin`/`Admin@2026` or `sysop`/`Sysop#123`): a green "Login Successful" fullscreen banner appears showing username and session time

### Alert page (`/alert`)

Reads the threat data from `sessionStorage.threat` and renders a dramatic full-screen threat response display with all event metadata including risk score, ML score, origin, and snapshot.

---

## 16. Live Event Stream (SSE)

**Route:** `GET /api/live`

Implements Server-Sent Events (SSE) for real-time dashboard updates.

```
Content-Type: text/event-stream
Cache-Control: no-cache
X-Accel-Buffering: no
```

The generator function maintains a `seen` set of timestamps. Every 2 seconds it checks for new events not in `seen`. If found, it emits a `data:` frame with the new events plus current stats. If not, it emits a heartbeat comment (`: hb`) to keep the TCP connection alive through proxies.

The dashboard subscribes to this stream using the browser's `EventSource` API and updates all counters, the live event table, and snapshot gallery without page reload.

---

## 17. Dataset & Synthetic Data

**File:** `data/login_events.csv` — 1,000 labelled rows
**File:** `data/generate_dataset.py` — regeneration script
**File:** `data/attack_patterns.json` — dataset statistics

### Dataset composition

| Category | Count |
|---|---|
| Normal logins | 700 |
| Brute force attacks | 150 |
| SQL injection attempts | 50 |
| Total | 1,000 |

### CSV columns

`hour_sin`, `hour_cos`, `uname_len`, `pwd_len`, `pwd_entropy`, `uname_risk`, `sql_flag`, `ip_var`, `ua_len`, `weekend`, `label`

`label` is binary: `0` = normal, `1` = attack

### Known attack IPs (from `attack_patterns.json`)

`185.220.101.45`, `94.102.49.180`, `45.33.32.156`, `198.20.69.74`, `92.118.160.10`

### Known attack usernames

`root`, `admin`, `administrator`, `test`, `oracle`, `sa`, `pi`, `guest`

### Synthetic fallback

If `login_events.csv` is missing, `AnomalyDetector._synth()` generates in-memory data:
- 300 normal samples: hour drawn from `Gaussian(10, 3)`, low risk scores, no flags
- 60 attack samples: hour from `{0,1,2,3,4,23}` (off-hours), high risk scores, random SQL/risk flags

---

## 18. Frontend Templates

### `dashboard.html`

The primary interface. Four panels:

1. **Overview** — stat cards (total events, anomalies, critical threats, honeypot hits), threat distribution chart, top origins list, and live event table (auto-updates via SSE)
2. **Intruders** — snapshot gallery with delete buttons (hover to reveal trash icon), bulk "Delete All" option
3. **Demo** — interactive login form with 3-attempt lockout, shows real-time risk scores and ML labels per attempt, displays snapshot thumbnails on failure
4. **Controls** — simulate attack button (⚡), link to open honeypot portal

### `analytics.html`

ML performance dashboard:

- Confusion matrix (TP/TN/FP/FN)
- Precision, recall, F1 score, accuracy
- IF vs LOF model agreement %
- DBSCAN cluster count, silhouette score, noise ratio
- Feature importance bar chart (10 features)
- Score distribution histogram
- 2D cluster scatter plot (first two features: hour_sin vs hour_cos)

### `alert.html`

Full-screen threat response shown after honeypot trigger. Reads `sessionStorage.threat` for:
- Risk score (large radial display)
- ML score and label
- Threat level badge
- Attack origin
- Username
- Snapshot image (if available)
- Timestamp and source label

### `decoy.html`

Described fully in [Section 15](#15-honeypot-design).

### `index.html`

Introductory landing/splash page. Links to the main dashboard.

### `static/js/liquid.js`

Canvas-based animated liquid/blob background effect used across templates for visual atmosphere.

---

## 19. Attack Simulation

**Route:** `POST /api/simulate`

Generates one synthetic attack event:

```python
username = random.choice(["admin","root","test","oracle","sa","pi","postgres","mysql"])
ip       = random.choice(["185.220.101.45","94.102.49.180","45.33.32.156","92.118.160.10"])
password = random.choices("abcdefghijklmnopqrstuvwxyz0123456789!@#", k=9)
```

Passes through the full `_process()` pipeline with `source="simulated"`. User-Agent is hardcoded to `"python-requests/2.28"` to mimic scripted attacks.

A snapshot is captured for every simulated attack. The event is logged and counted in stats. Voice and Pushover are **not** triggered for simulated events — only for real demo lockouts and honeypot hits.

---

## 20. Output Files

All runtime output goes to `outputs/` (created automatically).

| File pattern | Created by | Content |
|---|---|---|
| `threat_logs.jsonl` | `SecurityLogger` | Append-only JSONL event log |
| `suspicious_logins.csv` | `SecurityLogger` | Same events in CSV format |
| `snap_*.jpg` | `CameraCapture` (webcam or PIL) | JPEG intruder snapshot |
| `snap_*.png` | `CameraCapture` (pure Python PNG) | PNG intruder snapshot |
| `snap_*.svg` | `CameraCapture` (SVG fallback) | SVG intruder snapshot |
| `snap_*.json` | `CameraCapture` | Metadata sidecar for each snapshot |

Files can be deleted via the dashboard UI (individual snapshots) or via `DELETE /api/snapshots/<filename>`. The `outputs/` directory itself is never deleted.

---

## 21. Dependencies

### `requirements.txt`

```
flask>=3.0.0
Pillow>=10.0.0      # recommended
# opencv-python     # optional — real webcam
# pyttsx3           # optional — voice alerts
```

### Full dependency map

| Import | Source | Used in |
|---|---|---|
| `flask` | pip required | `app.py` |
| `PIL` (Pillow) | pip recommended | `security/camera.py` |
| `cv2` (opencv-python) | pip optional | `security/camera.py` |
| `pyttsx3` | pip optional | `security/voice_alert.py` |
| `math`, `random`, `csv`, `collections`, `os`, `json`, `struct`, `zlib`, `threading`, `hashlib`, `urllib` | stdlib | Various |

---

## 22. Configuration & Environment Variables

| Variable | Default | Effect |
|---|---|---|
| `PUSHOVER_USER` | `""` | Pushover user key — push notifications disabled if empty |
| `PUSHOVER_TOKEN` | `""` | Pushover app token — push notifications disabled if empty |

Flask config in `app.py`:

| Setting | Value |
|---|---|
| `app.secret_key` | `"sentinel-open-v4"` |
| `debug` | `True` |
| `port` | `5000` |
| `threaded` | `True` |

---

## 23. Known Design Decisions & Caveats

| Area | Decision | Implication |
|---|---|---|
| No authentication on `/` | Dashboard is open by design | Anyone on the network can see all events and snapshots |
| In-memory failed login tracker | Resets on restart | Brute-force counter does not persist across server restarts |
| Attack origin is randomised | Not real GeoIP | Labels like "Moscow, Russia" are illustrative, not accurate |
| `snapshot` field in JSONL | Not retroactively patched | Log file will show `null` for snapshot even after capture; only in-memory copy is updated |
| ML model agreement | IF and LOF agree ~70–80% | LOF is slower (O(n²)) so it runs on a 40-point subsample at query time |
| DBSCAN silhouette | Uses random sample of 100 | Approximation — may vary between calls on the same data |
| SSE `seen` set | Grows unbounded | Long-running streams accumulate timestamps in memory; not an issue at demo scale |
| `RETRAIN_FREQ = 30` | Retrains every 30 events | Low-traffic installs may take a while to first retrain beyond the bootstrap data |
| Secret key hardcoded | `"sentinel-open-v4"` | Change this before any production or internet-facing deployment |

---

## 24. Full Threat Processing Diagram

```
Browser / Client
      │
      │  POST /api/demo-login
      │  POST /portal/login
      │  POST /api/simulate
      │
      ▼
┌─────────────────────────────────────────────────────────┐
│                     app.py  _process()                  │
│                                                         │
│  username, password, ip, ua, source                     │
│         │                                               │
│         ▼                                               │
│  FeatureExtractor.extract()                             │
│  → [sin, cos, uname_len, pwd_len, entropy,              │
│     uname_risk, sql_flag, ip_var, ua_len, weekend]      │
│         │                                               │
│         ▼                                               │
│  WelfordScaler.scale()  ← live mean/variance            │
│  → normalised 10-dim vector                             │
│         │                          ┌──────────────────┐ │
│         ├─────────────────────────▶│  IsolationForest │ │
│         │                          │  80 trees        │ │
│         │                          │  → ml_score      │ │
│         │                          │  → ml_label      │ │
│         │                          └──────────────────┘ │
│         │                                               │
│         ▼                                               │
│  ThreatEngine.compute_risk()                            │
│  fails×15 + username_risk×20 + ml_score×35 + noise     │
│  → risk_score (0–100)                                   │
│         │                                               │
│         ▼                                               │
│  ThreatEngine.classify_threat()                         │
│  → "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"               │
│         │                                               │
│         ▼                                               │
│  SecurityLogger.log()                                   │
│  → threat_logs.jsonl  +  suspicious_logins.csv          │
│         │                                               │
│         ▼                                               │
│  AnomalyDetector.update()                               │
│  → rolling buffer (max 600)                             │
│  → retrain every 30 events                              │
└─────────────────────────────────────────────────────────┘
      │
      │  (route handler continues)
      │
      ├── CameraCapture.capture()
      │     webcam → PIL → pure-PNG → SVG
      │     → outputs/snap_*.{jpg,png,svg} + .json
      │
      ├── VoiceAlert.warn_async()     [daemon thread]
      │     pyttsx3 TTS warning
      │
      ├── MobileNotifier.send()       [daemon thread]
      │     Pushover HTTP POST
      │
      └── JSON response to client
            ↓
        Browser updates dashboard via SSE (/api/live)
```

---

*Documentation generated for SENTINEL IDS v4 — updated build including honeypot credentials and success-state response.*
