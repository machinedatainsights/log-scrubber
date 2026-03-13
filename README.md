# Log Scrubber — User Guide

`log_scrubber.py` is a standalone command-line utility for scrubbing PII and sensitive data from Splunk field-value exports and log samples. Uses the same scrubbing algorithm and configuration format as the CIM Automation Suite (CAS) web interface.

**No dependencies** beyond Python 3.9+ standard library.

## Quick Start

```
log_scrubber/
├── log_scrubber.py
├── log_scrubbing_config.csv    ← place your config here
└── LOG_SCRUBBER_GUIDE.md
```

```bash
# Scrub a fieldsummary export (outputs scrubbed values only)
python log_scrubber.py fieldsummary my_fields.csv

# Scrub a fieldsummary export (include raw values for comparison)
python log_scrubber.py fieldsummary my_fields.csv --include-raw

# Scrub log samples
python log_scrubber.py samples my_events.csv
```

Output is written to `my_fields_scrubbed_20260227_103045.csv` (auto-timestamped).

## Output Format

### Fieldsummary Mode

By default, the output contains **scrubbed values only** — the raw values column is removed so the output is safe to share:

```
Field Name, Scrubbed Values, Count, Distinct Count
```

Use `--include-raw` to keep the original raw values alongside the scrubbed values (useful for reviewing what was changed):

```
Field Name, Raw Values, Scrubbed Values, Count, Distinct Count
```

### Samples Mode

Log sample events are scrubbed in place — the output file contains only scrubbed events.

## Step-by-Step Workflow

### 1. Export Field Values from Splunk Web

Run this SPL in Splunk Web (adjust index, sourcetype, and time range):

```spl
index=<your_index> sourcetype="<your_sourcetype>" earliest=-7d@d latest=now
| fieldsummary maxvals=5
| search field!="_*" AND field!="date_*" AND field!="linecount"
  AND field!="punct" AND field!="timestartpos" AND field!="timeendpos"
  AND field!="splunk_server_group"
```

Click **Export** → choose **CSV** → save the file (e.g., `guardduty_fields.csv`).

### 2. Export Log Samples from Splunk Web

```spl
index=<your_index> sourcetype="<your_sourcetype>" earliest=-1d@d latest=now
| dedup punct | head 20
```

Click **Export** → choose **CSV** → save the file (e.g., `guardduty_samples.csv`).

Alternatively, you can copy/paste raw events into a plain `.txt` file (one event per line). The scrubber auto-detects the format.

### 3. Scrub the Exports

```bash
python log_scrubber.py fieldsummary guardduty_fields.csv
python log_scrubber.py samples guardduty_samples.csv
```

### 4. Review and Send

Check the `*_scrubbed_*` output files to verify sensitive data was replaced, then email the scrubbed files for processing.

## Configuration

### Config File Location

The scrubber automatically looks for `log_scrubbing_config.csv` in these locations (first match wins):

1. Current working directory: `./log_scrubbing_config.csv`
2. Data subdirectory: `./data/log_scrubbing_config.csv`
3. Same directory as the script: `<script_dir>/log_scrubbing_config.csv`
4. Data subdirectory of script: `<script_dir>/data/log_scrubbing_config.csv`

The simplest approach is to **place the config file in the same folder as `log_scrubber.py`**.

You can also specify a config explicitly with `--config`:

```bash
python log_scrubber.py fieldsummary fields.csv --config /path/to/my_rules.csv
```

### Built-in Scrubbing (Always Active)

Even without a config file, the scrubber applies these regex patterns automatically:

| Pattern | Replacement |
|---------|-------------|
| IP addresses (`192.168.1.50`) | `10.0.0.x` |
| AWS ip- hostnames (`ip-10-50-26-117`) | `ip-10-0-0-x` |
| Email addresses (`admin@corp.com`) | `user@example.com` |
| FQDN hostnames (`server01.company.com`) | `host.example.com` |
| UNC paths (`\\server\share`) | `\\SERVER\SHARE` |
| Domain usernames (`CORP\jsmith`) | `DOMAIN\user` |
| MAC addresses (`00:1A:2B:3C:4D:5E`) | `00:00:00:00:00:00` |

### Config File Format

The config file is a CSV with three types of rules:

**Text substitution** — replaces literal strings anywhere in the data:

```csv
# Simple replacement
sensitive-hostname,single,REDACTED_HOST

# Random replacement (picks one each time)
my-secret-domain.com,random,"example1.com,example2.com,example3.com"

# Two-column shorthand (implicit single mode)
my-company.com,example.com
```

**JSON field rules** (`@json` prefix) — targets specific field names at any nesting depth in JSON data:

```csv
@json,accessKeyId,REDACTED_KEY
@json,accountId,random,"000000000001,000000000002,000000000003"
@json,userName,REDACTED_USER
```

**Key-value tag matching** — handles AWS/Azure/GCP tag structures like `{"key": "Owner", "value": "admin@corp.com"}`:

```csv
# Use the tag's key name (not "key" itself)
@json,Owner,random,"user_a@example.com,user_b@example.com"
@json,Environment,REDACTED_ENV
```

Lines starting with `#` are treated as comments.

### Example Config File

```csv
# === Text Substitution Rules ===
ns2.com,single,example.com
sapns2,single,examplecorp
my-splunk-server,single,splunk-host

# === JSON Field Rules ===
@json,accessKeyId,REDACTED_KEY
@json,accountId,random,"000000000001,000000000002,000000000003"
@json,userName,REDACTED_USER
@json,sourceIPAddress,10.0.0.x
@json,Owner,random,"user_a@example.com,user_b@example.com"
@json,Name,REDACTED_NAME
@json,Environment,random,"dev,staging,prod"
```

## Command Reference

```
usage: log_scrubber.py [-h] [--config CONFIG] [--output OUTPUT]
                       [--include-raw] [--dry-run] [--quiet]
                       {fieldsummary,samples} input
```

| Argument | Description |
|----------|-------------|
| `fieldsummary` | Scrub a Splunk fieldsummary CSV export |
| `samples` | Scrub log sample events (CSV with `_raw` column, or plain text) |
| `input` | Input file path |
| `--config`, `-c` | Path to scrubbing config CSV (auto-detected if not specified) |
| `--output`, `-o` | Output file path (default: `<input>_scrubbed_<timestamp>.<ext>`) |
| `--include-raw` | Include the original raw values column in fieldsummary output (default: scrubbed only) |
| `--dry-run` | Show what would be done without writing output |
| `--quiet`, `-q` | Suppress informational output |

## Supported Input Formats

### Fieldsummary Mode

Accepts two CSV formats (auto-detected):

1. **Splunk fieldsummary export** — columns: `field`, `count`, `distinct_count`, `values`, etc.
2. **CAS web UI export** — columns: `Field Name`, `Raw Values`, `Scrubbed Values`, `Count`, `Distinct Count`

Both formats are handled automatically. Output column headers are normalized to `Field Name` and `Scrubbed Values` regardless of input format.

### Samples Mode

Handles three formats (auto-detected):

1. **CSV with `_raw` column** — standard Splunk CSV export. The `_raw` column is scrubbed in place.
2. **Plain text** — one event per line (syslog, key=value, etc.)
3. **JSON / JSONL** — single-line or multi-line JSON events. Brace depth tracking handles multi-line JSON objects that span multiple lines.

## Tips

**Use the same config as the CAS web interface.** If you already have a `log_scrubbing_config.csv` for your CAS project, copy it alongside `log_scrubber.py` — the format is identical.

**Review output before sending.** Automated scrubbing handles known patterns, but always spot-check the output for any environment-specific data the rules might have missed.

**Large JSON events (GuardDuty, CloudTrail, etc.)** are handled natively — the scrubber parses JSON at any nesting depth and applies `@json` rules recursively, including AWS/Azure/GCP tag structures.

**Add rules incrementally.** Start with the built-in regex patterns, review the output, then add `@json` and text rules to the config for anything that slipped through.

---

## Version History

### v1.0.0 (Original)
- 03/13/2026
- Initial adaptation from the CIM Normalization Automation Suite (CAS)

---

**Machine Data Insights Inc. *"There's Gold In That Data!"™***  
<a href="https://machinedatainsights.com" target="_blank">machinedatainsights.com</a>
