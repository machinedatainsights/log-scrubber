#!/usr/bin/env python3
"""
Log Scrubber — Standalone CLI Utility
Extracted from the CIM Automation Suite (CAS)
Machine Data Insights Inc. | machinedatainsights.com

Scrubs PII and sensitive data from Splunk field-value exports and log samples
using the same algorithm and log_scrubbing_config.csv as the CAS web interface.

Usage:
    # Scrub a fieldsummary CSV export
    python log_scrubber.py fieldsummary splunk_web_access_fields.csv

    # Scrub a log samples file (CSV with _raw column, or raw text)
    python log_scrubber.py samples splunk_web_access_samples.csv

    # Specify a custom scrubbing config
    python log_scrubber.py fieldsummary fields.csv --config my_scrubbing_config.csv

    # Specify output path
    python log_scrubber.py samples events.csv --output scrubbed_events.csv

Splunk SPL for exporting field values (run in Splunk Web → export as CSV):
    search index=<idx> sourcetype="<st>" earliest=-7d@d latest=now
    | fieldsummary maxvals=5
    | search field!="_*" AND field!="date_*" AND field!="linecount"
      AND field!="punct" AND field!="timestartpos" AND field!="timeendpos"
      AND field!="splunk_server_group"

Splunk SPL for exporting log samples (run in Splunk Web → export as CSV):
    search index=<idx> sourcetype="<st>" earliest=-1d@d latest=now
    | dedup punct | head 20

Version: 1.0.0
Copyright (c) 2026 Machine Data Insights Inc.
https://machinedatainsights.com
"""

import argparse
import csv
import json
import os
import random
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Tuple


# ============================================================================
# Config Parser
# ============================================================================

def parse_scrubbing_config(config_path: str) -> Tuple[list, list]:
    """
    Parse scrubbing config CSV into text rules and JSON field rules.

    Returns:
        (text_rules, json_field_rules)
        text_rules:       [(search_term, mode, replacement_values), ...]
        json_field_rules: [(field_name, mode, replacement_values), ...]

    Config formats:
        # Text substitution
        search_term,single,replacement
        search_term,random,"val1,val2,val3"

        # JSON field scrubbing
        @json,field_name,replacement                    (implicit single)
        @json,field_name,single,replacement
        @json,field_name,random,"val1,val2,val3"
    """
    text_rules = []
    json_field_rules = []

    if not config_path or not os.path.exists(config_path):
        return text_rules, json_field_rules

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row or not row[0].strip() or row[0].strip().startswith("#"):
                    continue
                if len(row) < 3:
                    continue

                first = row[0].strip()

                if first.lower() == "@json":
                    field_name = row[1].strip()
                    if not field_name:
                        continue
                    if len(row) >= 4 and row[2].strip().lower() in ("single", "random"):
                        mode = row[2].strip().lower()
                        replacement_values = row[3].strip()
                        json_field_rules.append((field_name, mode, replacement_values))
                    else:
                        replacement = row[2].strip()
                        json_field_rules.append((field_name, "single", replacement))
                else:
                    # Text rule: 2-col (search,replacement) or 3-col (search,mode,replacement)
                    if len(row) == 2:
                        text_rules.append((first, "single", row[1].strip()))
                    else:
                        mode = row[1].strip().lower()
                        if mode not in ("single", "random"):
                            # Treat as 2-col: search_term,replacement
                            text_rules.append((first, "single", row[1].strip()))
                        else:
                            text_rules.append((first, mode, row[2].strip()))
    except Exception as e:
        print(f"  ⚠ Warning: Could not parse config '{config_path}': {e}", file=sys.stderr)

    return text_rules, json_field_rules


# ============================================================================
# Replacement Resolver
# ============================================================================

def resolve_replacement(mode: str, replacement_values: str) -> str:
    """Resolve a replacement value based on mode (single or random)."""
    if mode == "random":
        choices = [v.strip() for v in replacement_values.split(",") if v.strip()]
        return random.choice(choices) if choices else replacement_values
    return replacement_values


# ============================================================================
# JSON Scrubbing
# ============================================================================

def scrub_json_obj(obj, field_rules: list):
    """
    Recursively walk a parsed JSON object and replace values for matching
    field names at any nesting depth.

    Handles two patterns:
      1. Direct field match:  {"accountId": "123"} — replaces "123"
      2. Key-value pair:      {"key": "Owner", "value": "admin"} — replaces "admin"
         Common in AWS tags, Azure tags, GCP labels, CloudTrail requestParameters.
    """
    if isinstance(obj, dict):
        # Pattern 2: Key-value pair detection
        kv_key_field = None
        kv_val_field = None

        keys_lower_map = {k.lower(): k for k in obj}

        for candidate in ("key", "name"):
            if candidate in keys_lower_map:
                kv_key_field = keys_lower_map[candidate]
                break

        for candidate in ("value",):
            if candidate in keys_lower_map:
                kv_val_field = keys_lower_map[candidate]
                break

        if (kv_key_field is not None and kv_val_field is not None
                and isinstance(obj[kv_key_field], str)):
            tag_name = obj[kv_key_field]
            for rule in field_rules:
                fn = rule[0]
                if tag_name == fn:
                    mode = rule[1] if len(rule) > 2 else "single"
                    repl_vals = rule[2] if len(rule) > 2 else rule[1]
                    obj[kv_val_field] = resolve_replacement(mode, repl_vals)
                    for k in obj:
                        if k != kv_val_field:
                            obj[k] = scrub_json_obj(obj[k], field_rules)
                    return obj

        # Pattern 1: Direct field match
        for key in obj:
            matched = False
            for rule in field_rules:
                fn = rule[0]
                if key == fn:
                    mode = rule[1] if len(rule) > 2 else "single"
                    repl_vals = rule[2] if len(rule) > 2 else rule[1]
                    obj[key] = resolve_replacement(mode, repl_vals)
                    matched = True
                    break
            if not matched:
                obj[key] = scrub_json_obj(obj[key], field_rules)
        return obj
    elif isinstance(obj, list):
        return [scrub_json_obj(item, field_rules) for item in obj]
    else:
        return obj


def apply_json_field_scrubbing(text: str, field_rules: list) -> str:
    """
    Apply JSON field scrubbing to a text string.

    Handles:
      1. Entire string is a JSON object/array
      2. JSON embedded after a syslog-style prefix
      3. Key-value pair regex fallback
      4. Direct field regex fallback
    """
    if not field_rules or not text:
        return text

    stripped = text.strip()

    def _try_json_parse_and_scrub(json_str):
        try:
            obj = json.loads(json_str)
            scrub_json_obj(obj, field_rules)
            compact = "\n" not in json_str
            return json.dumps(obj, separators=(",", ":") if compact
                              else (",", ": "), ensure_ascii=False)
        except (json.JSONDecodeError, ValueError):
            pass

        for trim in [",", "},", "}],", "]},", "\n", " "]:
            if json_str.rstrip().endswith(trim.rstrip()):
                candidate = json_str.rstrip()
                while candidate and not candidate.endswith("}") and not candidate.endswith("]"):
                    candidate = candidate[:-1]
                if candidate:
                    try:
                        obj = json.loads(candidate)
                        scrub_json_obj(obj, field_rules)
                        compact = "\n" not in json_str
                        suffix = json_str[len(candidate):]
                        return json.dumps(obj, separators=(",", ":") if compact
                                          else (",", ": "), ensure_ascii=False) + suffix
                    except (json.JSONDecodeError, ValueError):
                        pass
        return None

    # Case 1: Entire string is JSON
    if stripped.startswith("{") or stripped.startswith("["):
        result = _try_json_parse_and_scrub(stripped)
        if result is not None:
            return result

    # Case 2: JSON embedded after prefix
    brace_idx = text.find("{")
    if brace_idx > 0:
        prefix = text[:brace_idx]
        json_part = text[brace_idx:]
        result = _try_json_parse_and_scrub(json_part)
        if result is not None:
            return prefix + result

    # Regex fallback
    rule_map = {}
    for rule in field_rules:
        fn = rule[0]
        mode = rule[1] if len(rule) > 2 else "single"
        repl_vals = rule[2] if len(rule) > 2 else rule[1]
        rule_map[fn] = (mode, repl_vals)

    # Case 3: Key-value pair patterns
    def _kv_replacer_dq(m):
        tag_name = m.group(1)
        if tag_name in rule_map:
            mode, repl_vals = rule_map[tag_name]
            replacement = resolve_replacement(mode, repl_vals)
            return m.group(0).replace(m.group(2), replacement)
        return m.group(0)

    text = re.sub(
        r'"(?:key|Key|name|Name)"\s*:\s*"([^"]*)"\s*,\s*"(?:value|Value)"\s*:\s*"([^"]*)"',
        _kv_replacer_dq, text
    )

    def _kv_replacer_sq(m):
        tag_name = m.group(1)
        if tag_name in rule_map:
            mode, repl_vals = rule_map[tag_name]
            replacement = resolve_replacement(mode, repl_vals)
            return m.group(0).replace(m.group(2), replacement)
        return m.group(0)

    text = re.sub(
        r"'(?:key|Key|name|Name)'\s*:\s*'([^']*)'\s*,\s*'(?:value|Value)'\s*:\s*'([^']*)'",
        _kv_replacer_sq, text
    )

    # Case 4: Direct field patterns
    for fn, (mode, repl_vals) in rule_map.items():
        replacement = resolve_replacement(mode, repl_vals)
        pattern = r'("' + re.escape(fn) + r'")\s*:\s*"[^"]*"'
        repl = r'\1: "' + replacement.replace("\\", "\\\\") + '"'
        text = re.sub(pattern, repl, text)
        pattern_sq = r"('" + re.escape(fn) + r"')\s*:\s*'[^']*'"
        repl_sq = r"\1: '" + replacement.replace("\\", "\\\\") + "'"
        text = re.sub(pattern_sq, repl_sq, text)

    return text


# ============================================================================
# Fieldsummary-aware Value Replacement
# ============================================================================

def scrub_fieldsummary_values(raw_values: str, replacement: str) -> str:
    """
    Replace the 'value' entries in Splunk fieldsummary format while
    preserving structure and counts.

    Input:  {'value': '736350333106', 'count': 446}, {'value': '113968', 'count': 6}
    Output: {'value': 'REDACTED', 'count': 446}, {'value': 'REDACTED', 'count': 6}
    """
    result = raw_values
    result = re.sub(
        r"('value':\s*')([^']*?)(')",
        lambda m: m.group(1) + replacement + m.group(3),
        result,
    )
    result = re.sub(
        r'("value":\s*")([^"]*?)(")',
        lambda m: m.group(1) + replacement + m.group(3),
        result,
    )
    return result


# ============================================================================
# Core Scrubbing Functions
# ============================================================================

def scrub_text(text: str, text_rules: list, json_field_rules: list,
               field_name: str = None) -> str:
    """
    Scrub a single text value using the full CAS scrubbing pipeline:

    1. If field_name matches a @json rule, do fieldsummary-aware replacement
    2. Built-in regex patterns (IP, email, FQDN, UNC, DOMAIN\\user, MAC)
    3. Custom text substitution rules from config
    4. JSON field-level scrubbing (parsed JSON or regex fallback)
    """
    if not text or not text.strip():
        return text

    scrubbed = text

    # @json field-name shortcut (for fieldsummary data)
    json_field_map = {fn: (mode, repl) for fn, mode, repl in json_field_rules}
    if field_name and field_name in json_field_map:
        mode, repl_vals = json_field_map[field_name]
        replacement = resolve_replacement(mode, repl_vals)
        return scrub_fieldsummary_values(scrubbed, replacement)

    # Built-in regex patterns
    scrubbed = re.sub(
        r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "10.0.0.x", scrubbed
    )
    scrubbed = re.sub(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "user@example.com", scrubbed,
    )
    scrubbed = re.sub(
        r"\b[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+\.(com|net|org|io|local|internal)\b",
        "host.example.com", scrubbed,
    )
    scrubbed = re.sub(
        r"\\\\[a-zA-Z0-9._-]+\\[a-zA-Z0-9._$-]+",
        r"\\\\SERVER\\SHARE", scrubbed,
    )
    scrubbed = re.sub(
        r"\b[A-Z][A-Z0-9_-]+\\[a-zA-Z0-9._-]+\b",
        r"DOMAIN\\user", scrubbed,
    )
    scrubbed = re.sub(
        r"\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
        "00:00:00:00:00:00", scrubbed,
    )

    # Custom text substitution rules
    for search_term, mode, replacement_values in text_rules:
        if search_term in scrubbed:
            if mode == "random":
                choices = [v.strip() for v in replacement_values.split(",") if v.strip()]
                replacement = random.choice(choices) if choices else replacement_values
            else:
                replacement = replacement_values
            scrubbed = scrubbed.replace(search_term, replacement)

    # JSON field scrubbing
    if json_field_rules:
        scrubbed = apply_json_field_scrubbing(scrubbed, json_field_rules)

    return scrubbed


# ============================================================================
# File Processors
# ============================================================================

def scrub_fieldsummary_csv(input_path: str, output_path: str,
                           text_rules: list, json_field_rules: list) -> dict:
    """
    Scrub a Splunk fieldsummary CSV export.

    Expected columns from Splunk: field, count, distinct_count, is_exact,
    max, mean, min, numeric_count, stdev, values

    The 'values' column contains fieldsummary-formatted sample values like:
        [{"value":"192.168.1.1","count":5},{"value":"admin@corp.com","count":3}]

    Adds a 'scrubbed_values' column with the scrubbed version.
    """
    stats = {"rows": 0, "scrubbed": 0, "skipped": 0}

    # Increase CSV field size limit for large JSON events
    csv.field_size_limit(10 * 1024 * 1024)

    with open(input_path, "r", encoding="utf-8", errors="replace") as fin:
        reader = csv.DictReader(fin)
        if not reader.fieldnames:
            print(f"  ⚠ Empty or invalid CSV: {input_path}", file=sys.stderr)
            return stats

        # Determine the values column name
        values_col = None
        for candidate in ("values", "Values", "VALUES"):
            if candidate in reader.fieldnames:
                values_col = candidate
                break

        # Determine the field name column
        field_col = None
        for candidate in ("field", "Field", "FIELD", "field_name"):
            if candidate in reader.fieldnames:
                field_col = candidate
                break

        # Build output fieldnames with scrubbed_values added after values
        out_fields = list(reader.fieldnames)
        if values_col and "scrubbed_values" not in out_fields:
            idx = out_fields.index(values_col) + 1
            out_fields.insert(idx, "scrubbed_values")

        with open(output_path, "w", encoding="utf-8", newline="") as fout:
            writer = csv.DictWriter(fout, fieldnames=out_fields, extrasaction="ignore")
            writer.writeheader()

            for row in reader:
                stats["rows"] += 1
                raw_values = row.get(values_col, "") if values_col else ""
                field_name = row.get(field_col, "") if field_col else None

                if raw_values.strip():
                    scrubbed = scrub_text(raw_values, text_rules, json_field_rules,
                                          field_name=field_name)
                    row["scrubbed_values"] = scrubbed
                    stats["scrubbed"] += 1
                else:
                    row["scrubbed_values"] = ""
                    stats["skipped"] += 1

                writer.writerow(row)

    return stats


def scrub_samples_csv(input_path: str, output_path: str,
                      text_rules: list, json_field_rules: list) -> dict:
    """
    Scrub a log samples CSV export from Splunk.

    Handles two formats:
      1. CSV with _raw column (from Splunk CSV export)
      2. Plain text file (one event per line or multi-line JSON)
    """
    stats = {"events": 0, "scrubbed": 0}

    csv.field_size_limit(10 * 1024 * 1024)

    # Detect format: try CSV first
    is_csv = False
    try:
        with open(input_path, "r", encoding="utf-8", errors="replace") as f:
            sample = f.read(4096)
            sniffer = csv.Sniffer()
            try:
                sniffer.sniff(sample)
                # Check if it has a _raw header
                f.seek(0)
                reader = csv.DictReader(f)
                if reader.fieldnames and "_raw" in reader.fieldnames:
                    is_csv = True
            except csv.Error:
                pass
    except Exception:
        pass

    if is_csv:
        return _scrub_samples_csv_format(input_path, output_path,
                                          text_rules, json_field_rules)
    else:
        return _scrub_samples_text_format(input_path, output_path,
                                           text_rules, json_field_rules)


def _scrub_samples_csv_format(input_path: str, output_path: str,
                               text_rules: list, json_field_rules: list) -> dict:
    """Scrub CSV-format log samples (with _raw column)."""
    stats = {"events": 0, "scrubbed": 0}

    with open(input_path, "r", encoding="utf-8", errors="replace") as fin:
        reader = csv.DictReader(fin)

        with open(output_path, "w", encoding="utf-8", newline="") as fout:
            writer = csv.DictWriter(fout, fieldnames=reader.fieldnames, extrasaction="ignore")
            writer.writeheader()

            for row in reader:
                stats["events"] += 1
                raw = row.get("_raw", "")
                if raw.strip():
                    row["_raw"] = scrub_text(raw, text_rules, json_field_rules)
                    stats["scrubbed"] += 1
                writer.writerow(row)

    return stats


def _scrub_samples_text_format(input_path: str, output_path: str,
                                text_rules: list, json_field_rules: list) -> dict:
    """
    Scrub plain-text log samples (one event per line, or multi-line JSON).

    Handles:
      - Single-line events (syslog, key=value, etc.)
      - Multi-line JSON events (detects { on one line, accumulates until matching })
      - JSONL (one JSON object per line)
    """
    stats = {"events": 0, "scrubbed": 0}

    with open(input_path, "r", encoding="utf-8", errors="replace") as fin:
        content = fin.read()

    # Try to detect JSONL or multi-line JSON
    lines = content.splitlines(keepends=True)
    events = []
    json_buffer = []
    brace_depth = 0

    for line in lines:
        stripped = line.strip()

        # Track JSON brace depth for multi-line events
        if json_buffer or (stripped.startswith("{") and brace_depth == 0):
            json_buffer.append(line)
            brace_depth += stripped.count("{") - stripped.count("}")
            if brace_depth <= 0:
                events.append("".join(json_buffer))
                json_buffer = []
                brace_depth = 0
        elif stripped:
            events.append(line)

    # Flush any remaining buffer
    if json_buffer:
        events.append("".join(json_buffer))

    scrubbed_events = []
    for event in events:
        stats["events"] += 1
        scrubbed = scrub_text(event, text_rules, json_field_rules)
        scrubbed_events.append(scrubbed)
        stats["scrubbed"] += 1

    with open(output_path, "w", encoding="utf-8") as fout:
        fout.write("".join(scrubbed_events))

    return stats


# ============================================================================
# Output Path Builder
# ============================================================================

def build_output_path(input_path: str, explicit_output: str = None) -> str:
    """Build output path: explicit path, or input_scrubbed_<timestamp>.ext"""
    if explicit_output:
        return explicit_output

    p = Path(input_path)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return str(p.parent / f"{p.stem}_scrubbed_{timestamp}{p.suffix}")


# ============================================================================
# CLI
# ============================================================================

def find_default_config() -> str:
    """Look for log_scrubbing_config.csv in common locations."""
    candidates = [
        Path("log_scrubbing_config.csv"),
        Path("data/log_scrubbing_config.csv"),
        Path(__file__).parent / "log_scrubbing_config.csv",
        Path(__file__).parent / "data" / "log_scrubbing_config.csv",
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Log Scrubber — Scrub PII from Splunk field-value exports and log samples",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s fieldsummary my_fields.csv
  %(prog)s fieldsummary my_fields.csv --config custom_rules.csv
  %(prog)s samples my_events.csv
  %(prog)s samples raw_logs.txt --output scrubbed_logs.txt
  %(prog)s samples guardduty_events.json --config aws_scrub_rules.csv

Export SPL for fieldsummary (Splunk Web → Export → CSV):
  search index=<idx> sourcetype="<st>" earliest=-7d@d latest=now
  | fieldsummary maxvals=5
  | search field!="_*" AND field!="date_*" AND field!="linecount"
    AND field!="punct" AND field!="timestartpos" AND field!="timeendpos"
    AND field!="splunk_server_group"

Export SPL for log samples (Splunk Web → Export → CSV):
  search index=<idx> sourcetype="<st>" earliest=-1d@d latest=now
  | dedup punct | head 20
        """,
    )

    parser.add_argument(
        "mode",
        choices=["fieldsummary", "samples"],
        help="Type of data to scrub: 'fieldsummary' for field-value CSV, 'samples' for log events",
    )
    parser.add_argument(
        "input",
        help="Input file path (CSV from Splunk export, or raw text for samples)",
    )
    parser.add_argument(
        "--config", "-c",
        help="Path to log_scrubbing_config.csv (auto-detected if not specified)",
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file path (default: <input>_scrubbed_<timestamp>.<ext>)",
    )
    parser.add_argument(
        "--no-builtin",
        action="store_true",
        help="Disable built-in regex patterns (IP, email, hostname, etc.)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without writing output",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress informational output",
    )

    args = parser.parse_args()

    # Validate input
    if not os.path.exists(args.input):
        print(f"Error: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    # Find config
    config_path = args.config or find_default_config()

    # Parse config
    text_rules, json_field_rules = [], []
    if config_path and os.path.exists(config_path):
        text_rules, json_field_rules = parse_scrubbing_config(config_path)
        if not args.quiet:
            print(f"  Config: {config_path}")
            print(f"    Text rules: {len(text_rules)}")
            print(f"    @json rules: {len(json_field_rules)}")
    else:
        if not args.quiet:
            print("  Config: None found (using built-in regex patterns only)")

    # Build output path
    output_path = build_output_path(args.input, args.output)

    if not args.quiet:
        print(f"  Input:  {args.input}")
        print(f"  Output: {output_path}")
        print(f"  Mode:   {args.mode}")
        print()

    if args.dry_run:
        print("  [DRY RUN] No output written.")
        sys.exit(0)

    # Process
    if args.mode == "fieldsummary":
        stats = scrub_fieldsummary_csv(args.input, output_path,
                                        text_rules, json_field_rules)
        if not args.quiet:
            print(f"  ✅ Scrubbed {stats['scrubbed']}/{stats['rows']} fields")
            print(f"     Skipped {stats['skipped']} empty fields")
    else:
        stats = scrub_samples_csv(args.input, output_path,
                                   text_rules, json_field_rules)
        if not args.quiet:
            print(f"  ✅ Scrubbed {stats['scrubbed']}/{stats['events']} events")

    if not args.quiet:
        print(f"  📄 Output: {output_path}")


if __name__ == "__main__":
    print()
    print("═══════════════════════════════════════════════════")
    print("  Log Scrubber v1.0.0")
    print("  CIM Automation Suite — Machine Data Insights")
    print("  machinedatainsights.com")
    print("═══════════════════════════════════════════════════")
    print()
    main()
    print()
