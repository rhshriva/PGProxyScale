#!/usr/bin/env python3
"""Extract and classify the PostgreSQL GUC surface for PG 14-18.

Produces the evidence behind docs/architecture/session-state-taxonomy.md.

    cd spikes/s2 && python3 extract.py

Downloads the authoritative GUC tables from the PostgreSQL source tree:
  PG 14, 15  -> src/backend/utils/misc/guc.c          (tables lived here before PG 16)
  PG 16-18   -> src/backend/utils/misc/guc_tables.c   (split out in PG 16)

Outputs:
  gucs.json                   full per-version dump: name -> [context, category, flags]
  userset-guc-inventory.tsv   PG18 client-settable GUCs with our classification

The .c files are re-downloadable and are gitignored.
"""
import collections
import json
import os
import re
import subprocess
import sys

VERSIONS = (14, 15, 16, 17, 18)
RAW = "https://raw.githubusercontent.com/postgres/postgres/REL_{v}_STABLE/src/backend/utils/misc/{f}"

# `{"name", PGC_CONTEXT, CATEGORY,` starts a GUC definition.
ENTRY = re.compile(r'^\s*\{"([^"]+)",\s*(PGC_\w+),\s*(\w+),')

# GUCs that change how SQL text is parsed or how values are rendered. The proxy's own
# parser must mirror these or it will mis-tokenise the client's statements.
PARSER_AFFECTING = {
    "standard_conforming_strings", "backslash_quote", "escape_string_warning",
    "client_encoding", "DateStyle", "IntervalStyle", "bytea_output",
    "extra_float_digits", "default_text_search_config",
}

# Substrings that mark a GUC as planner-relevant: it can change plan selection, so it
# must be part of any prepared-statement cache key.
PLANNER_HINTS = (
    "enable_", "_cost", "geqo", "collapse_limit", "cursor_tuple_fraction",
    "default_statistics_target", "effective_cache_size", "work_mem",
    "random_page_cost", "min_parallel", "parallel_setup", "jit", "plan_cache_mode",
    "recursive_worktable_factor", "constraint_exclusion",
    "default_table_access_method",
)


def source_for(version):
    return "guc.c" if version < 16 else "guc_tables.c"


def fetch(version):
    fname = source_for(version)
    local = f"guc_tables_pg{version}.c"
    if not os.path.exists(local) or os.path.getsize(local) < 10_000:
        url = RAW.format(v=version, f=fname)
        print(f"  downloading PG{version} {fname}", file=sys.stderr)
        subprocess.run(["curl", "-sS", "--max-time", "60", "-o", local, url], check=True)
    return local


def parse(path):
    out = {}
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    i = 0
    while i < len(lines):
        m = ENTRY.match(lines[i])
        if not m:
            i += 1
            continue
        name, ctx, cat = m.groups()
        buf, j = [lines[i]], i
        # The entry ends at the line closing the inner struct.
        while j < len(lines) and "}," not in lines[j]:
            j += 1
            buf.append(lines[j])
            if j - i > 12:
                break
        out[name] = (ctx, cat, set(re.findall(r"GUC_[A-Z_0-9]+", " ".join(buf))))
        i = j + 1
    return out


def main():
    data = {v: parse(fetch(v)) for v in VERSIONS}

    print("GUC entries per version:", {v: len(d) for v, d in data.items()})
    reported = {
        v: {n for n, (_, _, f) in d.items() if "GUC_REPORT" in f} for v, d in data.items()
    }
    for v in VERSIONS:
        print(f"PG{v} reported ({len(reported[v])}): {', '.join(sorted(reported[v]))}")
    print("added 14->18:", sorted(reported[18] - reported[14]))
    print("removed 14->18:", sorted(reported[14] - reported[18]))

    pg18 = data[18]
    ctx_dist = collections.Counter(c for c, _, _ in pg18.values())
    print("PG18 context distribution:", dict(ctx_dist))

    userset = sorted(n for n, (c, _, _) in pg18.items() if c == "PGC_USERSET")
    print(f"PGC_USERSET: {len(userset)}")
    gap = sorted(set(userset) - reported[18])
    print(f"userset but NOT reported: {len(gap)}")

    rows = []
    for n in userset:
        _, cat, _ = pg18[n]
        cls = "A-parser" if n in PARSER_AFFECTING else (
            "A-planner" if any(h in n for h in PLANNER_HINTS) else "A"
        )
        rows.append((n, cat, cls, "yes" if n in reported[18] else "no"))
    with open("userset-guc-inventory.tsv", "w") as fh:
        fh.write("guc\tcategory\tclass\treported_to_client\n")
        for r in rows:
            fh.write("\t".join(r) + "\n")
    print("by class:", dict(collections.Counter(r[2] for r in rows)))

    json.dump(
        {str(v): {n: [c, cat, sorted(f)] for n, (c, cat, f) in d.items()}
         for v, d in data.items()},
        open("gucs.json", "w"), indent=0,
    )
    print("wrote gucs.json and userset-guc-inventory.tsv")


if __name__ == "__main__":
    main()
