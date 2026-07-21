"""
aggregator.py
Stage 3.5: Second-level aggregation (super-templates).

After templating + dedup there are often still HUNDREDS of templates that are
identical except for a SINGLE token (e.g. a different username):

    sshd[<PID>]: Invalid user oracle from <IP>
    sshd[<PID>]: Invalid user test from <IP>
    sshd[<PID>]: Invalid user admin from <IP>
    ...

This module merges them into ONE line, masking the varying token as <VAR> and
recording how many distinct values were seen:

    sshd[<PID>]: Invalid user <VAR> from <IP>   (312 distinct values)

The result is small enough to fit inside any model's context window without
truncation. Trade-off: the specific values (usernames) are no longer listed
one by one, only their distinct count.
"""

from collections import defaultdict
from typing import List


def aggregate_templates(logs: List[dict], min_group: int = 3) -> List[dict]:
    """
    Merge templates that differ in exactly one token position.
    `min_group`: minimum number of templates required before a merge happens.
    Logs without a `_template` are left untouched.
    """
    items = [l for l in logs if l.get("_template")]
    others = [l for l in logs if not l.get("_template")]

    toks_list = [t["_template"].split(" ") for t in items]

    # Candidate groups: templates identical except at position i
    groups = defaultdict(list)
    for idx, toks in enumerate(toks_list):
        for i in range(len(toks)):
            key = (len(toks), i, "\x00".join(toks[:i]) + "\x01" + "\x00".join(toks[i + 1:]))
            groups[key].append(idx)

    consumed = set()
    merged: List[dict] = []

    # Prefer the largest groups first (biggest reduction)
    for key, members in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        members = [m for m in members if m not in consumed]
        if len(members) < min_group:
            continue
        i = key[1]
        toks = list(toks_list[members[0]])
        toks[i] = "<VAR>"
        total = sum(items[m].get("_count", 1) for m in members)
        distinct = len(members)
        new_template = " ".join(toks) + f"  ({distinct} distinct values)"
        merged.append({"_template": new_template, "_count": total})
        consumed.update(members)

    # Templates that were not merged
    for idx, t in enumerate(items):
        if idx not in consumed:
            merged.append(t)

    return merged + others
