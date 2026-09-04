#!/usr/bin/env python3
"""Generate AWS-CHANGES.md from commit trailers on the fork delta vs upstream.

Range uses --right-only --cherry-pick (three-dot): commits whose patch exists
identically upstream (absorbed cherry-picks/backports) drop out automatically.
`.aws-changes-overrides.yaml` (optional, repo root): `{<our-sha>: "absorbed-by <upstream-sha>"}`
drops rows upstream merged in modified form.
Entries of the form `<sha>: type=build` reclassify a commit's group instead of
dropping it. Release plumbing (vendor/go.mod/go.sum with no product source) and
commits confined to `.github/` are classified without any trailer.
A revert moves to "Removed changes" only
when its target is provably one of our own delta commits (or an explicit
`Reverts-AWS-Change:` trailer says so); reverts of upstream commits are changes we carry,
so they stay live under "Reverts we carry". A change never leaves the live list without
positive proof.
"""
import argparse, os, re, subprocess, sys
from collections import defaultdict

FS = "\x1f"; RS = "\x1e"
FMT = FS.join(["%H", "%s", "%b", "%ae", "%ce",
               "%(trailers:key=AWS-Change,valueonly,separator=)",
               "%(trailers:key=Upstream-Status,valueonly,separator=)",
               "%(trailers:key=Upstream-PR,valueonly,separator=)",
               "%(trailers:key=Issue,valueonly,separator=)",
               "%(trailers:key=AWS-Owner,valueonly,separator=)",
               "%(trailers:key=Reverts-AWS-Change,valueonly,separator=)",
               "%(trailers:key=AWS-Manifest,valueonly,separator=)"]) + RS
ORDER = ["feature", "fix", "backport", "build", "revert", "legacy"]
TITLES = {"feature": "Features", "fix": "Fixes", "backport": "Backports from upstream",
          "build": "Build/tooling",
          "revert": "Reverts we carry (upstream commits we deliberately revert)",
          "legacy": "Legacy (pre-process, no trailers)"}
REVERT_RE = re.compile(r"This reverts commit ([0-9a-f]{7,40})")
REVERT_SUBJ_RE = re.compile(r'^Revert "(.+)"\s*$')

# Dependency wiring and CI/tooling paths. Deliberately an ALLOW-list: a commit is
# release plumbing only when every path it touches is in here, so an unfamiliar
# repo layout can never make a real source change look like plumbing and vanish.
DEP_EXACT = {"go.mod", "go.sum", "go.work", "go.work.sum"}
DEP_PREFIXES = ("vendor/", ".github/")

def is_dependency_wiring(path):
    return path in DEP_EXACT or path.startswith(DEP_PREFIXES)

def is_release_plumbing(paths):
    """Dependency pin + vendor churn and nothing else.

    Keyed on what the commit touches, never on a repo's directory layout: the
    five dependency forks are flat (config/, notify/, tsdb/), not pkg/cmd/tools
    like Cortex, and an allow-list keyed on Cortex's layout silently dropped a
    real carried change (alertmanager "Add wsARN for SNS Config").
    """
    if not paths:
        return False
    touches_deps = any(p in DEP_EXACT or p.startswith("vendor/") for p in paths)
    return touches_deps and all(is_dependency_wiring(p) for p in paths)

def files_by_commit(upstream_ref):
    """sha -> set(changed paths) for the same range the manifest covers."""
    out, cur = {}, None
    raw = subprocess.run(
        ["git", "-c", "core.quotePath=false", "log", "--right-only", "--cherry-pick", "--no-merges",
         "--name-only", "--format=\x02%H", f"{upstream_ref}...HEAD"],
        check=True, capture_output=True, text=True).stdout
    for line in raw.splitlines():
        if line.startswith("\x02"):
            cur = line[1:].strip()
            out[cur] = set()
        elif line.strip() and cur:
            out[cur].add(line.strip())
    return out

def _git_ok(*args):
    """True when the git command exits 0 — used for existence/ancestry probes."""
    return subprocess.run(["git", *args], capture_output=True).returncode == 0

def is_upstream_commit(sha, upstream_ref):
    """True when sha exists locally and is an ancestor of the upstream ref."""
    return (_git_ok("cat-file", "-e", f"{sha}^{{commit}}")
            and _git_ok("merge-base", "--is-ancestor", sha, upstream_ref))

def owner_of(author_email, committer_email, trailer):
    """AWS-Owner trailer wins; else author alias; else committer alias; else '-'."""
    if trailer:
        return trailer.splitlines()[0].strip()
    for email in (author_email, committer_email):
        if email.endswith("@amazon.com"):
            return email.split("@")[0]
    return "-"

def load_overrides(path=".aws-changes-overrides.yaml"):
    """Flat `sha: value` map, parsed without a yaml dep.

    Returns (dropped, retyped): `absorbed-by ...` values drop the row,
    `type=<group>` values reclassify it.
    """
    dropped, retyped = {}, {}
    if os.path.exists(path):
        for line in open(path):
            line = line.split("#")[0].strip()
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            k, v = k.strip(), v.strip().strip('"')
            if v.startswith("type="):
                grp = v[len("type="):].strip()
                if grp in ORDER or grp == "removed":
                    retyped[k] = grp
                else:
                    print(f"warning: ignoring unknown override type '{grp}' for {k}", file=sys.stderr)
            else:
                dropped[k] = v
    return dropped, retyped

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--upstream-ref", required=True)
    p.add_argument("--repo-url", required=True)
    p.add_argument("--source-sha", default="", help="SHA the manifest was generated from (provenance)")
    p.add_argument("--source-ref", default="", help="Ref the manifest was generated from (provenance)")
    a = p.parse_args()
    raw = subprocess.run(
        ["git", "log", "--right-only", "--cherry-pick", "--no-merges",
         f"--format={FMT}", f"{a.upstream_ref}...HEAD"],
        check=True, capture_output=True, text=True).stdout
    dropped, retyped = load_overrides()
    changed = files_by_commit(a.upstream_ref)

    # Pass 1 — parse every delta commit. Classification needs the whole set,
    # because whether a revert is a removal depends on membership in it.
    records = []
    for rec in raw.split(RS):
        rec = rec.strip("\n")
        if not rec:
            continue
        (sha, subj, body, aemail, cemail, change, ustatus, upr, issue,
         otrailer, reverts, manifest) = (rec.split(FS) + [""] * 12)[:12]
        if subj.strip() == "Regenerate AWS-CHANGES.md" and aemail == "noreply@amazon.com":
            continue   # the manifest workflow's own commits must not appear in the manifest
        if manifest.splitlines()[0].strip() == "omit" if manifest else False:
            continue   # AWS-Manifest: omit — internal churn (e.g. add+remove of our own tooling), not a carried change
        records.append({
            "sha": sha,
            "subj": subj,
            "body": body,
            "change": change.splitlines()[0].strip() if change else "",
            "owner": owner_of(aemail, cemail, otrailer),
            "ustatus": ustatus.strip() or "-",
            "upr": upr.strip(),
            "issue": issue.strip(),
            "reverts": reverts.splitlines()[0].strip() if reverts else "",
            "grp": "",
            "flag": "",
        })

    delta_shas = {r["sha"] for r in records}
    delta_by_subject = {}
    for r in records:
        delta_by_subject.setdefault(r["subj"].strip(), r["sha"])

    def resolve_ours(ref):
        """Full delta SHA that `ref` names, else None.

        Positive proof only: a hex ref must be >=7 chars and match exactly one
        delta commit; a non-hex ref is treated as a commit subject and must match
        exactly one commit too. Anything ambiguous or short resolves to None, so
        the caller keeps the change live rather than removing it on a guess.
        """
        ref = (ref or "").strip()
        if not ref:
            return None
        if re.fullmatch(r"[0-9a-fA-F]{7,40}", ref):
            ref = ref.lower()
            hits = [s for s in delta_shas if s.startswith(ref)]
            return hits[0] if len(hits) == 1 else None
        hits = [r["sha"] for r in records if r["subj"].strip() == ref]
        return hits[0] if len(hits) == 1 else None

    # Pass 2 — classify reverts. removed_targets maps our reverted commit -> its revert.
    removed_targets = {}
    for r in records:
        m = REVERT_RE.search(r["body"])
        target = m.group(1) if m else ""
        subj_match = REVERT_SUBJ_RE.match(r["subj"] or "")
        if not (m or subj_match or r["change"] == "revert" or r["reverts"]):
            continue                                    # not a revert at all
        ours = resolve_ours(r["reverts"]) or resolve_ours(target)
        if ours:
            r["grp"] = "removed"                        # proven: we reverted our own change
            removed_targets[ours] = r["sha"]
            continue
        # Not ours, or unprovable — stays live.
        r["grp"] = "revert"
        if not (target and is_upstream_commit(target, a.upstream_ref)):
            # target is not a carried upstream commit — attach a disclosure flag
            if subj_match and subj_match.group(1).strip() in delta_by_subject:
                r["flag"] = "likely removal — confirm"
            else:
                r["flag"] = "revert target unresolved"

    # Pass 3 — everything else, then let proven removals win over any earlier group.
    groups = defaultdict(list)
    for r in records:
        if r["sha"] in dropped:
            continue                                    # absorbed upstream (confirmed)
        paths = changed.get(r["sha"], set())
        if is_release_plumbing(paths):
            continue                                    # release plumbing, not a carried change
        if r["sha"] in retyped:
            grp = retyped[r["sha"]]                      # explicit human reclassification
        elif paths and all(p.startswith(".github/") for p in paths):
            grp = "build"                                # CI/tooling only
        else:
            grp = r["grp"] or (r["change"] if r["change"] in ORDER else "legacy")
        if r["sha"] in removed_targets:
            grp = "removed"                              # target of one of our own reverts
        groups[grp].append((r["sha"], r["subj"], r["owner"], r["ustatus"],
                            r["upr"], r["issue"], r["flag"]))
    out = ["# AWS Changes vs upstream", "",
           f"Auto-generated — do not edit by hand. Delta of `main` vs `{a.upstream_ref}` "
           "(patch-id aware: upstream-absorbed changes drop out automatically).", ""]
    if a.source_sha:
        branch = a.source_ref.rsplit("/", 1)[-1] if a.source_ref else "HEAD"
        out += [f"Generated from `{branch}` @ `{a.source_sha[:10]}` vs `{a.upstream_ref}` on "
                f"{__import__('datetime').datetime.now(__import__('datetime').timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}.", ""]
    total = sum(len(groups[g]) for g in ORDER)
    out.insert(3, f"**Total carried changes: {total}**")
    for g in ORDER + ["removed"]:
        if not groups[g]:
            continue
        title = TITLES.get(g, "Removed changes (our own changes we reverted — not live)")
        out += [f"## {title}", "", "| Change | Owner | Upstream status | PR | Issue | Commit |", "|---|---|---|---|---|---|"]
        for sha, subj, owner, ustatus, upr, issue, flag in groups[g]:
            pr = f"[link]({upr})" if upr else "-"
            label = f"{subj} — *{flag}*" if flag else subj
            out.append(f"| {label} | {owner} | {ustatus} | {pr} | {issue or '-'} | [`{sha[:10]}`]({a.repo_url}/commit/{sha}) |")
        out.append("")
    print("\n".join(out))

if __name__ == "__main__":
    sys.exit(main())
