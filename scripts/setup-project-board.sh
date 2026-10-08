#!/usr/bin/env bash
# Idempotent creator for the "Identity & Billing Platform" Projects v2 board on
# the jedi-knights org. If the project already exists (matched by title), the
# script skips creation and only adds any missing issue items.
#
# Prereq: your active gh token has the `project` scope. `read:org` is NOT
# required — this script uses REST for org/issue node-id lookups and GraphQL
# for the Projects v2 mutations, sidestepping GraphQL's read:org requirement
# on `Organization.id`.

set -euo pipefail

ORG=jedi-knights
REPO=jedi-knights/identity-platform-go
TITLE="Identity & Billing Platform"
FIRST=138
LAST=194

python3 - <<PYEOF
import json, subprocess, sys

ORG      = "$ORG"
REPO     = "$REPO"
TITLE    = "$TITLE"
FIRST    = $FIRST
LAST     = $LAST

def rest(path):
    r = subprocess.run(["gh", "api", path], capture_output=True, text=True)
    if r.returncode:
        sys.exit(f"REST {path} failed: {r.stderr}")
    return json.loads(r.stdout)

def gql(q):
    r = subprocess.run(["gh", "api", "graphql", "-f", f"query={q}"],
                       capture_output=True, text=True)
    if r.returncode:
        sys.exit(f"GraphQL failed: {r.stderr}")
    resp = json.loads(r.stdout)
    if "errors" in resp:
        sys.exit(f"GraphQL errors: {json.dumps(resp['errors'], indent=2)}")
    return resp

# Org node ID (public info, no read:org needed)
org_node_id = rest(f"/orgs/{ORG}")["node_id"]

# Find or create the project
existing = gql(f'''query {{
  node(id:"{org_node_id}") {{
    ... on Organization {{
      projectsV2(first:100) {{ nodes {{ id number title }} }}
    }}
  }}
}}''')["data"]["node"]["projectsV2"]["nodes"]

proj = next((p for p in existing if p["title"] == TITLE), None)
if proj:
    project_id, project_num = proj["id"], proj["number"]
    print(f"Existing project #{project_num}")
else:
    r = gql(f'''mutation {{
      createProjectV2(input: {{ownerId:"{org_node_id}", title:"{TITLE}"}}) {{
        projectV2 {{ id number url }}
      }}
    }}''')
    p = r["data"]["createProjectV2"]["projectV2"]
    project_id, project_num = p["id"], p["number"]
    print(f"Created project #{project_num}: {p['url']}")

# Items already in the project (skip these)
already = gql(f'''query {{
  node(id:"{project_id}") {{
    ... on ProjectV2 {{
      items(first:200) {{
        nodes {{ content {{ ... on Issue {{ number }} }} }}
      }}
    }}
  }}
}}''')["data"]["node"]["items"]["nodes"]
present = {n["content"]["number"] for n in already if n["content"]}
print(f"Already in project: {len(present)}")

# Resolve node IDs for target issues via REST paging
target = set(range(FIRST, LAST + 1)) - present
if not target:
    print("Nothing to add.")
else:
    ids = {}
    page = 1
    while target and page <= 20:
        batch = rest(f"/repos/{REPO}/issues?state=all&per_page=100&page={page}")
        if not batch: break
        for i in batch:
            if "pull_request" in i: continue
            n = i["number"]
            if n in target:
                ids[n] = i["node_id"]
                target.discard(n)
        page += 1

    def chunks(lst, n):
        lst = list(lst); return [lst[i:i+n] for i in range(0, len(lst), n)]

    added = 0
    for c in chunks(ids.items(), 20):
        m = "\n".join(
            f'  a{num}: addProjectV2ItemById(input:{{projectId:"{project_id}", contentId:"{nid}"}}) {{ item {{ id }} }}'
            for num, nid in c
        )
        gql(f"mutation {{\n{m}\n}}")
        added += len(c)
    print(f"Added {added} new items.")

print(f"URL: https://github.com/orgs/{ORG}/projects/{project_num}")
PYEOF
