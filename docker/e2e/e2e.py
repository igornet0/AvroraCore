#!/usr/bin/env python3
"""Docker E2E: AvroraCore creates/restores backups through BackupSAS nodes.

Run via docker/e2e/run.sh (or `make -f Makefile.docker e2e-backupsas`).
Uses only the dev test credentials shipped in docker/env.dev. Stdlib only.
"""
import base64, hashlib, hmac, json, os, re, struct, subprocess, sys, time, urllib.error, urllib.request

API = f"http://127.0.0.1:{os.environ.get('E2E_HTTP_PORT', '28787')}/api"
HERE = os.path.dirname(os.path.abspath(__file__))
ENV = {}
COMPOSE = ["docker", "compose", "-f", os.path.join(HERE, "compose.yml")]
for line in open(os.path.join(HERE, "..", "env.dev")):
    if "=" in line and not line.lstrip().startswith("#"):
        k, v = line.strip().split("=", 1)
        ENV[k] = v
MASTER_HEX = ENV["AVRORA_MASTER_KEY_HEX"]
results = []


def step(name, ok, detail=""):
    results.append((name, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""), flush=True)
    if not ok:
        summary()
        sys.exit(1)


def summary():
    passed = sum(1 for _, ok in results if ok)
    print(f"\n{passed}/{len(results)} checks passed")


def totp(secret_b32):
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    msg = struct.pack(">Q", int(time.time()) // 30)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return f"{(struct.unpack('>I', h[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


TOKEN = None


def call(method, path, body=None, expect=200):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(API + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if TOKEN:
        req.add_header("Authorization", f"Bearer {TOKEN}")
    try:
        with urllib.request.urlopen(req, timeout=300) as r:
            code, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        code, raw = e.code, e.read()
    text = raw.decode(errors="replace")
    try:
        payload = json.loads(text) if text else None
    except json.JSONDecodeError:
        payload = text
    if expect is not None and code != expect:
        raise RuntimeError(f"{method} {path} -> {code}: {text[:500]}")
    return payload


def sh(*args, check=True, stdin=None):
    p = subprocess.run(list(args), capture_output=True, text=True, cwd=HERE, input=stdin)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(args)}: {p.stderr or p.stdout}")
    return p.stdout


def dexec(svc, *cmd):
    return sh(*COMPOSE, "exec", "-T", svc, *cmd)


def secret(svc, kind="database"):
    out = dexec(svc, "backupsas", "enroll-secret", "--data-dir", "/data", "--kind", kind)
    return re.search(r"bs_enroll_[0-9a-f]+", out).group(0)


# ---------------------------------------------------------------- startup
for _ in range(120):
    try:
        call("GET", "/health", expect=None)
        break
    except Exception:
        time.sleep(1)
else:
    step("avrora HTTP is up", False)
step("avrora HTTP is up", True)

TOKEN = call("POST", "/auth/login", {"access_key": ENV["AVRORA_UI_ACCESS_KEY"],
                                     "totp_code": totp(ENV["AVRORA_UI_TOTP_SECRET"])})["token"]
step("UI login (access key + TOTP)", bool(TOKEN))
st = {}
for _ in range(30):
    st = call("GET", "/db/status", expect=None) or {}
    if isinstance(st, dict) and st.get("status") == "unlocked":
        break
    time.sleep(1)
step("vault unlocked (dev auto-unlock)", st.get("status") == "unlocked", json.dumps(st)[:120])
sess = call("POST", "/session/activate", {"role_id": "root"})
step("root role active", sess["active_role"]["id"] == "root")

# ---------------------------------------------------------------- connect bsas1
desc1 = json.loads(dexec("bsas1", "cat", "/data/connect.json"))
step("bsas1 publishes signed connect JSON", desc1["format"] == "backupsas-connect/v1"
     and desc1["endpoints"] == ["bsas1:7420"] and len(desc1["signature"]) == 128)

bad = dict(desc1, endpoints=["evil:7420"])
r = call("POST", "/backup/targets", {"id": "evil", "connect": bad, "secret": "bs_enroll_00"}, expect=None)
step("tampered connect JSON rejected", "invalid signature" in json.dumps(r) or "signature" in json.dumps(r), json.dumps(r)[:100])

s1 = secret("bsas1")
t = call("POST", "/backup/targets", {"id": "bsas1", "connect": desc1, "secret": s1})
step("target bsas1 added (enrolled)", t["server_id"] == desc1["server_id"])
r = call("POST", "/backup/targets", {"id": "again", "connect": desc1, "secret": s1}, expect=None)
step("same node / used secret cannot be added twice", "already" in json.dumps(r), json.dumps(r)[:100])
trust = dexec("bsas1", "backupsas", "trust", "show", "--data-dir", "/data")
step("bsas1 trusts Avrora identity (kind=database)", "kind:        database" in trust)

# ---------------------------------------------------------------- backup
rep = call("POST", "/backup", {"backup_id": "e2e-full", "targets": ["local", "bsas1"]})
step("backup e2e-full → local + bsas1", all(x["ok"] for x in rep["results"]), json.dumps(rep["results"])[:200])
remote_id = next(x["detail"] for x in rep["results"] if x["target_id"] == "bsas1")

rep2 = call("POST", "/backup", {"backup_id": "e2e-remote", "targets": ["bsas1"], "sections": ["base", "journal"]})
step("remote-only backup with sections base+journal", all(x["ok"] for x in rep2["results"]))

cat = call("GET", "/backup/catalog")
entries = {e["backup_id"]: e for e in cat["entries"]}
step("catalog: e2e-full on local+bsas1", sorted(l["target_id"] for l in entries["e2e-full"]["locations"]) == ["bsas1", "local"])
step("catalog: e2e-remote only on bsas1, no local copy",
     [l["target_id"] for l in entries["e2e-remote"]["locations"]] == ["bsas1"]
     and "missing" in sh(*COMPOSE, "exec", "-T", "avrora", "sh", "-c",
                         "test -d /var/lib/avrora/backups/backup-e2e-remote && echo present || echo missing")
     and "present" in sh(*COMPOSE, "exec", "-T", "avrora", "sh", "-c",
                         "test -d /var/lib/avrora/backups/backup-e2e-full && echo present || echo missing"))

status = dexec("bsas1", "backupsas", "status", "--data-dir", "/data")
step("bsas1 stores 2 COMPLETE backups", status.count("COMPLETE") == 2, remote_id)
verify = dexec("bsas1", "backupsas", "verify", "--data-dir", "/data", "--all")
step("bsas1 integrity verify (chunks, Merkle, commit)", "INVALID" not in verify and "VALID" in verify)
leak = sh(*COMPOSE, "exec", "-T", "bsas1", "sh", "-c",
          "grep -rl -e avrora-vault -e checkpoint_sequence /data/repositories || true")
step("bsas1 holds ciphertext only (no plaintext manifest markers)", leak.strip() == "")
mleak = sh(*COMPOSE, "exec", "-T", "bsas1", "sh", "-c", f"grep -rl {MASTER_HEX} /data || true")
step("master key never reaches bsas1", mleak.strip() == "")

# ---------------------------------------------------------------- restore
call("POST", "/backup/restore", {"backup_id": "e2e-full", "target_id": "r-bsas1", "from_target": "bsas1"})
call("POST", "/backup/restore", {"backup_id": "e2e-full", "target_id": "r-local", "from_target": "local"})
diff = sh(*COMPOSE, "exec", "-T", "avrora", "sh", "-c",
          "cd /var/lib/avrora/restores && diff -r -x recovery.json restore-r-bsas1 restore-r-local && echo IDENTICAL", check=False)
step("restore from bsas1 == local copy (byte-for-byte)", "IDENTICAL" in diff, diff.strip()[-200:])

# ---------------------------------------------------------------- node move bsas1 -> bsas2
cfg = call("PUT", "/backup/config", {"targets": ["bsas1"], "retention_keep": 5})
step("schedule targets = bsas1", cfg["schedule"]["targets"] == ["bsas1"])
desc2 = json.loads(dexec("bsas2", "cat", "/data/connect.json"))
sh(*COMPOSE, "exec", "-T", "bsas1", "sh", "-c", "cat > /tmp/bsas2.json", stdin=json.dumps(desc2))
ns = secret("bsas2", "node")
dexec("bsas1", "backupsas", "peer", "add", "--data-dir", "/data", "--name", "bsas2",
      "--connect", "/tmp/bsas2.json", "--secret", ns)
step("bsas1 paired with bsas2 as node", "bsas2" in dexec("bsas1", "backupsas", "peer", "list", "--data-dir", "/data"))
out = dexec("bsas1", "backupsas", "transfer", "--data-dir", "/data", "--to", "bsas2", "--mode", "move")
step("bsas1 → bsas2 transfer --mode move", "Transferred 2 backup(s)" in out, out.strip().splitlines()[0])
step("source keeps data until Avrora acks",
     dexec("bsas1", "backupsas", "status", "--data-dir", "/data").count("COMPLETE") == 2)

sync = call("POST", "/backup/sync")
step("Avrora relocation sync applied", len(sync["applied"]) == 1 and not sync["errors"], json.dumps(sync)[:200])
new_t = sync["new_targets"][0]
cat = call("GET", "/backup/catalog")
locs = {e["backup_id"]: [l["target_id"] for l in e["locations"]] for e in cat["entries"]}
step("catalog moved bsas1 → " + new_t, locs["e2e-remote"] == [new_t] and sorted(locs["e2e-full"]) == sorted(["local", new_t]))
cfg = call("GET", "/backup/config")
step("schedule follows the move", cfg["schedule"]["targets"] == [new_t])
time.sleep(1)
step("bsas1 deleted moved copies after ack",
     "COMPLETE" not in dexec("bsas1", "backupsas", "status", "--data-dir", "/data"))
step("bsas2 holds both backups (delegated trust)",
     dexec("bsas2", "backupsas", "status", "--data-dir", "/data").count("COMPLETE") == 2
     and "delegated" in dexec("bsas2", "backupsas", "trust", "show", "--data-dir", "/data"))
listing = call("POST", f"/backup/targets/{new_t}/test")
step("Avrora lists bsas2 with its existing identity", len(listing) == 2)

call("POST", "/backup/restore", {"backup_id": "e2e-full", "target_id": "r-bsas2", "from_target": new_t})
diff = sh(*COMPOSE, "exec", "-T", "avrora", "sh", "-c",
          "cd /var/lib/avrora/restores && diff -r -x recovery.json restore-r-bsas2 restore-r-local && echo IDENTICAL", check=False)
step("restore from bsas2 after move == original", "IDENTICAL" in diff)

rep3 = call("POST", "/backup", {"backup_id": "e2e-after-move", "targets": [new_t]})
step("new backup goes to bsas2", all(x["ok"] for x in rep3["results"]))

# ---------------------------------------------------------------- recovery kit
kit = call("POST", "/backup/export-kit")
blob = json.dumps(kit)
step("export-kit has no master key / secrets in clear",
     MASTER_HEX not in blob and "bs_enroll_" not in blob and kit["identity"]["secret_key"]["alg"] == "aes-256-gcm")

summary()
