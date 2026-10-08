# AvroraCore ↔ BackupSAS E2E stand

Three containers on one Docker network:

| Service | Image | Role |
|---|---|---|
| `avrora` | `avrora-core:e2e` (repo `Dockerfile`) | AvroraCore in DEV mode (`docker/env.dev`, vault auto-unlock) |
| `bsas1`, `bsas2` | `backupsas:e2e` (`Dockerfile.backupsas`) | BackupSAS nodes; publish `connect.json` with `PUBLIC_ENDPOINT` |

Requires sibling checkouts `../AvroraClient` and `../BackupSAS` and Python 3 (stdlib only).

```bash
make -f Makefile.docker e2e-backupsas        # build, run checks, tear down
make -f Makefile.docker e2e-backupsas-up     # build + start, no checks
make -f Makefile.docker e2e-backupsas-down   # stop and wipe volumes
KEEP=1 docker/e2e/run.sh                     # run checks, keep the stand
E2E_HTTP_PORT=38787 docker/e2e/run.sh        # other host port (default 28787)
```

`e2e.py` drives the Avrora HTTP API (`/api`, UI login with the DEV access key +
TOTP) and the `backupsas` CLI inside the node containers:

1. import `bsas1` from its signed connect JSON + one-time secret (tampered JSON and
   duplicate node are rejected);
2. backups to `local+bsas1` and remote-only with `base,journal`; catalog, node-side
   `verify`, no plaintext markers or Master Key on the node;
3. restore from `bsas1` byte-for-byte equal to the local copy;
4. `bsas1 → bsas2` move: source kept until Avrora syncs, catalog and schedule follow,
   source deleted after ack, delegated trust on `bsas2`, restore from `bsas2`;
5. new backup lands on `bsas2`; recovery kit contains no Master Key or secrets.

Only the fixed DEV secrets from `docker/env.dev` are used. Never point this stand
at production data.
