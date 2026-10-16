#!/bin/sh
# Snapshot FalkorDB (all graphs: ops_live, ops_sandbox, ...) to /opt/rootgraph/backups, keep the newest 14.
# Installed as /etc/cron.d/rootgraph-backup (daily 03:00 IST). Restore: stop falkordb, copy a file over
# /opt/rootgraph/data/falkordb/dump.rdb, start falkordb.
set -eu
DEST=/opt/rootgraph/backups
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
docker exec app-falkordb-1 sh -c 'redis-cli -a "$FALKORDB_PASSWORD" --no-auth-warning SAVE' | grep -q OK
cp /opt/rootgraph/data/falkordb/dump.rdb "$DEST/falkordb-$STAMP.rdb"
chmod 600 "$DEST/falkordb-$STAMP.rdb"
ls -1t "$DEST"/falkordb-*.rdb | tail -n +15 | xargs -r rm -f
echo "backup ok: $DEST/falkordb-$STAMP.rdb ($(stat -c %s "$DEST/falkordb-$STAMP.rdb") bytes)"
