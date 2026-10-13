#!/bin/bash
# nightly dump of the staging database, copied to the backup host
set -e
STAMP=$(date +%F)
mysqldump -h 10.20.0.6 -u app -p'@LURE_DB_PASS@' appdb | gzip > /srv/backups/app-$STAMP.sql.gz
scp /srv/backups/app-$STAMP.sql.gz deploy@10.20.0.7:/srv/backups/
find /srv/backups -name 'app-*.sql.gz' -mtime +14 -delete
