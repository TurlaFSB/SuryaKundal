cd /opt/app
ls -la
cat .env
cd /home/deploy
cat backup.sh
./backup.sh
tail -n 40 /var/log/syslog
scp /srv/backups/app-latest.tar.gz deploy@10.20.0.7:/srv/backups/
ssh deploy@10.20.0.7
cat ~/.ssh/known_hosts
crontab -l
vi /etc/cron.d/backup
systemctl status cron
df -h
free -m
exit
