cd /srv
ls -la
df -h
sudo systemctl status cron
journalctl -u cron --since yesterday
sudo apt update
sudo apt list --upgradable
free -m
uptime
exit
