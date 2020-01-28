#
# Regular cron jobs for the kk package
#
0 4	* * *	root	[ -x /usr/bin/kk_maintenance ] && /usr/bin/kk_maintenance
