#ifndef _MONITOR_H
#define _MONITOR_H

typedef void (*disc_notify_cb)(const char *argstr, int instance);
typedef void (*disc_query_dev_cb)(const char *argstr, char **device);

struct monitor_callbacks {
	disc_notify_cb notify;
	disc_query_dev_cb query_dev;
};

extern int aen_monitor(const char *desc, int argc, char **argv);

#endif
