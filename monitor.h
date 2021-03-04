#ifndef _MONITOR_H
#define _MONITOR_H

typedef void (*disc_notify_cb)(const char *argstr, int instance);

struct monitor_callbacks {
	disc_notify_cb notify;
};

extern int aen_monitor(const char *desc, int argc, char **argv);

#endif
