#ifndef _DISCOVER_H
#define _DISCOVER_H

#define NVMF_DEF_DISC_TMO	30

extern char *hostnqn_read(void);

extern int fabrics_discover(const char *desc, int argc, char **argv, bool connect);
extern int fabrics_connect(const char *desc, int argc, char **argv);
extern int fabrics_disconnect(const char *desc, int argc, char **argv);
extern int fabrics_disconnect_all(const char *desc, int argc, char **argv);

#endif
