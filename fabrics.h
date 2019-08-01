#ifndef _DISCOVER_H
#define _DISCOVER_H

#define NVMF_DEF_DISC_TMO	30

extern int discover(const char *desc, int argc, char **argv, bool connect);
extern int connect(const char *desc, int argc, char **argv);
extern int disconnect(const char *desc, int argc, char **argv);
extern int disconnect_all(const char *desc, int argc, char **argv);

#endif
