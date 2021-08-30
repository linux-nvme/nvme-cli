#ifndef _FABRICS_H
#define _FABRICS_H

extern int nvmf_discover(const char *desc, int argc, char **argv, bool connect);
extern int nvmf_connect(const char *desc, int argc, char **argv);
extern int nvmf_disconnect(const char *desc, int argc, char **argv);
extern int nvmf_disconnect_all(const char *desc, int argc, char **argv);

#endif
