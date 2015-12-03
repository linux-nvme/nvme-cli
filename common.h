#ifndef COMMON_H
#define COMMON_H

#include "linux/nvme.h"

enum {
	TERSE = 0x1u,	// only show a few useful fields
	HUMAN = 0x2u,	// interpret some values for humans
	VS    = 0x4u,	// print vendor specific data area
	RAW   = 0x8u,	// just dump raw bytes
};

void d(unsigned char *buf, int len, int width, int group);

long double int128_to_double(__u8 *data);

void show_nvme_id_ctrl(struct nvme_id_ctrl *ctrl, unsigned int mode);
void show_nvme_id_ns(struct nvme_id_ns *ns, unsigned int flags);

#endif
