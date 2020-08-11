#ifndef SFX_NVME_DEF_H
#define SFX_NVME_DEF_H

#define INVALID_PARAM			-1
#define SFX_NVME_DEV_C_VANDA	"sfxv"
#define SFX_NVME_DEV_B_VANDA	"sfdv"
#define SFX_NVME_DEV_LEN_VANDA	4

#define SFX_NVME_DEV_C_TPLUS	"sfx"
#define SFX_NVME_DEV_B_TPLUS	"sfd"
#define SFX_NVME_DEV_LEN_TPLUS	3

#define SFX_PAGE_SHIFT						12
#define SECTOR_SHIFT						9

#define SFX_GET_FREESPACE			_IOWR('N', 0x240, struct sfx_freespace_ctx)
#define NVME_IOCTL_CLR_CARD			_IO('N', 0x47)
#define SFX_BLK_FTL_IOCTL_GET_PHY_CAP_RANGE     _IOWR('N', 0x23c, unsigned long)

#define IDEMA_CAP(exp_GB)			(((__u64)exp_GB - 50ULL) * 1953504ULL + 97696368ULL)
#define IDEMA_CAP2GB(exp_sector)		(((__u64)exp_sector - 97696368ULL) / 1953504ULL + 50ULL)


typedef enum {
    NVME_DEV_STD = 0,
    NVME_SFX_C_DEV_TPLUS,
    NVME_SFX_B_DEV_TPLUS,
    NVME_SFX_C_DEV_VANDA,
    NVME_SFX_B_DEV_VANDA,
    NVME_DEV_INVALID,
}NVME_DEV_TYPE;

static inline NVME_DEV_TYPE sfx_dev_type(char *devname)
{
    if (!devname)
        return NVME_DEV_INVALID;
    if (strncmp(devname, SFX_NVME_DEV_C_VANDA, SFX_NVME_DEV_LEN_VANDA) == 0)
        return NVME_SFX_C_DEV_VANDA;
    else if (strncmp(devname, SFX_NVME_DEV_B_VANDA, SFX_NVME_DEV_LEN_VANDA) == 0)
        return NVME_SFX_B_DEV_VANDA;
    else if (strncmp(devname, SFX_NVME_DEV_C_TPLUS, SFX_NVME_DEV_LEN_TPLUS) == 0)
        return NVME_SFX_C_DEV_TPLUS;
    else if (strncmp(devname, SFX_NVME_DEV_B_TPLUS, SFX_NVME_DEV_LEN_TPLUS) == 0)
        return NVME_SFX_B_DEV_TPLUS;
    else if (strncmp(devname, "nvme", 4) == 0)
        return NVME_SFX_B_DEV_TPLUS;
    else
        return NVME_DEV_INVALID;
}
#endif
