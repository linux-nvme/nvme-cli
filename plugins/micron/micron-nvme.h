#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/micron/micron-nvme

#if !defined(MICRON_NVME) || defined(CMD_HEADER_MULTI_READ)
#define MICRON_NVME

#include "cmd.h"

PLUGIN(NAME("micron", "Micron vendor specific extensions"),
	COMMAND_LIST(ENTRY("select-download", "Selective Firmware Download", micron_selective_download)
		ENTRY("vs-temperature-stats", "Retrieve Micron temperature statistics ", micron_temp_stats)
		ENTRY("vs-pcie-stats", "Retrieve Micron PCIe error stats", micron_pcie_stats)
		ENTRY("clear-pcie-correctable-errors", "Clear correctable PCIe errors", micron_clear_pcie_correctable_errors)
		ENTRY("vs-internal-log", "Retrieve Micron logs", micron_internal_logs)
		ENTRY("vs-nand-stats", "Retrieve NAND Stats", micron_nand_stats)
	)
);

#endif

#include "define_cmd.h"
