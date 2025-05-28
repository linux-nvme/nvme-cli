// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2024 Solidigm.
 *
 * Authors: leonardo.da.cunha@solidigm.com
 */

#include "common.h"
#include "nvme-print.h"
#include <errno.h>
#include <time.h>

#define LID 0xf9
#define FID 0xf1
#define WLT2US 25
#define WLT2MS (WLT2US * 1000)
#define MAX_WORKLOAD_LOG_ENTRIES 126
#define MAX_WORKLOAD_LOG_ENTRY_SIZE 32
#define MAX_FIELDS 15

char const *samplet[] = {
	"default",
	"1ms",
	"5ms",
	"10ms",
	"50ms",
	"100ms",
	"500ms",
	"1s",
	"5s",
	"10s",
	"30s",
	"1m",
	"5m",
	"10m",
	"30m",
	"1h"
};

char const *trk_types[] = {
	"Base",
	"CmdQ",
	"Pattern",
	"RandSeq",
	"Throttle",
	"Power",
	"Defrag"
};

struct field {
	__u8 size;
	char *name;
	char *desc;
};

struct field group_fields[][MAX_FIELDS] = {
{ // Base, group 0
	{4, "hostReads", "Host Read Count in Sectors"},
	{4, "hostWrites", "Host Write Count in Sectors"},
	{4, "nandWrites", "Nand Write Count in Sectors"},
	{1, "misalignment%", "% of Misaligned Sectors"},
	{1, "collision%", "% of Colliding Sectors"},
	{1, "randomWrite%", "% of Random Write Sectors vs. Sequential"},
	{1, "randomRead%", "% of Random Read Sectors vs. Sequential"},
	{4, "xorInvokedCount", "Count of XOR Operations Invoked"},
	{4, "hostSoftReadSuccess", "Count of Soft Reads Completed Successfully."},
	{4, "bandDefragRelocation", "Count of BDRs"},
	{1, "pwrThrottle%", "% of Throttle Period due to Power Regulation"},
	{1, "thmThrottle%", "% of Throttle Period due to Thermal Levels"},
	{1, "tbufBg%", "% of Background TBUF Work vs. All Available Work"},
	{1, "tbufHost%", "% of Host Requested TBUF Work vs. All Available Work"},
	{0}
},
{ //CmdQ stats, group 1
	{4, "CmdQ_InternalReadQDepth", "Snapshot of the Internal Read Queue Depth"},
	{4, "CmdQ_DetectedWriteQDepth", "Snapshot of the Internal Write Queue Depth"},
	{4, "CmdQ_ReadCmdsPending", "Snapshot of the Internal Read Commands Pending"},
	{1, "misalignment%", "% of Misaligned Sectors"},
	{1, "collision%", "% of Colliding Sectors"},
	{1, "randomWrite%", "% of Random Write Sectors vs. Sequential"},
	{1, "randomRead%", "% of Random Read Sectors vs. Sequential"},
	{4, "CmdQ_WriteCmdsPending", "Snapshot of the Internal Write Commands Pending"},
	{4, "CmdQ_ReadCmdsOutstanding", "Snapshot of the Internal Read Commands Outstanding"},
	{4, "CmdQ_WriteCmdsOutstanding", "Snapshot of the Internal Read Commands Outstanding"},
	{1, "pwrThrottle%", "% of Throttle Period due to Power Regulation"},
	{1, "thmThrottle%", "% of Throttle Period due to Thermal Levels"},
	{1, "tbufBg%", "% of Background TBUF Work vs. All Available Work"},
	{1, "tbufHost%", "% of Host Requested TBUF Work vs. All Available Work"},
	{0}
},
{ // test pattern, group 2
	{4, "x11223300"},
	{4, "x44556600_"},
	{4, "x77889900_"},
	{4, "xAABBCC00_"},
	{2, "xDD00"},
	{2, "xEE00"},
	{2, "xFF00"},
	{2, "x0_"},
	{1, "x00"},
	{1, "x80"},
	{1, "x__"},
	{1, "x8_"},
	{4, "x33322100"},
	{0}
},
{ // Random vs. Sequential Data, group 3
	{4, "hostReads", "Host Read Count in Sectors"},
	{4, "hostWrites", "Host Write Count in Sectors"},
	{4, "nandWrites", "Nand Write Count in Sectors"},
	{4, "randomReadCmd", "Count of Random Read Commands (vs. Sequential)"},
	{4, "randomWriteCmd", "Count of Random Write Commands (vs. Sequential)"},
	{4, "hostReadCmd", "Count of Total Host Read Commands (vs. Sequential)"},
	{4, "hostWriteCmd", "Count of Total Host Read Commands (vs. Sequential)"},
	{1, NULL},
	{1, NULL},
	{1, "randomWrite%", "% of Random Write Sectors vs. Sequential"},
	{1, "randomThrottleRead%", "% of Random Read Sectors vs. Sequential"},
	{0}
},
{ //Detailed Throttle Data, group 4
	{4, "pwrThrottleOn_ms", "Duration of Power Throttling in mS."},
	{4, "thmThrottleOn_ms", "Duration of Thermal Throttling in mS."},
	{4, "powerOn_us", "Duration of Power-on in uS."},
	{4, NULL},
	{4, NULL},
	{4, NULL},
	{4, NULL},
	{1, "pwrThrottle%", "% of Throttle Period due to Power Regulation"},
	{1, "thmThrottle%", "% of Throttle Period due to Thermal Levels"},
	{0}
},
{ // Detailed Power Data, group 5
	// PMIC and/or Input Voltage Power
	{4, "vin1Power", "in uW"},
	{4, "vin2Power"},
	 // NAND Workload
	{4, "nandWrites", "Nand Write Count in Sectors"},
	{4, "nandReads", "Nand Read Count in Sectors"},
	// Power Governor (if not enabled, all-0s)
	{4, "lastNandAvgPwr"},
	{4, "lastDriveAvgPwr"},
	{4, "NscPwgSysCreditCnt"},
	{4, "burstPowerBudget"},
	{0}
},
{ // Defrag, group 6
	{4, "hostReads", "Host Read Count in Sectors"},
	{4, "hostWrites", "Host Write Count in Sectors"},
	{4, "nandWrites", "Nand Write Count in Sectors"},
	{4, "defragSlots", "Current defragSlots"},
	{4, "hostSlots", "hostSlots"},
	{4, "totalSlots", "Total slots"},
	{1, "hostBufferUse%", "% of WCM_GetHostBuffersInUse to WCM_GetDesiredHostBuffer"},
	{1, "defragBufferUse%", "% of defragBuffer to Desired defrag buffer %"},
	{1, "defragSlotsUse%", "defragSlots to Total defrag slots %"},
	{1, "hostSlotsUse%", "hostSlots to Total defrag slots %"},
	{1, "aiuUse%", "% of AvailableIndirectionUnits to Start Setpoint IU"},
	{1, "isImminentFRorWL", "defrag/Wear leveling is imminent"},
	{1, "defragType", "defrag type"},
	{0}
}};

#pragma pack(push, 1)
union WorkloadLogEnable {
	struct {
	    __u32 trackerEnable        : 1;
	    __u32 triggerEnable        : 1;
	    __u32 triggerSynchronous   : 1; // trigger mode, 1=Synchronous,0=ASynchronous(Latency)
	    __u32 triggerDelta         : 1; // trigger value mode, 1=delta, 0=current value
	    __u32 triggerDwordIndex    : 3; // trigger dword index, 0~7 of a log entry
	    __u32 triggerByteWordIndex : 2; // trigger byte or word index,byte=0~3, word=0~1
	    __u32 triggerSize          : 2; // trigger size, 1=byte, 2=word, 3=dword as a trigger
	    __u32 sampleTime           : 4; // trigger sample time
	    __u32 contentGroup         : 4; // content group select
	    __u32 stopCount            : 12;// event limit,if<>0,stop tracker after stopCount events
	    __u32 eventDumpEnable      : 1; // trigger event dump enable
	};
	__u32 dword;
};

struct workloadLog { // Full WL Log Structure
	__u16 majorVersion;                // Major Version
	__u16 minorVersion;                // Minor Version
	__u32 workloadLogCount;            // Number of Entries in the Workload Log
	__u32 reserved;                    // reserve for future
	__u32 triggeredEvents;             // Count of events triggered
	__u32 samplePeriodInMilliseconds;  // Sample Period In Milliseconds
	__u64 timestamp_lastEntry;         // Timestamp for the last full entry
	__u64 timestamp_triggered;         // Timestamp at the point of trigger
	union WorkloadLogEnable config;    // Workload trigger and enable settings
	__u32 triggerthreshold;            // Trigger threshold
	__u32 triggeredValue;              // Actual value fired the trigger
	__u8 entry[MAX_WORKLOAD_LOG_ENTRIES][MAX_WORKLOAD_LOG_ENTRY_SIZE];
};
#pragma pack(pop)

struct wltracker {
	struct nvme_transport_handle *hdl;
	__u8 uuid_index;
	struct workloadLog workload_log;
	size_t poll_count;
	bool show_wall_timestamp;
	__u64 us_epoch_ssd_delta;
	__u64 start_time_us;
	__u64 run_time_us;
	bool disable;
};

static void wltracker_print_field_names(struct wltracker *wlt)
{
	struct workloadLog *log = &wlt->workload_log;

	if (log->workloadLogCount == 0)
		return;

	printf("%-16s", "timestamp");

	for (int i = 0 ; i < MAX_FIELDS; i++) {
		struct field f = group_fields[log->config.contentGroup][i];

		if (f.size == 0)
			break;
		if (f.name == NULL)
			continue;
		printf("%s ", f.name);
	}

	if (wlt->show_wall_timestamp)
		printf("%-*s", (int)sizeof("YYYY-MM-DD-hh:mm:ss.uuuuuu"), "wall-time");

	if (nvme_cfg.verbose > 1)
		printf("%s", "entry# ");

	printf("\n");
}

static void wltracker_print_header(struct wltracker *wlt)
{
	struct workloadLog *log = &wlt->workload_log;

	printf("%-24s %u.%u\n", "Log page version:", le16_to_cpu(log->majorVersion),
	       le16_to_cpu(log->minorVersion));
	printf("%-24s %u\n", "Sample period(ms):", le32_to_cpu(log->samplePeriodInMilliseconds));
	printf("%-24s %lu\n", "timestamp_lastChange:", le64_to_cpu(log->timestamp_lastEntry));
	printf("%-24s %lu\n", "timestamp_triggered:", le64_to_cpu(log->timestamp_triggered));
	printf("%-24s 0x%x\n", "config:", le32_to_cpu(log->config.dword));
	printf("%-24s %u\n", "Triggerthreshold:", le32_to_cpu(log->triggerthreshold));
	printf("%-24s %u\n", "ValueTriggered:", le32_to_cpu(log->triggeredValue));
	printf("%-24s %s\n", "Tracker Type:", trk_types[log->config.contentGroup]);
	printf("%-24s %u\n", "Total log page entries:", le32_to_cpu(log->workloadLogCount));
	printf("%-24s %u\n", "Trigger count:", log->triggeredEvents);
	if (nvme_cfg.verbose > 1)
		printf("%-24s %ld\n", "Poll count:", wlt->poll_count);
	if (wlt->poll_count != 0)
		wltracker_print_field_names(wlt);
}

__u64 micros_id(clockid_t clk_id)
{
	struct timespec ts;
	__u64 us;

	clock_gettime(clk_id, &ts);
	us = (((__u64)ts.tv_sec)*1000000) + (((__u64)ts.tv_nsec)/1000);
	return us;
}

__u64 micros(void)
{
	return micros_id(CLOCK_REALTIME);
}

int wltracker_config(struct wltracker *wlt, union WorkloadLogEnable *we)
{
	struct nvme_set_features_args args = {
		.args_size	= sizeof(args),
		.fid		= FID,
		.cdw11		= we->dword,
		.uuidx		= wlt->uuid_index,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
	};
	return nvme_set_features(wlt->hdl, &args);
}

static int wltracker_show_newer_entries(struct wltracker *wlt)
{
	struct workloadLog *log = &wlt->workload_log;
	__u8 cnt;
	__u8 content_group;
	static __u64 last_timestamp_us;
	__u64 timestamp_us = 0;
	__u64 timestamp = 0;
	union WorkloadLogEnable workloadEnable;

	struct nvme_get_log_args args = {
		.lpo	= 0,
		.result = NULL,
		.log	= log,
		.args_size = sizeof(args),
		.uuidx	= wlt->uuid_index,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid	= LID,
		.len	= sizeof(*log),
	};
	int err = nvme_get_log(wlt->hdl, &args);

	if (err > 0) {
		nvme_show_status(err);
		return err;
	}
	if (err < 0)
		return err;

	if (nvme_cfg.verbose)
		wltracker_print_header(wlt);

	cnt = log->workloadLogCount;
	workloadEnable = log->config;
	content_group = workloadEnable.contentGroup;

	if (cnt == 0) {
		nvme_show_error("Warning : No valid workload log data\n");
		return 0;
	}

	timestamp_us = (le64_to_cpu(log->timestamp_lastEntry) / WLT2US) -
		       (log->samplePeriodInMilliseconds * 1000 * (cnt - 1));
	timestamp = le64_to_cpu(log->timestamp_lastEntry) -
		    (log->samplePeriodInMilliseconds * WLT2MS * (cnt - 1));

	if (wlt->poll_count++ == 0) {
		__u64 tle = log->timestamp_lastEntry;
		__u8 tracker_enable_bit = workloadEnable.trackerEnable;

		wltracker_print_field_names(wlt);

		if (wlt->show_wall_timestamp &&
		   ((log->triggeredEvents && wlt->disable) || !tracker_enable_bit)) {
			// retrieve fresh timestamp to reconstruct wall time
			union WorkloadLogEnable we = log->config;

			if (nvme_cfg.verbose > 1) {
				printf("Temporarily enabling tracker to find current timestamp\n");
				printf("Original config value: 0x%08x\n", we.dword);
			}
			we.trackerEnable = true;
			we.triggerEnable = false;
			we.sampleTime = 1;

			if (nvme_cfg.verbose > 1)
				printf("Modified config value: 0x%08x\n", we.dword);

			err = wltracker_config(wlt, &we);
			usleep(1000);
			if (!err) {
				struct workloadLog tl;

				err = nvme_get_log_simple(wlt->hdl, LID, sizeof(tl), &tl);
				tle = tl.timestamp_lastEntry;
			}
			if (err) {
				nvme_show_error("Failed to retrieve latest SSD timestamp");
			} else {
				// Restore original config , but don't reenable trigger
				we = log->config;
				we.triggerEnable = false;
				err = wltracker_config(wlt, &we);
				if (nvme_cfg.verbose > 1)
					printf("Restored config value: 0x%08x\n",
					       we.dword);
			}
		}
		wlt->us_epoch_ssd_delta = (micros() - le64_to_cpu(tle) / WLT2US);
	}

	for (int i = cnt - 1; i >= 0; i--) {
		int offset = 0;
		__u8 *entry = (__u8 *) &log->entry[i];
		// allow 10% sample skew
		bool is_old = timestamp_us <= last_timestamp_us +
			      (log->samplePeriodInMilliseconds * 100);

		if (is_old) {
			timestamp_us += (log->samplePeriodInMilliseconds * 1000);
			timestamp += log->samplePeriodInMilliseconds * WLT2MS;
			continue;
		}
		printf("%-16llu", timestamp);
		for (int j = 0; j < MAX_FIELDS; j++) {
			__u32 val = 0;
			struct field f = group_fields[content_group][j];

			if (f.size == 0) {
				if (wlt->show_wall_timestamp) {
					time_t epoch_ts_us = timestamp_us +
							     wlt->us_epoch_ssd_delta;
					time_t ts_s = epoch_ts_us / 1000000;
					struct tm ts = *localtime(&ts_s);
					char buf[80];

					strftime(buf, sizeof(buf), "%Y-%m-%d-%H:%M:%S", &ts);
					printf("%s.%06" PRIu64 " ", buf,
					       (uint64_t)(epoch_ts_us % 1000000ULL));
				}

				if (nvme_cfg.verbose > 1)
					printf("%-*i", (int)sizeof("entry#"), i);

				printf("\n");
				break;
			}
			if (f.name == NULL)
				continue;

			switch (f.size) {
			case 1:
				val = *(entry+offset);
				break;
			case 2:
				val = *(__u16 *)(entry + offset);
				break;
			case 4:
				val = *(__u32 *)(entry + offset);
				break;
			default:
				nvme_show_error("Bad field size");
			}
			offset += f.size;

			printf("%-*u ", (int)strlen(f.name), val);
		}
		timestamp_us += (log->samplePeriodInMilliseconds * 1000);
		timestamp += log->samplePeriodInMilliseconds * WLT2MS;
	}
	last_timestamp_us = log->timestamp_lastEntry / WLT2US;
	return 0;
}

void wltracker_run_time_update(struct wltracker *wlt)
{
	wlt->run_time_us = micros() - wlt->start_time_us;
	if (nvme_cfg.verbose > 0)
		printf("run_time: %lluus\n", wlt->run_time_us);
}

static int stricmp(char const *a, char const *b)
{
	if (!a || !b)
		return 1;
	for (; *a || *b; a++, b++)
		if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
			return 1;
	return 0;
}

static int find_option(char const *list[], int size, const char *val)
{
	for (int i = 0; i < size; i++) {
		if (!stricmp(val, list[i]))
			return i;
	}
	return -EINVAL;
}

static void join_options(char *dest, char const *list[], size_t list_size)
{
	strcat(dest, list[0]);
	for (int i = 1; i < list_size; i++) {
		strcat(dest, "|");
		strcat(dest, list[i]);
	}
}

static int find_field(struct field *fields, const char *val)
{
	for (int i = 0; i < MAX_FIELDS; i++) {
		if (!stricmp(val, fields[i].name))
			return i;
	}
	return -EINVAL;
}

static void join_fields(char *dest, struct field *fields)
{
	strcat(dest, fields[0].name);
	for (int i = 1; i < MAX_FIELDS; i++) {
		char *name = fields[i].name;

		if (name) {
			strcat(dest, "|");
			strcat(dest, name);
		}
	}
}

int sldgm_get_workload_tracker(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Real Time capture Workload Tracker samples";
	const char *sample_interval = "Sample interval";
	const char *run_time = "Limit runtime capture time in seconds";
	const char *flush_frequency =
		"Samples (1 to 126) to wait for extracting data. Default 100 samples";
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct wltracker wlt = {0};
	union WorkloadLogEnable we = {0};
	char type_options[80] = {0};
	char sample_options[80] = {0};
	__u64 stop_time_us;
	__u64 next_sample_us = 0;
	int opt;
	int err;

	struct config {
		bool enable;
		bool disable;
		bool trigger_on_delta;
		bool trigger_on_latency;
		const char *tracker_type;
		const char *sample_time;
		__u32 run_time_s;
		int flush_frequency;
		char *trigger_field;
		__u32 trigger_treshold;
	};

	struct config cfg = {
		.sample_time = samplet[0],
		.flush_frequency = 100,
		.tracker_type = trk_types[0],
		.trigger_field = "",
	};

	join_options(type_options, trk_types, ARRAY_SIZE(trk_types));
	join_options(sample_options, samplet, ARRAY_SIZE(samplet));

	OPT_ARGS(opts) = {
		OPT_BYTE("uuid-index",   'U', &wlt.uuid_index, "specify uuid index"),
		OPT_FLAG("enable", 'e', &cfg.enable, "tracker enable"),
		OPT_FLAG("disable", 'd', &cfg.disable, "tracker disable"),
		OPT_STRING("sample-time", 's', sample_options, &cfg.sample_time, sample_interval),
		OPT_STRING("type", 't', type_options, &cfg.tracker_type, "Tracker type"),
		OPT_UINT("run-time", 'r', &cfg.run_time_s, run_time),
		OPT_INT("flush-freq", 'f', &cfg.flush_frequency, flush_frequency),
		OPT_FLAG("wall-clock", 'w', &wlt.show_wall_timestamp,
			 "Logs current wall timestamp when entry was retrieved"),
		OPT_STR("trigger-field", 'T', &cfg.trigger_field, "Field name to stop trigger on"),
		OPT_UINT("trigger-threshold", 'V', &cfg.trigger_treshold,
			 "Field value to trigger stop sampling"),
		OPT_FLAG("trigger-on-delta", 'D', &cfg.trigger_on_delta,
			 "Trigger on delta to stop sampling"),
		OPT_FLAG("trigger-on-latency", 'L', &cfg.trigger_on_latency,
			 "Use latency tracker to trigger stop sampling"),
		OPT_INCR("verbose", 'v', &nvme_cfg.verbose, "Increase logging verbosity"),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (wlt.uuid_index > 127) {
		nvme_show_error("invalid uuid index param: %u", wlt.uuid_index);
		return -1;
	}

	wlt.hdl = hdl;

	if ((cfg.flush_frequency < 1) || (cfg.flush_frequency > MAX_WORKLOAD_LOG_ENTRIES)) {
		nvme_show_error("Invalid number of samples: %s. Valid values: 1-%d",
				cfg.flush_frequency, MAX_WORKLOAD_LOG_ENTRIES);
		return -EINVAL;
	}

	opt = find_option(samplet, ARRAY_SIZE(samplet), cfg.sample_time);
	if (opt < 0) {
		nvme_show_error("invalid Sample interval: %s. Valid values: %s",
				cfg.sample_time, sample_options);
		return -EINVAL;
	}
	we.sampleTime = opt;

	opt = find_option(trk_types, ARRAY_SIZE(trk_types), cfg.tracker_type);
	if (opt < 0) {
		nvme_show_error("Invalid tracker type: \"%s\". Valid types: %s",
				cfg.tracker_type, type_options);
		return -EINVAL;
	}
	we.contentGroup = opt;
	if (argconfig_parse_seen(opts, "trigger-field")) {
		int field_pos = find_field(group_fields[opt], cfg.trigger_field);
		int field_offset = 0;

		if (field_pos < 0) {
			char field_options[256];

			join_fields(field_options, group_fields[opt]);
			nvme_show_error(
				"Invalid field name: %s. For type: \"%s\", valid fields are: %s",
				 cfg.trigger_field, cfg.tracker_type, field_options);
			return -EINVAL;
		}
		for (int i = 0; i < field_pos; i++)
			field_offset += group_fields[opt][i].size;

		we.triggerDwordIndex += field_offset / 4;
		we.triggerSize =
			group_fields[opt][field_pos].size ==
			4 ? 3 : group_fields[opt][field_pos].size;
		we.triggerByteWordIndex = field_offset % 4 /
					  group_fields[opt][field_pos].size;
		we.triggerEnable = true;
		we.triggerDelta = cfg.trigger_on_delta;
		we.triggerSynchronous = !cfg.trigger_on_latency;
		struct nvme_set_features_args args = {
			.args_size	= sizeof(args),
			.fid		= 0xf5,
			.cdw11		= cfg.trigger_treshold,
			.uuidx		= wlt.uuid_index,
			.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		};
		err = nvme_set_features(wlt.hdl, &args);
		if (err < 0) {
			nvme_show_error("Trigger Threshold set-feature: %s", nvme_strerror(errno));
			return err;
		} else if (err > 0) {
			nvme_show_status(err);
			return err;
		}
	}

	if (cfg.enable && cfg.disable) {
		nvme_show_error("Can't enable disable simultaneously");
		return -EINVAL;
	}
	wlt.disable = cfg.disable;

	if (cfg.enable) {
		we.trackerEnable = true;
		err = wltracker_config(&wlt, &we);
		if (err < 0) {
			nvme_show_error("tracker set-feature: %s", nvme_strerror(errno));
			return err;
		} else if (err > 0) {
			nvme_show_status(err);
			return err;
		}
	}

	wlt.start_time_us = micros();
	stop_time_us = cfg.run_time_s * 1000000;
	while (wlt.run_time_us < stop_time_us) {
		__u64 interval;
		__u64 elapsed;
		__u64 prev_run_time_us = wlt.run_time_us;

		err = wltracker_show_newer_entries(&wlt);

		if (err > 0) {
			nvme_show_status(err);
			return err;
		}
		interval = ((__u64)wlt.workload_log.samplePeriodInMilliseconds) * 1000 *
			   cfg.flush_frequency;
		next_sample_us += interval;
		wltracker_run_time_update(&wlt);

		if (wlt.workload_log.triggeredEvents)
			break;
		elapsed = wlt.run_time_us - prev_run_time_us;
		if (interval > elapsed) {
			__u64 period_us = min(next_sample_us - wlt.run_time_us,
					      stop_time_us - wlt.run_time_us);
			if (nvme_cfg.verbose > 1)
				printf("Sleeping %lluus..\n", period_us);
			usleep(period_us);
			wltracker_run_time_update(&wlt);
		}
	}

	if (!wlt.workload_log.triggeredEvents) {
		err = wltracker_show_newer_entries(&wlt);
		wltracker_run_time_update(&wlt);
	}

	if (cfg.disable) {
		union WorkloadLogEnable we2 = wlt.workload_log.config;

		if (nvme_cfg.verbose > 1)
			printf("Original config value: 0x%08x\n", we2.dword);

		we2.trackerEnable = false;
		we2.triggerEnable = false;
		err = wltracker_config(&wlt, &we2);
		if (err < 0) {
			nvme_show_error("tracker set-feature: %s", nvme_strerror(errno));
			return err;
		} else if (err > 0) {
			nvme_show_status(err);
			return err;
		}
		if (nvme_cfg.verbose > 1)
			printf("Modified config value: 0x%08x\n", we2.dword);
		printf("Tracker disabled\n");
		return 0;
	}

	if (err > 0) {
		nvme_show_status(err);
		return err;
	}
	return err;
}
