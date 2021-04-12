#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>

#include "common.h"
#include "nvme.h"
#include "nvme-print.h"
#include "plugin.h"

#include <sys/ioctl.h>
#define CREATE_CMD
#include "shannon-nvme.h"

typedef enum {
	PROGRAM_FAIL_CNT,
	ERASE_FAIL_CNT,
	WEARLEVELING_COUNT,
	E2E_ERR_CNT,
	CRC_ERR_CNT,
	TIME_WORKLOAD_MEDIA_WEAR,	
	TIME_WORKLOAD_HOST_READS, 	
	TIME_WORKLOAD_TIMER,	  	
	THERMAL_THROTTLE,	      
	RETRY_BUFFER_OVERFLOW,		
	PLL_LOCK_LOSS,			 	
	NAND_WRITE,
	HOST_WRITE,
	SRAM_ERROR_CNT,
	ADD_SMART_ITEMS,
}addtional_smart_items;

#pragma pack(push,1)
struct nvme_shannon_smart_log_item {
	__u8			rsv1[3];
	__u8			norm;
	__u8			rsv2;
	union {
		__u8		item_val[6];
		struct wear_level {
			__le16	min;
			__le16	max;
			__le16	avg;
		} wear_level ;
		struct thermal_throttle {
			__u8	st;
			__u32	count;
		} thermal_throttle;
	};
	__u8			_resv;
};
#pragma pack(pop)

struct nvme_shannon_smart_log {
	struct nvme_shannon_smart_log_item items[ADD_SMART_ITEMS];
	 __u8  vend_spec_resv; 
};

static void show_shannon_smart_log(struct nvme_shannon_smart_log *smart,
		unsigned int nsid, const char *devname)
{
	printf("Additional Smart Log for NVME device:%s namespace-id:%x\n",
		devname, nsid);
	printf("key                               normalized value\n");
	printf("program_fail_count              : %3d%%       %"PRIu64"\n",
		smart->items[PROGRAM_FAIL_CNT].norm,
		int48_to_long(smart->items[PROGRAM_FAIL_CNT].item_val));
	printf("erase_fail_count                : %3d%%       %"PRIu64"\n",
		smart->items[ERASE_FAIL_CNT].norm,
		int48_to_long(smart->items[ERASE_FAIL_CNT].item_val));
	printf("wear_leveling                   : %3d%%       min: %u, max: %u, avg: %u\n",
		smart->items[WEARLEVELING_COUNT].norm,
		le16_to_cpu(smart->items[WEARLEVELING_COUNT].wear_level.min),
		le16_to_cpu(smart->items[WEARLEVELING_COUNT].wear_level.max),
		le16_to_cpu(smart->items[WEARLEVELING_COUNT].wear_level.avg));
	printf("end_to_end_error_detection_count: %3d%%       %"PRIu64"\n",
		smart->items[E2E_ERR_CNT].norm,
		int48_to_long(smart->items[E2E_ERR_CNT].item_val));
	printf("crc_error_count                 : %3d%%       %"PRIu64"\n",
		smart->items[CRC_ERR_CNT].norm,
		int48_to_long(smart->items[CRC_ERR_CNT].item_val));
	printf("timed_workload_media_wear       : %3d%%       %.3f%%\n",
		smart->items[TIME_WORKLOAD_MEDIA_WEAR].norm,
		((float)int48_to_long(smart->items[TIME_WORKLOAD_MEDIA_WEAR].item_val)) / 1024);
	printf("timed_workload_host_reads       : %3d%%       %"PRIu64"%%\n",
		smart->items[TIME_WORKLOAD_HOST_READS].norm,
		int48_to_long(smart->items[TIME_WORKLOAD_HOST_READS].item_val));
	printf("timed_workload_timer            : %3d%%       %"PRIu64" min\n",
		smart->items[TIME_WORKLOAD_TIMER].norm,
		int48_to_long(smart->items[TIME_WORKLOAD_TIMER].item_val));
	printf("thermal_throttle_status         : %3d%%       CurTTSta: %u%%, TTCnt: %u\n",
		smart->items[THERMAL_THROTTLE].norm,
		smart->items[THERMAL_THROTTLE].thermal_throttle.st,
		smart->items[THERMAL_THROTTLE].thermal_throttle.count);
	printf("retry_buffer_overflow_count     : %3d%%       %"PRIu64"\n",
		smart->items[RETRY_BUFFER_OVERFLOW].norm,
		int48_to_long(smart->items[RETRY_BUFFER_OVERFLOW].item_val));
	printf("pll_lock_loss_count             : %3d%%       %"PRIu64"\n",
		smart->items[PLL_LOCK_LOSS].norm,
		int48_to_long(smart->items[PLL_LOCK_LOSS].item_val));
	printf("nand_bytes_written              : %3d%%       sectors: %"PRIu64"\n",
		smart->items[NAND_WRITE].norm,
		int48_to_long(smart->items[NAND_WRITE].item_val));
	printf("host_bytes_written              : %3d%%       sectors: %"PRIu64"\n",
		smart->items[HOST_WRITE].norm,
		int48_to_long(smart->items[HOST_WRITE].item_val));
	printf("sram_error_count		: %3d%%       %"PRIu64"\n",
		smart->items[RETRY_BUFFER_OVERFLOW].norm,
		int48_to_long(smart->items[SRAM_ERROR_CNT].item_val));
}


static int get_additional_smart_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct nvme_shannon_smart_log smart_log;
	int err, fd;
	char *desc = "Get Shannon vendor specific additional smart log (optionally, "\
		      "for the specified namespace), and show it.";
	const char *namespace = "(optional) desired namespace";
	const char *raw = "dump output in binary format";
	struct config {
		__u32 namespace_id;
		int   raw_binary;
	};

	struct config cfg = {
		.namespace_id = NVME_NSID_ALL,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);
	err = nvme_get_nsid_log(fd, 0xca, cfg.namespace_id,
		   sizeof(smart_log), &smart_log);
	if (!err) {
		if (!cfg.raw_binary)
			show_shannon_smart_log(&smart_log, cfg.namespace_id, devicename);
		else
			d_raw((unsigned char *)&smart_log, sizeof(smart_log));
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
					nvme_status_to_string(err), err);
	return err;
}
