#ifndef _DMS_DEV_H_
#define _DMS_DEV_H_

#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <sys/wait.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>

#include "wireless.h"
#include "debug.h"
#include "list.h"
#include "cJSON.h"
#include "dms_manage_wifi.h"

enum CmdKey {
	INVALID = 0,
	CREATE_ENV,
	DELETE_ENV,
	INSTALL_APP,
	UNSTALL_APP,
	START_APP,
	STOP_APP,
	GET_STATUS,
};

enum WifiStaSM {
	ONLINE = 0,
	AUTH,
	JOINED,
	OFFLINE,
};


enum ZigbeeStaSM {
	ZIG_INIT = 0,
	ZIG_COMING,
	ZIG_ONLINE,
	ZIG_OFFLINE,
	ZIG_LEAVE,
};


struct globals {
	enum CmdKey cmdkey; 
	char* dmspath;
	char* serverpath;
	int wifista_crondtime;
	int zigbeesta_crondtime;
	int wifista_recv_timeout;
	int debuglevel;
	int log_syslog;
	int syslog_facility;
};

/* wireless */
typedef struct _RT_802_11_MAC_ENTRY {
	unsigned char			ApIdx;
	unsigned char           Addr[6];
	unsigned char           Aid;
	unsigned char           Psm;     // 0:PWR_ACTIVE, 1:PWR_SAVE
	unsigned char           MimoPs;  // 0:MMPS_STATIC, 1:MMPS_DYNAMIC, 3:MMPS_Enabled
	char                    AvgRssi0;
	char                    AvgRssi1;
	char                    AvgRssi2;
	unsigned int            ConnectedTime;
	MACHTTRANSMIT_SETTING	TxRate;
	unsigned int			LastRxRate;
	short					StreamSnr[3];
	short					SoundingRespSnr[3];
	//linux2.6.21为short类型，2.6.36为int类型
	//int					StreamSnr[3];
	//int					SoundingRespSnr[3];
} RT_802_11_MAC_ENTRY;

#define MAX_NUMBER_OF_MAC               75

typedef struct _RT_802_11_MAC_TABLE {
	unsigned long            Num;
	RT_802_11_MAC_ENTRY      Entry[MAX_NUMBER_OF_MAC]; //MAX_LEN_OF_MAC_TABLE = 32
} RT_802_11_MAC_TABLE;


/* wifi module */
#define ETH_ALEN 6
#define ETH_CHAR 12 

#define TYPE_INFORM "inform"
#define SUBTYPE_ONLINE "online"
#define SUBTYPE_OFFLINE "offline"
#define MODULE_WIFI "wifi"
#define MODULE_ZIGBEE "zigbee"


#define SIOCDEVPRIVATE              0x8BE0
#define SIOCIWFIRSTPRIV             SIOCDEVPRIVATE
#define RTPRIV_IOCTL_GET_MAC_TABLE_STRUCT   (SIOCIWFIRSTPRIV + 0x1F)

struct wifista_record {
	unsigned char  wmac[ETH_ALEN]; //wifi sta mac地址
	unsigned int	mark;	//标记为1，存在无线客户端列表中。标记为0，不存在，删除该记录
	enum WifiStaSM	wifistate;	//wifi sta状态机online、auth、joined、offline
	struct list_head list;
};

struct zigbeesta_record {
	/* 灯的唯一标识符[254509099, 5260233] ieeeaddr_high=254509099 ieeeaddr_low=5260233 */
	char *ieeeaddr_high;
	char *ieeeaddr_low;
	unsigned int	mark;	//标记为1，存在zigbee列表中。标记为0，不存在，删除该记录
	enum ZigbeeStaSM	zigbeestate;	//wifi sta状态机online、auth、joined、offline
	struct list_head list;
};

struct auth_proto {
	char* type; 	//inform
	char* subtype;	//online\offline
	char* module;	//wifi\zigbee
	char* info;     //mac addr\device id
};


void auth_thread(void *data);
struct auth_proto* alloc_auth_proto(char* type,char* subtype,char* module,unsigned char* id);

#endif /* _DMS_DEV_H_ */