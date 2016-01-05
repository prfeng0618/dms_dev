#include "dms_dev.h"


/*
当DEFAULT_WIFISTA_CRONDTIME < DEFAULT_WIFISTA_RCV_TIMEOUT，注意两个问题
1、是否会重复发送认证消息？ 不会，只有第一次加入列表才会发送认证消息。
2、dms_dev发送消息顺序online-》offline，接收消息顺序offline-》online。online结果是非法，
那么iptables会存在一个非法规则，但mac指的终端并不在线。
答：这个问题影响不大，当终端重新上线的时候，会重新认证。只有终端数量不是随意变化且大量，多个规则不影响使用。
*/
#define DEFAULT_DEBUGLEVEL LOG_INFO
#define DEFAULT_LOG_SYSLOG 0
#define DEFAULT_WIFISTA_CRONDTIME 5
#define DEFAULT_ZIGBEESTA_CRONDTIME 60
#define DEFAULT_WIFISTA_RCV_TIMEOUT 20
#define DEFAULT_SYSLOG_FACILITY LOG_DAEMON

#define DMS_UNIX_DOMAIN "/tmp/DMS_UNIX.domain"

#define SIOCDEVPRIVATE              0x8BE0
#define SIOCIWFIRSTPRIV             SIOCDEVPRIVATE
#define RTPRIV_IOCTL_GET_MAC_TABLE_STRUCT   (SIOCIWFIRSTPRIV + 0x1F)



struct globals G;
static pthread_t tid_wificrond = 0;
static pthread_t tid_zigbeecrond = 0;
static pthread_t tid_controlcond = 0;

static LIST_HEAD(head_wifista); 
static LIST_HEAD(head_zigbeesta); 
pthread_mutex_t wifista_table_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t zigbeesta_table_mutex = PTHREAD_MUTEX_INITIALIZER;


/* Control Message */
#define SERVER_UNIX_DOMAIN "/tmp/DEV_CONTROL.domain"
#define BACKLOG 5     // how many pending connections queue will hold
#define BUF_SIZE 1024



void auth_thread(void *data);
static void zigbee_turnon(char *zigbee_id);
static void zigbee_turnoff(char *zigbee_id);
static void send_zigbeesta_onlinemsg(char* sHigh,char* sLow);
static void send_zigbeesta_offlinemsg(char* sHigh,char* sLow);




static int init_resource(){	
	G.cmdkey = INVALID;
	G.dmspath = strdup(DMS_UNIX_DOMAIN);
	G.serverpath = strdup(SERVER_UNIX_DOMAIN);
	G.wifista_crondtime = DEFAULT_WIFISTA_CRONDTIME;
	G.zigbeesta_crondtime = DEFAULT_ZIGBEESTA_CRONDTIME;
	G.wifista_recv_timeout = DEFAULT_WIFISTA_RCV_TIMEOUT;
	G.debuglevel = DEFAULT_DEBUGLEVEL;
	G.log_syslog = DEFAULT_LOG_SYSLOG;
	G.syslog_facility = DEFAULT_SYSLOG_FACILITY;
	
	
	INIT_LIST_HEAD(&head_wifista);
	INIT_LIST_HEAD(&head_zigbeesta);
	return 0;
}

static void init_signals(void)
{
	//signal(SIGINT, unregister_heartbeatserver);
	//signal(SIGTERM, unregister_heartbeatserver);
	return;
}

static void usage(void)
{
	const char *cmd = "dms_dev";
	fprintf(stderr,
		"Usage:\n"
		"%s arguments\n"
		"\t-g --dmspath : dms unix path\n"
		"\t-p --serverpath : server path\n"
		"\t-w --wifista_crondtime : check wifi sta crond time\n"
		"\t-z --zigbeesta_crondtime : check zigbee sta crond time\n"
		"\t-d --debuglevel :  set debug level\n"
		"\t-s --syslog :  use syslog \n"
		"\t-h --help : usage help\n"
		"", cmd);

	exit(0);
}

//解析命令字create-env；delete-env；install-app；unstall-app；start-app；stop-app；get-status
static int parse_cmdkey(char *cmd)
{
	if( cmd == NULL ) {
		debug(LOG_ERR, "parse_cmdkey():  cmdkey(%s) is null, exit!", cmd);
		exit(0);		
	}
	
	if( strcmp(cmd,"create-env") == 0 ) {
		G.cmdkey=CREATE_ENV;
	} else if( strcmp(cmd,"delete-env") == 0 ) {
		G.cmdkey=DELETE_ENV;
	} else if( strcmp(cmd,"install-app") == 0 ) {
		G.cmdkey=INSTALL_APP;
	} else if( strcmp(cmd,"unstall-app") == 0 ) {
		G.cmdkey=UNSTALL_APP;
	} else if( strcmp(cmd,"start-app") == 0 ) {
		G.cmdkey=START_APP;
	} else if( strcmp(cmd,"stop-app") == 0 ) {
		G.cmdkey=STOP_APP;
	} else if( strcmp(cmd,"get-status") == 0 ) {
		G.cmdkey=GET_STATUS;
	} else if( strcmp(cmd,"help") == 0 ) {
		usage();
	} else {
		G.cmdkey=INVALID;
	}
	
	if ( G.cmdkey == INVALID ){
		debug(LOG_ERR, "parse_cmdkey():  cmdkey(%s) is invalid, exit!", cmd);
		exit(-1);
	}
	
	return 0;
}


static struct auth_proto* alloc_auth_proto(char* type,char* subtype,char* module,unsigned char* id)
{
	struct auth_proto *ppro;
	
	debug(LOG_ERR, "%s : type(%s),subtype(%s),module(%s),id(%s)",__FUNCTION__,type,subtype,module,id);	
	ppro = (struct auth_proto *)malloc(sizeof(struct auth_proto));
	ppro->type = strdup(type);
	ppro->subtype = strdup(subtype);
	ppro->module = strdup(module);

	if ( strncmp( ppro->module, MODULE_WIFI, strlen(MODULE_WIFI)) == 0 ) {
		ppro->info = (char *)malloc((ETH_CHAR+1)*sizeof(char));
		sprintf(ppro->info,"%02x%02x%02x%02x%02x%02x",id[0],id[1],
				id[2],id[3],id[4],id[5]);		
		ppro->info[ETH_CHAR] = '\0';
		
	} else if ( strncmp( ppro->module, MODULE_ZIGBEE, strlen(MODULE_ZIGBEE)) == 0 ) {
		ppro->info = strdup((char *)id);
		
	} else {
		debug(LOG_ERR, "%s : Can't find module(%s)!",__FUNCTION__,module);
	}
	return ppro;
}

static void free_auth_proto(struct auth_proto *proto)
{
	if(!proto) {
		return;
	}
	if(proto->type) {
		free(proto->type);
	}
	if(proto->subtype) {
		free(proto->subtype);
	}
	if(proto->module) {
		free(proto->module);
	}
	if(proto->info) {
		free(proto->info);
	}	
	free(proto);
}

/** Uses getopt() to parse the command line and set configuration values
 * also populates restartargv
 */
static void parse_commandline(int argc, char **argv) {
	int c;

	//解析参数
	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"cmd", 1, NULL, 'c'},
			{"dmspath", 1, NULL, 'g'},
			{"serverpath", 1, NULL, 'p'},
			{"wifista_crondtime", 1, NULL, 'w'},
			{"zigbeesta_crondtime", 1, NULL, 'z'},
			{"debuglevel", 1, NULL, 'd'},
			{"syslog", 0, NULL, 's'},
			{"help", 0, NULL, 'h'},
			{0, 0, 0, 0}
		};
	
		c = getopt_long(argc, argv, "c:g:p:w:z:d:sh",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'c':
			parse_cmdkey(optarg);
			break;
		case 'g':
			G.dmspath = strdup(optarg);
			break;
		case 'p':
			G.serverpath = strdup(optarg);
			break;
		case 'w':
			G.wifista_crondtime = atoi(optarg);
			break;
		case 'z':
			G.zigbeesta_crondtime = atoi(optarg);
			break;
		case 'd':
			G.debuglevel = atoi(optarg);
			break;
		case 's':
			G.log_syslog = 1;
			break;
		case 'h':
			usage();
			break;	
		default:
		  usage();
		}
	}
	
	return;
}

static void dump_wifista()
{
	struct wifista_record *pos_item;
	/*
	struct auth_proto *ppro;
	pthread_t pth_ids;
	int ret;
	*/
	
	pthread_mutex_lock(&wifista_table_mutex);
	
	printf("dump wifista info \n");
	list_for_each_entry(pos_item, &head_wifista, list) {
		printf("	record : \n");
		printf("	wmac[%02x:%02x:%02x:%02x:%02x:%02x] mark %d wifistate %d\n",
				pos_item->wmac[0],pos_item->wmac[1],pos_item->wmac[2],
				pos_item->wmac[3],pos_item->wmac[4],pos_item->wmac[5],
				pos_item->mark,pos_item->wifistate);
		
		/*
		//pengruofeng debug
		ppro = alloc_auth_proto(TYPE_INFORM,SUBTYPE_ONLINE,MODULE_WIFI,pos_item->wmac);
		ret=pthread_create(&pth_ids,NULL,(void *)auth_thread,(void *)ppro);
		if(ret!=0)
		{
			printf ("Create pthread error!\n");
			exit(1);
		}
		pthread_detach(pth_ids);
		*/
	}
	pthread_mutex_unlock(&wifista_table_mutex);
	printf("dump wifista end \n");
}


static void dump_zigbeesta()
{
	struct zigbeesta_record *pos_item;
	#if 1
	char strBuf[256] = {0};
	#endif
	
	printf("dump zigbeesta info [%x] \n" ,&head_zigbeesta);
	pthread_mutex_lock(&zigbeesta_table_mutex);
	list_for_each_entry(pos_item, &head_zigbeesta, list) {
		printf("	record[%x] : \n",pos_item);
		printf("	zigbeeid[%s, %s] \n", pos_item->ieeeaddr_high,pos_item->ieeeaddr_low);
		
			#if 0
			sprintf(strBuf,"\{\"cmd_url\":\"/zigbeeservice/light\", \"cmd_name\":\"switch\", \"set\":1, \"node\":[%s, %s], \"on\":1\}", pos_item->ieeeaddr_high,pos_item->ieeeaddr_low);
			printf("Send data( %s ) to zigbeeserver.\n",strBuf);
			requestHandler(strBuf);
			
			sleep(5);
			
			sprintf(strBuf,"\{\"cmd_url\":\"/zigbeeservice/light\", \"cmd_name\":\"switch\", \"set\":1, \"node\":[%s, %s], \"on\":0\}", pos_item->ieeeaddr_high,pos_item->ieeeaddr_low);
			printf("Send data( %s ) to zigbeeserver.\n",strBuf);
			requestHandler(strBuf);
			
			sleep(3);
			
			sprintf(strBuf,"\{\"cmd_url\":\"/zigbeeservice/node\", \"cmd_name\":\"status\", \"node\":[%s, %s]\}", pos_item->ieeeaddr_high,pos_item->ieeeaddr_low);
			printf("Send data( %s ) to zigbeeserver.\n",strBuf);
			requestHandler(strBuf);
			#endif
	}
	
		
	pthread_mutex_unlock(&zigbeesta_table_mutex);
	printf("dump zigbeesta end \n");
}

static int get_wifista(RT_802_11_MAC_TABLE *ptable)
{
	int i=0, s;
	struct iwreq iwr;

	debug(LOG_ERR, "%s : check wifi station!",__FUNCTION__);
	s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(iwr.ifr_name, "ra1", IFNAMSIZ);
	iwr.u.data.pointer = (void *) ptable;

	if (s < 0) {
		printf("ioctl sock failed!");
		return -1;
	}

	if (ioctl(s, RTPRIV_IOCTL_GET_MAC_TABLE_STRUCT, &iwr) < 0) {
		close(s);
		return -1;
	}
	
	close(s);
}

static int add_wifista_table(unsigned char *wmac)
{
	struct wifista_record *witem;
	
	witem = (struct wifista_record *)malloc(sizeof(struct wifista_record));
	strncpy((char *)witem->wmac, (char *)wmac, ETH_ALEN);;
	witem->mark = 1;
	witem->wifistate = ONLINE;
	list_add_tail(&witem->list, &head_wifista);

}

static int del_wifista_table(struct wifista_record *record)
{
	list_del(&record->list);
	free(record);
}

static int add_zigbeesta_table(char *sHigh, char *sLow)
{
	struct zigbeesta_record *zitem;

	debug(LOG_ERR, "%s : add [%s-%s] to zigbee table ",__FUNCTION__,sHigh,sLow);
	zitem = (struct zigbeesta_record *)malloc(sizeof(struct zigbeesta_record));
	zitem->ieeeaddr_high=strdup(sHigh);
	zitem->ieeeaddr_low=strdup(sLow);
	zitem->mark = 1;
	zitem->zigbeestate= ZIG_INIT;
	list_add_tail(&zitem->list, &head_zigbeesta);
	zitem->zigbeestate= ZIG_COMING;

}

static int del_zigbeesta_table(struct zigbeesta_record *record)
{
	debug(LOG_ERR, "%s : delete [%s-%s] from zigbee table ",__FUNCTION__,record->ieeeaddr_high,record->ieeeaddr_low);
	list_del(&record->list);
	free(record->ieeeaddr_high);
	free(record->ieeeaddr_low);
	free(record);
}

/* auth_mac格式为 AA:BB:CC:DD:EE:FF */
static void deal_legality(char *auth_mac)
{

	char sys_cmd[128] = {0};
	sprintf(sys_cmd,"iptables -D FORWARD -m mac --mac-source %s -j DROP",auth_mac);
	printf("sys_cmd = %s\n",sys_cmd);
	system(sys_cmd);
	return;
}

/* auth_mac格式为 AA:BB:CC:DD:EE:FF */
static void deal_illegality(char *auth_mac)
{
	char sys_cmd[128] = {0};
	sprintf(sys_cmd,"iptables -D FORWARD -m mac --mac-source %s -j DROP",auth_mac);
	printf("sys_cmd = %s\n",sys_cmd);
	system(sys_cmd);
	sprintf(sys_cmd,"iptables -A FORWARD -m mac --mac-source %s -j DROP",auth_mac);
	printf("sys_cmd = %s\n",sys_cmd);
	system(sys_cmd);
	return;
}



/* auth_mac格式为 AA:BB:CC:DD:EE:FF */
static void deal_offline(char *auth_mac)
{
	char sys_cmd[128] = {0};
	sprintf(sys_cmd,"iptables -D FORWARD -m mac --mac-source %s -j DROP",auth_mac);
	printf("sys_cmd = %s\n",sys_cmd);
	system(sys_cmd);
	return;
}

static void set_zigrecord_sm(char* sHigh,char* sLow,enum ZigbeeStaSM sm)
{
	struct zigbeesta_record *pos_item;
	int exist = 0;
	/* 判断队列中zigbee设备是否继续在线，在线则mark置为1，不在线需要踢出用户 */
	pthread_mutex_lock(&zigbeesta_table_mutex);
	list_for_each_entry(pos_item, &head_zigbeesta, list) {
		if ( strncmp((char *)pos_item->ieeeaddr_high, sHigh, strlen(pos_item->ieeeaddr_high)) == 0 && 
			strncmp((char *)pos_item->ieeeaddr_low, sLow, strlen(pos_item->ieeeaddr_low)) == 0) {
			pos_item->zigbeestate = sm;
			break;
		}
	}
	pthread_mutex_unlock(&zigbeesta_table_mutex);

	return;

}

static void deal_zigbee_legality(char *zigbee_id)
{
	debug(LOG_ERR, "%s : [ %s ] Turn on light .... ",__FUNCTION__,zigbee_id);
	char sHigh[16] = {0};
	char sLow[16] = {0};

	sscanf(zigbee_id, "%[^+]+%s",sHigh, sLow);
	set_zigrecord_sm(sHigh,sLow,ZIG_ONLINE);
	return;
}


static void deal_zigbee_illegality(char *zigbee_id)
{	
	char sHigh[16] = {0};
	char sLow[16] = {0};
	char strBuf[100] = {0};
	char *response;
			
	sscanf(zigbee_id, "%[^+]+%s",sHigh, sLow);	

	set_zigrecord_sm(sHigh,sLow,ZIG_LEAVE);	
	
	sprintf(strBuf,"\{\"cmd_url\":\"/zigbeeservice/node\", \"cmd_name\":\"remove\", \"node\":[%s, %s], \"force\":1\}",sHigh, sLow);
    response = requestHandler(strBuf);
	//cJSON *pJson = cJSON_Parse(response);
	free(response);
	return;
}


static void zigbee_turnon(char *zigbee_id)
{
	char sHigh[16] = {0};
	char sLow[16] = {0};
	char strBuf[256] = {0};
	char *response;
	
	debug(LOG_ERR, "%s : [ %s ].... ",__FUNCTION__,zigbee_id);
	
	sscanf(zigbee_id, "%[^+]+%s",sHigh, sLow);	
	sprintf(strBuf,"\{\"cmd_url\":\"/zigbeeservice/light\", \"cmd_name\":\"switch\", \"set\":1, \"node\":[%s, %s], \"on\":1\}", sHigh, sLow);
	debug(LOG_ERR, "%s : send zigbee message : %s",__FUNCTION__,strBuf);
	response = requestHandler(strBuf);
	//cJSON *pJson = cJSON_Parse(response);
	free(response);
	return;
}

static void zigbee_turnoff(char *zigbee_id)
{
	char sHigh[16] = {0};
	char sLow[16] = {0};
	char strBuf[256] = {0};
	char *response;
	
	debug(LOG_ERR, "%s : [ %s ].... ",__FUNCTION__,zigbee_id);

	sscanf(zigbee_id, "%[^+]+%s",sHigh, sLow);	
	sprintf(strBuf,"\{\"cmd_url\":\"/zigbeeservice/light\", \"cmd_name\":\"switch\", \"set\":1, \"node\":[%s, %s], \"on\":0\}", sHigh, sLow);
	response = requestHandler(strBuf);
	//cJSON *pJson = cJSON_Parse(response);
	free(response);
	return;
}



void auth_thread(void *data)
{
	int connect_fd;
	struct sockaddr_un srv_addr;
	char snd_buf[1024] = {0};
	char rev_buf[1024] =  {0};
	int ret, i ,rev_num;
	fd_set read_fds;
	struct timeval tv;

	//char auth_subtype[16] = {0};
	char auth_mac[32] = {0};
	char auth_ret[32] = {0};
	
	struct auth_proto* proto = (struct auth_proto*)data;

	//create client socket
	connect_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if(connect_fd < 0)
	{
		perror("client create socket failed");
		exit(1);
	}

	//set server sockaddr_un
	srv_addr.sun_family = AF_UNIX;
	strcpy(srv_addr.sun_path, G.dmspath);

	/* 连接dms服务器，进行验证工作 */
	ret = connect(connect_fd, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
	if(ret == -1)
	{
		perror("connect to server failed!");
		close(connect_fd);
		//unlink(G.dmspath);
		exit(1);
	}
	
	memset(snd_buf, '\0', 1024);
	sprintf(snd_buf,"type=%s;subtype=%s;module=%s;info=%s",proto->type,proto->subtype,proto->module,proto->info);
	debug(LOG_ERR, "%s : [ %s ] send auth mesagee : %s ",__FUNCTION__,proto->info,snd_buf);
 
	/* 
	发送认证消息；
	协议格式：type=inform;subtype=online（或offline）;module=wifi(或zigbee);info=终端mac地址 
	*/
	write(connect_fd, snd_buf, sizeof(snd_buf));
	
	FD_ZERO(&read_fds);
	FD_SET(connect_fd, &read_fds);
	// timeout setting
	tv.tv_sec = G.wifista_recv_timeout;
	tv.tv_usec = 0;


	ret = select(connect_fd + 1, &read_fds, NULL, NULL, &tv);
	if (ret < 0) {
		printf("select");
		
	/* select 超时 */
	} 
	else if (ret == 0) {
		if ( strncmp(proto->subtype, "online", strlen("online")) == 0 ) {
			if ( strncmp( proto->module, MODULE_WIFI, strlen(MODULE_WIFI)) == 0 ) {
				sprintf(auth_mac,"%c%c:%c%c:%c%c:%c%c:%c%c:%c%c",proto->info[0],proto->info[1],proto->info[2],proto->info[3],
						proto->info[4],proto->info[5],proto->info[6],proto->info[7],proto->info[8],proto->info[9],
						proto->info[10],proto->info[11]);
				debug(LOG_ERR, "%s : [%s] recv auth mesagee time out, default deal_illegality",__FUNCTION__,auth_mac);
				deal_illegality(auth_mac);
						
			} else if ( strncmp( proto->module, MODULE_ZIGBEE, strlen(MODULE_ZIGBEE)) == 0 ) {
				debug(LOG_ERR, "%s : [%s] recv auth mesagee time out, default deal_zigbee_illegality",__FUNCTION__,proto->info);
				deal_zigbee_illegality(proto->info);
				
			} else {
				debug(LOG_ERR, "%s : Can't find module(%s)!",__FUNCTION__,proto->module);
			}
		} 
		else if ( strncmp(proto->subtype, "offline", strlen("offline")) == 0 ) {
			if ( strncmp( proto->module, MODULE_WIFI, strlen(MODULE_WIFI)) == 0 ) {
				sprintf(auth_mac,"%c%c:%c%c:%c%c:%c%c:%c%c:%c%c",proto->info[0],proto->info[1],proto->info[2],proto->info[3],
						proto->info[4],proto->info[5],proto->info[6],proto->info[7],proto->info[8],proto->info[9],
						proto->info[10],proto->info[11]);
				deal_offline(auth_mac);
			}
			else if ( strncmp( proto->module, MODULE_ZIGBEE, strlen(MODULE_ZIGBEE)) == 0 ) {
				debug(LOG_ERR, "%s : Nothing!",__FUNCTION__);
			} 
			else {
				debug(LOG_ERR, "%s : Can't find module(%s)!",__FUNCTION__,proto->module);
			}
		} 
		else {
			debug(LOG_ERR, "%s : Nothing!",__FUNCTION__);
		}
	
	/* select接收到消息 */
	}
	else {	
	
		/* 
		接收认证消息；
		协议格式：type=inform;subtype=online（或offline）;module=wifi(或zigbee);info=终端mac地址;result=legality（或illegality） 
		*/
		rev_num = read(connect_fd, rev_buf, sizeof(rev_buf));
		if( rev_num < 0 ) {
			debug(LOG_ERR, "%s : [Fail] recv auth data is null !",__FUNCTION__);
		}
		debug(LOG_ERR, "%s : [ %s ] recv auth mesagee : %s ",__FUNCTION__,proto->info,rev_buf);
		//sscanf(rev_buf,"%*[^;];subtype=%[^;];%*[^;];info=%[^;];result=%s",auth_subtype, auth_mac, auth_ret);
		sscanf(rev_buf,"%*[^;];%*[^;];info=%[^;];result=%s",auth_mac, auth_ret);

		if ( strncmp(auth_mac, proto->info, strlen(proto->info)) !=0 ) {
			debug(LOG_ERR, "%s : [Fail] auth mac and recv mac is mismatch!",__FUNCTION__);
			goto exit;
		}
		
		/* wifi模块下，转换auth_mac格式 */
		if ( strncmp( proto->module, MODULE_WIFI, strlen(MODULE_WIFI)) == 0 ) {
			sprintf(auth_mac,"%c%c:%c%c:%c%c:%c%c:%c%c:%c%c",proto->info[0],proto->info[1],proto->info[2],proto->info[3],
					proto->info[4],proto->info[5],proto->info[6],proto->info[7],proto->info[8],proto->info[9],
					proto->info[10],proto->info[11]);					
		}
		
		/* 处理online */
		if ( strncmp(proto->subtype, "online", strlen("online")) == 0 ) {
			if ( strncmp(auth_ret, "legality", strlen("legality")) == 0 ) {
				if ( strncmp( proto->module, MODULE_WIFI, strlen(MODULE_WIFI)) == 0 ) {
					deal_legality(auth_mac);
				} else {
					deal_zigbee_legality(proto->info);
					zigbee_turnon(proto->info);
				}
				
			} else if( strncmp(auth_ret, "illegality", strlen("illegality")) == 0 ) {
				if ( strncmp( proto->module, MODULE_WIFI, strlen(MODULE_WIFI)) == 0 ) {
					deal_illegality(auth_mac);
				} else {
					deal_zigbee_illegality(proto->info);
				}
				
			} else {
				debug(LOG_ERR, "%s : [Fail] parse auth result!",__FUNCTION__);
			}
			
		/* 处理offline */
		} else if ( strncmp(proto->subtype, "offline", strlen("offline")) ==0 && strncmp(auth_ret, "ok", strlen("ok")) == 0 ) {
			if ( strncmp( proto->module, MODULE_WIFI, strlen(MODULE_WIFI)) == 0 ) {
				deal_offline(auth_mac);
			} else {
			}		

		/* 错误:  发送的subtype与接收subtype不一致 */
		} else {
			debug(LOG_ERR, "%s : [Fail] auth_mac[%s] ; proto->subtype[%s]",__FUNCTION__,auth_mac,proto->subtype);
		}
		
	}

exit:
	close(connect_fd);
	free_auth_proto(proto);
}

static int process_wifista()
{
	int i=0, ret;
	int exist_dev;
	RT_802_11_MAC_TABLE table = {0};
	struct wifista_record *pos_item;
	struct wifista_record *pos_next_item;
	pthread_t pth_ids;
	struct auth_proto *ppro;
	
	//获取客户端列表
	if ( get_wifista(&table) < 0 ) {
		debug(LOG_ERR, "%s : [Fail] get wifi station list !",__FUNCTION__);
	}

	
	/* head_wifista列表中mark置为0，可能已经离开网络 */
	pthread_mutex_lock(&wifista_table_mutex);
	list_for_each_entry(pos_item, &head_wifista, list) {
		pos_item->mark = 0;
	}
	pthread_mutex_unlock(&wifista_table_mutex);
	
	/* 是否有新终端加入到网络中 */
	debug(LOG_ERR, "%s : There is %d sta in stalist",__FUNCTION__,table.Num);
	for (i = 0; i < table.Num; i++) {
		exist_dev = 0;
		
		pthread_mutex_lock(&wifista_table_mutex);
		list_for_each_entry(pos_item, &head_wifista, list) {
			if ( strncmp((char *)pos_item->wmac, (char *)table.Entry[i].Addr, ETH_ALEN) == 0 ) {
				pos_item->mark = 1;
				exist_dev = 1;
				break;
			}
		}
		pthread_mutex_unlock(&wifista_table_mutex);
		
		
		if (!exist_dev) {
			debug(LOG_ERR, "%s : new sta coming , mac is %02x:%02x:%02x:%02x:%02x:%02x ",__FUNCTION__,
			table.Entry[i].Addr[0], table.Entry[i].Addr[1],
			table.Entry[i].Addr[2], table.Entry[i].Addr[3],
			table.Entry[i].Addr[4], table.Entry[i].Addr[5]);
			add_wifista_table(table.Entry[i].Addr);
			
			/* 新终端上线进行验证工作 */
			debug(LOG_ERR, "%s : create auth_thread",__FUNCTION__);			
			ppro = alloc_auth_proto(TYPE_INFORM,SUBTYPE_ONLINE,MODULE_WIFI,table.Entry[i].Addr);
			ret=pthread_create(&pth_ids,NULL,(void *)auth_thread,(void *)ppro);
			if(ret!=0)
			{
				printf ("Create pthread error!\n");
				exit(1);
			}
			pthread_detach(pth_ids);
		}
	}
	
	pthread_mutex_lock(&wifista_table_mutex);
	/* 删除不存在客户端列表的用户 */
	list_for_each_entry_safe(pos_item, pos_next_item, &head_wifista, list) {
		if ( pos_item->mark == 0 ) {
			debug(LOG_ERR, "%s : one sta leaving , mac is %02x:%02x:%02x:%02x:%02x:%02x ",__FUNCTION__,
			pos_item->wmac[0], pos_item->wmac[1],
			pos_item->wmac[2], pos_item->wmac[3],
			pos_item->wmac[4], pos_item->wmac[5]);
			//del_wifista_table(pos_item);
			
			/* 新终端下线通知dms */
			debug(LOG_ERR, "%s : create auth_thread for del one station",__FUNCTION__);			
			ppro = alloc_auth_proto(TYPE_INFORM,SUBTYPE_OFFLINE,MODULE_WIFI,pos_item->wmac);
			ret=pthread_create(&pth_ids,NULL,(void *)auth_thread,(void *)ppro);
			if(ret!=0)
			{
				printf ("Create pthread error!\n");
				exit(1);
			}
			pthread_detach(pth_ids);

			/* 从列表中删除*/
			del_wifista_table(pos_item);
		}
	}
	pthread_mutex_unlock(&wifista_table_mutex);
	
	dump_wifista();
	return 0;
}


void debug_thread(void *data)
{
	#if 1
	int connect_fd;
	struct sockaddr_un srv_addr;
	char snd_buf[1024];
	char rev_buf[1024];
	int ret, rev_num, i;
	
	//create client socket
	connect_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if(connect_fd < 0)
	{
		perror("client create socket failed");
		exit(1);
	}

	//set server sockaddr_un
	srv_addr.sun_family = AF_UNIX;
	strcpy(srv_addr.sun_path, "/tmp/DMS_UNIX.domain");

	//connect to server
	ret = connect(connect_fd, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
	if(ret == -1)
	{
		perror("connect to server failed!");
		close(connect_fd);
		exit(1);
	}
	
	memset(snd_buf, '\0', 1024);
	sprintf(snd_buf,"message from client[%d] [%d]",getpid(),pthread_self());
	printf("send data : %s \n",snd_buf);
	write(connect_fd, snd_buf, sizeof(snd_buf));
	sleep(20);
	rev_num = read(connect_fd, rev_buf, sizeof(rev_buf));
	if( rev_num < 0 ) {
		debug(LOG_ERR, "%s : [Fail] recv auth data is null !",__FUNCTION__);
	}	
	printf("rev data : %s\n",rev_buf);
	close(connect_fd);
	pthread_exit(0);
	#endif
}

static int debug_zigbeesta()
{
	pthread_t ptid= 0;
	int ret = 0;
	void *status;

	printf("Create thread thread_crond!!\n");
	ret = pthread_create(&ptid, NULL, (void *)debug_thread, NULL);
	if (ret != 0) {
	    printf("FATAL: Failed to create a new thread (crond) - exiting");
		exit(1);
	}

	#if 1
	printf("pthread_join(ptid,&status) ptid(%d),pthread_self(%d)............. \n",ptid,pthread_self());
	if (pthread_join(ptid,&status)!=0){
		printf(" wait for crond thread!\n");
		return;
	}
	#endif
	
	#if 0
	printf("pthread_detach(ptid) ptid(%d),pthread_self(%d)............. \n",ptid,pthread_self());
	pthread_detach(ptid);
	#endif
	
	#if 1
	int kill_rc = pthread_kill(ptid,0);

	if(kill_rc == ESRCH)
		printf("the specified thread did not exists or already quit\n");
	else if(kill_rc == EINVAL)
		printf("signal is invalid\n");
	else {
		printf("the specified thread is alive , kill pthread\n");
		//pthread_kill(ptid,SIGQUIT);
		//printf("the specified thread is alive , kill pthread pthread_self\n");
		//pthread_kill(pthread_self(),SIGQUIT);
	}
	
	sleep(5);

	int kill_rc1 = pthread_kill(ptid,0);

	if(kill_rc1 == ESRCH)
		printf("1 the specified thread did not exists or already quit\n");
	else if(kill_rc == EINVAL)
		printf("1 signal is invalid\n");
	else {
		printf("1 the specified thread is alive , kill pthread\n");
		//pthread_kill(ptid,SIGQUIT);
		//printf("the specified thread is alive , kill pthread pthread_self\n");
		//pthread_kill(pthread_self(),SIGQUIT);
	}	
	#endif
	
	return 0;
}

static void clear_zigbee_mark()
{
	struct zigbeesta_record *pos_item;
	
	pthread_mutex_lock(&zigbeesta_table_mutex);
	list_for_each_entry(pos_item, &head_zigbeesta, list) {
		pos_item->mark = 0;
	}
	pthread_mutex_unlock(&zigbeesta_table_mutex);	
}

/* zigbeeserver返回zigbee设备结点，数据为json格式，信息如下
	{
		"cmd_url":      "/zigbeeservice/node",
		"cmd_name":     "enum",
		"result":       0,
		"extra":        {
				"value":        [{
								"index":        -1,
								"ieeeaddr":     [254509099, 5260233],
								"shortaddr":    56172,
								"status":       2,
								"category":     1,
								"subcategory":  15,
								"alias":        "Unknown",
								"description":  "ct_color_light",
								"version":      "0.0.0.0"
						}]
		}
	}
*/

static cJSON* get_zigbeesta_jsonarray(cJSON *pJson)
{
	cJSON *pExtraSub;
	cJSON *pValueSub;
	char *p;
	
	if (!pJson) {
		return NULL;
	}
	
	pExtraSub = cJSON_GetObjectItem(pJson, "extra");	
	p = cJSON_Print(pExtraSub);
	if( strncmp(p,"null",strlen("null")) == 0 ) {
		free(p);
		return NULL;
	}
	free(p);
	
	pValueSub = cJSON_GetObjectItem(pExtraSub, "value");
	p = cJSON_Print(pValueSub);
	//printf("p = %s \n",p);
	if( strncmp(p,"null",strlen("null")) == 0 ) {
		free(p);
		return NULL;
	}	
	free(p);
	return pValueSub;
	
	/*
	p = cJSON_Print(pJson);
	printf("p = %s \n",p);
	free(p);

	cJSON *pExtraSub = cJSON_GetObjectItem(pJson, "extra");	
	p = cJSON_Print(pExtraSub);
	printf("p = %s \n",p);
	free(p);
	

	
	cJSON *pValueSub = cJSON_GetObjectItem(pExtraSub, "value");
	p = cJSON_Print(pValueSub);
	printf("p = %s \n",p);
	free(p);
	*/	
}

/* 判断队列中zigbee设备是否继续在线，在线则mark置为1*/
static int zigbeesta_in_table(char *sHigh, char *sLow)
{
	struct zigbeesta_record *pos_item;
	int exist = 0;
	/* 判断队列中zigbee设备是否继续在线，在线则mark置为1，不在线需要踢出用户 */
	pthread_mutex_lock(&zigbeesta_table_mutex);
	list_for_each_entry(pos_item, &head_zigbeesta, list) {
		if ( strncmp((char *)pos_item->ieeeaddr_high, sHigh, strlen(pos_item->ieeeaddr_high)) == 0 && 
			strncmp((char *)pos_item->ieeeaddr_low, sLow, strlen(pos_item->ieeeaddr_low)) == 0 &&
			pos_item->zigbeestate != ZIG_LEAVE ) {
			pos_item->mark = 1;
			exist = 1;
			break;
		}			
	}
	pthread_mutex_unlock(&zigbeesta_table_mutex);
	
	return exist;
}


/* 判断队列中wifi设备是在列表中*/
static int wifista_in_table(char *wifimac)
{
	struct wifista_record *pos_item;
	char auth_mac[20] = {0};
	int exist = 0;

	pthread_mutex_lock(&wifista_table_mutex);
	list_for_each_entry(pos_item, &head_wifista, list) {
		sprintf(auth_mac,"%02x%02x%02x%02x%02x%02x",pos_item->wmac[0],pos_item->wmac[1],pos_item->wmac[2],
				pos_item->wmac[3],pos_item->wmac[4],pos_item->wmac[5]);
		
		debug(LOG_ERR, "%s : auth_mac(%s),wifimac(%s)",__FUNCTION__,auth_mac,wifimac);
		if ( strncmp((char *)auth_mac, wifimac, strlen(wifimac)) == 0 ) {
			exist = 1;
			break;
		}
	}
	
	pthread_mutex_unlock(&wifista_table_mutex);

	return exist;
}


/*   */
static int zigbee_send_connect()
{
	char strBuf[100]="\{\"cmd_url\":\"/zigbeeservice/gateway\", \"cmd_name\":\"connect\"\}";
    char *cgivars = strBuf;
	char *response;
	
    if (cgivars != NULL) {
		//dms_client_init();
		//dms_client_connect();
		printf("Send data to zigbeeserver.\n");
		//response = dms_requestHandler(cgivars);
        response = requestHandler(cgivars);
		free(response);
	}
	return 0;
}


/* 判断队列中zigbee设备是否继续在线，在线则mark置为1*/
static int zigbee_send_permit()
{
	char strBuf[100]="\{\"cmd_url\":\"/zigbeeservice/gateway\", \"cmd_name\":\"permitjoin\", \"timeout\":120\}";
    char *cgivars = strBuf;
	char *response;
	
    if (cgivars != NULL) {
		//dms_client_init();
		//dms_client_connect();
		printf("Send data to zigbeeserver.\n");
		//response = dms_requestHandler(cgivars);
        response = requestHandler(cgivars);
		free(response);
	}
	return 0;
}


/* BUG: 智能灯加入zigbee server中后会行程一个节点，但无论智能灯上下电，这个节点状态一直都是online，因此我们必须对灯进行配置，如果result返回非0，表示灯未插上
判断状态时未在线的，mark置为0 */
#if 0
static int check_zigbeesta_status() 
{
	struct zigbeesta_record *pos_item;
	
	pthread_mutex_lock(&zigbeesta_table_mutex);
	list_for_each_entry(pos_item, &head_zigbeesta, list) {
		char sHigh[16] = {0};
		char sLow[16] = {0};
	
		strncpy(sHigh,pos_item->ieeeaddr_high,strlen(pos_item->ieeeaddr_high));
		strncpy(sLow,pos_item->ieeeaddr_low,strlen(pos_item->ieeeaddr_low));
		if ( pos_item->mark == 1 ) {
			char strBuf[256] = {0};
			char *response;
			char *pStrLevel;
			int iLevel;
			char sZigbeeId[32] = {0};
			cJSON * pLevel = NULL;
			
			sprintf(strBuf,"\{\"cmd_url\":\"/zigbeeservice/light\", \"cmd_name\":\"level\", \"set\":1, \"node\":[%s, %s], \"level\":200, \"transtime\":0\}", sHigh, sLow);


			response = requestHandler(strBuf);
			pLevel = cJSON_Parse(response);
			free(response);
			
			cJSON *pRet = cJSON_GetObjectItem(pLevel, "result");
			pStrLevel = cJSON_Print(pRet);
			sscanf(pStrLevel,"%d",&iLevel);
			
			free(pStrLevel);
			cJSON_Delete(pLevel);
			
			if(iLevel){
				pos_item->mark = 0;
			}
		}
	}
	pthread_mutex_unlock(&zigbeesta_table_mutex);
	return 0;
}

#else
/*   恩辅改了灯的状态，待验证 */
static int check_zigbeesta_status() 
{
	struct zigbeesta_record *pos_item;
	
	pthread_mutex_lock(&zigbeesta_table_mutex);
	list_for_each_entry(pos_item, &head_zigbeesta, list) {
		char sHigh[16] = {0};
		char sLow[16] = {0};
	
		strncpy(sHigh,pos_item->ieeeaddr_high,strlen(pos_item->ieeeaddr_high));
		strncpy(sLow,pos_item->ieeeaddr_low,strlen(pos_item->ieeeaddr_low));
		if ( pos_item->mark == 1 ) {
			char strBuf[256] = {0};
			char *response;
			char *pStrLevel;
			int iLevel;
			char sZigbeeId[32] = {0};
			cJSON * pLevel = NULL;
			
			sprintf(strBuf,"\{\"cmd_url\":\"/zigbeeservice/node\", \"cmd_name\":\"status\", \"node\":[%s, %s] \}", sHigh, sLow);


			response = requestHandler(strBuf);
			pLevel = cJSON_Parse(response);
			free(response);
			
			cJSON *pRet = cJSON_GetObjectItem(pLevel, "result");
			pStrLevel = cJSON_Print(pRet);
			sscanf(pStrLevel,"%d",&iLevel);
			
			free(pStrLevel);
			cJSON_Delete(pLevel);

			if ((iLevel == 0 || iLevel == 3) && ZIG_ONLINE == pos_item->zigbeestate) {
				char zigbee_id[32];
				
				send_zigbeesta_offlinemsg(sHigh,sLow);
				pos_item->zigbeestate= ZIG_OFFLINE;

				sprintf(zigbee_id,"%s+%s",sHigh,sLow);
				debug(LOG_ERR, "%s : [ %s ] Turn off light ...",__FUNCTION__,zigbee_id);
				zigbee_turnoff(zigbee_id);

			}
			
			if ( 2 == iLevel && (ZIG_COMING == pos_item->zigbeestate|| ZIG_OFFLINE== pos_item->zigbeestate)) {
				send_zigbeesta_onlinemsg(sHigh,sLow);
				//pos_item->wifistate = ZIG_ONLINE;
			}

			/*
			if(iLevel == 0 || iLevel == 3){
				//pos_item->mark = 0;
				send_zigbeesta_offlinemsg(sHigh,sLow);
			} else (
				send_zigbeesta_onlinemsg(sHigh,sLow);
			)
			*/
		}
	}
	pthread_mutex_unlock(&zigbeesta_table_mutex);
	return 0;
}
#endif

static void send_zigbeesta_onlinemsg(char* sHigh,char* sLow)
{
	char zigbee_id[32];
	struct auth_proto *ppro;
	pthread_t pth_ids;
	int ret;

	//新终端上线进，发送消息至dms server进行认证工作
	debug(LOG_ERR, "%s : create new thread , one zigbee sta(%s-%s) join ",__FUNCTION__,sHigh,sLow);
	sprintf(zigbee_id,"%s+%s",sHigh,sLow);
	ppro = alloc_auth_proto(TYPE_INFORM,SUBTYPE_ONLINE,MODULE_ZIGBEE,(unsigned char *)zigbee_id);
	ret=pthread_create(&pth_ids,NULL,(void *)auth_thread,(void *)ppro);
	if(ret!=0)
	{
		printf ("Create pthread error!\n");
		exit(1);
	}
	pthread_detach(pth_ids);

	return;
}

static void send_zigbeesta_offlinemsg(char* sHigh,char* sLow)
{
	char zigbee_id[32];
	struct auth_proto *ppro;
	pthread_t pth_ids;
	int ret;

	/* 通知dms server节点下线消息 */
	debug(LOG_ERR, "%s : create new thread, one zigbee sta(%s+%s) leaving ",__FUNCTION__,sHigh,sLow);
	sprintf(zigbee_id,"%s+%s",sHigh,sLow);
	ppro = alloc_auth_proto(TYPE_INFORM,SUBTYPE_OFFLINE,MODULE_ZIGBEE,zigbee_id);
	ret=pthread_create(&pth_ids,NULL,(void *)auth_thread,(void *)ppro);
	if(ret!=0)
	{
		printf ("Create pthread error!\n");
		exit(1);
	}
	pthread_detach(pth_ids);

	return;
}


static int process_zigbeesta()
{
	int i=0, ret;
	int exist_dev;
	struct zigbeesta_record *pos_item = NULL;
	struct zigbeesta_record *pos_next_item = NULL;
	pthread_t pth_ids;
	struct auth_proto *ppro;
	char *p;
	
	/* send permit join msg */
	zigbee_send_permit();

#if 1
	/* 在zigbee设备队列的mark置为0，重新判断是否这些设备还在线  */
	clear_zigbee_mark();
	
	char strBuf[256]={0};
	cJSON *pJson;	
	cJSON *pZigStaJson;

#if 1
	char *response;
	sprintf(strBuf,"\{\"cmd_url\":\"/zigbeeservice/node\", \"cmd_name\":\"enum\", \"category\":0\}");
    response = requestHandler(strBuf);
#else
    char response[2048] = "{ \n\
        \"cmd_url\":      \"/zigbeeservice/node\", \n\
        \"cmd_name\":     \"enum\",\n\
        \"result\":       0,\n\
        \"extra\":        {\n\
                \"value\":        [{\n\
                                \"index\":        -1,\n\
                                \"ieeeaddr\":     [-1624499832, 5260233],\n\
                                \"shortaddr\":    720,\n\
                                \"status\":       2,\n\
                                \"category\":     1,\n\
                                \"subcategory\":  15,\n\
                                \"alias\":        \"Unknown\",\n\
                                \"description\":  \"ct_color_light\",\n\
                                \"version\":      \"0.0.0.0\"\n\
                        }, {\n\
                                \"index\":        -1,\n\
                                \"ieeeaddr\":     [-1624499832, 5260233],\n\
                                \"shortaddr\":    720,\n\
                                \"status\":       2,\n\
                                \"category\":     1,\n\
                                \"subcategory\":  15,\n\
                                \"alias\":        \"Unknown\",\n\
                                \"description\":  \"ct_color_light\",\n\
                                \"version\":      \"0.0.0.0\"\n\
                        }]\n\
        }\n\
}";

	printf(" response = %s \n",response);
#endif
	pJson = cJSON_Parse(response);
	free(response);
	pZigStaJson = get_zigbeesta_jsonarray(pJson);
	
	if (pZigStaJson)
	{
		int iSize = cJSON_GetArraySize(pZigStaJson);
		int iCnt = 0;
		/* 轮询从zigbee server上获取的节点信息 */
		for(iCnt = 0; iCnt < iSize; iCnt++)
		{
			char sHigh[16] = {0};
			char sLow[16] = {0};
			exist_dev = 0;
			cJSON * pNodeSub = cJSON_GetArrayItem(pZigStaJson, iCnt);
			if(NULL == pNodeSub)
			{
				continue;
			}
			
			cJSON *pIeeeaddrSub = cJSON_GetObjectItem(pNodeSub, "ieeeaddr");
			p = cJSON_Print(pIeeeaddrSub);
			sscanf(p,"[%[^,], %[^]]",sHigh,sLow);
			free(p);
			
			/* 从zigbee server获取的节点是否在zigbee table中 ， 存在的话则mark置为1 */
			exist_dev = zigbeesta_in_table(sHigh, sLow);
			
			/* 得到是新节点，则加入到zigbee table中 */
			if (!exist_dev) {
				char zigbee_id[32];
				void *status;
				
				/* 将新终端加入到zigbee table中 */
				add_zigbeesta_table(sHigh,sLow);			
#if 0				
				//新终端上线进，发送消息至dms server进行认证工作
				debug(LOG_ERR, "%s : create new thread , one zigbee sta(%s-%s) join ",__FUNCTION__,sHigh,sLow);
				sprintf(zigbee_id,"%s+%s",sHigh,sLow);
				ppro = alloc_auth_proto(TYPE_INFORM,SUBTYPE_ONLINE,MODULE_ZIGBEE,(unsigned char *)zigbee_id);
				ret=pthread_create(&pth_ids,NULL,(void *)auth_thread,(void *)ppro);
				if(ret!=0)
				{
					printf ("Create pthread error!\n");
					exit(1);
				}
				pthread_detach(pth_ids);
#endif
			}		
		} 
	}
	cJSON_Delete(pJson);

	/* BUG: 智能灯加入zigbee server中后会行程一个节点，但无论智能灯上下电，这个节点状态一直都是online，因此我们必须对灯进行配置，如果result返回非0，表示灯未插上 */
	check_zigbeesta_status();

	/* zigbee table中已下线设备做下线处理 */
	pthread_mutex_lock(&zigbeesta_table_mutex);
	list_for_each_entry_safe(pos_item, pos_next_item, &head_zigbeesta, list){
		if ( pos_item->mark == 0 ) {
#if 0
			char zigbee_id[32];
			pthread_t pid_temp;
			struct auth_proto *pProto;
			char sHigh[16] = {0};
			char sLow[16] = {0};
						
			strncpy(sHigh,pos_item->ieeeaddr_high,strlen(pos_item->ieeeaddr_high));
			strncpy(sLow,pos_item->ieeeaddr_low,strlen(pos_item->ieeeaddr_low));
	
			/* 将新终端加入到zigbee table中 */	
			del_zigbeesta_table(pos_item);

			/* 通知dms server节点下线消息 */
			debug(LOG_ERR, "%s : create new thread, one zigbee sta(%s+%s) leaving ",__FUNCTION__,sHigh,sLow);
			sprintf(zigbee_id,"%s+%s",sHigh,sLow);
			pProto = alloc_auth_proto(TYPE_INFORM,SUBTYPE_OFFLINE,MODULE_ZIGBEE,zigbee_id);
			ret=pthread_create(&pid_temp,NULL,(void *)auth_thread,(void *)pProto);
			if(ret!=0)
			{
				printf ("Create pthread error!\n");
				exit(1);
			}
			pthread_detach(pid_temp);
			
			/* 从zigbee server中删除节点信息 */
			deal_zigbee_illegality(zigbee_id);
#else

			/* 将新终端从zigbee table中删除 */
			del_zigbeesta_table(pos_item);
			
#endif
		}
	}
	pthread_mutex_unlock(&zigbeesta_table_mutex);
#endif
	dump_zigbeesta();
	return 0;
}

void thread_wificrond(void *arg)
{
	pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct	timespec timeout;
	
	while (1) {
		process_wifista();
		/* Sleep for config.crondinterval seconds... */
		timeout.tv_sec = time(NULL) + G.wifista_crondtime;
		timeout.tv_nsec = 0;
	
		/* Mutex must be locked for pthread_cond_timedwait... */
		pthread_mutex_lock(&cond_mutex);
		
		/* Thread safe "sleep" */
		pthread_cond_timedwait(&cond, &cond_mutex, &timeout);

		/* No longer needs to be locked */
		pthread_mutex_unlock(&cond_mutex);
	}
}

void thread_zigbeecrond(void *arg)
{
	pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct	timespec timeout;

	/* send permit connect msg */
	zigbee_send_connect();
	
	while (1) {
		process_zigbeesta();
		/* Sleep for config.crondinterval seconds... */
		timeout.tv_sec = time(NULL) + G.zigbeesta_crondtime;
		timeout.tv_nsec = 0;
	
		/* Mutex must be locked for pthread_cond_timedwait... */
		pthread_mutex_lock(&cond_mutex);
		
		/* Thread safe "sleep" */
		pthread_cond_timedwait(&cond, &cond_mutex, &timeout);

		/* No longer needs to be locked */
		pthread_mutex_unlock(&cond_mutex);
	}
}


void thread_controlcrond(void *arg)
{
	int client_fd[BACKLOG] = {0};    // accepted connection fd
	int conn_amount = 0;	  // current connection amount
	int listen_fd, new_fd;
	struct sockaddr_un srv_addr;
	struct sockaddr_un clt_addr;
	socklen_t clt_len;

	int ret;
	int i;
	char rev_buf[BUF_SIZE];
	char snd_buf[BUF_SIZE];

	/*  prevent pipe broken */
	signal(SIGPIPE,SIG_IGN);

	//create socket to bind local IP and PORT
	listen_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if(listen_fd < 0)
	{
		debug(LOG_ERR, "%s : can't create communication socket! ",__FUNCTION__);
		return;
	}


	//create local IP and PORT
	srv_addr.sun_family = AF_UNIX;
	strncpy(srv_addr.sun_path, SERVER_UNIX_DOMAIN, sizeof(srv_addr.sun_path) - 1);
	unlink(SERVER_UNIX_DOMAIN);

	//bind sockfd and sockaddr
	ret = bind(listen_fd, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
	if(ret == -1)
	{
		debug(LOG_ERR, "%s : can't bind local sockaddr! ",__FUNCTION__);
		close(listen_fd);
		unlink(SERVER_UNIX_DOMAIN);
		return;
	}



	//listen listen_fd, try listen 1
	ret = listen(listen_fd, BACKLOG);
	if(ret == -1)
	{
		debug(LOG_ERR, "%s : can't listen client connect request! ",__FUNCTION__);
		close(listen_fd);
		unlink(SERVER_UNIX_DOMAIN);
		return;
	}


	fd_set read_fds;
	int maxsock;
	struct timeval tv;

	clt_len = sizeof(clt_addr);
	maxsock = listen_fd;

	while (1) {
		
		// timeout setting
		tv.tv_sec = 30;
		tv.tv_usec = 0;

		// initialize file descriptor set
		FD_ZERO(&read_fds);
		FD_SET(listen_fd, &read_fds);
		
		// add active connection to fd set
		for (i = 0; i < BACKLOG; i++) {
			if (client_fd[i] != 0) {
				FD_SET(client_fd[i], &read_fds);
			}
		}

		ret = select(maxsock + 1, &read_fds, NULL, NULL, &tv);
		if (ret < 0) {
			debug(LOG_ERR, "%s : [Fail] create select ! ",__FUNCTION__);
			break;
		} else if (ret == 0) {
			debug(LOG_ERR, "%s : select timeout! ",__FUNCTION__);
			continue;
		}

		// check whether a new connection comes
		if (FD_ISSET(listen_fd, &read_fds)) {
			new_fd = accept(listen_fd, (struct sockaddr*)&clt_addr, &clt_len);
			if (new_fd <= 0) {
				debug(LOG_ERR, "%s : [Fail] accept new conection! ",__FUNCTION__);
				continue;
			}

			// add to fd queue
			if (conn_amount >= BACKLOG) {
				debug(LOG_ERR, "%s : [Fail] max connections arrive, exit! ",__FUNCTION__);
				write(new_fd, "bye", 4);
				close(new_fd);
				continue;				
			}

			debug(LOG_ERR, "%s : new connection client %d:%s ; total = %d",__FUNCTION__,
				clt_addr.sun_family, clt_addr.sun_path,conn_amount);
			for (i = 0; i < BACKLOG; i++) {
				if ( client_fd[i] == 0 ) {
					client_fd[i] = new_fd;
					FD_SET(client_fd[i], &read_fds);
					conn_amount++;
					break;
				}
			}
			if (new_fd > maxsock) {
				maxsock = new_fd;
			}
		}
		
		// check every fd in the set
		for (i = 0; i < BACKLOG; i++) {
			if ( FD_ISSET(client_fd[i], &read_fds) ) {
				debug(LOG_ERR, "%s : client[%d] %d ready read! ",__FUNCTION__,i,client_fd[i]);
				memset(rev_buf, '\0', 1024);
				int rcv_num = read(client_fd[i], rev_buf, sizeof(rev_buf));
				if (rcv_num <= 0) { 	   // client close
					debug(LOG_ERR, "%s : client[%d] close! ",__FUNCTION__,i);
					close(client_fd[i]);
					FD_CLR(client_fd[i], &read_fds);
					client_fd[i] = 0;
					conn_amount--;
				} 
				else {		// receive data
					char auth_type[16] = {0};
					char auth_module[32] = {0};
					char auth_mac[32] = {0};
					char auth_op[32] = {0};

					/* receive message format
					* type=command;module=wifi(zigbee);info=id;option=register(unregister)
					* send result message
					* type=command;module=wifi(zigbee);info=id;result=ok(failure)
					*/
					debug(LOG_ERR, "%s : recv client[%d] message :%s",__FUNCTION__,i,rev_buf);
					sscanf(rev_buf,"type=%[^;];module=%[^;];info=%[^;];option=%s",auth_type,auth_module,auth_mac,auth_op);
					
					//sleep(5);
					memset(snd_buf, '\0', BUF_SIZE);
					if ( strncmp(auth_module,"wifi",strlen("wifi")) == 0 ) {
						char iptables_mac[32] = {0};
						
						/* wifi模块下，转换auth_mac格式 */
						sprintf(iptables_mac,"%c%c:%c%c:%c%c:%c%c:%c%c:%c%c",auth_mac[0],auth_mac[1],auth_mac[2],auth_mac[3],
								auth_mac[4],auth_mac[5],auth_mac[6],auth_mac[7],auth_mac[8],auth_mac[9],
								auth_mac[10],auth_mac[11]);	
						
						if ( strncmp(auth_op,"register",strlen("register")) == 0 ) {

							if (wifista_in_table(auth_mac) == 1){
								deal_legality(iptables_mac);
								sprintf(snd_buf,"type=command;module=wifi;info=%s;result=ok",auth_mac);
							} 
							else {
								sprintf(snd_buf,"type=command;module=wifi;info=%s;result=failure",auth_mac);
							}
						} 
						else if ( strncmp(auth_op,"unregister",strlen("unregister")) == 0 ) {						
							deal_offline(iptables_mac);
							sprintf(snd_buf,"type=command;module=wifi;info=%s;result=ok",auth_mac);	
						}
						else {
							sprintf(snd_buf,"[dms] error message(option)");
						}
						
					} 
					else if ( strncmp(auth_module,"zigbee",strlen("zigbee")) == 0 ) {
						if ( strncmp(auth_op,"register",strlen("register")) == 0 ) {
							char sHigh[16] = {0};
							char sLow[16] = {0};
							sscanf(auth_mac, "%[^+]+%s",sHigh, sLow);
							
							if (zigbeesta_in_table(sHigh,sLow) == 1){
								deal_zigbee_legality(auth_mac);
								zigbee_turnon(auth_mac);
								sprintf(snd_buf,"type=command;module=zigbee;info=%s;result=ok",auth_mac);
							}
							else {
								sprintf(snd_buf,"type=command;module=zigbee;info=%s;result=failure",auth_mac);
							}
						} 
						else if ( strncmp(auth_op,"unregister",strlen("unregister")) == 0 ) {
							zigbee_turnoff(auth_mac);
							deal_zigbee_illegality(auth_mac);
							sprintf(snd_buf,"type=command;module=zigbee;info=%s;result=ok",auth_mac);
						} 
						else {
							sprintf(snd_buf,"[dms] error message(option)");
						}
					} 
					else {
						sprintf(snd_buf," [dms] error message(module) ");
					}
					debug(LOG_ERR, "%s : client[%d] send data : %s",__FUNCTION__,i,snd_buf);
					write(client_fd[i], snd_buf, sizeof(snd_buf));
				}
			}
		}
	}

	close(listen_fd);
	unlink(SERVER_UNIX_DOMAIN);
	return;
}

static int do_process()
{
	int ret;
	void *status;
	
#if 1
	debug(LOG_ERR, "%s : Creation of thread_crond check wifi station !",__FUNCTION__);
	ret = pthread_create(&tid_wificrond, NULL, (void *)thread_wificrond, NULL);
	if (ret != 0) {
	    printf("FATAL: Failed to create a new thread (wificrond) - exiting");
		exit(1);
	}
#endif

	
#if 1
	debug(LOG_ERR, "%s : Creation of thread_crond check zigbee station !",__FUNCTION__);
	ret = pthread_create(&tid_zigbeecrond, NULL, (void *)thread_zigbeecrond, NULL);
	if (ret != 0) {
	    printf("FATAL: Failed to create a new thread (zigbeecrond) - exiting");
		exit(1);
	}
#endif


#if 1
	debug(LOG_ERR, "%s : Creation of thread_crond receive control message!",__FUNCTION__);
	ret = pthread_create(&tid_controlcond, NULL, (void *)thread_controlcrond, NULL);
	if (ret != 0) {
	    printf("FATAL: Failed to create a new thread (controlcond) - exiting");
		exit(1);
	}
#endif

#if 0
	if (pthread_join(tid_zigbeecrond,&status)!=0){
		printf(" wait for crond thread!\n");
		return;
	}
#endif

#if 1
	if (pthread_join(tid_wificrond,&status)!=0){
		printf(" wait for crond thread!\n");
		return;
	}
#endif
	
	return 0;
}

int main (int argc, char **argv)
{
	
	//初始化必要的资源
	if( init_resource() < 0 ){
		debug(LOG_ERR, " init_resource fail !");
		return -1;		
	}
	
	parse_commandline(argc, argv);
	
	/* Init the signals to catch chld/quit/etc */
	init_signals();

	if( do_process() < 0 ) {
		debug(LOG_ERR, " do_process fail !");
		exit(-1);
	}
	debug(LOG_ERR, "%s : QUIT do_process()",__FUNCTION__);
	return 0;
}
