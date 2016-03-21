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
#define DEFAULT_ZIGBEESTA_CRONDTIME 10
#define DEFAULT_WIFISTA_RCV_TIMEOUT 20
#define DEFAULT_SYSLOG_FACILITY LOG_DAEMON

#define DMS_UNIX_DOMAIN "/tmp/DMS_UNIX.domain"

struct globals G;
pthread_t tid_wificrond = 0;
pthread_t tid_zigbeecrond = 0;
pthread_t tid_controlcond = 0;

LIST_HEAD(head_wifista); 
LIST_HEAD(head_zigbeesta); 

pthread_mutex_t wifista_table_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t zigbeesta_table_mutex = PTHREAD_MUTEX_INITIALIZER;


/* Control Message */
#define SERVER_UNIX_DOMAIN "/tmp/DEV_CONTROL.domain"
#define BACKLOG 5     // how many pending connections queue will hold
#define BUF_SIZE 1024

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


struct auth_proto* alloc_auth_proto(char* type,char* subtype,char* module,unsigned char* id)
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
		goto exit;
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
							//deal_zigbee_illegality(auth_mac);
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
	
	dms_process_wifista();

	dms_process_zigbee();



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
