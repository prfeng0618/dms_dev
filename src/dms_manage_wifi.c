#include "dms_dev.h"

extern pthread_mutex_t wifista_table_mutex;
extern struct globals G;
extern struct list_head head_wifista;
extern int RESTORE_WIFI_FIRWALL;


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

static void restoreWifiFirwall(void)
{
	struct wifista_record *pos_item;
	
	struct auth_proto *ppro;
	pthread_t pth_ids;
	int ret;
	
	pthread_mutex_lock(&wifista_table_mutex);
	printf("begin: receiv usr1 sig	\n");
	list_for_each_entry(pos_item, &head_wifista, list) {
		printf("	record : \n");
		printf("	wmac[%02x:%02x:%02x:%02x:%02x:%02x] mark %d wifistate %d\n",
				pos_item->wmac[0],pos_item->wmac[1],pos_item->wmac[2],
				pos_item->wmac[3],pos_item->wmac[4],pos_item->wmac[5],
				pos_item->mark,pos_item->wifistate);

		ppro = alloc_auth_proto(TYPE_INFORM,SUBTYPE_ONLINE,MODULE_WIFI,pos_item->wmac);
		ret=pthread_create(&pth_ids,NULL,(void *)auth_thread,(void *)ppro);
		if(ret!=0)
		{
			printf ("Create pthread error!\n");
			exit(1);
		}
		pthread_detach(pth_ids);
	}
	pthread_mutex_unlock(&wifista_table_mutex);
	printf("end: receiv usr1 sig  \n");

}


static int get_wifista_info(RT_802_11_MAC_TABLE *ptable)
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
	memcpy(witem->wmac, wmac, ETH_ALEN);;
	witem->mark = 1;
	witem->wifistate = ONLINE;
	list_add_tail(&witem->list, &head_wifista);

}

static int del_wifista_table(struct wifista_record *record)
{
	list_del(&record->list);
	free(record);
}


/* 判断队列中wifi设备是在列表中*/
int wifista_in_table(char *wifimac)
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


/* auth_mac格式为 AA:BB:CC:DD:EE:FF */
void deal_legality(char *auth_mac)
{

	char sys_cmd[128] = {0};
	sprintf(sys_cmd,"iptables -D FORWARD -m mac --mac-source %s -j DROP",auth_mac);
	printf("sys_cmd = %s\n",sys_cmd);
	system(sys_cmd);
	return;
}

/* auth_mac格式为 AA:BB:CC:DD:EE:FF */
void deal_illegality(char *auth_mac)
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
void deal_offline(char *auth_mac)
{
	char sys_cmd[128] = {0};
	sprintf(sys_cmd,"iptables -D FORWARD -m mac --mac-source %s -j DROP",auth_mac);
	printf("sys_cmd = %s\n",sys_cmd);
	system(sys_cmd);
	return;
}


int process_wifista()
{
	int i=0, ret;
	int exist_dev;
	RT_802_11_MAC_TABLE table = {0};
	struct wifista_record *pos_item;
	struct wifista_record *pos_next_item;
	//pthread_t pth_ids;
	//struct auth_proto *ppro;


	/* 完成拨号上网， 需要重置iptables规则和重新认证wifi下用户 */
	if( RESTORE_WIFI_FIRWALL ) {
		restoreWifiFirwall();
		RESTORE_WIFI_FIRWALL = 0;
	}

	
	
	//获取客户端列表
	if ( get_wifista_info(&table) < 0 ) {
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
			debug(LOG_ERR, "%s : create auth_thread for sending online msg for wifista",__FUNCTION__); 		
			dms_work_thread_auth(TYPE_INFORM,SUBTYPE_ONLINE,MODULE_WIFI,table.Entry[i].Addr);
#if 0
			debug(LOG_ERR, "%s : create auth_thread",__FUNCTION__);			
			ppro = alloc_auth_proto(TYPE_INFORM,SUBTYPE_ONLINE,MODULE_WIFI,table.Entry[i].Addr);
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
			debug(LOG_ERR, "%s : create auth_thread for sending offline msg for wifista",__FUNCTION__);
			dms_work_thread_auth(TYPE_INFORM,SUBTYPE_OFFLINE,MODULE_WIFI,pos_item->wmac);
#if 0 
			debug(LOG_ERR, "%s : create auth_thread for del one station",__FUNCTION__);			
			ppro = alloc_auth_proto(TYPE_INFORM,SUBTYPE_OFFLINE,MODULE_WIFI,pos_item->wmac);
			ret=pthread_create(&pth_ids,NULL,(void *)auth_thread,(void *)ppro);
			if(ret!=0)
			{
				printf ("Create pthread error!\n");
				exit(1);
			}
			pthread_detach(pth_ids);
#endif
			/* 从列表中删除*/
			del_wifista_table(pos_item);

		}
	}
	pthread_mutex_unlock(&wifista_table_mutex);
	
	dump_wifista();
	return 0;
}

