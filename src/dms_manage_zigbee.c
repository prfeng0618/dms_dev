#include "dms_dev.h"

extern pthread_mutex_t zigbeesta_table_mutex;
extern struct globals G;
extern struct list_head head_zigbeesta;

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


int zigbee_send_connect()
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
int zigbee_send_permit()
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

static void set_zigbeecord_sm(char* sHigh,char* sLow,enum ZigbeeStaSM sm)
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
	ppro = alloc_auth_proto(TYPE_INFORM,SUBTYPE_OFFLINE,MODULE_ZIGBEE,(unsigned char *)zigbee_id);
	ret=pthread_create(&pth_ids,NULL,(void *)auth_thread,(void *)ppro);
	if(ret!=0)
	{
		printf ("Create pthread error!\n");
		exit(1);
	}
	pthread_detach(pth_ids);

	return;
}


void deal_zigbee_legality(char *zigbee_id)
{
	debug(LOG_ERR, "%s : [ %s ] Turn on light .... ",__FUNCTION__,zigbee_id);
	char sHigh[16] = {0};
	char sLow[16] = {0};

	sscanf(zigbee_id, "%[^+]+%s",sHigh, sLow);
	set_zigbeecord_sm(sHigh,sLow,ZIG_ONLINE);
	return;
}

#if 0
void deal_zigbee_illegality(char *zigbee_id)
{	
	char sHigh[16] = {0};
	char sLow[16] = {0};
	char strBuf[100] = {0};
	char *response;
			
	sscanf(zigbee_id, "%[^+]+%s",sHigh, sLow);	

	set_zigbeecord_sm(sHigh,sLow,ZIG_LEAVE);	
	
	sprintf(strBuf,"\{\"cmd_url\":\"/zigbeeservice/node\", \"cmd_name\":\"remove\", \"node\":[%s, %s], \"force\":1\}",sHigh, sLow);
    response = requestHandler(strBuf);
	//cJSON *pJson = cJSON_Parse(response);
	free(response);
	return;
}
#else
void deal_zigbee_illegality(char *zigbee_id)
{	
	zigbee_turnoff(zigbee_id);
	return;
}

#endif


void zigbee_turnon(char *zigbee_id)
{
	char sHigh[16] = {0};
	char sLow[16] = {0};
	int turnOffCount = 0;
	
	debug(LOG_ERR, "%s : [ %s ].... ",__FUNCTION__,zigbee_id);
	
	sscanf(zigbee_id, "%[^+]+%s",sHigh, sLow);	

	for(turnOffCount = 0;turnOffCount < 5;turnOffCount++){
		char strBuf[256] = {0};
		char *response;
		cJSON * pLevel = NULL;
		char *pStrResult;
		int iResult;
		
		sprintf(strBuf,"\{\"cmd_url\":\"/zigbeeservice/light\", \"cmd_name\":\"switch\", \"set\":1, \"node\":[%s, %s], \"on\":1\}", sHigh, sLow);
		debug(LOG_ERR, "%s : send zigbee message : %s",__FUNCTION__,strBuf);

		response = requestHandler(strBuf);
		pLevel = cJSON_Parse(response);
		free(response);
		
		cJSON *pRet = cJSON_GetObjectItem(pLevel, "result");
		pStrResult = cJSON_Print(pRet);
		sscanf(pStrResult,"%d",&iResult);
		
		free(pStrResult);
		cJSON_Delete(pLevel);

		if(0 == iResult)
			break;

		sleep(3);
			
	}
	return;
}

void zigbee_turnoff(char *zigbee_id)
{
	char sHigh[16] = {0};
	char sLow[16] = {0};
	int turnOffCount = 0;
	
	debug(LOG_ERR, "%s : [ %s ].... ",__FUNCTION__,zigbee_id);
	sscanf(zigbee_id, "%[^+]+%s",sHigh, sLow);	

	for(turnOffCount = 0;turnOffCount < 5;turnOffCount++){
		char strBuf[256] = {0};
		char *response;
		cJSON * pLevel = NULL;
		char *pStrResult;
		int iResult;
		
		sprintf(strBuf,"\{\"cmd_url\":\"/zigbeeservice/light\", \"cmd_name\":\"switch\", \"set\":1, \"node\":[%s, %s], \"on\":0\}", sHigh, sLow);
		debug(LOG_ERR, "%s : send zigbee message : %s",__FUNCTION__,strBuf);

		response = requestHandler(strBuf);
		pLevel = cJSON_Parse(response);
		free(response);
		
		cJSON *pRet = cJSON_GetObjectItem(pLevel, "result");
		pStrResult = cJSON_Print(pRet);
		sscanf(pStrResult,"%d",&iResult);
		
		free(pStrResult);
		cJSON_Delete(pLevel);

		if(0 == iResult)
			break;

		sleep(3);
			
	}
	return;
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

			if ((iLevel == 0 || iLevel == 3) && ZIG_COMING == pos_item->zigbeestate) {
				char zigbee_id[32];
				
				pos_item->zigbeestate= ZIG_LEAVE;
				//sprintf(zigbee_id,"%s+%s",sHigh,sLow);
				//debug(LOG_ERR, "%s : [ %s ] Turn off light ...",__FUNCTION__,zigbee_id);
				//zigbee_turnoff(zigbee_id);
				pos_item->mark = 0;

			}
			
			if ((iLevel == 0 || iLevel == 3) && ZIG_ONLINE == pos_item->zigbeestate) {
				char zigbee_id[32];
				
				send_zigbeesta_offlinemsg(sHigh,sLow);
				pos_item->zigbeestate= ZIG_OFFLINE;

				sprintf(zigbee_id,"%s+%s",sHigh,sLow);
				debug(LOG_ERR, "%s : [ %s ] Turn off light ...",__FUNCTION__,zigbee_id);
				zigbee_turnoff(zigbee_id);
				pos_item->mark = 0;

			}
			
			if ( 2 == iLevel && (ZIG_COMING == pos_item->zigbeestate|| ZIG_OFFLINE== pos_item->zigbeestate)) {
				send_zigbeesta_onlinemsg(sHigh,sLow);
				pos_item->zigbeestate= ZIG_ONLINE;
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
int zigbeesta_in_table(char *sHigh, char *sLow)
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


int process_zigbeesta()
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

	/* BUG: 智能灯加入zigbee server中后会行程一个节点，但无论智能灯上下电， 
	这个节点状态一直都是online，因此我们必须对灯进行配置，如果result返回非0， 
	表示灯未插上 */
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
	dump_zigbeesta();
	return 0;
}

