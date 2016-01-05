#include "dms_zigbee.h"

const char host[16] = "127.0.0.1";
const char port[8] = "8090";

CClient* dms_client ;
int dms_token;


/**
 *@brief convert char to hex integer
 *
 *@param chr          char
 *@return             hex integer
 **/
uint8_t hexc2bin(char chr)
{
    if (chr >= '0' && chr <= '9')
        chr -= '0';
    else if (chr >= 'A' && chr <= 'F')
        chr -= ('A' - 10);
    else if (chr >= 'a' && chr <= 'f')
        chr -= ('a' - 10);
    return chr;
}

/**
 *@brief convert string to hex integer
 *
 *@param s            A pointer string buffer
 *@return             hex integer
 **/
uint32_t a2hex(const char *s)
{
    uint32_t val = 0;

    while (*s && isxdigit(*s)) {
        val = (val << 4) + hexc2bin(*s++);
    }
    return val;
}

char* str2json(char* response) {
    if (response != NULL) {
        char* ch1 = strchr(response, '{');
        char* ch2 = strrchr(response, '}');
        int len = ch2 - ch1 + 1;
        char* jsonresponse = (char *)malloc(len + 1);
        strncpy(jsonresponse, ch1, len);
        jsonresponse[len] = '\0';
        return jsonresponse;
    }
    return NULL;
}

int connect(CClient* client)
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "cmd_url", "/zigbeeservice/gateway");
    cJSON_AddStringToObject(root, "cmd_name", "connect");
    char *action = cJSON_Print(root);
    client->SendACTION(action);
    cJSON_Delete(root);
    free(action);

    int token = -1;
    char response[128];
    client->GetStatus(response);
    if (response != NULL) {
        char* jstring = str2json(response);
        if (jstring != NULL) {
            char* pch = strtok (jstring,",{}");
            while (pch != NULL) {
                if (strstr(pch, "result") != NULL) {
                    char* tk = strtok(pch, ":");
                    while (tk != NULL) {
                        tk = strtok(NULL, ":");
                        if (!strstr(tk, "result")) {
                            token = atoi(tk);
                            //printf("token %d\n", token);
                            break;
                        }
                    }
                    break;
                }
                //printf("%s\n", pch);
                pch = strtok(NULL, ",{}");
            }
            free(jstring);
        }
    }
    return token;
}

int disconnect(CClient* client, const int token)
{
    assert(client != NULL);
    if (token >= 0) {
        cJSON *root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "cmd_url", "/zigbeeservice/gateway");
        cJSON_AddStringToObject(root, "cmd_name", "disconnect");
        cJSON_AddNumberToObject(root, "token", token);
        char *action = cJSON_Print(root);
        client->SendACTION(action);
        cJSON_Delete(root);
        free(action);
    }
    return 0;
}

char* requestHandler(const char* userparam) {
    CClient* client = new CClient(host, atoi(port));
	char* jstring = NULL;

    if (client != NULL) {
        int token = connect(client);
        if (token >= 0) {
            usleep(100 * 1000);
            client->SendACTION(userparam);
            char response[MAX_PACKET_SIZE];
refetch:
            memset(response, 0, MAX_PACKET_SIZE);
            client->GetStatus(response);
            if (response != NULL && strlen(response) > 0) {
                char len_c[5];
                strncpy(len_c, response + 4, 4);
                len_c[4] = '\0';
                int len = a2hex(len_c);
                //char* jstring = NULL;
                if (len > MAX_PAYLOAD_SIZE) {
                    jstring = (char *) malloc (len + 1);
                    strncpy(jstring, response + HEADER_SIZE, MAX_PACKET_SIZE - HEADER_SIZE);
                    int left = len - MAX_PAYLOAD_SIZE;
                    while (left > 0) {
                        int toread;
                        if (left / MAX_PACKET_SIZE >= 1) {
                            toread = MAX_PACKET_SIZE;
                        } else {
                            toread = left;
                        }
                        char tmpbuf[toread];
                        memset(tmpbuf, 0, toread);
                        client->GetStatus(tmpbuf);
                        strcat(jstring, tmpbuf);
                        left -= toread;
                    }
                } else {					
                    jstring = str2json(response);
                }

                if (jstring != NULL) {
                    if (strstr(jstring, "/zigbeeservice/event") != NULL) {
                        free(jstring);
                        goto refetch;
                    }
                    printf("%s\n", jstring);
                    //free(jstring);
                }
            } else {
                printf("ZigbeeCore not responsed, HTTPServer done\n");
            }
            disconnect(client, token);
        }
        delete client;
    }
	return jstring;
}


void dms_client_init()
{
	dms_client = new CClient(host, atoi(port));
}

int dms_client_connect()
{
	dms_token = connect(dms_client);
	return dms_token;
}


int dms_client_disconnect()
{
	int token = connect(dms_client);
	return disconnect(dms_client, dms_token);
}


char* dms_requestHandler(const char* userparam) {
	char* jstring = NULL;
	
	printf("userparam = %s\n", userparam);
    usleep(100 * 1000);
    dms_client->SendACTION(userparam);
    char response[MAX_PACKET_SIZE];
refetch:
    memset(response, 0, MAX_PACKET_SIZE);
    dms_client->GetStatus(response);
	//printf("111111111111111111111111111 \n");
    if (response != NULL && strlen(response) > 0) {
        char len_c[5];
        strncpy(len_c, response + 4, 4);
        len_c[4] = '\0';
        int len = a2hex(len_c);
        char* jstring = NULL;
		//printf("2222222222222222222222222 \n");
        if (len > MAX_PAYLOAD_SIZE) {
            jstring = (char *) malloc (len + 1);
            strncpy(jstring, response + HEADER_SIZE, MAX_PACKET_SIZE - HEADER_SIZE);
            int left = len - MAX_PAYLOAD_SIZE;
            while (left > 0) {
                int toread;
                if (left / MAX_PACKET_SIZE >= 1) {
                    toread = MAX_PACKET_SIZE;
                } else {
                    toread = left;
                }
                char tmpbuf[toread];
                memset(tmpbuf, 0, toread);
                dms_client->GetStatus(tmpbuf);
                strcat(jstring, tmpbuf);
                left -= toread;
            }
        } else {
            jstring = str2json(response);
        }
		//printf("3333333333333333 \n");
        if (jstring != NULL) {
            if (strstr(jstring, "/zigbeeservice/event") != NULL) {
                free(jstring);
                goto refetch;
            }
            printf("%s\n", jstring);
            free(jstring);
        }
    } else {
        printf("ZigbeeCore not responsed, HTTPServer done\n");
    }
	return jstring;
}

