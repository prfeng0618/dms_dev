#ifndef _DMS_ZIGBEE_H_
#define _DMS_ZIGBEE_H_

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sys/prctl.h>
#include "InnerClient.h"
#include "cJSON.h"

int connect(CClient* client);
int disconnect(CClient* client, const int token);
extern "C" char* requestHandler(const char* userparam);
extern "C" void dms_client_init();
extern "C" int dms_client_connect();
extern "C" int dms_client_disconnect();
extern "C" char* dms_requestHandler(const char* userparam);

#endif /* _DMS_ZIGBEE_H_ */