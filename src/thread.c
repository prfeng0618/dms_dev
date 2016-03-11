#include "dms_dev.h"

extern pthread_t tid_wificrond;
extern pthread_t tid_zigbeecrond;
extern pthread_t tid_controlcond;

extern pthread_mutex_t wifista_table_mutex;
extern pthread_mutex_t zigbeesta_table_mutex;

extern struct globals G;


void dms_thread_wificrond(void *arg)
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

void dms_work_thread_wifista()
{
	int ret;
	
	debug(LOG_ERR, "%s : Creation of thread_crond check wifi station !",__FUNCTION__);
	ret = pthread_create(&tid_wificrond, NULL, (void *)dms_thread_wificrond, NULL);
	if (ret != 0) {
		printf("FATAL: Failed to create a new thread (wificrond) - exiting");
		exit(1);
	}
}


void dms_process_wifista()
{
	dms_work_thread_wifista();
}


void dms_thread_zigbeecrond(void *arg)
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


void dms_work_thread_zigbee()
{
	int ret;
	
	debug(LOG_ERR, "%s : Creation of thread_crond check zigbee station !",__FUNCTION__);
	ret = pthread_create(&tid_zigbeecrond, NULL, (void *)dms_thread_zigbeecrond, NULL);
	if (ret != 0) {
	    printf("FATAL: Failed to create a new thread (zigbeecrond) - exiting");
		exit(1);
	}

}

void dms_process_zigbee()
{
	dms_work_thread_zigbee();
}


void dms_work_thread_auth(char* type,char* subtype,char* module,unsigned char *addr)
{
	int ret;
	pthread_t pth_ids;
	struct auth_proto *ppro;

	ppro = alloc_auth_proto(type,subtype,module,addr);
	ret=pthread_create(&pth_ids,NULL,(void *)auth_thread,(void *)ppro);
	if(ret!=0)
	{
		printf ("Create auth pthread error!\n");
		exit(1);
	}
	pthread_detach(pth_ids);
}


