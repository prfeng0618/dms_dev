#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>
#include "wireless.h"
//#include "oid.h"

#define UNIX_DOMAIN "/tmp/DEV_CONTROL.domain"

static pthread_t tid_crond = 0;

void thread(void)
{
	int connect_fd;
	struct sockaddr_un srv_addr;
	char snd_buf[1024];
	int ret, i;
	
	//create client socket
	connect_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if(connect_fd < 0)
	{
		perror("client create socket failed");
		exit(1);
	}

	//set server sockaddr_un
	srv_addr.sun_family = AF_UNIX;
	strcpy(srv_addr.sun_path, UNIX_DOMAIN);

	//connect to server
	ret = connect(connect_fd, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
	if(ret == -1)
	{
		perror("connect to server failed!");
		close(connect_fd);
		unlink(UNIX_DOMAIN);
		exit(1);
	}
	
	memset(snd_buf, '\0', 1024);
	sprintf(snd_buf,"message from client[%d] [%d]",getpid(),pthread_self());
	printf("send data : %s \n",snd_buf);
	write(connect_fd, snd_buf, sizeof(snd_buf));
	sleep(20);
	close(connect_fd);
}

int main(void)
{
/*
	int ret, i;
	void *status;
	
	ret = pthread_create(&tid_crond, NULL, (void *)thread, NULL);
	if (ret != 0) {
	    printf("FATAL: Failed to create a new thread (crond) - exiting");
		exit(1);
	}

	if (pthread_join(tid_crond,&status)!=0){
		printf(" wait for crond thread!\n");
		return;
	}
*/
	int connect_fd;
	struct sockaddr_un srv_addr;
	char snd_buf[1024] = {0};
	char rev_buf[1024] = {0};
	int ret, i;
	
	//create client socket
	connect_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if(connect_fd < 0)
	{
		perror("client create socket failed");
		exit(1);
	}

	//set server sockaddr_un
	srv_addr.sun_family = AF_UNIX;
	strcpy(srv_addr.sun_path, UNIX_DOMAIN);

	//connect to server
	ret = connect(connect_fd, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
	if(ret == -1)
	{
		perror("connect to server failed!");
		close(connect_fd);
		exit(1);
	}
	
	memset(snd_buf, '\0', 1024);
	//sprintf(snd_buf,"type=command;module=wifi;info=112233445566;option=unregister");
	sprintf(snd_buf,"type=command;module=zigbee;info=254509099+5260233;option=register");
	printf("send data : %s \n",snd_buf);
	write(connect_fd, snd_buf, sizeof(snd_buf));
	sleep(1);
	int rcv_num = read(connect_fd, rev_buf, sizeof(rev_buf));
	if(rcv_num > 0){
		printf("recv data : %s \n",rev_buf);
	}
	
	close(connect_fd);
	return 0;
}

