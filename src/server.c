#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <signal.h>

#define UNIX_DOMAIN "/tmp/DMS_UNIX.domain"
#define BACKLOG 5     // how many pending connections queue will hold
#define BUF_SIZE 1024


int client_fd[BACKLOG];    // accepted connection fd
int conn_amount = 0;    // current connection amount


void showclient()
{
    int i;
    printf("client amount: %d\n", conn_amount);
    for (i = 0; i < BACKLOG; i++) {
        printf("[%d]:%d  ", i, client_fd[i]);
    }
    printf("\n\n");
}


int main(void)
{

	int listen_fd, new_fd;
	struct sockaddr_un srv_addr;
	struct sockaddr_un clt_addr;
	socklen_t clt_len;

	int ret;
	int i;
	char buf[BUF_SIZE];
	char snd_buf[BUF_SIZE];



	
	signal(SIGPIPE,SIG_IGN);
	
	//create socket to bind local IP and PORT
	listen_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if(listen_fd < 0)
	{
		perror("can't create communication socket!");
		return 1;
	}



	//create local IP and PORT
	srv_addr.sun_family = AF_UNIX;
	strncpy(srv_addr.sun_path, UNIX_DOMAIN, sizeof(srv_addr.sun_path) - 1);
	unlink(UNIX_DOMAIN);

	//bind sockfd and sockaddr
	ret = bind(listen_fd, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
	if(ret == -1)
	{
		perror("can't bind local sockaddr!");
		close(listen_fd);
		unlink(UNIX_DOMAIN);
		return 1;
	}



	//listen listen_fd, try listen 1
	ret = listen(listen_fd, BACKLOG);
	if(ret == -1)
	{
		perror("can't listen client connect request");
		close(listen_fd);
		unlink(UNIX_DOMAIN);
		return 1;
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
            perror("select");
            break;
        } else if (ret == 0) {
            printf("timeout\n");
            continue;
        }

        // check whether a new connection comes
        if (FD_ISSET(listen_fd, &read_fds)) {
			new_fd = accept(listen_fd, (struct sockaddr*)&clt_addr, &clt_len);
            if (new_fd <= 0) {
                perror("accept");
                continue;
            }

            // add to fd queue
			if (conn_amount >= BACKLOG) {
                printf("max connections arrive, exit\n");
                write(new_fd, "bye", 4);
                close(new_fd);
                continue;				
			}
            
			printf("new connection client %d:%s ; total = %d \n",
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
				printf("client[%d] %d ready read\n",i,client_fd[i]);
				memset(buf, '\0', 1024);
                int rcv_num = read(client_fd[i], buf, sizeof(buf));
                if (rcv_num <= 0) {        // client close
                    printf("client[%d] close\n", i);
                    close(client_fd[i]);
                    FD_CLR(client_fd[i], &read_fds);
                    client_fd[i] = 0;
					conn_amount--;
                } else {        // receive data
					char auth_subtype[16] = {0};
					char auth_module[32] = {0};
					char auth_mac[32] = {0};
					char auth_ret[32] = {0};
					
                    printf("client[%d] send:%s\n", i, buf);
					sscanf(buf,"%*[^;];subtype=%[^;];module=%[^;];info=%[^;];result=%s",auth_subtype,auth_module,auth_mac,auth_ret);
					
					//sleep(5);
					memset(snd_buf, '\0', BUF_SIZE);
					//sprintf(snd_buf,"type=inform;subtype=online;module=wifi;info=c46ab74884fd;result=legality");
					if ( strncmp(auth_subtype,"online",strlen("online")) == 0 ) {
						sprintf(snd_buf,"type=inform;module=%s;info=%s;result=legality",auth_module,auth_mac);
					} else if ( strncmp(auth_subtype,"offline",strlen("offline")) == 0 ) {
						sprintf(snd_buf,"type=inform;module=%s;info=%s;result=ok",auth_module,auth_mac);
					} else {
						sprintf(snd_buf," reflit %s ",buf);
					}
					printf("send data : %s \n",snd_buf);
					write(client_fd[i], snd_buf, sizeof(snd_buf));
                }
            }
        }
        showclient();
    }

	close(listen_fd);
	unlink(UNIX_DOMAIN);
	return 0;
}
