#include "http_post.h"

int sockfd;
int port = 80;
//int port = 8080;

char *ip = "158.182.8.220";

char *host = "158.182.8.220:80";

char *page = "/locations/";

int setup_http_request()
{
	//struct hostent* hostent;
	struct sockaddr_in servaddr;
	struct timeval timeout;
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;

	/*hostent = gethostbyname(host);
	if(hostent == NULL) {
		perror("Can't get host by hostname\n");  
		return 0;
	}*/

	//ip = inet_ntoa(*((struct in_addr*) hostent->h_addr));

	if((sockfd=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP))<0){
		perror("Can't create TCP socket!\n");  
		return 0;
	}
	
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);

	int tmpres = inet_pton(AF_INET, ip, &servaddr.sin_addr);
	if(tmpres<0){
	  perror("Can't set remote->sin_addr.s_addr");
	  return 0;
	}else if(tmpres==0){
		fprintf(stderr,"%s is not a valid IP address\n", ip);
		return 0;
	}

	if (setsockopt (sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
	{
		perror("Setsockopt failed\n");
		return 0;
	}
  if (setsockopt (sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
  {
  	perror("Setsockopt failed\n");
  	return 0;
  }

	if(connect(sockfd, (SA *) & servaddr, sizeof(servaddr))<0){
		perror("Could not connect!\n");  
		return 0;
  }

  return 1;
}

int process_post(char *params)
{
	if(setup_http_request()) {
		//printf("setup http requet succeed\n");
	} else {
		printf("Setup http requet failed\n");
		return -1;
	}

	char sendline[MAXLINE + 1], recvline[MAXLINE + 1];
	int n;

  char content[100] = {'\0'};
	strcat(content, page);
	strcat(content, params);

	snprintf(sendline, strlen(content) + MAXSUB,
		 "GET %s HTTP/1.0\r\n"
		 "Host: %s\r\n"
		 "Content-type: application/x-www-form-urlencoded\r\n"
		 "Content-length: %d\r\n\r\n", content, host, strlen(content));

	write(sockfd, sendline, strlen(sendline));
  if((n = read(sockfd, recvline, MAXLINE)) > 0) {
		recvline[n] = '\0';
		//printf("%s\n", recvline);
		int i=0;
		while(i < n-6)
		{
			if (recvline[i] == 's' && recvline[i+1] == 't'
					&& recvline[i+2] == 'a' && recvline[i+3] == 't'
					&& recvline[i+4] == 'e')
			{
				if(recvline[i+6] == '1')
					printf("Please send parameters\n");
				else if(recvline[i+6] == '2')
					printf("Parameters not correct\n");
				else
					printf("Send succeed\n");
				break;
			}
			i++;
		}
	}

	close(sockfd);
	return n;
}