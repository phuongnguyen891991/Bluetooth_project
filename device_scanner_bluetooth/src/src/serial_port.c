#include "serial_port.h"

unsigned char discovery_done_flag[] = {0x04,0xFF,0x66,0x01,0x06,0x00,0x05};
unsigned char connection_done_flag[] = {0x04,0xFF,0x0B,0X07,0X06};
unsigned char disconnection_done_flag[] = {0x04,0xFF,0x06,0x06,0x06};
unsigned char pair_done_flag[] = {0x04,0xFF,0x6A,0x0A,0x06};
unsigned char discovery_command[] = {0x01,// Command
                                     0x04,0xfe,// GAP_DeviceDiscoveryRequest
                                     0x03,// Data Length
                                     0x01,// Mode(All)
                                     0x01,// ActiveScan(Enable)
                                     0x00};// WhiteList(Disable)
unsigned char connect_command[] = {0x01,// Command
                                   0x09,0xFE,// GAP_EstablishLinkRequest
                                   0x09,// Data Length
                                   0x00,// HighDutyCycle(Disable)
                                   0x00,// WhiteList(Disable)
                                   0x03,// AddrType(PrivateResolve)
                                   0x00,0x00,0x00,0x00,0x00,0x00};// Addrress
unsigned char disconnect_command[] = {0x01,// Command
                                      0x0A,0XFE, // GAP_TerminateLinkRequest
                                      0x03,// Data Length
                                      0X00,0X00,// Connection Handle
                                      0x13};// Disconnect Reason(Remote User Terminated Connection)
unsigned char pairing_command[] = {0x01,// Command
                                  0x0B,0XFE,// GAP_Authenticate
                                  0X1D,// Data Length
                                  0X00,0X00,// Connection Handle
                                  0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,// security parameters
                                  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,// security parameters
                                  0x05,0x10,0x3F,0x00,0x03,0x00,0x01,0x10,0X3F};// pair parameters
int my_fd;

int init_port(char *port)
{
	int fd = open (port, O_RDWR | O_NOCTTY | O_SYNC);
  if (fd < 0)
  {
    printf("error %d opening %s: %s\n", errno, port, strerror (errno));
    return -1;
  }
  // set speed to 115,200 bps, 8n1 (no parity)
  if(set_interface_attribs (fd, SPEED, 0) == -1)
  	return -1;
  // set no blocking
  if(set_blocking (fd, 0) == -1)
  	return -1;

  return fd;
}

int init_hci(int fd)
{
	unsigned char init0[] = {0x01,0x00,0xFE,0x26,0x08,0x0a,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00};
  if(write (fd, &init0, sizeof init0) <= 0)
    return -1;
  sleep(0.1);

  unsigned char init1[] = {0x01,0x31,0xFE,0X01,0X15};
  if(write (fd, &init1, sizeof init1) <= 0)
    return -1;
  sleep(0.1);

  unsigned char init2[] = {0x01,0x31,0xFE,0X01,0X16};
  if(write (fd, &init2, sizeof init2) <= 0)
    return -1;
  sleep(0.1);

  unsigned char init3[] = {0x01,0x31,0xFE,0X01,0X1A};
  if(write (fd, &init3, sizeof init3) <= 0)
    return -1;
  sleep(0.1);

  unsigned char init4[] = {0x01,0x31,0xFE,0X01,0X19};
  if(write (fd, &init4, sizeof init4) <=0)
    return -1;
  sleep(1);

  printf("HCI initialize done.\n");
  return 1;
}

int send_request(int fd, int request, char *mac_address, char *handle)
{
  int result = 0;
  int i;
  char temp[2];
  switch(request)
  {
    case REQUEST_DISCOVERY:
    case REQUEST_SCAN:
      result = write (fd, &discovery_command, sizeof discovery_command);
      if(result <= 0)
        printf("Discovery request failed\n");
      else
        printf("Start discovering......\n");
      break;
    case REQUEST_CONNECT:
      for(i=0; i<6; i++)
      {
        temp[0] = *mac_address++;
        temp[1] = *mac_address++;
        mac_address++;
        connect_command[12-i] = strtol(temp, NULL, 16);
      }
      /*for(i=0; i<sizeof connect_command; i++)
      {
        printf("%02x ", connect_command[i]);
      }
      printf("\n");*/
      result = write (fd, &connect_command, sizeof connect_command);
      if(result <= 0)
        printf("Connection request failed\n\n");
      else
        printf("Start connecting......\n\n");
      break;
    case REQUEST_DISCONNECT:
      for (i = 0; i < 2; ++i)
      {
        temp[0] = *handle++;
        temp[1] = *handle++;
        disconnect_command[4+i] = strtol(temp, NULL, 16);
      }
      /*for(i=0; i<sizeof disconnect_command; i++)
      {
        printf("%02x ", disconnect_command[i]);
      }
      printf("\n");*/
      result = write (fd, &disconnect_command, sizeof disconnect_command);
      if(result <= 0)
        printf("Disconnection request failed\n\n");
      else
        printf("Start disconnecting......\n\n");
      break;
    case REQUEST_PAIRING:
    case REQUEST_PAIRING_REGISTER:
      for (i = 0; i < 2; ++i)
      {
        temp[0] = *handle++;
        temp[1] = *handle++;
        pairing_command[4+i] = strtol(temp, NULL, 16);
      }
      result = write (fd, &pairing_command, sizeof pairing_command);
      if(result <= 0)
        printf("Pair request failed\n\n");
      else
        printf("Start Pairing......\n\n");
      break;
  }
  return result;
}

void listen_serial_port(int fd, int request, char *mac_address, char *handle)
{
  my_fd = fd;
  fd_set rfds;
	struct timeval tv;
	unsigned char read_buf [500];
	int read_buf_size = sizeof read_buf;
	int retval, ret;
	
	FD_ZERO(&rfds);
  FD_SET(fd, &rfds);
  tv.tv_sec = 15;
  tv.tv_usec = 0;

  if(send_request(fd, request, mac_address, handle) <= 0)
    return; 
    
  while(FD_ISSET(fd, &rfds))
  {
  	FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
 		retval = select(fd+1, &rfds, NULL, NULL, &tv);

 		if(retval == -1)
    {
      perror("select()");
      break;
    }
    else if(retval)
    {
      memset(read_buf, '\0', sizeof(read_buf));
    	ret = read(fd, read_buf, read_buf_size);
    	process_receive_data(request, ret, read_buf);
    }
    else
    {
    	break;
    }
 	}
}

void process_receive_data(int request, int len, unsigned char buf[])
{
  /*int index;
  for(index=0; index<len; index++)
  {
    printf("%02x ", buf[index]);
  }
  printf("\n\n");*/
      
  switch(request)
  {
    case REQUEST_DISCOVERY:
      is_discovery_done(len, buf);
      break;
    case REQUEST_CONNECT:
      is_connection_done(len, buf);
      break;
    case REQUEST_DISCONNECT:
      is_disconnection_done(len, buf);
      break;
    case REQUEST_PAIRING:
      is_pair_done(len, buf, 0);
      break;
    case REQUEST_PAIRING_REGISTER:
      is_pair_done(len, buf, 1);
      break;  
    case REQUEST_SCAN:
      is_scan_done(len, buf);
      break;
  }
}

int set_interface_attribs (int fd, int speed, int parity)
{
  struct termios tty;
  memset (&tty, 0, sizeof tty);
  if (tcgetattr (fd, &tty) != 0)
  {
    printf("error %d from tcgetattr\n", errno);
    return -1;
  }

  cfsetospeed (&tty, speed);
  cfsetispeed (&tty, speed);

  tty.c_cflag = (tty.c_cflag & ~CSIZE) | CS8;     // 8-bit chars
  // disable IGNBRK for mismatched speed tests; otherwise receive break as \000 chars
  tty.c_iflag &= ~IGNBRK;         // disable break processing
  tty.c_lflag = 0;                // no signaling chars, no echo, no canonical processing
  tty.c_oflag = 0;                // no remapping, no delays
  tty.c_cc[VMIN]  = 1;            // read doesn't block
  tty.c_cc[VTIME] = 0;            // 0.5 seconds read timeout

  tty.c_iflag &= ~(IXON | IXOFF | IXANY); // shut off xon/xoff ctrl

  tty.c_cflag |= (CLOCAL | CREAD);// ignore modem controls,
                                  // enable reading
  tty.c_cflag &= ~(PARENB | PARODD);      // shut off parity
  tty.c_cflag |= parity;
  tty.c_cflag &= ~CSTOPB;
  tty.c_cflag &= ~CRTSCTS;

  if (tcsetattr (fd, TCSANOW, &tty) != 0)
  {
    printf("error %d from tcsetattr\n", errno);
    return -1;
  }
  return 0;
}

int set_blocking (int fd, int should_block)
{
  struct termios tty;
  memset (&tty, 0, sizeof tty);
  if (tcgetattr (fd, &tty) != 0)
  {
    printf("error %d from tggetattr\n", errno);
    return -1;
  }

  tty.c_cc[VMIN]  = should_block ? 1 : 0;
  tty.c_cc[VTIME] = 5;            // 0.5 seconds read timeout

  if (tcsetattr (fd, TCSANOW, &tty) != 0)
  {
  	printf("error %d setting term attributes\n", errno);
  	return -1;
  }
  return 0;
}

void is_discovery_done(int len, unsigned char buf[])
{
	if(len < FLAG_LENGTH)
		return;
  if(buf[EVENT_INDEX_1] == discovery_done_flag[EVENT_INDEX_1]
      && buf[EVENT_INDEX_2] == discovery_done_flag[EVENT_INDEX_2])
  {
    // Success
    if(buf[STATUS_INDEX] == SUCCESS)
    {
      int i = sizeof discovery_done_flag;
      printf("\n");
      while(len >= i+8+6)
      {
        printf("original address=%02x:%02x:%02x:%02x:%02x:%02x[%02x]\t", 
          buf[i+7],buf[i+6],buf[i+5],buf[i+4],buf[i+3],buf[i+2],buf[i+1]);
        i+=6;
        printf("resolved address=%02x:%02x:%02x:%02x:%02x:%02x\n", 
          buf[i+7],buf[i+6],buf[i+5],buf[i+4],buf[i+3],buf[i+2]);
        i+=8;
      }
      printf("\n");
    }
    else
    {
      printf("Discovery failed\n");
    }
  }
}

void is_connection_done(int len, unsigned char buf[])
{
  if(len < FLAG_LENGTH)
    return;
  if(buf[EVENT_INDEX_1] == connection_done_flag[EVENT_INDEX_1]
      && buf[EVENT_INDEX_2] == connection_done_flag[EVENT_INDEX_2])
  {
    // Success
    if(buf[STATUS_INDEX] == SUCCESS)
    {
      int i = sizeof connection_done_flag;
      printf("Connectin succeed, connection handle: %02x%02x\n\n", buf[i+1],buf[i+2]);
    }
    else
      printf("Connection failed\n");
  }
}

void is_disconnection_done(int len, unsigned char buf[])
{
  if(len < FLAG_LENGTH)
    return;
  if(buf[EVENT_INDEX_1] == disconnection_done_flag[EVENT_INDEX_1]
      && buf[EVENT_INDEX_2] == disconnection_done_flag[EVENT_INDEX_2])
  {
    // Success
    if(buf[STATUS_INDEX] == SUCCESS)
    {
      int i = sizeof disconnection_done_flag;
      printf("Disconnection succeed, connection handle:%02x%02x\n\n", buf[i+1],buf[i+2]);
    }
    else
      printf("Disconnection failed\n");
  }
}

void is_pair_done(int len, unsigned char buf[], int need_register)
{
  char addrress[18]; //6*2+5+1
  char irk[48]; //16*2+5+1
  char irk_level[2];

  if(len < FLAG_LENGTH)
    return;

  if(buf[EVENT_INDEX_1] == pair_done_flag[EVENT_INDEX_1]
      && buf[EVENT_INDEX_2] == pair_done_flag[EVENT_INDEX_2])
  {
    // Success
    if(buf[STATUS_INDEX] == SUCCESS)
    {
      int i = sizeof pair_done_flag;
      printf("Pair succeed, connection handle:%02x%02x\n", buf[i+1],buf[i+2]);
      for(i=0; i<6; i++)
      {
        //printf("%02x", buf[66+16+5-i]);
        sprintf(&addrress[i*3], "%02X", buf[66+16+5-i]);
        if(i != 5)
        {
          //printf(":");
          addrress[(i+1)*3-1] = ':';
        }
      }
      for(i=0; i<16; i++)
      {
        //printf("%02x", buf[i+66]);
        sprintf(&irk[i*3], "%02X", buf[i+66]);
        if(i != 15)
        {
          //printf(":");
          irk[(i+1)*3-1] = ':';
        }
      }
      printf("\n");
      irk_level[0] = irk[46];
      irk_level[1] = '\0';
      printf("Address: %s\n", addrress);
      printf("IRK: %s\n", irk);
      printf("IRK level: %s\n", irk_level);
      if(need_register == 1)
      {
        char *params = (char *) malloc(100);
        strcpy(params,"");
        strcat(params, "register/?");
        strcat(params, "address=");
        strcat(params, addrress);
        strcat(params, "&irk=");
        strcat(params, irk);
        strcat(params, "&irk_level=");
        strcat(params, irk_level);
        process_post(params);
      }
    }
    else
      printf("Pair failed\n");
  }
}

void is_scan_done(int len, unsigned char buf[])
{
  if(len < FLAG_LENGTH)
    return;
  if(buf[EVENT_INDEX_1] == discovery_done_flag[EVENT_INDEX_1]
      && buf[EVENT_INDEX_2] == discovery_done_flag[EVENT_INDEX_2])
  {
    // Success
    if(buf[STATUS_INDEX] == SUCCESS)
    {
      int i = sizeof discovery_done_flag;
      printf("\n");
      char address[18]; //6*2+5+1
      char *params = (char *) malloc(256);
      strcpy(params,"");
      strcat(params, "scan/?router_id=1&data=");
      while(len >= i+8+6)
      {
        if(buf[i+1] == 0x03)
        {
          sprintf(&address[0], "%02X", buf[i+13]);
          address[2] = ':';
          sprintf(&address[3], "%02X", buf[i+12]);
          address[5] = ':';
          sprintf(&address[6], "%02X", buf[i+11]);
          address[8] = ':';
          sprintf(&address[9], "%02X", buf[i+10]);
          address[11] = ':';
          sprintf(&address[12], "%02X", buf[i+9]);
          address[14] = ':';
          sprintf(&address[15], "%02X", buf[i+8]);
          strcat(params, address);
          // resolve address unsucceed
          if(buf[i+2] == buf[i+8] && buf[i+3] == buf[i+9]
            && buf[i+4] == buf[i+10] && buf[i+5] == buf[i+11]
            && buf[i+6] == buf[i+12] && buf[i+7] == buf[i+13])
          {
            strcat(params, ":0_");
          }
          else
          {
            strcat(params, ":1_");
          }
        }
        printf("original address=%02x:%02x:%02x:%02x:%02x:%02x[%02x]\t", 
          buf[i+7],buf[i+6],buf[i+5],buf[i+4],buf[i+3],buf[i+2],buf[i+1]);
        i+=6;
        printf("resolved address=%02x:%02x:%02x:%02x:%02x:%02x\n", 
          buf[i+7],buf[i+6],buf[i+5],buf[i+4],buf[i+3],buf[i+2]);
        i+=8;
      }
      printf("%s\n", params);
      printf("\n");
      process_post(params);
      free(params);
      listen_serial_port(my_fd, REQUEST_SCAN, NULL, NULL);
    }
    else
    {
      printf("Scan failed, retry\n");
      listen_serial_port(my_fd, REQUEST_SCAN, NULL, NULL);
    }
  }
}
