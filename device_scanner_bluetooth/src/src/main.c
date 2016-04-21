#include "main.h"

void list_help()
{
  printf("Usage:\n");
  printf("        resolvable-scanner \"port\" <command> [command parameters]\n");
  printf("options:\n");
  printf("        -h            Display Help\n");
  printf("        -d            Discover Devices\n");
  printf("        -c [bdaddr]   Connect Devices\n");
  printf("        -q [handle]   Disconnect Devices\n");
  printf("        -p [handle]   Pair Devices\n");
  printf("        -r [handle]   Pair devices and then register to server\n");
  printf("        -s            Scan nearby devices and upload to server\n");
}

int main(int argc, char *argv[])
{
	int fd;
	if(argc <= 2) {
    list_help();
    return -1;
  }
  if(strcmp(argv[2], "-d") == 0 || strcmp(argv[2], "-c") == 0
      || strcmp(argv[2], "-q") == 0 || strcmp(argv[2], "-p") == 0
      || strcmp(argv[2], "-s") == 0 || strcmp(argv[2], "-r") == 0)
  {
    // connect devices
    if(strcmp(argv[2], "-c") == 0)
    {
      if (argc <= 3)
      {
        printf("resolvable-scanner \"port\" -c [bdaddr]\n");
        return -1;
      }
      else
      {
        char *pattern = "^\\w{2}:\\w{2}:\\w{2}:\\w{2}:\\w{2}:\\w{2}$";
        int cflags = REG_EXTENDED;
        regmatch_t pmatch[1];
        regex_t reg;
        regcomp(&reg, pattern, cflags);
        int status = regexec(&reg, argv[3], 1, pmatch, 0);
        regfree(&reg);
        if(status == REG_NOMATCH)
        {
          printf("invalid mac address\n");
          return -1;
        }
      }
    }
    // disconnect deivces
    else if(strcmp(argv[2], "-q") == 0)
    {
      if (argc <= 3)
      {
        printf("test \"port\" -q [handle]\n");
        return -1;
      }
      if(strlen(argv[3]) != 4)
      {
        printf("invalid handle(length != 4)\n");
        return -1;
      }
    }
    // pair devices & register to server
    else if(strcmp(argv[2], "-p") == 0 || strcmp(argv[2], "-r") == 0)
    {
      if (argc <= 3)
      {
        printf("test \"port\" -p [handle]\n");
        return -1;
      }
      if(strlen(argv[3]) != 4)
      {
        printf("invalid handle(length != 4)\n");
        return -1;
      }
    }
  	fd = init_port(argv[1]);
  	if(fd == -1)
  		return -1;
  	if(init_hci(fd)<=0)
    {
      printf("HCI initialize failed\n");
      return -1;
    }
  }
  else
  {
    list_help();
    return -1;
  }

  if(strcmp(argv[2], "-d") == 0)
		listen_serial_port(fd, REQUEST_DISCOVERY, NULL, NULL);
  else if(strcmp(argv[2], "-c") == 0)
    listen_serial_port(fd, REQUEST_CONNECT, argv[3], NULL);
  else if(strcmp(argv[2],"-q") == 0)
    listen_serial_port(fd, REQUEST_DISCONNECT,NULL,argv[3]);
  else if(strcmp(argv[2],"-p") == 0)
    listen_serial_port(fd, REQUEST_PAIRING,NULL,argv[3]);
  else if(strcmp(argv[2],"-r") == 0)
    listen_serial_port(fd, REQUEST_PAIRING_REGISTER,NULL,argv[3]);
  if(strcmp(argv[2], "-s") == 0)
    listen_serial_port(fd, REQUEST_SCAN, NULL, NULL);
  return 0;
}