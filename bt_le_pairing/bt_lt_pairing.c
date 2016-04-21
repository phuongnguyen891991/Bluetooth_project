//#ifdef HAVE_CONFIG_H
//#include "config.h"
//#endif

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <curses.h>
#include <unistd.h>                                                                                   
#include <stdlib.h>                                                                                   
#include <stdint.h>
#include <string.h>                                                                                   
#include <getopt.h>                                                                                   
#include <sys/param.h>                                                                                
#include <sys/ioctl.h>                                                                                
#include <sys/socket.h>                                                                               
#include <sys/stat.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

struct hci_dev_info di;
static int all;
static void print_dev_hdr(struct hci_dev_info *di);
static void print_dev_info(int ctl, struct hci_dev_info *di);

static void print_dev_info(int ctl, struct hci_dev_info *di)
{
	struct hci_dev_stats *st = &di->stat;
	char *str;

	print_dev_hdr(di);

	str = hci_dflagstostr(di->flags);
	printf("\t%s\n", str);
	bt_free(str);

	printf("\tRX bytes:%d acl:%d sco:%d events:%d errors:%d\n",
		st->byte_rx, st->acl_rx, st->sco_rx, st->evt_rx, st->err_rx);

	printf("\tTX bytes:%d acl:%d sco:%d commands:%d errors:%d\n",
		st->byte_tx, st->acl_tx, st->sco_tx, st->cmd_tx, st->err_tx);

	if (all && !hci_test_bit(HCI_RAW, &di->flags)) {
		//print_dev_features(di, 0);

		if (((di->type & 0x30) >> 4) == HCI_BREDR) {
//			print_pkt_type(di);
//			print_link_policy(di);
//			print_link_mode(di);

			if (hci_test_bit(HCI_UP, &di->flags)) {
//				cmd_name(ctl, di->dev_id, NULL);
//				cmd_class(ctl, di->dev_id, NULL);
			}
		}

		if (hci_test_bit(HCI_UP, &di->flags)) ;
	//		cmd_version(ctl, di->dev_id, NULL);
	}

	printf("\n");
}
static void print_dev_hdr(struct hci_dev_info *di)
{
	static int hdr = -1;
	char addr[18];

	if (hdr == di->dev_id)
		return;
	hdr = di->dev_id;

	ba2str(&di->bdaddr, addr);

	printf("%s:\tType: %s  Bus: %s\n", di->name,
					hci_typetostr((di->type & 0x30) >> 4),
					hci_bustostr(di->type & 0x0f));
	printf("\tBD Address: %s  ACL MTU: %d:%d  SCO MTU: %d:%d\n",
					addr, di->acl_mtu, di->acl_pkts,
						di->sco_mtu, di->sco_pkts);
}
static void print_dev_list(int ctl, int flags)
{
	struct hci_dev_list_req *dl;
	struct hci_dev_req *dr;
	int i;

	if (!(dl = malloc(HCI_MAX_DEV * sizeof(struct hci_dev_req) +
		sizeof(uint16_t)))) {
		perror("Can't allocate memory");
		exit(1);
	}
	dl->dev_num = HCI_MAX_DEV;
	dr = dl->dev_req;

	if (ioctl(ctl, HCIGETDEVLIST, (void *) dl) < 0) {
		perror("Can't get device list");
		free(dl);
		exit(1);
	}

	for (i = 0; i< dl->dev_num; i++) {
		di.dev_id = (dr+i)->dev_id;
		if (ioctl(ctl, HCIGETDEVINFO, (void *) &di) < 0)
			continue;
		print_dev_info(ctl, &di);
	}

	free(dl);
}
int hci_write_simple_pairing_mode(int dd, uint8_t mode, int to)
{
        write_simple_pairing_mode_cp cp;
        write_simple_pairing_mode_rp rp;
        struct hci_request rq;

        memset(&cp, 0, sizeof(cp));
        cp.mode = mode;

        memset(&rq, 0, sizeof(rq));
        rq.ogf    = OGF_HOST_CTL;
        rq.ocf    = OCF_WRITE_SIMPLE_PAIRING_MODE;
        rq.cparam = &cp;
        rq.clen   = WRITE_SIMPLE_PAIRING_MODE_CP_SIZE;
        rq.rparam = &rp;
        rq.rlen   = WRITE_SIMPLE_PAIRING_MODE_RP_SIZE;

        if (hci_send_req(dd, &rq, to) < 0)
                return -1;

        if (rp.status) {
                errno = EIO;
                return -1;
        }

        return 0;
}


int hci_read_simple_pairing_mode(int dd, uint8_t *mode, int to)
{
        read_simple_pairing_mode_rp rp;
        struct hci_request rq;

        memset(&rq, 0, sizeof(rq));
        rq.ogf    = OGF_HOST_CTL;
        rq.ocf    = OCF_READ_SIMPLE_PAIRING_MODE;
        rq.rparam = &rp; 
        rq.rlen   = READ_SIMPLE_PAIRING_MODE_RP_SIZE;

        if (hci_send_req(dd, &rq, to) < 0) 
                return -1;

        if (rp.status) {
                errno = EIO; 
                return -1;
        }

        *mode = rp.mode;
        return 0;
}

static void cmd_ssp_mode(int ctl, int hdev, char *opt)
{
        int dd;

        dd = hci_open_dev(hdev);
        if (dd < 0) { 
                fprintf(stderr, "Can't open device hci%d: %s (%d)\n",
                                                hdev, strerror(errno), errno);
                exit(1);
        }    

        if (opt) {
                uint8_t mode = atoi(opt);

                if (hci_write_simple_pairing_mode(dd, mode, 2000) < 0) { 
                        fprintf(stderr, "Can't set Simple Pairing mode on hci%d: %s (%d)\n",
                                        hdev, strerror(errno), errno);
                        exit(1);
                }    
        } else 
	{
 		uint8_t mode;

                if (hci_read_simple_pairing_mode(dd, &mode, 1000) < 0) { 
                        fprintf(stderr, "Can't read Simple Pairing mode on hci%d: %s (%d)\n",
                                        hdev, strerror(errno), errno);
                        exit(1);
                }

                print_dev_hdr(&di);
                printf("\tSimple Pairing mode: %s\n",
                        mode == 1 ? "Enabled" : "Disabled");
        }

        hci_close_dev(dd);
}

int main (int argc , char *argv[])
{
 int dev_id = -1;
 int opt,ctl;

 if ((ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)) < 0) {
                perror("Can't open HCI socket.");
                exit(1);
        }

        if (argc < 1) {
                print_dev_list(ctl, 0);
                exit(0);
        }

        di.dev_id = atoi(argv[0] + 3);
	 if (ioctl(ctl, HCIGETDEVINFO, (void *) &di)) {
                perror("Can't get device info");
                exit(1);
        }
	cmd_ssp_mode(ctl,dev_id,argv[2]);

	close(ctl);
	return 0;


}

