/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unistd.h>

#include <stdbool.h>

#include <bluetooth/bluetooth.h>
#include <glib.h>

#include "lib/uuid.h"
#include "src/plugin.h"
#include "src/adapter.h"
#include "src/shared/util.h"
#include "src/log.h"
#include "attrib/gattrib.h"
#include "attrib/gatt-service.h"
#include "attrib/att.h"
#include "attrib/gatt.h"
#include "attrib/att-database.h"
#include "src/attrib-server.h"

/* Header for Advertise Data */
#include <errno.h>
#include <curses.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <sys/time.h>

#include "lib/hci.h"
#include "lib/hci_lib.h"
#include "lib/bluetooth.h"

#define MAX_STR_LEN       (256)

#define SIMPLE_PERIPHERAL_UUID	"81244ae0179c495ca0b18698d63e0778"

#define SIMPLE_SVC_UUID      0xfff0
#define SIMPLE_READ1_CHAR_UUID    0xfff1
#define SIMPLE_READ2_CHAR_UUID    0xfff2
#define SIMPLE_WRITE_CHAR_UUID    0xfff3
#define SIMPLE_NOTIFY_CHAR_UUID    0xfff4

enum devicetype {
	LINKSYS_DEV = 0,
	WEEBOO_DEV,
};

enum devicestatus {
	DEV_UNCONFIGURED = 0,
	DEV_CONFIGURED,
};

static char read1Data[MAX_STR_LEN];
static char read2Data[MAX_STR_LEN];

static int notifyData;

#define cmd_opcode_pack(ogf, ocf) (uint16_t)((ocf & 0x03ff)|(ogf << 10))

#define EIR_FLAGS                   0X01
#define EIR_NAME_SHORT              0x08
#define EIR_NAME_COMPLETE           0x09
#define EIR_MANUFACTURE_SPECIFIC    0xFF

static unsigned int *uuid_str_to_data(char *uuid)
{
	char conv[] = "0123456789ABCDEF";
	int len = strlen(uuid);
	unsigned int *data = (unsigned int*)malloc(sizeof(unsigned int) * len);
	unsigned int *dp = data;
	char *cu = uuid;

	for(; cu<uuid+len; dp++,cu+=2)
	{
		*dp = ((strchr(conv, toupper(*cu)) - conv) * 16)
			+ (strchr(conv, toupper(*(cu+1))) - conv);
	}

	return data;
}

static unsigned int twoc(int in, int t)
{
	return (in < 0) ? (in + (2 << (t-1))) : in;
}

static void advertise_start(void)
{
	uint8_t status;
	struct hci_request rq;
	int i;
	int ret;
	unsigned int *uuid;
	uint8_t segment_length;
	int device_id, device_handle;

	le_set_advertising_data_cp adv_data_cp;
	le_set_advertising_parameters_cp adv_params_cp;
	le_set_advertise_enable_cp advertise_cp;

	device_handle = 0;
	device_id = hci_get_route(NULL);
	if((device_handle = hci_open_dev(device_id)) < 0)
	{
		perror("Could not open device");
		exit(1);
	}

	/* Disable Advertise */
	memset(&advertise_cp, 0, sizeof(advertise_cp));

	memset(&rq, 0, sizeof(rq));
	rq.ogf = OGF_LE_CTL;
	rq.ocf = OCF_LE_SET_ADVERTISE_ENABLE;
	rq.cparam = &advertise_cp;
	rq.clen = LE_SET_ADVERTISE_ENABLE_CP_SIZE;
	rq.rparam = &status;
	rq.rlen = 1;

	ret = hci_send_req(device_handle, &rq, 1000);
	if (ret < 0)
		goto done;

	sleep(2);

	/* Set Advertise Data */
	memset(&adv_data_cp, 0, sizeof(adv_data_cp));
	segment_length = 1;
	adv_data_cp.data[adv_data_cp.length + segment_length] = htobs(EIR_FLAGS); segment_length++;
	adv_data_cp.data[adv_data_cp.length + segment_length] = htobs(0x16); segment_length++;
	adv_data_cp.data[adv_data_cp.length] = htobs(segment_length - 1);
	adv_data_cp.length += segment_length;

	segment_length = 1;
	adv_data_cp.data[adv_data_cp.length + segment_length] = htobs(EIR_MANUFACTURE_SPECIFIC); segment_length++;
	adv_data_cp.data[adv_data_cp.length + segment_length] = htobs(0x5C); segment_length++;
	adv_data_cp.data[adv_data_cp.length + segment_length] = htobs(0x00); segment_length++;

	uuid = uuid_str_to_data(SIMPLE_PERIPHERAL_UUID);

        for(i = 0; i < strlen(SIMPLE_PERIPHERAL_UUID) / 2; i++) {
                adv_data_cp.data[adv_data_cp.length + segment_length]  = htobs(uuid[i]); segment_length++;
        }

	adv_data_cp.data[adv_data_cp.length + segment_length] = htobs(LINKSYS_DEV); segment_length++;
	adv_data_cp.data[adv_data_cp.length + segment_length] = htobs(DEV_CONFIGURED); segment_length++;
	adv_data_cp.data[adv_data_cp.length] = htobs(segment_length - 1);
	adv_data_cp.length += segment_length;

	DBG("Segment_length:%x", adv_data_cp.length);

	memset(&rq, 0, sizeof(rq));
	rq.ogf = OGF_LE_CTL;
	rq.ocf = OCF_LE_SET_ADVERTISING_DATA;
	rq.cparam = &adv_data_cp;
	rq.clen = LE_SET_ADVERTISING_DATA_CP_SIZE;
	rq.rparam = &status;
	rq.rlen = 1;

	ret = hci_send_req(device_handle, &rq, 1000);
	if (ret < 0)
		goto done;

	sleep(2);

	/* Set Advertise Params */
	memset(&adv_params_cp, 0, sizeof(adv_params_cp));
	adv_params_cp.min_interval = htobs(0x0800);
	adv_params_cp.max_interval = htobs(0x0800);
	adv_params_cp.chan_map = 7;

	memset(&rq, 0, sizeof(rq));
	rq.ogf = OGF_LE_CTL;
	rq.ocf = OCF_LE_SET_ADVERTISING_PARAMETERS;
	rq.cparam = &adv_params_cp;
	rq.clen = LE_SET_ADVERTISING_PARAMETERS_CP_SIZE;
	rq.rparam = &status;
	rq.rlen = 1;

	ret = hci_send_req(device_handle, &rq, 1000);
	if (ret < 0)
		goto done;

	sleep(2);

	memset(&advertise_cp, 0, sizeof(advertise_cp));
	advertise_cp.enable = 0x01;

	memset(&rq, 0, sizeof(rq));
	rq.ogf = OGF_LE_CTL;
	rq.ocf = OCF_LE_SET_ADVERTISE_ENABLE;
	rq.cparam = &advertise_cp;
	rq.clen = LE_SET_ADVERTISE_ENABLE_CP_SIZE;
	rq.rparam = &status;
	rq.rlen = 1;

	ret = hci_send_req(device_handle, &rq, 1000);
	if (ret < 0)
		goto done;
done:
	hci_close_dev(device_handle);
}

static uint8_t SimpleCharacteristic1Read(struct attribute *a,
		struct btd_device *device, gpointer user_data)
{
	struct btd_adapter *adapter;

	printf("__FILE__ = %s, __FUNCTION__ = %s, __LINE__ =%d\n",
			__FILE__, __FUNCTION__, __LINE__);


	adapter = user_data;

	attrib_db_update(adapter, a->handle, NULL,
			(uint8_t*)&read1Data[0], strlen(&read1Data[0]), NULL);

	return 0;
}

static uint8_t SimpleCharacteristic2Read(struct attribute *a,
		struct btd_device *device, gpointer user_data)
{
	struct btd_adapter *adapter;

	printf("__FILE__ = %s, __FUNCTION__ = %s, __LINE__ =%d\n",
			__FILE__, __FUNCTION__, __LINE__);


	adapter = user_data;

	attrib_db_update(adapter, a->handle, NULL,
			(uint8_t*)&read2Data[0], strlen(&read2Data[0]), NULL);

	return 0;
}

static uint8_t SimpleCharacteristicWrite(struct attribute *a,
		struct btd_device *device, gpointer user_data)
{

	unsigned char data[MAX_STR_LEN];
	int i;

	printf("__FILE__ = %s, __FUNCTION__ = %s, __LINE__ =%d\n",
			__FILE__, __FUNCTION__, __LINE__);

	memset(&data[0], 0, MAX_STR_LEN);

	memcpy(&data[0], a->data, a->len);

	printf("written data : %s \n", &data[0]);

	for(i = 0; i< a->len;i++)
		printf("%#1x ", (unsigned char)(data[i]));
	printf("\n");

	return 0;
}

static uint8_t SimpleCharacteristicNotify(struct attribute *a,
		struct btd_device *device, gpointer user_data)
{
	struct btd_adapter *adapter;

	adapter = user_data;


	printf("__FILE__ = %s, __FUNCTION__ = %s, __LINE__ =%d\n",
			__FILE__, __FUNCTION__, __LINE__);

	do
	{
		attrib_db_update(adapter, a->handle, NULL,
				(uint8_t*)&notifyData, sizeof(notifyData), NULL);

		usleep(1*1000*1000);
		notifyData++;
	} while(0);

	return 0;
}


static void RegisterSimpleService(struct btd_adapter *adapter)
{
	bt_uuid_t uuid;
	printf("__FILE__ = %s, __FUNCTION__ = %s, __LINE__ =%d\n",
			__FILE__, __FUNCTION__, __LINE__);

	bt_uuid16_create(&uuid, SIMPLE_SVC_UUID);

	gatt_service_add(adapter, GATT_PRIM_SVC_UUID, &uuid,
		/* characteristic register*/
		/*read 1*/
		GATT_OPT_CHR_UUID16, SIMPLE_READ1_CHAR_UUID,
		GATT_OPT_CHR_PROPS, GATT_CHR_PROP_READ ,
		GATT_OPT_CHR_VALUE_CB, ATTRIB_READ,
		SimpleCharacteristic1Read, adapter,

		/*read 2*/
		GATT_OPT_CHR_UUID16, SIMPLE_READ2_CHAR_UUID,
		GATT_OPT_CHR_PROPS, GATT_CHR_PROP_READ ,
		GATT_OPT_CHR_VALUE_CB, ATTRIB_READ,
		SimpleCharacteristic2Read, adapter,

		/*write*/
		GATT_OPT_CHR_UUID16, SIMPLE_WRITE_CHAR_UUID,
		GATT_OPT_CHR_PROPS, GATT_CHR_PROP_WRITE_WITHOUT_RESP,
		GATT_OPT_CHR_VALUE_CB, ATTRIB_WRITE,
		SimpleCharacteristicWrite, adapter,

		/*NOTIFY*/
		GATT_OPT_CHR_UUID16, SIMPLE_NOTIFY_CHAR_UUID,
		GATT_OPT_CHR_PROPS, GATT_CHR_PROP_READ|GATT_CHR_PROP_NOTIFY,
		GATT_OPT_CHR_VALUE_CB, ATTRIB_READ,
		SimpleCharacteristicNotify, adapter,
		/*end*/
		GATT_OPT_INVALID);

	return ;
}

#define DEVICEINFO_SVC_UUID     0x180a

char versionStr[MAX_STR_LEN] = "0.0.1";
char manufacturerStr[MAX_STR_LEN] = "Belkin";

static uint8_t SoftwareRevisionStringRead(struct attribute *a,
		struct btd_device *device, gpointer user_data)
{
	struct btd_adapter *adapter;


	printf("__FILE__ = %s, __FUNCTION__ = %s, __LINE__ =%d\n",
			__FILE__, __FUNCTION__, __LINE__);

	adapter = user_data;

	attrib_db_update(adapter, a->handle, NULL,
			(uint8_t*)&versionStr[0], strlen(&versionStr[0]), NULL);

	return 0;
}

static uint8_t ManufacturerStringRead(struct attribute *a,
		struct btd_device *device, gpointer user_data)
{
	struct btd_adapter *adapter;

	printf("__FILE__ = %s, __FUNCTION__ = %s, __LINE__ =%d\n",
			__FILE__, __FUNCTION__, __LINE__);

	adapter = user_data;

	attrib_db_update(adapter, a->handle, NULL,
			(uint8_t*)&manufacturerStr[0], strlen(&manufacturerStr[0]), NULL);

	return 0;
}

static void RegisterDeviceInfo(struct btd_adapter *adapter)
{
	bt_uuid_t uuid;
	printf("__FILE__ = %s, __FUNCTION__ = %s, __LINE__ =%d\n",
			__FILE__, __FUNCTION__, __LINE__);

	bt_uuid16_create(&uuid, DEVICEINFO_SVC_UUID);

	gatt_service_add(adapter, GATT_PRIM_SVC_UUID, &uuid,
		/*GATT_CHARAC_SOFTWARE_REVISION_STRING*/
		GATT_OPT_CHR_UUID16, GATT_CHARAC_SOFTWARE_REVISION_STRING,
		GATT_OPT_CHR_PROPS, GATT_CHR_PROP_READ ,
		GATT_OPT_CHR_VALUE_CB, ATTRIB_READ,
		SoftwareRevisionStringRead, adapter,

		/*GATT_CHARAC_MANUFACTURER_NAME_STRING*/
		GATT_OPT_CHR_UUID16, GATT_CHARAC_MANUFACTURER_NAME_STRING,
		GATT_OPT_CHR_PROPS, GATT_CHR_PROP_READ ,
		GATT_OPT_CHR_VALUE_CB, ATTRIB_READ,
		ManufacturerStringRead, adapter,
		/*end*/
		GATT_OPT_INVALID);

	return ;
}

static void update_name(struct btd_adapter *adapter, gpointer user_data)
{
	adapter_set_name(adapter, (char*)user_data);
}

static void alarm_wakeup (int i)
{
	DBG("\n Wakeup!!!\n");
	DBG("========= Start Advertising");
	advertise_start();
	DBG("========= Done Advertising");
}

static void abc_disconnect_cb(struct btd_device *dev, uint8_t reason)
{
	struct itimerval tout_val;

	DBG("==== abc_disconnect_cb called: %p", abc_disconnect_cb);
	DBG("=============== abc_disconnect_cb called: %p ==================", abc_disconnect_cb);
	tout_val.it_interval.tv_sec = 0;
	tout_val.it_interval.tv_usec = 0;
	tout_val.it_value.tv_sec = 5; /* 10 seconds timer */
	tout_val.it_value.tv_usec = 0;
	setitimer(ITIMER_REAL, &tout_val,0);

	DBG("========= Trigger Timer");
	signal(SIGALRM,alarm_wakeup);
}

static int wii_probe(struct btd_adapter *adapter)
{
	struct itimerval tout_val;

	update_name(adapter, "LINKSYSNODE");
	RegisterDeviceInfo(adapter);
	RegisterSimpleService(adapter);

	btd_add_disconnect_cb(abc_disconnect_cb);
	DBG("=========abc_disconnect_cb: %p\n", abc_disconnect_cb);

	/* Register to advertise 5s later */
	tout_val.it_interval.tv_sec = 0;
	tout_val.it_interval.tv_usec = 0;
	tout_val.it_value.tv_sec = 5;
	tout_val.it_value.tv_usec = 0;
	setitimer(ITIMER_REAL, &tout_val,0);

	DBG("========= Trigger Timer");
	signal(SIGALRM,alarm_wakeup);

	return 0;
}

static void wii_remove(struct btd_adapter *adapter)
{

}

/*function pointers*/
static struct btd_adapter_driver wii_driver = {
	.name = "wiimote",
	.probe = wii_probe,
	.remove = wii_remove,
};


static int wii_init(void)
{
	printf("__FUNCTION__ = %s\n", __FUNCTION__);

	memset(&read1Data[0], 0, MAX_STR_LEN);
	memset(&read2Data[0], 0, MAX_STR_LEN);
	notifyData = 0;

	snprintf(&read1Data[0], MAX_STR_LEN, "it is read 1");
	snprintf(&read2Data[0], MAX_STR_LEN, "it is read 2");

	return btd_register_adapter_driver(&wii_driver);
}

static void wii_exit(void)
{
	printf("__FUNCTION__ = %s\n", __FUNCTION__);
	btd_remove_disconnect_cb(abc_disconnect_cb);
	btd_unregister_adapter_driver(&wii_driver);
}

BLUETOOTH_PLUGIN_DEFINE(wiimote, VERSION,
		BLUETOOTH_PLUGIN_PRIORITY_LOW, wii_init, wii_exit)
