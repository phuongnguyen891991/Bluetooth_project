BLUEZ_PATH = ./bluez-5.28

BLUEZ_SRCS  = lib/bluetooth.c lib/hci.c lib/sdp.c lib/uuid.c
BLUEZ_SRCS += attrib/att.c attrib/gatt.c attrib/gattrib.c attrib/utils.c
BLUEZ_SRCS += btio/btio.c src/log.c src/shared/mgmt.c
BLUEZ_SRCS += src/shared/crypto.c src/shared/att.c src/shared/queue.c src/shared/util.c
BLUEZ_SRCS += src/shared/io-glib.c src/shared/timeout-glib.c

IMPORT_SRCS = $(addprefix $(BLUEZ_PATH)/, $(BLUEZ_SRCS))
SRCS_NAME = bt_auto_connect
LOCAL_SRCS  = $(SRCS_NAME).c

CC = gcc
CFLAGS =-g 

CPPFLAGS = -DHAVE_CONFIG_H

CPPFLAGS += -I$(BLUEZ_PATH)/attrib -I$(BLUEZ_PATH) -I$(BLUEZ_PATH)/lib -I$(BLUEZ_PATH)/src -I$(BLUEZ_PATH)/gdbus -I$(BLUEZ_PATH)/btio

CPPFLAGS += `pkg-config glib-2.0 --cflags`
LDLIBS += `pkg-config glib-2.0 --libs`
LIBS_PATH+= -lreadline
all: $(SRCS_NAME)

$(SRCS_NAME): $(LOCAL_SRCS) $(IMPORT_SRCS)
	$(CC) -L. $(CFLAGS) $(CPPFLAGS)  -o $@ $(LOCAL_SRCS) $(IMPORT_SRCS) $(LDLIBS) $(LIBS_PATH)

clean:
	rm -f *.o $(SRCS_NAME)

