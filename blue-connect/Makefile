BLUEZ_PATH=../bluez-lib

BLUEZ_SRCS  = lib/bluetooth.c lib/hci.c lib/sdp.c lib/uuid.c
BLUEZ_SRCS += attrib/att.c attrib/gatt.c attrib/gattrib.c attrib/utils.c attrib/interactive.c 
BLUEZ_SRCS += btio/btio.c src/log.c

IMPORT_SRCS = $(addprefix $(BLUEZ_PATH)/, $(BLUEZ_SRCS))
LOCAL_SRCS  = blue-connect.c

CC = gcc
CFLAGS = -O0 -g

CPPFLAGS = -DHAVE_CONFIG_H

CPPFLAGS += -I$(BLUEZ_PATH)/attrib -I$(BLUEZ_PATH) -I$(BLUEZ_PATH)/lib -I$(BLUEZ_PATH)/src -I$(BLUEZ_PATH)/gdbus -I$(BLUEZ_PATH)/btio

CPPFLAGS += `pkg-config glib-2.0 --cflags`
LDLIBS += `pkg-config glib-2.0 --libs`
LIBS_PATH+= -lsqlite3 
LIBS_PATH+= -lreadline
all: blue-connect

blue-connect: $(LOCAL_SRCS) $(IMPORT_SRCS)
	$(CC) -L. $(CFLAGS) $(CPPFLAGS)  -o $@ $(LOCAL_SRCS) $(IMPORT_SRCS) $(LDLIBS) $(LIBS_PATH)

clean:
	rm -f *.o blue-connect

