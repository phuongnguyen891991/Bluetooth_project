
SRCS_NAME = bt_lt_pairing
LOCAL_SRCS = $(SRCS_NAME).c
CC=gcc
CFLAGS= -O0 -g

#CPPFLAGS= -DHAVE_CONFIG_H
LIBS_PATH += -lbluetooth
LIBS_PATH += -lcurses
all: $(SRCS_NAME)

$(SRCS_NAME): $(LOCAL_SRCS)
	$(CC) -L. $(CFLAGS) $(CPPFLAGS) -o $@ $(LOCAL_SRCS) $(LIBS_PATH)
clean:
	rm -f *.o release

