DIR_INC = ./include
DIR_SRC = ./src
DIR_OBJ = ./obj
DIR_BIN = ./

SRC = $(wildcard ${DIR_SRC}/*.c)
OBJ = $(patsubst %.c,${DIR_OBJ}/%.o,$(notdir ${SRC}))

TARGET = resolvable-scanner

BIN_TARGET = ${DIR_BIN}/${TARGET}

#CC = gcc
#CFLAGS = -g -Wall 
CFLAGS += -Wall -O2 -g -I${DIR_INC}

# Libraries to link
#LIBS = -lbluetooth -lpthread -lm

${BIN_TARGET}:${OBJ}
	$(CC) $(CFLAGS) $(OBJ) -o $@ $(LIBS)
    
${DIR_OBJ}/%.o:${DIR_SRC}/%.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY:clean
clean:
	find ${DIR_OBJ} -name *.o -exec rm -rf {} \;
