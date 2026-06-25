CROSS_COMPILE ?= 

LOCAL_DIR = $(shell pwd)
#objuect
MAINFILE    = main.c main.o
CC_OBJUECT  = $(patsubst %.c,%.o,$(wildcard *.c))
CC_OBJUECT += $(patsubst %.cpp,%.o,$(wildcard *.cpp))
LIB_OBJUECT = $(filter-out $(MAINFILE), $(CC_OBJUECT))
#gcc
CCFLAGS ?= -Wall -g3 -D_GNU_SOURCE
CC	?=$(CROSS_COMPILE)gcc
CXX	?=$(CROSS_COMPILE)g++
#link libs
LIBS    += -lpthread -std=c++0x -Wno-deprecated
LIBS    += -L$(LIB_DIR)
INCLUDE += -I$(INCLUDE_DIR)

all:$(LIB_OBJUECT)

%.o:%.c
	@mkdir -p $(INCLUDE_DIR)/libnetfilter_conntrack
	@cp -rf internal/ $(INCLUDE_DIR)/
	@cp -rf *.h $(INCLUDE_DIR)/libnetfilter_conntrack/
	$(CC) $(CCFLAGS) $^ -c -o $@ $(INCLUDE)
	@cp -rf *.o $(LOCAL_DIR)/../

%.o:%.cpp
	$(CXX) $(CCFLAGS) $^ -c -o $@ $(INCLUDE)

clean:
	@rm -rf *.o *.log

.PHONY:all clean

