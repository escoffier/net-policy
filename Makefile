CROSS_COMPILE ?= 

LOCAL_DIR   = $(shell pwd)
INCLUDE_DIR = $(LOCAL_DIR)/include
LIB_DIR     = $(LOCAL_DIR)/lib
SAMPLE_DIR  = $(LOCAL_DIR)/sample
INSTALL_DIR = $(LOCAL_DIR)/install
INSTALL_TAR = install.tar.gz
##
TEST_BIN = net-rule
#net socket public lib
LIBMNL_LIB = net
LIBMNL_DIR = $(LOCAL_DIR)/libmnl/
#
CONNTRACK_LIB = conntrack
CONNTRACK_DIR = $(LOCAL_DIR)/libnetfilter_conntrack/
#
NFNET_LIB = nfnetlink
NFNET_DIR = $(LOCAL_DIR)/libnfnetlink/
#
NFQUEUE_LIB = nfqueue
NFQUEUE_DIR = $(LOCAL_DIR)/libnetfilter_queue/
#object
CC_OBJUECT  = $(patsubst %.c,%.o,$(wildcard *.c))
CC_OBJUECT += $(patsubst %.cpp,%.o,$(wildcard *.cpp))
#gcc
CCFLAGS ?= -Wall -g3 -D_GNU_SOURCE -lstdc++
CC	?=$(CROSS_COMPILE)gcc
CXX	?=$(CROSS_COMPILE)g++
#link libs
LIBS    += -lpthread -std=c++11 -Wno-deprecated
##
all:$(LIBMNL_LIB) $(CONNTRACK_LIB) $(NFNET_LIB) $(NFQUEUE_LIB) $(TEST_BIN)

%.o:%.c
	$(CC) $(CCFLAGS) $^ -c -o $@ -I$(INCLUDE_DIR)

%.o:%.cpp
	$(CXX) $(CCFLAGS) $^ -c -o $@ -I$(INCLUDE_DIR) $(LIBS)

.PHONY:$(TEST_BIN)
$(TEST_BIN):$(CC_OBJUECT)
	$(CXX) $(CCFLAGS) -o $@ *.o -I$(INCLUDE_DIR) $(LIBS)
	@cp -rf $(TEST_BIN) $(BIN_DIR)



#libmnl
.PHONY:$(LIBMNL_LIB)
$(LIBMNL_LIB):
	$(MAKE) -C $(LIBMNL_DIR) LIB_DIR=$(LIB_DIR) INCLUDE_DIR=$(INCLUDE_DIR)

#conntrack
.PHONY:$(CONNTRACK_LIB)
$(CONNTRACK_LIB):$(LIBMNL_LIB) $(NFNET_LIB)
	$(MAKE) -C $(CONNTRACK_DIR) LIB_DIR=$(LIB_DIR) INCLUDE_DIR=$(INCLUDE_DIR)

#nfqueue
.PHONY:$(NFQUEUE_LIB)
$(NFQUEUE_LIB):
	$(MAKE) -C $(NFQUEUE_DIR) LIB_DIR=$(LIB_DIR) INCLUDE_DIR=$(INCLUDE_DIR)

#acc data
.PHONY:$(NFNET_LIB)
$(NFNET_LIB):
	$(MAKE) -C $(NFNET_DIR) LIB_DIR=$(LIB_DIR) INCLUDE_DIR=$(INCLUDE_DIR)


.PHONY:install
install: all $(SAMPLE_BIN)
	mkdir -p $(INSTALL_DIR)
	cp -rf $(INCLUDE_DIR) $(INSTALL_DIR)/
	cp -rf $(LIB_DIR) $(INSTALL_DIR)/
	cp -rf $(SAMPLE_DIR) $(INSTALL_DIR)/
	tar -zcf $(INSTALL_TAR) install/
	cp -rf $(LIB_DIR)/* /usr/lib/

clean:
	$(MAKE) clean -C $(LIBMNL_DIR)
	$(MAKE) clean -C $(CONNTRACK_DIR)
	$(MAKE) clean -C $(NFNET_DIR)
	$(MAKE) clean -C $(NFQUEUE_DIR)
	@rm -rf $(INCLUDE_DIR)/* *.o $(TEST_BIN)

.PHONY:all clean
