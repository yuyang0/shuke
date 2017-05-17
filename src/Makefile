#==========================================================================
#        Author:  Yu Yang
#         Email:  yyangplus@NOSPAM.gmail.com
#       Created:  2017-05-02 二 17:29
#==========================================================================
OPTIMIZATION?=-O2

# Default settings
STD=-std=gnu99 -pedantic
WARN=-Wall -W
OPT=$(OPTIMIZATION)
DEBUG=-g -ggdb

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = shuke-server

# all source are stored in SRCS-y

SRCS-y := admin.c ae.c anet.c conf.c dict.c dpdk_module.c ds.c mongo.c \
          protocol.c sds.c shuke.c str.c utils.c zone_parser.c

# CFLAGS += -O3
# CFLAGS += $(WERROR_FLAGS)
CFLAGS +=$(STD) $(WARN) $(OPT) $(DEBUG) $(SHUKE_CFLAGS)

include $(RTE_SDK)/mk/rte.extapp.mk

dnsbench: bench.c ae.c
	gcc -o $@ $^ $(STD) $(WARN) $(OPT) $(DEBUG) $(SHUKE_CFLAGS)
