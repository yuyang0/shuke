ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif
RTE_TARGET ?= x86_64-native-linuxapp-gcc

ifdef TEST
SHUKE_CFLAGS=-DSK_TEST
endif

SHUKE_BUILD_DIR ?= build
OPTIMIZATION?=-O2

# PROJECT_ROOT:=$(abspath .)
HIMONGO_STATICLIB:=3rd/himongo/libhimongo.a

SHUKE_SRC_DIR:=src
# Default settings
STD=-std=gnu99 -pedantic
WARN=-Wall -W
OPT=$(OPTIMIZATION)
DEBUG=-g -ggdb

LIB_DIR_LIST=/usr/local/lib \
						 $(RTE_SDK)/$(RTE_TARGET)/lib
INC_DIR_LIST=$(SHUKE_SRC_DIR) \
			       3rd/himongo \
				     3rd \
				     $(RTE_SDK)/$(RTE_TARGET)/include
SRC_LIST := admin.c ae.c anet.c conf.c dict.c dpdk_module.c ds.c mongo.c \
            protocol.c sds.c shuke.c str.c utils.c zone_parser.c replicate.c
SHUKE_SRC := $(foreach v, $(SRC_LIST), $(SHUKE_SRC_DIR)/$(v))
SHUKE_OBJ := $(patsubst %.c,$(SHUKE_BUILD_DIR)/%.o,$(SRC_LIST))

#include $(RTE_SDK)/mk/rte.vars.mk

FINAL_CFLAGS=$(STD) $(WARN) $(OPT) $(DEBUG) $(CFLAGS) $(SHUKE_CFLAGS)
FINAL_LDFLAGS=$(LDFLAGS) $(SHUKE_LDFLAGS) $(DEBUG)
FINAL_LIBS=$(HIMONGO_STATICLIB) -pthread -lrt -lnuma

FINAL_CFLAGS += -include $(RTE_SDK)/$(RTE_TARGET)/include/rte_config.h -msse4.2
FINAL_CFLAGS += $(addprefix -I,$(INC_DIR_LIST))

FINAL_LDFLAGS += $(addprefix -L,$(LIB_DIR_LIST))

SHUKE_CC=$(QUIET_CC)$(CC) $(FINAL_CFLAGS)
SHUKE_LD=$(QUIET_LINK)$(CC) $(FINAL_LDFLAGS)
SHUKE_INSTALL=$(QUIET_INSTALL)$(INSTALL)

CCCOLOR="\033[34m"
LINKCOLOR="\033[34;1m"
SRCCOLOR="\033[33m"
BINCOLOR="\033[37;1m"
MAKECOLOR="\033[32;1m"
ENDCOLOR="\033[0m"

ifndef V
QUIET_CC = @printf '    %b %b\n' $(CCCOLOR)CC$(ENDCOLOR) $(SRCCOLOR)$@$(ENDCOLOR) 1>&2;
QUIET_LINK = @printf '    %b %b\n' $(LINKCOLOR)LINK$(ENDCOLOR) $(BINCOLOR)$@$(ENDCOLOR) 1>&2;
QUIET_INSTALL = @printf '    %b %b\n' $(LINKCOLOR)INSTALL$(ENDCOLOR) $(BINCOLOR)$@$(ENDCOLOR) 1>&2;
endif

# include $(RTE_SDK)/mk/rte.extapp.mk

all: $(SHUKE_BUILD_DIR) $(SHUKE_BUILD_DIR)/shuke-server

Makefile.dep:
	-$(SHUKE_CC) -MM $(SHUKE_SRC_DIR)/*.c > Makefile.dep 2> /dev/null || true
	-sed "s/^\([^\.]*\.o\)/$(SHUKE_BUILD_DIR)\/\1/g" $@ > aaa.txt

dep:
	$(MAKE) Makefile.dep
.PHONY: dep

$(SHUKE_BUILD_DIR)/shuke-server: $(HIMONGO_STATICLIB) $(SHUKE_OBJ)
	$(SHUKE_LD) -o $@ $(SHUKE_OBJ) $(DPDKLIBS) $(FINAL_LIBS)

$(SHUKE_BUILD_DIR)/%.o: $(SHUKE_SRC_DIR)/%.c
	$(SHUKE_CC) -c $< -o $@

.PHONY:clean
clean:
	-rm -f $(SHUKE_BUILD_DIR)/shuke-server $(SHUKE_BUILD_DIR)/*.o dnsbench

@PHONY: $(SHUKE_BUILD_DIR)
$(SHUKE_BUILD_DIR):
	mkdir -p $(SHUKE_BUILD_DIR)

$(HIMONGO_STATICLIB): 3rd/himongo/Makefile
	cd 3rd/himongo && make

3rd/himongo/Makefile:
	git submodule update --init

update3rd:
	rm -rf 3rd/himongo && git submodule update --init

3rd: $(HIMONGO_STATICLIB)

dnsbench: src/bench.c src/ae.c
	$(SHUKE_CC) -o $@ $^ $(STD) $(WARN) $(OPT) $(DEBUG) $(SHUKE_CFLAGS) -DUSE_MALLOC


#Libraries of dpdk
#DPDKLIBS += --whole-archive
DPDKLIBS += -ldpdk
DPDKLIBS += -lrte_acl
DPDKLIBS += -lrte_cfgfile
DPDKLIBS += -lrte_cmdline
DPDKLIBS += -lrte_cryptodev
DPDKLIBS += -lrte_distributor
DPDKLIBS += -lrte_eal
DPDKLIBS += -lrte_ethdev
DPDKLIBS += -lrte_hash
DPDKLIBS += -lrte_ip_frag
DPDKLIBS += -lrte_jobstats
DPDKLIBS += -lrte_kni
DPDKLIBS += -lrte_kvargs
DPDKLIBS += -lrte_lpm
DPDKLIBS += -lrte_mbuf
DPDKLIBS += -lrte_mempool
DPDKLIBS += -lrte_meter
DPDKLIBS += -lrte_pdump
DPDKLIBS += -lrte_pipeline
DPDKLIBS += -lrte_pmd_af_packet
DPDKLIBS += -lrte_pmd_bnxt
DPDKLIBS += -lrte_pmd_bond
DPDKLIBS += -lrte_pmd_cxgbe
DPDKLIBS += -lrte_pmd_e1000
DPDKLIBS += -lrte_pmd_ena
DPDKLIBS += -lrte_pmd_enic
DPDKLIBS += -lrte_pmd_fm10k
DPDKLIBS += -lrte_pmd_i40e
DPDKLIBS += -lrte_pmd_ixgbe
DPDKLIBS += -lrte_pmd_null
DPDKLIBS += -lrte_pmd_ring
#DPDKLIBS += -lrte_pmd_vhost
DPDKLIBS += -lrte_pmd_virtio
#DPDKLIBS += -lrte_pmd_vmxnet3_uio
DPDKLIBS += -lrte_port
DPDKLIBS += -lrte_power

DPDKLIBS += -lrte_reorder
DPDKLIBS += -lrte_ring
DPDKLIBS += -lrte_sched
DPDKLIBS += -lrte_table
DPDKLIBS += -lrte_timer
#DPDKLIBS += -lrte_vhost
DPDKLIBS += -lrt
DPDKLIBS += -lm -ldl
