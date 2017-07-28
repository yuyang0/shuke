include config.mk

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

ifeq ($(DEBUG), 1)
SHUKE_CFLAGS=-DSK_TEST
OPTIMIZATION?=-O0
endif

SHUKE_BUILD_DIR ?= build
OPTIMIZATION?=-O3

# PROJECT_ROOT:=$(abspath .)
HIMONGO_STATICLIB:=3rd/himongo/libhimongo.a

SHUKE_SRC_DIR:=src
# Default settings
STD=-std=gnu99
WARN=-Wall -W
OPT=$(OPTIMIZATION)
DEBUG_FLAGS=-g -ggdb

LIB_DIR_LIST=/usr/local/lib \
						 $(RTE_SDK)/$(RTE_TARGET)/lib
INC_DIR_LIST=$(SHUKE_SRC_DIR) \
				     3rd
				     # $(RTE_SDK)/$(RTE_TARGET)/include
SRC_LIST := admin.c ae.c anet.c conf.c dict.c dpdk_module.c dpdk_kni.c ds.c debug.c mongo.c \
            protocol.c rbtree.c sds.c shuke.c str.c utils.c zone_parser.c \
            zmalloc.c tcpserver.c
SHUKE_SRC := $(foreach v, $(SRC_LIST), $(SHUKE_SRC_DIR)/$(v))
SHUKE_OBJ := $(patsubst %.c,$(SHUKE_BUILD_DIR)/%.o,$(SRC_LIST))


FINAL_CFLAGS=$(STD) $(WARN) $(OPT) $(DEBUG_FLAGS) $(CFLAGS) $(SHUKE_CFLAGS) $(MACROS)
FINAL_LDFLAGS=$(LDFLAGS) $(SHUKE_LDFLAGS) $(DEBUG_FLAGS)
FINAL_LIBS=$(HIMONGO_STATICLIB) -pthread -lrt

# FINAL_CFLAGS += -include $(RTE_SDK)/$(RTE_TARGET)/include/rte_config.h -msse4.2
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

include Makefile.dep

Makefile.dep:
	set -e; rm -f $@; \
	$(CC) -I$(SHUKE_SRC_DIR) -I3rd -MM $(SHUKE_SRC) > Makefile.dep 2> /dev/null || true; \
	sed "s/^\([^\.]*\.o\)/$(SHUKE_BUILD_DIR)\/\1/g" $@ > $@.$$$$; \
	mv -f $@.$$$$ $@; \
	rm -f $@.$$$$

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
	$(SHUKE_CC) -o $@ $^ $(STD) $(WARN) $(OPT) $(DEBUG_FLAGS) $(SHUKE_CFLAGS) -DUSE_MALLOC


#Libraries of dpdk
DPDKLIBS += -Wl,-lrte_kni
DPDKLIBS += -Wl,-lrte_pipeline
DPDKLIBS += -Wl,-lrte_table
DPDKLIBS += -Wl,-lrte_port
DPDKLIBS += -Wl,-lrte_pdump
DPDKLIBS += -Wl,-lrte_distributor
DPDKLIBS += -Wl,-lrte_reorder
DPDKLIBS += -Wl,-lrte_ip_frag
DPDKLIBS += -Wl,-lrte_meter
DPDKLIBS += -Wl,-lrte_sched
DPDKLIBS += -Wl,-lrte_lpm
DPDKLIBS += -Wl,--whole-archive
DPDKLIBS += -Wl,-lrte_acl
DPDKLIBS += -Wl,--no-whole-archive
DPDKLIBS += -Wl,-lrte_jobstats
DPDKLIBS += -Wl,-lrte_power
DPDKLIBS += -Wl,--whole-archive
DPDKLIBS += -Wl,-lrte_timer
DPDKLIBS += -Wl,-lrte_hash
DPDKLIBS += -Wl,-lrte_vhost
DPDKLIBS += -Wl,-lrte_kvargs
DPDKLIBS += -Wl,-lrte_mbuf
DPDKLIBS += -Wl,-lrte_net
DPDKLIBS += -Wl,-lrte_ethdev
DPDKLIBS += -Wl,-lrte_cryptodev
DPDKLIBS += -Wl,-lrte_mempool
DPDKLIBS += -Wl,-lrte_ring
DPDKLIBS += -Wl,-lrte_eal
DPDKLIBS += -Wl,-lrte_cmdline
DPDKLIBS += -Wl,-lrte_cfgfile
DPDKLIBS += -Wl,-lrte_pmd_bond
DPDKLIBS += -Wl,-lrte_pmd_af_packet
DPDKLIBS += -Wl,-lrte_pmd_bnxt
DPDKLIBS += -Wl,-lrte_pmd_cxgbe
DPDKLIBS += -Wl,-lrte_pmd_e1000
DPDKLIBS += -Wl,-lrte_pmd_ena
DPDKLIBS += -Wl,-lrte_pmd_enic
DPDKLIBS += -Wl,-lrte_pmd_fm10k
DPDKLIBS += -Wl,-lrte_pmd_i40e
DPDKLIBS += -Wl,-lrte_pmd_ixgbe
DPDKLIBS += -Wl,-lrte_pmd_null
DPDKLIBS += -Wl,-lrte_pmd_qede
DPDKLIBS += -Wl,-lrte_pmd_ring
DPDKLIBS += -Wl,-lrte_pmd_virtio
DPDKLIBS += -Wl,-lrte_pmd_vhost
DPDKLIBS += -Wl,-lrte_pmd_vmxnet3_uio
DPDKLIBS += -Wl,-lrte_pmd_null_crypto
DPDKLIBS += -Wl,--no-whole-archive
DPDKLIBS += -Wl,-lrt
DPDKLIBS += -Wl,-lm -Wl,-ldl -Wl,-export-dynamic
