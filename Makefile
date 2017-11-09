TOPDIR ?= ${CURDIR}

include config.mk

RTE_TARGET ?= x86_64-native-linuxapp-gcc
RTE_SDK = $(shell ls -d $(TOPDIR)/3rd/dpdk-*)
ifeq ($(shell test -e $(RTE_SDK)/$(RTE_TARGET) || echo -n no),no)
$(error please build DPDK first. build command: 'make -C $(RTE_SDK) install T=$(RTE_TARGET)')
endif

include $(RTE_SDK)/mk/rte.vars.mk

# these variables are exported as environment variables in dpdk makefile,
# but it is useless for himongo(ARCH will cause compile error) and liburcu.
# so unexport it.
unexport CFLAGS
unexport LDFLAGS
unexport ARCH

ifeq ($(DEBUG), 1)
SHUKE_CFLAGS=-DSK_TEST
OPTIMIZATION ?=-O0
endif

SHUKE_BUILD_DIR ?= build
OPTIMIZATION ?=-O3

PREFIX?=/usr/local
INSTALL_BIN=$(PREFIX)/bin
INSTALL=install

# PROJECT_ROOT:=$(abspath .)
HIMONGO_STATICLIB:=3rd/himongo/libhimongo.a
URCU_STATIC_LIBS:=3rd/liburcu/src/.libs/liburcu-cds.a 3rd/liburcu/src/.libs/liburcu.a
YAML_STATICLIB:=3rd/libyaml/src/.libs/libyaml.a

SHUKE_SRC_DIR:=src
# Default settings
STD=-std=gnu99
WARN=-Wall -W
OPT=$(OPTIMIZATION)
DEBUG_FLAGS=-g -ggdb

LIB_DIR_LIST=/usr/local/lib \
						 $(RTE_SDK)/$(RTE_TARGET)/lib
INC_DIR_LIST=$(SHUKE_SRC_DIR) \
				     3rd     \
						 3rd/liburcu/include \
						 3rd/liburcu/src   \
             3rd/libyaml/include
				     # $(RTE_SDK)/$(RTE_TARGET)/include
SRC_LIST := admin.c ae.c anet.c conf.c dict.c dpdk_module.c dpdk_kni.c \
						ds.c debug.c mongo.c protocol.c rbtree.c rculfhash-mm-socket.c \
						sds.c shuke.c str.c utils.c zone_parser.c zmalloc.c tcpserver.c
SHUKE_SRC := $(foreach v, $(SRC_LIST), $(SHUKE_SRC_DIR)/$(v))
SHUKE_OBJ := $(patsubst %.c,$(SHUKE_BUILD_DIR)/%.o,$(SRC_LIST))


FINAL_CFLAGS=$(STD) $(WARN) $(OPT) $(DEBUG_FLAGS) $(CFLAGS) $(SHUKE_CFLAGS) $(MACROS)
FINAL_LDFLAGS=$(LDFLAGS) $(SHUKE_LDFLAGS) $(DEBUG_FLAGS)
FINAL_LIBS=$(HIMONGO_STATICLIB) $(URCU_STATIC_LIBS) $(YAML_STATICLIB) -pthread -lrt

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


Makefile.dep:
	set -e; rm -f $@; \
	$(CC) -I$(SHUKE_SRC_DIR) -I3rd -MM $(SHUKE_SRC) > Makefile.dep 2> /dev/null || true; \
	sed "s/^\([^\.]*\.o\)/$(SHUKE_BUILD_DIR)\/\1/g" $@ > $@.$$$$; \
	mv -f $@.$$$$ $@; \
	rm -f $@.$$$$

-include Makefile.dep

-include $(SHUKE_BUILD_DIR)/.make-settings

persist-settings: clean
	echo PREV_FINAL_CFLAGS=$(FINAL_CFLAGS) >> $(SHUKE_BUILD_DIR)/.make-settings
	echo PREV_FINAL_LDFLAGS=$(FINAL_LDFLAGS) >> $(SHUKE_BUILD_DIR)/.make-settings

.PHONY: persist-settings

# Prerequisites target
$(SHUKE_BUILD_DIR)/.make-prerequisites:
	@touch $@

# Clean everything, persist settings and build dependencies if anything changed
ifneq ($(strip $(PREV_FINAL_CFLAGS)), $(strip $(FINAL_CFLAGS)))
$(SHUKE_BUILD_DIR)/.make-prerequisites: persist-settings
endif

ifneq ($(strip $(PREV_FINAL_LDFLAGS)), $(strip $(FINAL_LDFLAGS)))
$(SHUKE_BUILD_DIR)/.make-prerequisites: persist-settings
endif

$(SHUKE_BUILD_DIR)/shuke-server: 3rd $(SHUKE_OBJ)
	$(SHUKE_LD) -o $@ $(SHUKE_OBJ) $(DPDKLIBS) $(FINAL_LIBS)

$(SHUKE_BUILD_DIR)/%.o: $(SHUKE_SRC_DIR)/%.c $(SHUKE_BUILD_DIR)/.make-prerequisites
	$(SHUKE_CC) -c $< -o $@

clean:
	-rm -f $(SHUKE_BUILD_DIR)/shuke-server $(SHUKE_BUILD_DIR)/*.o Makefile.dep
	-(rm -f $(SHUKE_BUILD_DIR)/.make-*)

.PHONY:clean

distclean: clean
	-(make -C 3rd/himongo clean)
	-(make -C 3rd/liburcu clean)
	-(make -C 3rd/libyaml clean)

.PHONY: distclean

$(SHUKE_BUILD_DIR):
	mkdir -p $(SHUKE_BUILD_DIR)

@PHONY: $(SHUKE_BUILD_DIR)

3rd: $(HIMONGO_STATICLIB) $(URCU_STATIC_LIBS) $(YAML_STATICLIB)

update3rd:
	rm -rf 3rd/himongo 3rd/liburcu && git submodule update --init

$(HIMONGO_STATICLIB): 3rd/himongo/Makefile
	cd 3rd/himongo && make

3rd/himongo/Makefile:
	git submodule update --init

$(URCU_STATIC_LIBS): 3rd/liburcu/Makefile
	cd 3rd/liburcu && make

3rd/liburcu/Makefile: | 3rd/liburcu/bootstrap
	cd 3rd/liburcu && ./bootstrap && ./configure

3rd/liburcu/bootstrap:
	git submodule update --init

$(YAML_STATICLIB): 3rd/libyaml/Makefile
	cd 3rd/libyaml && make

3rd/libyaml/Makefile: | 3rd/libyaml/bootstrap
	cd 3rd/libyaml && ./bootstrap && ./configure

3rd/libyaml/bootstrap:
	git submodule update --init

install: all
	@mkdir -p $(INSTALL_BIN)
	$(SHUKE_INSTALL) build/shuke-server $(INSTALL_BIN)

#Libraries of dpdk
DPDKLIBS = -Wl,-lrte_pipeline -Wl,-lrte_table -Wl,-lrte_port -Wl,-lrte_pdump -Wl,-lrte_distributor -Wl,-lrte_ip_frag -Wl,-lrte_meter -Wl,-lrte_sched -Wl,-lrte_lpm -Wl,--whole-archive -Wl,-lrte_acl -Wl,--no-whole-archive -Wl,-lrte_jobstats -Wl,-lrte_metrics -Wl,-lrte_bitratestats -Wl,-lrte_latencystats -Wl,-lrte_power -Wl,-lrte_timer -Wl,-lrte_efd -Wl,-lrte_cfgfile -Wl,--whole-archive -Wl,-lrte_hash -Wl,-lrte_vhost -Wl,-lrte_kvargs -Wl,-lrte_mbuf -Wl,-lrte_net -Wl,-lrte_ethdev -Wl,-lrte_cryptodev -Wl,-lrte_eventdev -Wl,-lrte_mempool -Wl,-lrte_mempool_ring -Wl,-lrte_ring -Wl,-lrte_eal -Wl,-lrte_cmdline -Wl,-lrte_reorder -Wl,-lrte_kni -Wl,-lrte_mempool_stack -Wl,-lrte_pmd_af_packet -Wl,-lrte_pmd_ark -Wl,-lrte_pmd_avp -Wl,-lrte_pmd_bnxt -Wl,-lrte_pmd_bond -Wl,-lrte_pmd_cxgbe -Wl,-lrte_pmd_e1000 -Wl,-lrte_pmd_ena -Wl,-lrte_pmd_enic -Wl,-lrte_pmd_fm10k -Wl,-lrte_pmd_i40e -Wl,-lrte_pmd_ixgbe -Wl,-lrte_pmd_kni -Wl,-lrte_pmd_lio -Wl,-lrte_pmd_nfp -Wl,-lrte_pmd_null -Wl,-lrte_pmd_qede -Wl,-lrte_pmd_ring -Wl,-lrte_pmd_sfc_efx -Wl,-lrte_pmd_tap -Wl,-lrte_pmd_thunderx_nicvf -Wl,-lrte_pmd_virtio -Wl,-lrte_pmd_vhost -Wl,-lrte_pmd_vmxnet3_uio -Wl,-lrte_pmd_null_crypto -Wl,-lrte_pmd_crypto_scheduler -Wl,-lrte_pmd_skeleton_event -Wl,-lrte_pmd_sw_event -Wl,-lrte_pmd_octeontx_ssovf -Wl,--no-whole-archive -Wl,-lrt -Wl,-lm -Wl,-ldl -Wl,-export-dynamic -Wl,-export-dynamic
