# use software to calculate checksum, workaround for some stupid 82599 NIC which
# doesn't support checksum offload
DEBUG ?= 0

MACROS := -DSOFT_CKSUM
# change value to RTE_LOG_INFO to remove LOG_DEBUG statments in source code.
ifeq ($(DEBUG), 1)
MACROS += -D RTE_LOG_DP_LEVEL=RTE_LOG_DEBUG
else
MACROS += -D RTE_LOG_DP_LEVEL=RTE_LOG_INFO
endif
