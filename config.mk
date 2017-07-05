# use software to calculate checksum, workaround for some stupid 82599 NIC which doesn't
# support checksum offload
MACROS := -DSOFT_CKSUM
# change value to RTE_LOG_INFO to remove LOG_DEBUG statments in source code.
MACROS += -D RTE_LOG_DP_LEVEL=RTE_LOG_DEBUG
