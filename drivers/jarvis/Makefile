# SPDX-License-Identifier: GPL-2.0
#
# linux-jarvisos — JARVIS AI kernel integration driver
#

obj-$(CONFIG_JARVIS)		+= jarvis.o

# Always-on core
jarvis-y			+= jarvis_core.o

# Optional sub-modules compiled into the same jarvis.ko
jarvis-$(CONFIG_JARVIS_DIBS)	+= jarvis_dibs.o
jarvis-$(CONFIG_JARVIS_SYSMON)	+= jarvis_sysmon.o
jarvis-$(CONFIG_JARVIS_POLICY)	+= jarvis_policy.o
jarvis-$(CONFIG_JARVIS_KEYS)	+= jarvis_keys.o
