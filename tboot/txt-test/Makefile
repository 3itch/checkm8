# Copyright (c) 2006-2007, Intel Corporation
# All rights reserved.

# -*- mode: Makefile; -*-

#
# txt-test makefile
#

ROOTDIR ?= $(CURDIR)/..

include $(ROOTDIR)/Config.mk

LINUX_BASE_DIR = $(ROOTDIR)/../

LINUX_BUILD_DIR = $(LINUX_BASE_DIR)/build-linux-2.6.18-xen_$(TARGET_ARCH)
LINUX_SRC_DIR = $(LINUX_BASE_DIR)/linux-2.6.18-xen.hg

# uncomment to build test kernel module
#MOD_TARGET  := txt-test.ko


#
# universal targets
#
dist : install


build : $(MOD_TARGET)


install : build


clean :
	rm -f $(MOD_TARGET) *~ *.o *.mod.* *.symvers


distclean : clean


#
# dependencies
#

BUILD_DEPS := $(ROOTDIR)/Config.mk $(CURDIR)/Makefile

$(MOD_TARGET) : $(BUILD_DEPS) txt-test.c
	$(MAKE) -C $(LINUX_BUILD_DIR) M=$(CURDIR) modules

%.o : %.c $(BUILD_DEPS)
	$(CC) $(CFLAGS) -DNO_TBOOT_LOGLVL -c $< -o $@
