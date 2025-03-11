# Copyright (c) 2006-2010, Intel Corporation
# All rights reserved.

# -*- mode: Makefile; -*-

#
# tb_polgen makefile
#

ROOTDIR ?= $(CURDIR)/..

include $(ROOTDIR)/Config.mk


TARGET = tb_polgen

# libraries
LIBS += -lcrypto -lz $(ROOTDIR)/safestringlib/libsafestring.a


#
# universal rules
#


build : $(TARGET)


dist : install


install : $(DISTDIR)/usr/sbin/$(TARGET)

$(DISTDIR)/usr/sbin/$(TARGET) : $(TARGET)
	[ -d $(DISTDIR)/usr/sbin ] || $(INSTALL_DIR) $(DISTDIR)/usr/sbin
	$(INSTALL_PROG) -t $(DISTDIR)/usr/sbin $(TARGET)


clean :
	rm -f *~ *.a *.so *.o *.rpm $(DEP_FILES) $(TARGET)


mrproper : clean

distclean : clean


#
# dependencies
#

$(TARGET) : tb_polgen.o commands.o policy.o param.o hash.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LIBS) -o $@


#
# implicit rules
#

HDRS := $(wildcard $(ROOTDIR)/include/*.h) $(wildcard $(CURDIR)/*.h)

BUILD_DEPS := $(ROOTDIR)/Config.mk $(CURDIR)/Makefile

%.o : %.c $(HDRS) $(BUILD_DEPS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -DNO_TBOOT_LOGLVL -c $< -o $@
