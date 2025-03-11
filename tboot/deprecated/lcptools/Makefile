# Copyright (c) 2006-2010, Intel Corporation
# All rights reserved.

# -*- mode: Makefile; -*-

#
# lcptools makefile
#

ROOTDIR ?= $(CURDIR)/../..

include $(ROOTDIR)/Config.mk


TPMNV_TARGETS := \
	tpmnv_defindex \
	tpmnv_relindex \
	tpmnv_lock     \
	tpmnv_getcap   

LCP_TARGETS := \
	lcp_writepol   \
	lcp_readpol    

tpmnv : $(TPMNV_TARGETS) $(LCP_TARGETS)


#
# universal rules
#

build : tpmnv


dist : install


install :
	@set -e; for i in $(TPMNV_TARGETS) $(LCP_TARGETS);\
	do \
		$(MAKE) DISTDIR=$(DISTDIR) INST_TARGET=$(DISTDIR)/usr/sbin/$$i do_install; \
	done

.PHONY: do_install
do_install : $(INST_TARGET)

$(INST_TARGET) : $(notdir $(INST_TARGET))
	[ -d $(DISTDIR)/usr/sbin ] || $(INSTALL_DIR) $(DISTDIR)/usr/sbin
	$(INSTALL_PROG) -t $(DISTDIR)/usr/sbin $^


clean :
	rm -f *~ *.a *.so *.o *.rpm $(DEP_FILES) $(TPMNV_TARGETS) $(LCP_TARGETS) trousers_dep


mrproper : clean


distclean : clean

#
# trousers
#

trousers_dep:
	@printf "#include <trousers/tss.h>\n" | $(CC) -x c $(CFLAGS) $(LDFLAGS) $(LIBS) - -Wl,--defsym=main=0 -o $@ >/dev/null 2>&1 || (echo trousers-devel package is not installed && false)

#
# dependencies
#

LDFLAGS += -L.


# LCP v1 and tpmnv_*

UTIL_OBJS := lcptools.o lcputils.o

LIBS += -lcrypto -ltspi -lz

$(TPMNV_TARGETS) : tpmnv_% : %.o $(UTIL_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LIBS) $(ROOTDIR)/safestringlib/libsafestring.a -o $@

$(LCP_TARGETS) : lcp_% : %.o $(UTIL_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LIBS) $(ROOTDIR)/safestringlib/libsafestring.a -o $@


#
# implicit rules
#

HDRS := $(wildcard $(ROOTDIR)/include/*.h) $(wildcard $(CURDIR)/*.h)

BUILD_DEPS := $(ROOTDIR)/Config.mk $(CURDIR)/Makefile

%.o : %.c $(HDRS) $(BUILD_DEPS) trousers_dep
	$(CC) $(CFLAGS) -DNO_TBOOT_LOGLVL -c $< -o $@
