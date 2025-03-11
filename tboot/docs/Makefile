# Copyright (c) 2012, Intel Corporation
# All rights reserved.

# -*- mode: Makefile; -*-

#
# docs makefile
#

ROOTDIR ?= $(CURDIR)/..

include $(ROOTDIR)/Config.mk
TBOOT_MANPATH ?= $(DISTDIR)/usr/share/man


#
# universal rules
#


build : 


dist : install


install :
	[ -d $(TBOOT_MANPATH)/man8 ] || $(INSTALL_DIR) $(TBOOT_MANPATH)/man8
	$(INSTALL_DATA) -t $(TBOOT_MANPATH)/man8 \
	man/txt-acminfo.8 man/tb_polgen.8 man/txt-stat.8 man/lcp2_crtpol.8 \
	man/lcp2_crtpolelt.8 man/lcp2_crtpollist.8 man/lcp2_mlehash.8 \
	man/txt-parse_err.8


clean :

mrproper : clean

distclean : clean


#
# dependencies
#


#
# implicit rules
#

