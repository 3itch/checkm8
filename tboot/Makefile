# Copyright (c) 2006-2010, Intel Corporation
# All rights reserved.

# -*- mode: Makefile; -*-

#
# Grand Unified Makefile for tboot
#

# define ROOTDIR
export ROOTDIR=$(CURDIR)

# import global build config
include Config.mk

# (txt-test is not included because it requires pathing to Linux src)
SUBDIRS := tboot safestringlib lcptools-v2 tb_polgen utils docs

#
# build rules
#

#
#    manifest
#
.PHONY: manifest
manifest : build
	lcptools/lcp_mlehash tboot/tboot.gz > mle_file
	lcptools/lcp_crtpol -t 0 -m mle_file -o policy_file


#
#    install
#
install :
	@set -e; for i in $(SUBDIRS); do \
		$(MAKE) install-$$i; \
	done

install-% :
	$(MAKE) -C $* install


#
#    build
#
build :
	@set -e; for i in $(SUBDIRS); do \
		$(MAKE) build-$$i; \
	done

build-% :
	$(MAKE) -C $* build


#
#    dist
#
dist : $(patsubst %,dist-%,$(SUBDIRS))
	[ -d $(DISTDIR) ] || $(INSTALL_DIR) $(DISTDIR)
	$(INSTALL_DATA) COPYING $(DISTDIR)
	$(INSTALL_DATA) README.md $(DISTDIR)

dist-% :
	$(MAKE) -C $* dist


#
#    world
#
# build tboot and tools, and place them in the install directory.
# 'make install' should then copy them to the normal system directories
.PHONY: world
world :
	$(MAKE) clean
	$(MAKE) dist


#
#    clean
#
clean :
	rm -f *~ include/*~ docs/*~
	@set -e; for i in $(SUBDIRS); do \
		$(MAKE) clean-$$i; \
	done

clean-% :
	$(MAKE) -C $* clean


#
#    distclean
#
distclean :
	@set -e; for i in $(SUBDIRS); do \
		$(MAKE) distclean-$$i; \
	done

distclean-% :
	$(MAKE) -C $* distclean


#
#    mrproper
#
# Linux name for GNU distclean
mrproper : distclean


#
#    help
#
.PHONY: help
help :
	@echo 'Installation targets:'
	@echo '  install          - build and install everything'
	@echo '  install-*        - build and install the * module'
	@echo ''
	@echo 'Building targets:'
	@echo '  dist             - build and install everything into local dist directory'
	@echo '  world            - clean everything'
	@echo ''
	@echo 'Cleaning targets:'
	@echo '  clean            - clean tboot and tools'
	@echo '  distclean        - clean and local downloaded files'
	@echo ''
	@echo '  uninstall        - attempt to remove installed tools'
	@echo '                     (use with extreme care!)'

#
#    uninstall
#
# Use this target with extreme care!
.PHONY: uninstall
uninstall : D=$(DESTDIR)
uninstall :
	rm -rf $(D)/boot/tboot*
