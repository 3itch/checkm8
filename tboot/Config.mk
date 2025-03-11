# Copyright (c) 2006-2010, Intel Corporation
# All rights reserved.

# -*- mode: Makefile; -*-

#
# global build settings
#

# supported targets
.PHONY: all build install dist clean distclean mrproper

# Default target
all : build


# debug build
debug ?= n

# for dist targets
ifdef DESTDIR
DISTDIR = $(DESTDIR)
#else
#DISTDIR     ?= /
endif

DESTDIR     ?= $(ROOTDIR)/dist

dist : DISTDIR=$(DESTDIR)


#
# tools and flags for components built to run on build (host)
#

# cc-option: Check if compiler supports first option, else fall back to second.
# Usage: cflags-y += $(call cc-option,$(CC),-march=winchip-c6,-march=i586)
cc-option = $(shell if test -z "`$(1) $(2) -S -o /dev/null -xc \
              /dev/null 2>&1`"; then echo "$(2)"; else echo "$(3)"; fi ;)


CFLAGS_WARN       = -Wall -Wformat-security -Werror -Wstrict-prototypes \
	            -Wextra -Winit-self -Wswitch-default -Wunused-parameter \
	            -Wwrite-strings \
	            $(call cc-option,$(CC),-Wlogical-op,) \
	            -Wno-missing-field-initializers -Wno-address-of-packed-member

AS         ?= as
LD         ?= ld
CC         ?= gcc
CPP        ?= cpp
AR         ?= ar
RANLIB     ?= ranlib
NM         ?= nm
STRIP      ?= strip
OBJCOPY    ?= objcopy
OBJDUMP    ?= objdump

ifeq ($(debug),n)
INSTALL_STRIP ?= -s
endif

INSTALL      ?= install
INSTALL_DIR  = $(INSTALL) -d -m0755 -p
INSTALL_DATA = $(INSTALL) -m0644 -p
INSTALL_PROG = $(INSTALL) $(INSTALL_STRIP) -m0755 -p


#
# tools and flags for components built to run on target
#
TARGET_ARCH  ?= $(shell uname -m | sed -e s/i.86/x86_32/ -e s/i86pc/x86_32/)

CFLAGS += $(CFLAGS_WARN) -fno-strict-aliasing -std=gnu99
# due to bug in gcc v4.2,3,?
CFLAGS += $(call cc-option,$(CC),-Wno-array-bounds,)


ifeq ($(debug),y)
CFLAGS += -g -DDEBUG
else
CFLAGS += -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
endif

ifeq ($(TARGET_ARCH),x86_64)
LIBDIR := lib64
CFLAGS += -m64
else
LIBDIR := lib
CFLAGS += -m32 -march=i686
endif

CFLAGS += -I$(ROOTDIR)/safestringlib/include

export CFLAGS

# common dummy rule to force execution
.PHONY: FORCE
FORCE :
	@: # do nothing
