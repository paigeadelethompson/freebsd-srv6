# Makefile for building an out-of-tree FreeBSD kernel module.
#
# Follows the conventions of in-tree modules under /usr/src/sys/modules:
#   1. Set SYSDIR to the kernel source sys/ directory
#   2. Include ${SYSDIR}/conf/kern.opts.mk for KERN_OPTS/opt_*.h handling
#   3. Set KMOD, SRCS, and optional variables
#   4. Include <bsd.kmod.mk> from /usr/share/mk
#
# To build:        make
# To install:      make install   (as root)
# To load:         make load
# To unload:       make unload
# To reload:       make reload
# To clean:        make clean
#
# Override on command line or environment:
#   KMOD        Module name (default: example)
#   SRCS        Source files (default: example.c)
#   SYSDIR      Kernel source sys/ dir (default: /usr/src/sys)
#   SRCTOP      Kernel source root (default: ${SYSDIR}/..)
#   KERNBUILDDIR Kernel build dir for opt_*.h headers
#   DESTDIR     Install target root (default: /)
#   KMODDIR     Install dir for .ko (default: /boot/kernel)
#   EXPORT_SYMS YES, a filename, or NO (default: NO)

SYSDIR?=	/usr/src/sys
SRCTOP?=	${SYSDIR}/..

.include "${SYSDIR}/conf/kern.opts.mk"

KMOD?=		srv6
SRCS?=		srv6.c srv6.h

EXPORT_SYMS?=	NO

.include <bsd.kmod.mk>
