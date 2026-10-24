# Makefile for the SRv6 test kernel module.
#
# Follows the pattern from /usr/src/sys/modules/tests/fib_lookup/Makefile:
#   - Set SYSDIR to the kernel source sys/ directory
#   - Set KMOD and SRCS
#   - Include <bsd.kmod.mk>
#
# This builds a test kernel module that can be loaded and tested
# with an ATF test program.

SYSDIR?=	/usr/src/sys

KMOD=		test_srv6
SRCS=		test_srv6.c

.include <bsd.kmod.mk>
