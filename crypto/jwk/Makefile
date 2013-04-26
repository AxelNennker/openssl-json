#
# OpenSSL/crypto/jwk/Makefile
#

DIR=	jwk
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= jwk_pkey.c jwk_rsa.c

LIBOBJ=	jwk_pkey.o jwk_rsa.o

SRC= $(LIBSRC)

EXHEADER= pem.h pem2.h
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links: $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

jwk_pkey.o: ../../e_os.h ../../include/openssl/asn1.h
jwk_pkey.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
jwk_pkey.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
jwk_pkey.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
jwk_pkey.o: ../../include/openssl/ecdsa.h ../../include/openssl/engine.h
jwk_pkey.o: ../../include/openssl/err.h ../../include/openssl/evp.h
jwk_pkey.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
jwk_pkey.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
jwk_pkey.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
jwk_pkey.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
jwk_pkey.o: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
jwk_pkey.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
jwk_pkey.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
jwk_pkey.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
jwk_pkey.o: ../../include/openssl/x509_vfy.h ../asn1/asn1_locl.h ../cryptlib.h
jwk_pkey.o: jwk_pkey.c
