/* crypto/pem/jwk_pkey.c */
/* Copyright (C) 2013 Axel Nennker (axel@nennker.de)
 * All rights reserved.
 *
 * This code is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Axel Nennker's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Axel Nennker should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Axel Nennker (axel@nennker.de)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/buffer.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <openssl/jwk.h>
#include <openssl/pem.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include "asn1_locl.h"

int pem_check_suffix(const char *jwk_str, const char *suffix);

int JWK_write_bio_PrivateKey(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc,
                                               unsigned char *kstr, int klen,
                                               pem_password_cb *cb, void *u)
	{
		int r;

		//char alg[8];
 		//BIO_snprintf(alg, 8, "%s", "RS256");

		char pem_str[1024];
 		BIO_snprintf(pem_str, 1024, 
			"{\n \"alg\":\"%s\",\n", 
			x->ameth->pem_str);
		r = BIO_write(bp, pem_str, strlen(pem_str));

		r = jwk_rsa_priv_print(bp, x, 1, NULL);

 		BIO_snprintf(pem_str, 1024, "}");
		return BIO_write(bp, pem_str, strlen(pem_str));
	}

int JWK_write_PrivateKey(FILE *fp, EVP_PKEY *x, const EVP_CIPHER *enc,
                                               unsigned char *kstr, int klen,
                                               pem_password_cb *cb, void *u)
	{
 		return 1;
	}

int JWK_write_bio_PKCS8_PRIV_KEY_INFO(BIO *out, PKCS8_PRIV_KEY_INFO *p8inf)
	{
		fprintf(stderr, "ERROR NOT IMPLEMENTED: JWK_write_bio_PKCS8_PRIV_KEY_INFO");
 		return 1;
	}

int JWK_write_bio_PUBKEY(BIO* out, EVP_PKEY *pkey)
	{
fprintf(stderr, "ERROR NOT IMPLEMENTED: JWK_write_bio_PUBKEY");
 		return 1;
	}


