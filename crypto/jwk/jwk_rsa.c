/* crypto/rsa/rsa_ameth.c */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#ifndef OPENSSL_NO_CMS
#include <openssl/cms.h>
#endif
#include "asn1_locl.h"


static char *base64(const unsigned char *input, int length)
{
  BIO *bmem, *b64;
  BUF_MEM *bptr;

  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_write(b64, input, length);
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);

  char *buff = (char *)malloc(bptr->length);
  memcpy(buff, bptr->data, bptr->length-1);

  /* remove trailing = or == */
  if (buff[bptr->length-2] == '=') {
   bptr->length--;
   if (buff[bptr->length-2] == '=') bptr->length--; 
  }
  buff[bptr->length-1] = 0;
  char *p = buff;
  while (*p) {
    if (*p == '+') { 
      *p = '-';
      continue;
    }
    if (*p == '/')
      *p = '_';
    p++;
  }
  BIO_free_all(b64);

  return buff;
}

static char *base64file(const char *filename)
{
  	BIO *bmem, *b64;
  	BUF_MEM *bptr;
  	b64 = BIO_new(BIO_f_base64());
  	bmem = BIO_new(BIO_s_mem());
  	b64 = BIO_push(b64, bmem);

  	BIO *bio = BIO_new(BIO_s_file());
	if (1 != BIO_read_filename(bio, filename)) {
		fprintf(stderr, "error reading %s\n", filename);
		return NULL;
	}
	char chunk[4096];
	int r = BIO_read(bio, chunk, 4096);
	while (r > 0) {
  		BIO_write(b64, chunk, r);
		r = BIO_read(bio, chunk, 4096);
	}

	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

  	char *buff = (char *)malloc(bptr->length);
  	memcpy(buff, bptr->data, bptr->length-1);

  	/* remove trailing = or == */
  	if (buff[bptr->length-2] == '=') {
   	bptr->length--;
   	if (buff[bptr->length-2] == '=') bptr->length--;
  	}
  	buff[bptr->length-1] = 0;
  	char *p = buff;
  	while (*p) {
    		if (*p == '+') {
      			*p = '-';
      			continue;
    		}
    		if (*p == '/')
      			*p = '_';
    		p++;
  	}
  	BIO_free_all(b64);

  	return buff;
}

int base64url_bn_print(BIO *bp, const char *number, const BIGNUM *num,
			unsigned char *buf, int off)
	{
		int ret;
                int n=BN_bn2bin(num,&buf[0]);
		char* b64 = base64(buf,n);
                if (BIO_printf(bp, "%s%s", number, b64) <= 0)
                        ret = 0;
                ret = 1;
		free(b64);
		return ret;
	}

static void update_buflen(const BIGNUM *b, size_t *pbuflen)
        {
        size_t i;
        if (!b)
                return;
        if (*pbuflen < (i = (size_t)BN_num_bytes(b)))
                        *pbuflen = i;
        }

static int jwk_rsa_print(BIO *bp, const RSA *x, int off, int priv)
	{
	char *str;
	const char *s;
	unsigned char *m=NULL;
	int ret=0, mod_len = 0;
	size_t buf_len=0;

	update_buflen(x->n, &buf_len);
	update_buflen(x->e, &buf_len);

	if (priv)
		{
		update_buflen(x->d, &buf_len);
		update_buflen(x->p, &buf_len);
		update_buflen(x->q, &buf_len);
		update_buflen(x->dmp1, &buf_len);
		update_buflen(x->dmq1, &buf_len);
		update_buflen(x->iqmp, &buf_len);
		}

	m=(unsigned char *)OPENSSL_malloc(buf_len+10);
	if (m == NULL)
		{
		RSAerr(RSA_F_DO_RSA_PRINT,ERR_R_MALLOC_FAILURE);
		goto err;
		}

	if (x->n != NULL)
		mod_len = BN_num_bits(x->n);

	if(!BIO_indent(bp,off,128))
		goto err;

	if (priv && x->d)
		{
		if (BIO_printf(bp,"/*Private-Key: (%d bit)*/\n", mod_len)
			<= 0) goto err;
		str = " \"n\":\"";
		s = " \"e\":\"";
		}
	else
		{
		if (BIO_printf(bp,"/*Public-Key: (%d bit)*/\n", mod_len)
			<= 0) goto err;
		str = " \"n\":\"";
		s= " \"e\":\"";
		}
	if (!base64url_bn_print(bp,str,x->n,m,off)) goto err;
	if (BIO_printf(bp,"\",\n") <= 0) goto err;
	if (!base64url_bn_print(bp,s,x->e,m,off)) goto err;
	if (BIO_printf(bp,"\",\n") <= 0) goto err;
	if (priv)
		{ 
		/* privateExponent */
		if (!base64url_bn_print(bp," \"d\":\"",x->d,m,off))
			goto err;
		if (BIO_printf(bp,"\",\n") <= 0) goto err;
		/* prime1 */
		if (!base64url_bn_print(bp," \"p\":\"",x->p,m,off))
			goto err;
		if (BIO_printf(bp,"\",\n") <= 0) goto err;
		/* prime2 */
		if (!base64url_bn_print(bp," \"q\":\"",x->q,m,off))
			goto err;
		if (BIO_printf(bp,"\",\n") <= 0) goto err;
		/* exponent1 */
		if (!base64url_bn_print(bp," \"dp\":\"",x->dmp1,m,off))
			goto err;
		if (BIO_printf(bp,"\",\n") <= 0) goto err;
		/* exponent2 */
		if (!base64url_bn_print(bp," \"dq\":\"",x->dmq1,m,off))
			goto err;
		if (BIO_printf(bp,"\",\n") <= 0) goto err;
		/* coefficient */
		if (!base64url_bn_print(bp," \"qi\":\"",x->iqmp,m,off))
			goto err;
		if (BIO_printf(bp,"\"\n") <= 0) goto err;
		}
	ret=1;
err:
	if (m != NULL) OPENSSL_free(m);
	return(ret);
	}

int jwk_rsa_pub_print(BIO *bp, const EVP_PKEY *pkey, int indent,
							ASN1_PCTX *ctx)
	{
		return jwk_rsa_print(bp, pkey->pkey.rsa, indent, 0);
	}


int jwk_rsa_priv_print(BIO *bp, const EVP_PKEY *pkey, int indent,
							ASN1_PCTX *ctx)
	{
		return jwk_rsa_print(bp, pkey->pkey.rsa, indent, 1);
	}

int JWK_write_bio_RSA_PUBKEY(BIO *bg, RSA *rsa) {
  return 1;
}

int JWK_write_bio_RSAPublicKey(BIO *bg, RSA *rsa) {
  return 1;
}

int JWK_write_bio_RSAPrivateKey(BIO *bg, RSA *rsa, EVP_CIPHER *enc, void* d, int e, void* f, void* g) {
  return 1;
}

int JWS_write_signature(BIO *out, EVP_PKEY *key, 
	unsigned char *sigin, int siglen,
        const char *sig_name, const char *md_name,
        const char *file,
	const char *buf, int buflen) 
{
        // BIO_printf(out, "sig_name=%s md_name=%s\n", sig_name, md_name);
        BIO_printf(out, "filename=%s\n", file);
	if(key->type != EVP_PKEY_RSA) {
        	BIO_printf(out, "JWS signature key type not supported");
		return 0;
	}
	RSA *rsa = key->pkey.rsa;
        unsigned char header[32];
	sprintf(header, "{\"alg\":\"RS%d\"}", RSA_size(rsa));
	char *payloadB64 = base64file(file);
        BIO_printf(out, "%s.%s.%s", 
		base64(header, strlen(header)),
		payloadB64,
		base64(buf, buflen));
  	return 1;
}


