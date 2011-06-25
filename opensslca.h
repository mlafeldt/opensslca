/*
 * opensslca provides rudimentary CA functionality:
 *  - create X509 certificate request
 *  - create X509 certificate from certificate request
 *  - get issuer certificate
 *  - get RA certificate
 *
 * Copyright (C) Mathias Lafeldt 2007
 *
 * This file is part of a diploma thesis.
 */

#ifndef _OPENSSLCA_H_
#define _OPENSSLCA_H_

/* Error codes */
enum {
	OPENSSLCA_NO_ERR, /* 0 */
	OPENSSLCA_ERR_ARGS,
	OPENSSLCA_ERR_BUF_TOO_SMALL,

	OPENSSLCA_ERR_KEY_NEW, /* 3 */
	OPENSSLCA_ERR_KEY_OPEN,
	OPENSSLCA_ERR_KEY_READ,
	OPENSSLCA_ERR_KEY_ASSIGN,

	OPENSSLCA_ERR_REQ_NEW, /* 7 */
	OPENSSLCA_ERR_REQ_SET_PUBKEY,
	OPENSSLCA_ERR_REQ_GET_PUBKEY,
	OPENSSLCA_ERR_REQ_GET_SUBJECT,
	OPENSSLCA_ERR_REQ_SIGN, /* 11 */
	OPENSSLCA_ERR_REQ_VERIFY,
	OPENSSLCA_ERR_REQ_ENCODE,
	OPENSSLCA_ERR_REQ_DECODE,

	OPENSSLCA_ERR_CERT_NEW, /* 15 */
	OPENSSLCA_ERR_CERT_OPEN,
	OPENSSLCA_ERR_CERT_READ,
	OPENSSLCA_ERR_CERT_WRITE,
	OPENSSLCA_ERR_CERT_SET_VERSION,
	OPENSSLCA_ERR_CERT_SET_SERIAL,
	OPENSSLCA_ERR_CERT_SET_NOTBEFORE, /* 21 */
	OPENSSLCA_ERR_CERT_SET_NOTAFTER,
	OPENSSLCA_ERR_CERT_GET_PUBKEY,
	OPENSSLCA_ERR_CERT_SET_PUBKEY,
	OPENSSLCA_ERR_CERT_SET_SUBJECT,
	OPENSSLCA_ERR_CERT_GET_ISSUER,
	OPENSSLCA_ERR_CERT_SET_ISSUER,
	OPENSSLCA_ERR_CERT_SIGN, /* 28 */
	OPENSSLCA_ERR_CERT_VERIFY,
	OPENSSLCA_ERR_CERT_ENCODE,
	OPENSSLCA_ERR_CERT_DECODE,

	OPENSSLCA_ERR_RSA_NEW, /* 32 */
	OPENSSLCA_ERR_RSA_DECODE,

	OPENSSLCA_ERR_DN2SUBJECT_PARSE, /* 34 */
	OPENSSLCA_ERR_DN2SUBJECT_ADD,

	OPENSSLCA_ERR_EXT_MAKE, /* 36 */
	OPENSSLCA_ERR_EXT_ADD
};


#ifdef __cplusplus
#define EXPORT	extern "C" __declspec(dllexport)
#else
#define EXPORT	__declspec(dllexport)
#endif

/* Functions exported by DLL */
EXPORT int MakeCertificateRequest(unsigned char *reqbuf, int *reqlen, char *x500dn, unsigned char *rsabuf, int rsalen);
EXPORT int IssueUserCertificate(unsigned char *certbuf, int *certlen, unsigned char *reqbuf, int reqlen);
EXPORT int GetCACertificate(unsigned char *certbuf, int *certlen);
EXPORT int GetRACertificate(unsigned char *certbuf, int *certlen);

#endif /*_OPENSSLCA_H_*/
