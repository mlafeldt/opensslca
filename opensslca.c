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

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include "opensslca.h"

/* INI file stuff */
#define INI_FILE			"opensslca.ini"
#define INI_SECT			"opensslca"
#define INI_PASSWD_LEN		64

/* Struct to hold all INI values */
typedef struct {
	char	caDir[MAX_PATH];
	char	caCertFile[MAX_PATH];
	char	caKeyFile[MAX_PATH];
	char	caKeyPasswd[INI_PASSWD_LEN];
	char	raCertFile[MAX_PATH];
	char	raKeyFile[MAX_PATH];
	char	raKeyPasswd[INI_PASSWD_LEN];
	int		daysTillExpire;
	char	nsComment[1024];
	char	keyUsage[1024];
	char	newCertsDir[MAX_PATH];
	char	newCertsExt[10];
	char	serialFile[MAX_PATH];
	char	indexFile[MAX_PATH];
	int		signRequests;
	int		verifyRequests;
	int		verifyAfterSign;
	int		addToIndex;
	int		addToNewCerts;
#ifdef _DEBUG
	char	debugDir[MAX_PATH];
#endif
} caIni_t;

/* Global INI contents */
static caIni_t caIni;

/* Default INI values */
static caIni_t caIniDef = {
	"C:\\demoCA\\",
	"cacert.pem",
	"private\\cakey.pem",
	"1234",
	"racert.pem",
	"private\\rakey.pem",
	"1234",
	365,
	"OpenSSL Generated Certificate",
	"critical,nonRepudiation,digitalSignature,keyEncipherment,dataEncipherment",
	"newcerts\\",
	".cer",
	"serial.txt",
	"index.txt",
	1,
	1,
	1,
	1,
	1,
#ifdef _DEBUG
	"C:\\demoCA\\debug\\"
#endif
};

/* User certificate extensions */
typedef struct {
	int		nid;
	char	*value;
} ext_entry_t;

const ext_entry_t ext_entries[] = {
	{ NID_basic_constraints, "critical,CA:FALSE" },
	{ NID_netscape_comment, caIni.nsComment},
	{ NID_subject_key_identifier, "hash" },
	{ NID_authority_key_identifier, "keyid,issuer:always" },
	{ NID_key_usage, caIni.keyUsage },
	{ 0, NULL }
};

#define EXPIRE_SECS(days)	(60*60*24*days)
#define INVALID_SERIAL		0L

/* Easy path access */
#define CA_PATH(x)			build_path(caIni.caDir, x)
#ifdef _DEBUG
#define DBG_PATH(x)			build_path(caIni.debugDir, x) //build_path(build_path(caIni.caDir, caIni.debugDir), x)
#endif

/* Functions defined in this file */
void print_err(int ret);
int read_ini();
int write_ini();
char *build_path(const char *a, const char *b);
int read_cert(X509 **cert, const char *path);
int read_key(EVP_PKEY **key, const char *filename, char *passwd);
int write_cert(X509 *cert);
int add_to_index(X509 *cert);
int dn2subject(char *x500dn, X509_NAME *subject);
int add_ext(X509 *cacert, X509 *usrcert);
long read_serial();
int write_serial(long serial);
long get_serial();
int MakeCertificateRequest2(unsigned char *reqbuf, int *reqlen, char *x500dn, EVP_PKEY *usrkey);
EXPORT int MakeCertificateRequest(unsigned char *reqbuf, int *reqlen, char *x500dn, unsigned char *rsabuf, int rsalen);
EXPORT int IssueUserCertificate(unsigned char *certbuf, int *certlen, unsigned char *reqbuf, int reqlen);
int cert2der(unsigned char *certbuf, int *certlen, const char *filename);
EXPORT int GetCACertificate(unsigned char *certbuf, int *certlen);
EXPORT int GetRACertificate(unsigned char *certbuf, int *certlen);


/* Prints error information to stdout. */
void print_err(const char *str, int ret)
{
#ifdef _DEBUG
	if (ret != OPENSSLCA_NO_ERR) {
		printf("Error: %s, ret = %i\n", str, ret);
		ERR_print_errors_fp(stdout);
	}
#endif
}

/* Reads program settings from INI file. */
int read_ini(const char *dll_dir)
{
	char ini_path[MAX_PATH];

	/* Get full path to INI file */
	strcpy(ini_path, dll_dir);
	strcat(ini_path, "\\"INI_FILE);

	/* Read INI values */
	memset(&caIni, 0, sizeof(caIni));
	GetPrivateProfileStringA(INI_SECT, "caDir", caIniDef.caDir, caIni.caDir, sizeof(caIni.caDir), ini_path);
	GetPrivateProfileStringA(INI_SECT, "caCertFile", caIniDef.caCertFile, caIni.caCertFile, sizeof(caIni.caCertFile), ini_path);
	GetPrivateProfileStringA(INI_SECT, "caKeyFile", caIniDef.caKeyFile, caIni.caKeyFile, sizeof(caIni.caKeyFile), ini_path);
	GetPrivateProfileStringA(INI_SECT, "caKeyPasswd", caIniDef.caKeyPasswd, caIni.caKeyPasswd, sizeof(caIni.caKeyPasswd), ini_path);
	GetPrivateProfileStringA(INI_SECT, "raCertFile", caIniDef.raCertFile, caIni.raCertFile, sizeof(caIni.raCertFile), ini_path);
	GetPrivateProfileStringA(INI_SECT, "raKeyFile", caIniDef.raKeyFile, caIni.raKeyFile, sizeof(caIni.raKeyFile), ini_path);
	GetPrivateProfileStringA(INI_SECT, "raKeyPasswd", caIniDef.raKeyPasswd, caIni.raKeyPasswd, sizeof(caIni.raKeyPasswd), ini_path);
	caIni.daysTillExpire = GetPrivateProfileIntA(INI_SECT, "daysTillExpire", caIniDef.daysTillExpire, ini_path);
	GetPrivateProfileStringA(INI_SECT, "nsComment", caIniDef.nsComment, caIni.nsComment, sizeof(caIni.nsComment), ini_path);
	GetPrivateProfileStringA(INI_SECT, "keyUsage", caIniDef.keyUsage, caIni.keyUsage, sizeof(caIni.keyUsage), ini_path);
	GetPrivateProfileStringA(INI_SECT, "newCertsDir", caIniDef.newCertsDir, caIni.newCertsDir, sizeof(caIni.newCertsDir), ini_path);
	GetPrivateProfileStringA(INI_SECT, "newCertsExt", caIniDef.newCertsExt, caIni.newCertsExt, sizeof(caIni.newCertsExt), ini_path);
	GetPrivateProfileStringA(INI_SECT, "serialFile", caIniDef.serialFile, caIni.serialFile, sizeof(caIni.serialFile), ini_path);
	GetPrivateProfileStringA(INI_SECT, "indexFile", caIniDef.indexFile, caIni.indexFile, sizeof(caIni.indexFile), ini_path);
	caIni.signRequests = GetPrivateProfileIntA(INI_SECT, "signRequests", caIniDef.signRequests, ini_path);
	caIni.verifyRequests = GetPrivateProfileIntA(INI_SECT, "verifyRequests", caIniDef.verifyRequests, ini_path);
	caIni.verifyAfterSign = GetPrivateProfileIntA(INI_SECT, "verifyAfterSign", caIniDef.verifyAfterSign, ini_path);
	caIni.addToIndex = GetPrivateProfileIntA(INI_SECT, "addToIndex", caIniDef.addToIndex, ini_path);
	caIni.addToNewCerts = GetPrivateProfileIntA(INI_SECT, "addToNewCerts", caIniDef.addToNewCerts, ini_path);
#ifdef _DEBUG
	GetPrivateProfileStringA(INI_SECT, "debugDir", caIniDef.debugDir, caIni.debugDir, sizeof(caIni.debugDir), ini_path);
#endif

	return 0;
}

/* Writes program settings to INI file. */
int write_ini(const char *dll_dir)
{
	char ini_path[MAX_PATH];
	char buf[10];

	/* Get full path to INI file */
	strcpy(ini_path, dll_dir);
	strcat(ini_path, "\\"INI_FILE);

	/* Write INI values */
	WritePrivateProfileStringA(INI_SECT, "caDir", caIni.caDir, ini_path);
	WritePrivateProfileStringA(INI_SECT, "caCertFile", caIni.caCertFile, ini_path);
	WritePrivateProfileStringA(INI_SECT, "caKeyFile", caIni.caKeyFile, ini_path);
	WritePrivateProfileStringA(INI_SECT, "caKeyPasswd", caIni.caKeyPasswd, ini_path);
	WritePrivateProfileStringA(INI_SECT, "raCertFile", caIni.raCertFile, ini_path);
	WritePrivateProfileStringA(INI_SECT, "raKeyFile", caIni.raKeyFile, ini_path);
	WritePrivateProfileStringA(INI_SECT, "raKeyPasswd", caIni.raKeyPasswd, ini_path);
	WritePrivateProfileStringA(INI_SECT, "daysTillExpire", _itoa(caIni.daysTillExpire, buf, 10), ini_path);
	WritePrivateProfileStringA(INI_SECT, "nsComment", caIni.nsComment, ini_path);
	WritePrivateProfileStringA(INI_SECT, "keyUsage", caIni.keyUsage, ini_path);
	WritePrivateProfileStringA(INI_SECT, "newCertsDir", caIni.newCertsDir, ini_path);
	WritePrivateProfileStringA(INI_SECT, "newCertsExt", caIni.newCertsExt, ini_path);
	WritePrivateProfileStringA(INI_SECT, "serialFile", caIni.serialFile, ini_path);
	WritePrivateProfileStringA(INI_SECT, "indexFile", caIni.indexFile, ini_path);
	WritePrivateProfileStringA(INI_SECT, "signRequests", _itoa(caIni.signRequests, buf, 10), ini_path);
	WritePrivateProfileStringA(INI_SECT, "verifyRequests", _itoa(caIni.verifyRequests, buf, 10), ini_path);
	WritePrivateProfileStringA(INI_SECT, "verifyAfterSign", _itoa(caIni.verifyAfterSign, buf, 10), ini_path);
	WritePrivateProfileStringA(INI_SECT, "addToIndex", _itoa(caIni.addToIndex, buf, 10), ini_path);
	WritePrivateProfileStringA(INI_SECT, "addToNewCerts", _itoa(caIni.addToNewCerts, buf, 10), ini_path);
#ifdef _DEBUG
	WritePrivateProfileStringA(INI_SECT, "debugDir", caIni.debugDir, ini_path);
#endif

	return 0;
}

/* Builds absolute path to a file or directory. */
char *build_path(const char *a, const char *b)
{
	static char path[MAX_PATH];

	strcpy(path, a);
	strcat(path, b);

	return path;
}

/* Reads in a certificate from a PEM file. */
int read_cert(X509 **cert, const char *filename)
{
	X509 *x = NULL;
	FILE *fp = NULL;

	if (cert == NULL)
		return OPENSSLCA_ERR_ARGS;

	fp = fopen(filename, "r");
	if (fp == NULL)
		return OPENSSLCA_ERR_CERT_OPEN;

	x = PEM_read_X509(fp, NULL, NULL, NULL);
	if (x == NULL) {
		fclose(fp);
		return OPENSSLCA_ERR_CERT_READ;
	}

	*cert = x;
	fclose(fp);

	return OPENSSLCA_NO_ERR;
}

/* Reads in a private key from a PEM file. */
int read_key(EVP_PKEY **key, const char *filename, char *passwd)
{
	EVP_PKEY *k = NULL;
	FILE *fp = NULL;

	if (key == NULL)
		return OPENSSLCA_ERR_ARGS;

	fp = fopen(filename, "r");
	if (fp == NULL)
		return OPENSSLCA_ERR_KEY_OPEN;

	k = PEM_read_PrivateKey(fp, NULL, NULL, passwd);
	if (k == NULL) {
		fclose(fp);
		return OPENSSLCA_ERR_KEY_READ;
	}

	*key = k;
	fclose(fp);

	return OPENSSLCA_NO_ERR;
}

/* Writes a certificate to a new file. */
int write_cert(X509 *cert)
{
	FILE *fp = NULL;
	char filename[MAX_PATH], serialstr[20];
	long serial = ASN1_INTEGER_get(X509_get_serialNumber(cert));
	int ret;

	/* Create file name from serial number */
	strcpy(filename, CA_PATH(caIni.newCertsDir));
	strcat(filename, _ltoa(serial, serialstr, 10));
	strcat(filename, caIni.newCertsExt);

	fp = fopen(filename, "w");
	if (fp == NULL)
		return OPENSSLCA_ERR_CERT_OPEN;

	/* Write certificate text */
	if (X509_print_fp(fp, cert) != 1) {
		ret = OPENSSLCA_ERR_CERT_WRITE;
		goto err;
	}

	/* Write PEM */
	if (PEM_write_X509(fp, cert) != 1) {
		ret = OPENSSLCA_ERR_CERT_WRITE;
		goto err;
	}

err:
	if (fp)
		fclose(fp);

	return ret;
}

/* Appends information about an issued certificate to the index file. */
int add_to_index(X509 *cert)
{
	FILE *fp = NULL;
	BIO *bio = NULL;
	X509_NAME *subject = X509_get_subject_name(cert);
	long serial = ASN1_INTEGER_get(X509_get_serialNumber(cert));

	fp = fopen(CA_PATH(caIni.indexFile), "a");
	if (fp != NULL) {
		bio = BIO_new_fp(fp, BIO_CLOSE);

		/* Write serial */
		BIO_printf(bio, "%ld\t", serial);

		/* Write notBefore time */
		ASN1_TIME_print(bio, X509_get_notBefore(cert));
		BIO_printf(bio, "\t");

		/* Write subject */
		X509_NAME_print_ex(bio, subject, 0, 0);
		BIO_printf(bio, "\n");

		BIO_free(bio); /* Closes fp too */
		return 1;
	}

	return 0;
}

/* X500 distingutshed name defines */
#define DN_NUM_FIELDS	7
enum {
	DN_FIELD_C,
	DN_FIELD_S,
	DN_FIELD_L,
	DN_FIELD_O,
	DN_FIELD_OU,
	DN_FIELD_CN,
	DN_FIELD_E
};

/* Converts an X500 distinguished name to an X509 subject. */
int dn2subject(char *x500dn, X509_NAME *subject)
{
	const char *fields[DN_NUM_FIELDS] = { "C", "S", "L", "O", "OU", "CN", "E" }; /* .NET */
	const char *alt_fields[DN_NUM_FIELDS] = { NULL, "ST", NULL, NULL, NULL, NULL, "emailAddress" }; /* OpenSSL */
	char *values[DN_NUM_FIELDS] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL };
	const char sep[] = ",;";
	char *token = NULL, *p = NULL;
	size_t fieldsz;
	int i;

	if (x500dn == NULL || subject == NULL)
		return OPENSSLCA_ERR_ARGS;

	/* Parse distingutshed name, get field values */
	token = strtok(x500dn, sep);
	while (token != NULL) {
		p = token;
		while (*p == ' ' || *p == '\t') /* Skip whitespace */
			p++;

		for (i = 0; i < DN_NUM_FIELDS; i++) {
			fieldsz = strlen(fields[i]);
			if ((strlen(p) > fieldsz) && !strncmp(p, fields[i], fieldsz) && p[fieldsz] == '=') {
				if (values[i] == NULL)
					values[i] = p + fieldsz + 1;
				else
					return OPENSSLCA_ERR_DN2SUBJECT_PARSE; /* Value already set */
			}
		}

		token = strtok(NULL, sep);
	}

	/* Add field values to X509 subject */
	for (i = 0; i < DN_NUM_FIELDS; i++) {
		if (values[i] != NULL) {
			if (alt_fields[i]) { /* Use alternative if possible */
				if (!X509_NAME_add_entry_by_txt(subject, alt_fields[i], MBSTRING_ASC, values[i], -1, -1, 0))
					return OPENSSLCA_ERR_DN2SUBJECT_ADD;
			} else {
				if (!X509_NAME_add_entry_by_txt(subject, fields[i], MBSTRING_ASC, values[i], -1, -1, 0))
					return OPENSSLCA_ERR_DN2SUBJECT_ADD;
			}
		}
	}

	return OPENSSLCA_NO_ERR;
}

/* Adds X509v3 extensions to a certificate. */
int add_ext(X509 *cacert, X509 *usrcert)
{
	X509_EXTENSION *ext = NULL;
	X509V3_CTX ctx;
	int i = 0;

	if (cacert == NULL || usrcert == NULL)
		return OPENSSLCA_ERR_ARGS;

	/* Set extension context */
	X509V3_set_ctx_nodb(&ctx);
	X509V3_set_ctx(&ctx, cacert, usrcert, NULL, NULL, 0);

	/* Add all specified extensions */
	while (ext_entries[i].nid) {
		if ((ext = X509V3_EXT_conf_nid(NULL, &ctx, ext_entries[i].nid, ext_entries[i].value)) == NULL)
			return OPENSSLCA_ERR_EXT_MAKE;

		if (!X509_add_ext(usrcert, ext, -1))
			return OPENSSLCA_ERR_EXT_ADD;

		X509_EXTENSION_free(ext);
		i++;
	}

	return OPENSSLCA_NO_ERR;
}

/* Reads the current serial number from the serial file. */
long read_serial()
{
	long serial = INVALID_SERIAL;
	FILE *fp = fopen(CA_PATH(caIni.serialFile), "r");

	if (fp != NULL) {
		if (fscanf(fp, "%ld", &serial) != 1) /* Error reading serial */
			serial = INVALID_SERIAL;
		fclose(fp);
	}

	return serial;
}

/* Writes a serial number to the serial file. */
int write_serial(long serial)
{
	FILE *fp = fopen(CA_PATH(caIni.serialFile), "w");

	if (fp != NULL) {
		fprintf(fp, "%ld", serial);
		fclose(fp);
		return 1;
	}

	return 0;
}

/* Generates a new serial number for a certificate. */
long get_serial()
{
	long serial = read_serial();

	if (serial == INVALID_SERIAL) { /* Read failed */
		/* Generate a new serial */
		RAND_pseudo_bytes((unsigned char*)&serial, sizeof(serial));
		serial &= 0x0FFFFFFF; /* Fix sign and allow loads of serials before an overflow occurs */
		RAND_cleanup();
		write_serial(serial);
	} else
		write_serial(++serial); /* Update serial file */

	return serial;
}

/* Creates an X509 certificate request (2nd stage). */
int MakeCertificateRequest2(unsigned char *reqbuf, int *reqlen, char *x500dn, EVP_PKEY *usrkey)
{
	X509 *racert = NULL;
	EVP_PKEY *rakey = NULL;
	X509_REQ *x = NULL;
	X509_NAME *subject = NULL;
	unsigned char *p = NULL;
	int ret, len;

	if (reqbuf == NULL || reqlen == NULL || x500dn == NULL || usrkey == NULL)
		return OPENSSLCA_ERR_ARGS;

	/* Create new request */
	if ((x = X509_REQ_new()) == NULL) {
		ret = OPENSSLCA_ERR_REQ_NEW;
		goto err;
	}

	/* Set public key in request */
	if (X509_REQ_set_pubkey(x, usrkey) != 1) {
		ret = OPENSSLCA_ERR_REQ_SET_PUBKEY;
		goto err;
	}

	/* Set subject name */
	subject = X509_REQ_get_subject_name(x);
	if (subject == NULL) {
		ret = OPENSSLCA_ERR_REQ_GET_SUBJECT;
		goto err;
	}
	ret = dn2subject(x500dn, subject);
	if (ret != OPENSSLCA_NO_ERR)
		goto err;

	if (caIni.signRequests) {
		/* Sign request with RA's private key */
		ret = read_key(&rakey, CA_PATH(caIni.raKeyFile), caIni.raKeyPasswd);
		if (ret != OPENSSLCA_NO_ERR)
			goto err;
		if (!X509_REQ_sign(x, rakey, EVP_sha1())) {
			ret = OPENSSLCA_ERR_REQ_SIGN;
			goto err;
		}

		if (caIni.verifyAfterSign) {
			/* Get RA's public key */
			/* TODO: Validate RA certificate */
			ret = read_cert(&racert, CA_PATH(caIni.raCertFile));
			if (ret != OPENSSLCA_NO_ERR)
				goto err;

			EVP_PKEY_free(rakey);
			if ((rakey = X509_get_pubkey(racert)) == NULL) {
				ret = OPENSSLCA_ERR_CERT_GET_PUBKEY;
				goto err;
			}

			/* Verify signature on request */
			if (X509_REQ_verify(x, rakey) != 1) {
				ret = OPENSSLCA_ERR_REQ_VERIFY;
				goto err;
			}
		}
	}

#ifdef _DEBUG /* Output request in PEM format */
	{
		FILE *fp = fopen(DBG_PATH("request.pem"), "w");
		if (fp != NULL) {
			X509_REQ_print_fp(fp, x);
			PEM_write_X509_REQ(fp, x);
			fclose(fp);
		}
	}
#endif

	/* Encode request into DER format */
	len = i2d_X509_REQ(x, NULL);
	if (len < 0) {
		ret = OPENSSLCA_ERR_REQ_ENCODE;
		goto err;
	}
	if (len > *reqlen) {
		ret = OPENSSLCA_ERR_BUF_TOO_SMALL;
		goto err;
	}
	*reqlen = len;
	p = reqbuf;
	i2d_X509_REQ(x, &p);

err:
	if (racert)
		X509_free(racert);
	if (rakey)
		EVP_PKEY_free(rakey);
	if (x)
		X509_REQ_free(x);

	return ret;
}

/* Creates an X509 certificate request (1st stage). */
EXPORT int MakeCertificateRequest(unsigned char *reqbuf, int *reqlen, char *x500dn, unsigned char *rsabuf, int rsalen)
{
	EVP_PKEY *pkey = NULL;
	RSA *rsa = NULL;
	unsigned char *p = NULL;
	int ret = OPENSSLCA_NO_ERR;

	if (reqbuf == NULL || reqlen == NULL || x500dn == NULL || rsabuf == NULL || rsalen == 0)
		return OPENSSLCA_ERR_ARGS;

	/* Decode RSA public key from DER format */
	if ((rsa = RSA_new()) == NULL) {
		ret = OPENSSLCA_ERR_RSA_NEW;
		goto err;
	}
	p = rsabuf;
	if (d2i_RSAPublicKey(&rsa, &p, rsalen) == NULL) {
		ret = OPENSSLCA_ERR_RSA_DECODE;
		goto err;
	}

	/* Add RSA to EVP_PKEY */
	if ((pkey = EVP_PKEY_new()) == NULL) {
		ret = OPENSSLCA_ERR_KEY_NEW;
		goto err;
	}
	if (!EVP_PKEY_set1_RSA(pkey, rsa)) {
		ret = OPENSSLCA_ERR_KEY_ASSIGN;
		goto err;
	}

#ifdef _DEBUG
	{
		FILE *fp = fopen(DBG_PATH("rsa.bin"), "wb");
		if (fp != NULL) {
			i2d_RSAPublicKey_fp(fp, rsa);
			fclose(fp);
		}
	}
#endif

	ret = MakeCertificateRequest2(reqbuf, reqlen, x500dn, pkey);
err:
	print_err("MakeCertificateRequest()", ret);

	if (rsa)
		RSA_free(rsa);
	if (pkey)
		EVP_PKEY_free(pkey);

	return ret;
}

/* Creates an X509 certificate from a certificate request. */
EXPORT int IssueUserCertificate(unsigned char *certbuf, int *certlen, unsigned char *reqbuf, int reqlen)
{
	X509_REQ *req = NULL;
	EVP_PKEY *cakey = NULL, *rakey = NULL, *usrkey = NULL;
	X509 *cacert = NULL, *racert = NULL, *usrcert = NULL;
	X509_NAME *subject = NULL, *issuer = NULL;
	unsigned char *p = NULL;
	int ret = OPENSSLCA_NO_ERR, len;

	if (certbuf == NULL || certlen == NULL || reqbuf == NULL || reqlen == 0)
		return OPENSSLCA_ERR_ARGS;

	/* Decode request */
	if ((req = X509_REQ_new()) == NULL) {
		ret = OPENSSLCA_ERR_REQ_NEW;
		goto err;
	}
	p = reqbuf;
	if (d2i_X509_REQ(&req, &p, reqlen) == NULL) {
		ret = OPENSSLCA_ERR_REQ_DECODE;
		goto err;
	}

	/* Get public key from request */
	if ((usrkey = X509_REQ_get_pubkey(req)) == NULL) {
		ret = OPENSSLCA_ERR_REQ_GET_PUBKEY;
		goto err;
	}

	if (caIni.verifyRequests) {
		/* Get RA's public key */
		/* TODO: Validate RA certificate */
		ret = read_cert(&racert, CA_PATH(caIni.raCertFile));
		if (ret != OPENSSLCA_NO_ERR)
			goto err;
		if ((rakey = X509_get_pubkey(racert)) == NULL) {
			ret = OPENSSLCA_ERR_CERT_GET_PUBKEY;
			goto err;
		}

		/* Verify signature on request */
		if (X509_REQ_verify(req, rakey) != 1) {
			ret = OPENSSLCA_ERR_REQ_VERIFY;
			goto err;
		}
	}

	/* Get CA certificate */
	/* TODO: Validate CA certificate */
	ret = read_cert(&cacert, CA_PATH(caIni.caCertFile));
	if (ret != OPENSSLCA_NO_ERR)
		goto err;

	/* Get CA private key */
	ret = read_key(&cakey, CA_PATH(caIni.caKeyFile), caIni.caKeyPasswd);
	if (ret != OPENSSLCA_NO_ERR)
		goto err;

	/* Create user certificate */
	if ((usrcert = X509_new()) == NULL)
		return OPENSSLCA_ERR_CERT_NEW;

	/* Set version and serial number for certificate */
	if (X509_set_version(usrcert, 2) != 1) { /* V3 */
		ret = OPENSSLCA_ERR_CERT_SET_VERSION;
		goto err;
	}
	if (ASN1_INTEGER_set(X509_get_serialNumber(usrcert), get_serial()) != 1) {
		ret = OPENSSLCA_ERR_CERT_SET_SERIAL;
		goto err;
	}

	/* Set duration for certificate */
	if (X509_gmtime_adj(X509_get_notBefore(usrcert), 0) == NULL) {
		ret = OPENSSLCA_ERR_CERT_SET_NOTBEFORE;
		goto err;
	}
	if (X509_gmtime_adj(X509_get_notAfter(usrcert), EXPIRE_SECS(caIni.daysTillExpire)) == NULL) {
		ret = OPENSSLCA_ERR_CERT_SET_NOTAFTER;
		goto err;
	}

	/* Set public key */
	if (X509_set_pubkey(usrcert, usrkey) != 1) {
		ret = OPENSSLCA_ERR_CERT_SET_PUBKEY;
		goto err;
	}

	/* Set subject name */
	subject = X509_REQ_get_subject_name(req);
	if (subject == NULL) {
		ret = OPENSSLCA_ERR_REQ_GET_SUBJECT;
		goto err;
	}
	if (X509_set_subject_name(usrcert, subject) != 1) {
		ret = OPENSSLCA_ERR_CERT_SET_SUBJECT;
		goto err;
	}

	/* Set issuer name */
	issuer = X509_get_issuer_name(cacert);
	if (issuer == NULL) {
		ret = OPENSSLCA_ERR_CERT_GET_ISSUER;
		goto err;
	}
	if (X509_set_issuer_name(usrcert, issuer) != 1) {
		ret = OPENSSLCA_ERR_CERT_SET_ISSUER;
		goto err;
	}

	/* Add extensions */
	ret = add_ext(cacert, usrcert);
	if (ret != OPENSSLCA_NO_ERR)
		goto err;

	/* Sign user certificate with CA's private key */
	if (!X509_sign(usrcert, cakey, EVP_sha1()))
		return OPENSSLCA_ERR_CERT_SIGN;

	if (caIni.verifyAfterSign) {
		if (X509_verify(usrcert, cakey) != 1) {
			ret = OPENSSLCA_ERR_CERT_VERIFY;
			goto err;
		}
	}

#ifdef _DEBUG /* Output certificate in DER and PEM format */
	{
		FILE *fp = fopen(DBG_PATH("usrcert.der"), "wb");
		if (fp != NULL) {
			i2d_X509_fp(fp, usrcert);
			fclose(fp);
		}
		fp = fopen(DBG_PATH("usrcert.pem"), "w");
		if (fp != NULL) {
			X509_print_fp(fp, usrcert);
			PEM_write_X509(fp, usrcert);
			fclose(fp);
		}
	}
#endif

	/* Encode user certificate into DER format */
	len = i2d_X509(usrcert, NULL);
	if (len < 0) {
		ret = OPENSSLCA_ERR_CERT_ENCODE;
		goto err;
	}
	if (len > *certlen) {
		ret = OPENSSLCA_ERR_BUF_TOO_SMALL;
		goto err;
	}
	*certlen = len;
	p = certbuf;
	i2d_X509(usrcert, &p);

	if (caIni.addToIndex)
		add_to_index(usrcert);

	if (caIni.addToNewCerts)
		write_cert(usrcert);

err:
	print_err("IssueUserCertificate()", ret);

	/* Clean up */
	if (cacert)
		X509_free(cacert);
	if (cakey)
		EVP_PKEY_free(cakey);
	if (racert)
		X509_free(racert);
	if (rakey)
		EVP_PKEY_free(rakey);
	if (req)
		X509_REQ_free(req);
	if (usrcert != NULL)
		X509_free(usrcert);
	if (usrkey)
		EVP_PKEY_free(usrkey);

	return ret;
}

/* Encodes a certificate into DER format */
int cert2der(unsigned char *certbuf, int *certlen, const char *filename)
{
	X509 *x = NULL;
	unsigned char *next = certbuf;
	int ret, len;

	/* Get certificate */
	ret = read_cert(&x, filename);
	if (ret != OPENSSLCA_NO_ERR)
		goto err;

	/* Encode it */
	len = i2d_X509(x, NULL);
	if (len < 0) {
		ret = OPENSSLCA_ERR_CERT_ENCODE;
		goto err;
	}
	if (len > *certlen) {
		ret = OPENSSLCA_ERR_BUF_TOO_SMALL;
		goto err;
	}
	*certlen = len;
	i2d_X509(x, &next);

err:
	print_err("cert2der()", ret);

	if (x)
		X509_free(x);

	return ret;
}

/* Returns the CA's certificate in DER format. */
EXPORT int GetCACertificate(unsigned char *certbuf, int *certlen)
{
	return cert2der(certbuf, certlen, CA_PATH(caIni.caCertFile));
}

/* Returns the RA's certificate in DER format. */
EXPORT int GetRACertificate(unsigned char *certbuf, int *certlen)
{
	return cert2der(certbuf, certlen, CA_PATH(caIni.raCertFile));
}
