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

#include <windows.h>
#include <openssl/evp.h>

/* From opensslca.c */
extern int read_ini(const char *dll_dir);
extern int write_ini(const char *dll_dir);

/* Gets the directory where the DLL is in. */
static char *getDllDir(HANDLE hinstDLL)
{
	static char path[MAX_PATH];
	char *p;

	GetModuleFileNameA(hinstDLL, path, sizeof(path));
	p = &path[strlen(path)-1];
	while (*--p != '\\')
		;
	p[1] = '\0';

	return path;
}

/* DLL main function */
BOOL WINAPI DllMain(HANDLE hinstDLL, DWORD dwReason, LPVOID lpvReserved)
{
	switch (dwReason) {
		case DLL_PROCESS_ATTACH: /* DLL start */
			/* Init OpenSSL */
			ERR_load_crypto_strings();
			OpenSSL_add_all_algorithms();
			/* Read from INI file */
			read_ini(getDllDir(hinstDLL));
			break;

		case DLL_THREAD_ATTACH:
			break;

		case DLL_THREAD_DETACH:
			break;

		case DLL_PROCESS_DETACH: /* DLL exit */
			/* Write to INI file */
			write_ini(getDllDir(hinstDLL));
			/* Deinit OpenSSL */
			EVP_cleanup();
			ERR_free_strings();
			break;
	}

	return TRUE;
}
