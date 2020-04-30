/***
	Helper functions for calculating the authenticode digest
	for a portable executable file.
	
	Author:
		Mihaly Meszaros
		meszaros - at - mihaly.me
	
	Copyright (c) 2020 - Mihaly Meszaros

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all
	copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.
***/

#include "digest.h"
#include <bcrypt.h>
#include <ntimage.h>
#include "mm.h"

#define CALG_SHA1 0x8004u
#define CALG_SHA256 0x800cu
#define CALG_SHA384 0x800du
#define CALG_SHA512 0x800eu

#pragma comment(lib, "ksecdd.lib")

//
// Converts a wincrypt CALG_ID to a BCRYPT_ALGORITHM identifier
//
PCWSTR
Calg2BCryptAlg(
	_In_ UINT32 Calg
)
{
	switch (Calg)
	{
	case CALG_SHA1:
		return BCRYPT_SHA1_ALGORITHM;
	case CALG_SHA256:
		return BCRYPT_SHA256_ALGORITHM;
	case CALG_SHA384:
		return BCRYPT_SHA384_ALGORITHM;
	case CALG_SHA512:
		return BCRYPT_SHA512_ALGORITHM;
	}

	return L"unknown";
}

//
// Extracts the CALG_ID from a signed PE that was used to
// calcualte the message digest when it was signed
//
UINT32
GetPEDigestKind(
	_In_ PUCHAR					pPeBytes,
	_In_ PIMAGE_DATA_DIRECTORY	pImgDataDirectory
)
{
	if (!pImgDataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress)
	{
		Log("Security VA is 0, defaulting to CALG_SHA1!\n");
		return CALG_SHA1;
	}

	PVOID pBase = pPeBytes + pImgDataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
	LPWIN_CERTIFICATE pCert = (WIN_CERTIFICATE*)pBase;
	PUCHAR pMatch = NULL;

	if (NT_SUCCESS(MmSearchPattern(
		(const PUCHAR)"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14",
		0x00, 15, pBase, pCert->dwLength, (PVOID*)&pMatch)))
	{
		Log("SHA1\n");
		return CALG_SHA1;
	}

	if (NT_SUCCESS(MmSearchPattern(
		(const PUCHAR)"\x30\xcc\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\xcc\x05\x00\x04\xcc",
		0xcc, 19, pBase, pCert->dwLength, (PVOID*)&pMatch)))
	{
		if (pMatch[1] == 0x31 && pMatch[14] == 0x01 && pMatch[18] == 0x20)
		{
			Log("SHA256\n");
			return CALG_SHA256;
		}
		else if (pMatch[1] == 0x41 && pMatch[14] == 0x02 && pMatch[18] == 0x30)
		{
			Log("SHA384\n");
			return CALG_SHA384;
		}
		else if (pMatch[1] == 0x51 && pMatch[14] == 0x03 && pMatch[18] == 0x40)
		{
			Log("SHA512\n");
			return CALG_SHA512;
		}
	}

	Log("Could not extract digest algorithm for PE, defaulting to CALG_SHA1\n");
	return CALG_SHA1;
}

//
// Calculates the message digest for a signed PE
// Caller must free *pDigestOut
//
NTSTATUS
CalculatePeDigest(
	_In_	PUCHAR	pPeBytes,
	_In_	ULONG	PeSize,
	_Out_	PUINT32	pDigestCalgOut,
	_Out_	PULONG	pDigestSizeOut,
	_Out_	PVOID* pDigestOut,
	_Out_	LPWIN_CERTIFICATE* pCertOut,
	_Out_	PULONG pSizeOfSecurityDirectory
)
{

	PIMAGE_DOS_HEADER		phDos;
	PIMAGE_NT_HEADERS		phNt;
	PIMAGE_DATA_DIRECTORY	pImgDataDirectory;
	BOOL					is64Bit;
	BOOL					hasEmbeddedSig;
	PBYTE					pHash = NULL;
	PUCHAR					pBuf;
	ULONG					copySize;
	NTSTATUS				status;
	ULONG					remaining;
	BCRYPT_ALG_HANDLE		hbAlg = NULL;
	BCRYPT_HASH_HANDLE		hbHash = NULL;
	UINT32					hashLength = 0;
	ULONG					resultLength;
	UINT32					peDigestKind;
	ULONG					fileOffset = 0;

	phDos = (IMAGE_DOS_HEADER*)pPeBytes;
	if (phDos->e_magic != IMAGE_DOS_SIGNATURE)
		return STATUS_INVALID_IMAGE_NOT_MZ;			// Not an executable

	phNt = (PIMAGE_NT_HEADERS)(pPeBytes + phDos->e_lfanew);
	if (phNt->Signature != IMAGE_NT_SIGNATURE)
	{
		return STATUS_INVALID_IMAGE_FORMAT;			// Not a PE image
	}

	//
	//	Check if PE is 32 or 64 bits
	//
	switch (phNt->OptionalHeader.Magic)
	{
	case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
		is64Bit = FALSE;
		break;
	case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
		is64Bit = TRUE;
		break;
	default:
		return STATUS_INVALID_IMAGE_FORMAT;			// Unsupported architecture
	}

	//
	// TODO: Not sure if  16 * 512 * 512 is right. Do something better!
	//
	copySize = phDos->e_lfanew + sizeof(IMAGE_FILE_HEADER) + 4 + 0x40;
	pBuf = (PBYTE)ExAllocatePoolWithTag(NonPagedPool, 16 * 512 * 512, DIGEST_POOL_TAG);
	if (!pBuf)
		return STATUS_INSUFFICIENT_RESOURCES;

	//
	// Fetch the data directory from the PE.
	// Note that we can also use RtlImageDirectoryEntryToData to fetch
	// only the security directory entry but why not do it manually
	// when we have the full PE image anyway
	//
	if (is64Bit == TRUE)
		pImgDataDirectory = ((PIMAGE_NT_HEADERS64)phNt)->OptionalHeader.DataDirectory;
	else
		pImgDataDirectory = ((PIMAGE_NT_HEADERS32)phNt)->OptionalHeader.DataDirectory;

	//
	// Check if the PE file contains a signature
	//
	hasEmbeddedSig = pImgDataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress != 0;

	//
	// Boring bcrypt boilerplate code
	//
	peDigestKind = GetPEDigestKind(pPeBytes, pImgDataDirectory);
	status = BCryptOpenAlgorithmProvider(
		&hbAlg,
		Calg2BCryptAlg(peDigestKind),				// bcrypt doesn't understand standard wincrypt CALG IDs
		MS_PRIMITIVE_PROVIDER,
		0
	);
	if (!NT_SUCCESS(status))
	{
		Log("BCryptOpenAlgorithmProvider %008X", status);
		goto cleanup;
	}

	status = BCryptGetProperty(
		hbAlg,
		BCRYPT_HASH_LENGTH,
		(PUCHAR)&hashLength,						// put the length of the hash into hashLength
		sizeof(hashLength),
		&resultLength,
		0
	);
	if (!NT_SUCCESS(status))
	{
		Log("BCryptGetProperty %008X", status);
		goto cleanup;
	}

	//
	// Allocate a buffer to store the resulting hash
	//
	pHash = ExAllocatePoolWithTag(NonPagedPool, hashLength, DIGEST_POOL_TAG);
	if (!pHash)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto cleanup;
	}
	RtlZeroMemory(pHash, hashLength);

	//
	// Create a handle to the resulting hash
	//
	status = BCryptCreateHash(
		hbAlg,
		&hbHash,
		NULL, 0, NULL, 0, 0
	);
	if (!NT_SUCCESS(status))
	{
		Log("BCryptCreateHash %008X", status);
		goto cleanup;
	}

	//
	// Ok, if we haven't BSODed yet, we're ready to continue
	// parsing the PE/COFF and hash the needed values
	//
	memcpy(pBuf, pPeBytes, copySize);
	fileOffset += copySize;

	//
	// Hash everything up to the Checksum then skip it
	//
	status = BCryptHashData(
		hbHash,
		pBuf,
		copySize,
		0
	);
	if (!NT_SUCCESS(status))
	{
		Log("BCryptHashData %008X", status);
		goto cleanup;
	}

	fileOffset += 4; // Skipping the checksum field here

	//
	// Reach the security directory information.
	// For x64 PEs it's 10 bytes further
	//
	copySize = 0x3C;
	if (is64Bit == TRUE)
		copySize += 0x10;

	memcpy(pBuf, pPeBytes + fileOffset, copySize);
	fileOffset += copySize;

	//
	// Again, hash everything up to here then skip the ignored field.
	//
	status = BCryptHashData(
		hbHash,
		pBuf,
		copySize,
		0
	);
	if (!NT_SUCCESS(status))
	{
		Log("BCryptHashData %008X", status);
		goto cleanup;
	}

	fileOffset += 8; // Skipping an other ignored field here

	//
	// Now hash everything else in the file up to the certificate data.
	//
	remaining = hasEmbeddedSig
		? pImgDataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress - fileOffset
		: PeSize - fileOffset;

	while (remaining > 0)
	{
		ULONG chunk_size = min(remaining, 4096);
		ULONG read_bytes;
		memset(pBuf, 0, chunk_size);

		if (fileOffset + chunk_size > PeSize)
		{
			read_bytes = PeSize - chunk_size;
			memcpy(pBuf, pPeBytes + fileOffset, read_bytes);
			fileOffset += read_bytes;
			break;
		}
		else
		{
			memcpy(pBuf, pPeBytes + fileOffset, chunk_size);
			read_bytes = chunk_size;
			fileOffset += read_bytes;
		}

		status = BCryptHashData(
			hbHash,
			pBuf,
			read_bytes,
			0
		);
		if (!NT_SUCCESS(status))
		{
			Log("BCryptHashData %008X", status);
			goto cleanup;
		}

		remaining -= read_bytes;
	}

	//
	// Finish up the hash here
	//
	status = BCryptFinishHash(
		hbHash,
		pHash,
		hashLength,
		0
	);
	if (!NT_SUCCESS(status))
	{
		Log("BCryptFinishHash %008X", status);
		goto cleanup;
	}

	//
	// Supply the results to the caller
	//
	*pDigestCalgOut = peDigestKind;
	*pDigestSizeOut = hashLength;
	*pDigestOut = pHash;
	if (hasEmbeddedSig == TRUE)
	{
		*pCertOut = (LPWIN_CERTIFICATE)(pPeBytes + pImgDataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress);
		*pSizeOfSecurityDirectory = pImgDataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
	}
	else
	{
		*pCertOut = NULL;
		*pSizeOfSecurityDirectory = 0;
	}

	status = STATUS_SUCCESS;

cleanup:
	if (pBuf)
		ExFreePool(pBuf);

	if (hbHash)
		BCryptDestroyHash(hbHash);

	if (hbAlg)
		BCryptCloseAlgorithmProvider(hbAlg, 0);

	return status;
}