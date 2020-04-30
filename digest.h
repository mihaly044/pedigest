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

#pragma once
#include "ci.h"
#define DIGEST_POOL_TAG 'egiD'

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
	_Out_	PVOID*	pDigestOut,
	_Out_	LPWIN_CERTIFICATE* pCertOut,
	_Out_	PULONG pSizeOfSecurityDirectory
);