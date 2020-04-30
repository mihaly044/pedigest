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

#include "mm.h"

NTSTATUS
MmSearchPattern(
    _In_ PCUCHAR pcPattern,
    _In_ UCHAR uWildcard,
    _In_ ULONG_PTR puLen,
    _In_ const PVOID pcBase,
    _In_ ULONG_PTR puSize,
    _Out_ PVOID* ppMatch
)
{
    ASSERT(ppMatch != NULL && pcPattern != NULL && pcBase != NULL);
    if (ppMatch == NULL || pcPattern == NULL || pcBase == NULL)
        return STATUS_INVALID_PARAMETER;

    for (ULONG_PTR i = 0; i < puSize - puLen; i++)
    {
        BOOLEAN found = TRUE;
        for (ULONG_PTR j = 0; j < puLen; j++)
        {
            if (pcPattern[j] != uWildcard && pcPattern[j] != ((PCUCHAR)pcBase)[i + j])
            {
                found = FALSE;
                break;
            }
        }

        if (found != FALSE)
        {
            *ppMatch = (PUCHAR)pcBase + i;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}