#ifndef __SSDT_HH__
#define __SSDT_HH__

#include <ntifs.h>

typedef struct _SSDT_ITEM
{
	PULONG ServiceTable;
	ULONG count;
	ULONG ServiceLimit;
	PUCHAR ArgmentTable;
}SSDT_ITEM, *PSSDT_ITEM;

typedef struct _SSDT_TABLE
{
	SSDT_ITEM ServiceTable;
}SSDT_TABLE, *PSSDT_TABLE;

typedef struct _HOOK
{
	ULONG SystemCallNum;
	ULONG oldFunc;
	ULONG newFunc;
	ULONG isHookSuccess;
}HOOK, *PHOOK;


#endif





