#include "SsdtHook.h"

//函数声明
void wp_on();
void wp_off();
VOID SetHook(ULONG SystemCallNum, ULONG NewFuncAddr);
VOID UnHook();
NTSTATUS __stdcall MYNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferLength, PULONG ReturnLength);

//声明KeServiceDescriptorTable变量，该变量指向了SSDT表
extern SSDT_TABLE KeServiceDescriptorTable;
//用于存储SSDT_HOOK相关信息
HOOK hook = { 0 };

/**
* 卸载函数
* @param  pDriver 驱动对象
* @return
*/
VOID DriverUnLoad(PDRIVER_OBJECT pDriver)
{
	//卸载SSDT_HOOK
	UnHook();
	DbgPrint("卸载了 \n");
}


/**
* 驱动入口点
* @param  pDriver
* @param  pReg
* @return
*/
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg)
{
	DbgPrint("%x\n", *(((PULONG)*(KeServiceDescriptorTable.ServiceTable.ServiceTable)) + 0xBA));
	//设置SSDT_HOOK（传入系统调用号，与自己定义的函数的函数地址）
	SetHook(0xBA, (ULONG)MYNtReadVirtualMemory);
	//挂载卸载函数
	pDriver->DriverUnload = DriverUnLoad;
	return STATUS_SUCCESS;
}


/**
* 自定义的MYNtReadVirtualMemory()函数
* @param  ProcessHandle 进程句柄
* @param  BaseAddress   待读取内存基址
* @param  Buffer        缓冲区
* @param  BufferLength  缓冲区大小
* @param  ReturnLength  读取的长度
* @return               读取结果
*/
NTSTATUS __stdcall MYNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferLength, PULONG ReturnLength)
{
	//存放读取的结果
	NTSTATUS result = 0;
	DbgPrint("被我HOOK了 MYNtReadVirtualMemory %x %x %x %x %x\n", ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);
	//获取原来的 MYNtReadVirtualMemory()函数的函数地址
	ULONG oldFuncAddr = hook.oldFunc;

	//调用旧的MYNtReadVirtualMemory()函数
	__asm
	{
		push ReturnLength;
		push BufferLength;
		push Buffer;
		push BaseAddress;
		push ProcessHandle;
		call oldFuncAddr;

		mov result, eax;
	}
	return result;
}

/**
* 卸载SSDT_HOOK
* @return
*/
VOID UnHook()
{
	if (hook.isHookSuccess == 1)
	{
		//关闭写保护
		wp_off();
		//将系统调用号对应的函数的函数地址恢复成原来的
		*(((PULONG)*(KeServiceDescriptorTable.ServiceTable.ServiceTable)) + hook.SystemCallNum) = hook.oldFunc;
		//打开写保护
		wp_on();
		hook.isHookSuccess = 0;
	}
}

/**
* 设置SSDT_HOOK
* @param  SystemCallNum 系统调用号
* @param  NewFuncAddr   待替换的函数地址
* @return
*/
VOID SetHook(ULONG SystemCallNum, ULONG NewFuncAddr)
{
	if (hook.isHookSuccess == 0)
	{
		//保存原来的系统调用号所对应的函数的函数地址（以便之后的卸载）
		hook.oldFunc = *(((PULONG)*(KeServiceDescriptorTable.ServiceTable.ServiceTable)) + SystemCallNum);
		//关闭写保护
		wp_off();
		//将系统调用号对应的函数的函数地址替换成自己的
		*(((PULONG)*(KeServiceDescriptorTable.ServiceTable.ServiceTable)) + SystemCallNum) = NewFuncAddr;
		//开启写保护
		wp_on();
		//保存替换的函数地址
		hook.newFunc = NewFuncAddr;
		//保存系统调用号
		hook.SystemCallNum = SystemCallNum;
		//表示SSDT_HOOK成功
		hook.isHookSuccess = 1;
	}
}


/**
* 关闭写保护
*/
__declspec(naked) void wp_off()
{
	//将cr0寄存器的索引16位置0
	__asm
	{
		mov eax, cr0;
		and eax, 0xfffeffff;
		mov cr0, eax;
		ret;
	}
}

/**
* 开启写保护
*/
__declspec(naked) void wp_on()
{
	//将cr0寄存器的索引16位置1
	__asm
	{
		mov eax, cr0;
		or eax, 0x10000;
		mov cr0, eax;
		ret;
	}
}

