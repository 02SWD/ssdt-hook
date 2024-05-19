#include "SsdtHook.h"

//��������
void wp_on();
void wp_off();
VOID SetHook(ULONG SystemCallNum, ULONG NewFuncAddr);
VOID UnHook();
NTSTATUS __stdcall MYNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferLength, PULONG ReturnLength);

//����KeServiceDescriptorTable�������ñ���ָ����SSDT��
extern SSDT_TABLE KeServiceDescriptorTable;
//���ڴ洢SSDT_HOOK�����Ϣ
HOOK hook = { 0 };

/**
* ж�غ���
* @param  pDriver ��������
* @return
*/
VOID DriverUnLoad(PDRIVER_OBJECT pDriver)
{
	//ж��SSDT_HOOK
	UnHook();
	DbgPrint("ж���� \n");
}


/**
* ������ڵ�
* @param  pDriver
* @param  pReg
* @return
*/
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg)
{
	DbgPrint("%x\n", *(((PULONG)*(KeServiceDescriptorTable.ServiceTable.ServiceTable)) + 0xBA));
	//����SSDT_HOOK������ϵͳ���úţ����Լ�����ĺ����ĺ�����ַ��
	SetHook(0xBA, (ULONG)MYNtReadVirtualMemory);
	//����ж�غ���
	pDriver->DriverUnload = DriverUnLoad;
	return STATUS_SUCCESS;
}


/**
* �Զ����MYNtReadVirtualMemory()����
* @param  ProcessHandle ���̾��
* @param  BaseAddress   ����ȡ�ڴ��ַ
* @param  Buffer        ������
* @param  BufferLength  ��������С
* @param  ReturnLength  ��ȡ�ĳ���
* @return               ��ȡ���
*/
NTSTATUS __stdcall MYNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferLength, PULONG ReturnLength)
{
	//��Ŷ�ȡ�Ľ��
	NTSTATUS result = 0;
	DbgPrint("����HOOK�� MYNtReadVirtualMemory %x %x %x %x %x\n", ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);
	//��ȡԭ���� MYNtReadVirtualMemory()�����ĺ�����ַ
	ULONG oldFuncAddr = hook.oldFunc;

	//���þɵ�MYNtReadVirtualMemory()����
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
* ж��SSDT_HOOK
* @return
*/
VOID UnHook()
{
	if (hook.isHookSuccess == 1)
	{
		//�ر�д����
		wp_off();
		//��ϵͳ���úŶ�Ӧ�ĺ����ĺ�����ַ�ָ���ԭ����
		*(((PULONG)*(KeServiceDescriptorTable.ServiceTable.ServiceTable)) + hook.SystemCallNum) = hook.oldFunc;
		//��д����
		wp_on();
		hook.isHookSuccess = 0;
	}
}

/**
* ����SSDT_HOOK
* @param  SystemCallNum ϵͳ���ú�
* @param  NewFuncAddr   ���滻�ĺ�����ַ
* @return
*/
VOID SetHook(ULONG SystemCallNum, ULONG NewFuncAddr)
{
	if (hook.isHookSuccess == 0)
	{
		//����ԭ����ϵͳ���ú�����Ӧ�ĺ����ĺ�����ַ���Ա�֮���ж�أ�
		hook.oldFunc = *(((PULONG)*(KeServiceDescriptorTable.ServiceTable.ServiceTable)) + SystemCallNum);
		//�ر�д����
		wp_off();
		//��ϵͳ���úŶ�Ӧ�ĺ����ĺ�����ַ�滻���Լ���
		*(((PULONG)*(KeServiceDescriptorTable.ServiceTable.ServiceTable)) + SystemCallNum) = NewFuncAddr;
		//����д����
		wp_on();
		//�����滻�ĺ�����ַ
		hook.newFunc = NewFuncAddr;
		//����ϵͳ���ú�
		hook.SystemCallNum = SystemCallNum;
		//��ʾSSDT_HOOK�ɹ�
		hook.isHookSuccess = 1;
	}
}


/**
* �ر�д����
*/
__declspec(naked) void wp_off()
{
	//��cr0�Ĵ���������16λ��0
	__asm
	{
		mov eax, cr0;
		and eax, 0xfffeffff;
		mov cr0, eax;
		ret;
	}
}

/**
* ����д����
*/
__declspec(naked) void wp_on()
{
	//��cr0�Ĵ���������16λ��1
	__asm
	{
		mov eax, cr0;
		or eax, 0x10000;
		mov cr0, eax;
		ret;
	}
}

