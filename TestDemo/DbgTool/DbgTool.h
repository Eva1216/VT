#pragma once 
#include <ntddk.h>

typedef struct _save_handlentry {
	struct _save_handlentry*head;		//头指针
	HANDLE dbgProcessId;				//进程ID
	PEPROCESS dbgProcessStruct;			//进程PEPROCESS

	struct _save_handlentry*next;		//下一个节点

}_save_handlentry, *p_save_handlentry;

p_save_handlentry CreateList();
p_save_handlentry InsertList(HANDLE dbgProcessId,
	PEPROCESS dbgProcessStruct, p_save_handlentry phead);
p_save_handlentry QueryList(p_save_handlentry phead, HANDLE dbgProcessId, PEPROCESS dbgProcessStruct);
void DeleteList(p_save_handlentry pclid);