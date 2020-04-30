#include <pspsdk.h>
#include <pspkernel.h>
#include <psputilsforkernel.h>
#include <pspctrl.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <malloc.h>

PSP_MODULE_INFO("DecryptSP", 0x1000, 1, 0);
PSP_MAIN_THREAD_ATTR(0);

#define printf pspDebugScreenPrintf

u8 buffer[10000000] __attribute__((aligned(64)));
u32 outsize;


void ErrorExit(int milisecs, char *fmt, ...)
{
	va_list list;
	char msg[256];	

	va_start(list, fmt);
	vsprintf(msg, fmt, list);
	va_end(list);

	printf(msg);

	sceKernelDelayThread(milisecs*1000);
	sceKernelExitGame();
}

int ReadFile(char *file, void *buf, int size)
{
	SceUID fd = sceIoOpen(file, PSP_O_RDONLY, 0);
	if (fd < 0)
		return fd;

	int read = sceIoRead(fd, buf, size);
	sceIoClose(fd);

	return read;
}

int WriteFile(char *file, void *buf, int size)
{
	SceUID fd = sceIoOpen(file, PSP_O_WRONLY | PSP_O_CREAT | PSP_O_TRUNC, 0777);
	if (fd < 0)
		return fd;

	int written = sceIoWrite(fd, buf, size);
	sceIoClose(fd);

	return written;
}


u32 FindProc(const char* szMod, const char* szLib, u32 nid)
{
	struct SceLibraryEntryTable *entry;
	SceModule *pMod;
	void *entTab;
	int entLen;

	pMod = sceKernelFindModuleByName(szMod);

	if (!pMod)
	{
		printf("Cannot find module %s\n", szMod);
		return 0;
	}
	
	int i = 0;

	entTab = pMod->ent_top;
	entLen = pMod->ent_size;
	//***printf("entTab %p - entLen %d\n", entTab, entLen);
	while(i < entLen)
    {
		int count;
		int total;
		unsigned int *vars;

		entry = (struct SceLibraryEntryTable *) (entTab + i);

        if(entry->libname && !strcmp(entry->libname, szLib))
		{
			total = entry->stubcount + entry->vstubcount;
			vars = entry->entrytable;

			if(entry->stubcount > 0)
			{
				for(count = 0; count < entry->stubcount; count++)
				{
					if (vars[count] == nid)
						return vars[count+total];					
				}
			}
		}

		i += (entry->len * 4);
	}

	printf("Funtion not found.\n");
	return 0;
}

int (* jig_decrypt)(void *buf, int size, int *retSize);



int main()
{	
	pspDebugScreenInit();

	SceUID mod = pspSdkLoadStartModule("jigkick_bridge.prx", PSP_MEMORY_PARTITION_KERNEL);
	if (mod < 0)
	{
		ErrorExit(5000, "Error load/start module.\n");
	}

	printf("Module loaded.\n");

	jig_decrypt = (void *)FindProc("sceJigKick_Bridge", "sceJigKickBridge", 0xDE481572);

	if (jig_decrypt == NULL)
		ErrorExit(5000, "Cannot find func.\n");

	int size = ReadFile("ms0:/jig.bin", buffer, sizeof(buffer));
	if (size <= 0)
	{
		ErrorExit(5000, "Cannot read file.\n");
	}

	int res = jig_decrypt(buffer, size, &outsize);

	printf("Res = %d.\n", res);

	if (res >= 0)
	{
		WriteFile("ms0:/jig_dec.bin", buffer, outsize);

		SceUID mod = pspSdkLoadStartModule("scons.prx", PSP_MEMORY_PARTITION_KERNEL);

		printf("Result %08X.\n", mod);

		mod = pspSdkLoadStartModule("ms0:/jig_dec.bin", PSP_MEMORY_PARTITION_USER);
		printf("Res = %08X.\n", mod);
	}

	sceKernelSleepThread();	
	

	ErrorExit(10000, "Done.\n");

	return 0;
}
