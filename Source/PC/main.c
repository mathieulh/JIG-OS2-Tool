#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <malloc.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <kirk_engine.h>


uint8_t buffer[10000000] __attribute__((aligned(64)));
uint32_t outsize;

int ReadFile(char *file, void *buf, int size)
{
	int fd = open(file, O_RDONLY, 0);
	if (fd < 0)
		return fd;

	int myread = read(fd, buf, size);
	close(fd);

	return myread;
}

int WriteFile(char *file, void *buf, int size)
{
	int fd = open(file, O_WRONLY | O_CREAT | O_TRUNC, 0777);
	if (fd < 0)
		return fd;

	int written = write(fd, buf, size);
	close(fd);

	return written;
}

void hexDump(const void *data, size_t size) {
  size_t i;
  for (i = 0; i < size; i++) {
    printf("%02hhX%c", ((char *)data)[i], (i + 1) % 16 ? ' ' : '\n');
  }
  printf("\n");
}

uint32_t Demangle(const u8* pIn, u8* pOut)
{
	int i;
	u8 buffer[20+0x150];
	/*
	0x17, 0xC8, 0xE8, 0xC8, 0x3D, 0x5B, 0xE2, 0x61, 0x97, 0xAC, 0x84, 0x6D, 0x56, 0xD3, 0xF4, 0xF7
	0xF0, 0xE1, 0x5F, 0x96, 0x4F, 0x33, 0x70, 0xBE, 0x0B, 0xA1, 0xE8, 0x55, 0x4C, 0x65, 0x8D, 0xE3
	*/
	u8 K2[16] = {0x17, 0xC8, 0xE8, 0xC8, 0x3D, 0x5B, 0xE2, 0x61, 0x97, 0xAC, 0x84, 0x6D, 0x56, 0xD3, 0xF4, 0xF7};
	u8 K1[16] = {0xF0, 0xE1, 0x5F, 0x96, 0x4F, 0x33, 0x70, 0xBE, 0x0B, 0xA1, 0xE8, 0x55, 0x4C, 0x65, 0x8D, 0xE3};
	memcpy(buffer+20, pIn, 0x150);
	
		
	for ( i = 0; i < 0x150; ++i ) { buffer[20+i] ^= K1[i & 0xF]; }
	u32* pl = (u32*)buffer; // first 20 bytes
	pl[0] = 5;
	pl[1] = pl[2] = 0;
	pl[3] = 0x58;
	pl[4] = 0x150;
	
    int ret = sceUtilsBufferCopyWithRange(pOut, 20+0x150, buffer, 20+0x150, 0x7);
	
	//printf("%08X\n",ret);
	for ( i = 0; i < 0x150; ++i ) { pOut[i] ^= K2[i & 0xF]; }
	
	return 0;
}


int jig_decrypt(void *buf, u32 size){
	kirk_init();
	int ret = Demangle(buf, buf);
	return ret;
}

int main(int argc, char** argv)
{	
	
	if(argc != 3){
		printf("Usage: decrypt_sp os2.bin os2_out.bin\n");
		return -1;
	}
	
	u32 size = ReadFile(argv[1], buffer, sizeof(buffer));
	if (size <= 0)
	{
		printf("Cannot read file.\n");
		return -1;
	}

	
	
	int res = jig_decrypt(buffer, size);

	printf("Res = %d.\n", res);

	if (res >= 0)
	{
		WriteFile(argv[2], buffer + 0x40, size - 0x40);
	}	
	
	printf("Done.\n");

	return 0;
}
