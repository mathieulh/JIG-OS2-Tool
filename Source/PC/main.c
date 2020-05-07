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

// 0x49 0x06000000 OK!
u32 g_key06[] = {
  0x499E8617, 0x6F83909F, 0x388D9D19, 0xE82C3CCC, 0xC318ECEB, 0xAC7985E8,
  0x41376431, 0x29DCBDA5, 0xD5D327C7, 0xD2B3E4BD, 0x835F549D, 0xB8FD557D,
  0x4731EF1C, 0xA9E2DB95, 0xC5BF55BF, 0x40B9291E, 0xD470AF4B, 0xD44D096A,
  0xA9EBDF7B, 0xECD1D3E8, 0xD50EDB47, 0x8502CE1F, 0x8E87A3E5, 0x21D20C8A,
  0x0C4BB1D6, 0x342DD7B8, 0xBD1A3231, 0xF32BB408, 0x66CFDFD1, 0x367F9951,
  0xEBD037A9, 0x0DADBAA1, 0x2701FFE2, 0x8844AE3F, 0x8D1ACA23, 0x32049549,
};

// 0x51 0x0E000000 OK!
u32 g_key0E[] = {
  0x95FF0CA0, 0x7ED02497, 0x3163071F, 0x6E26FBC0, 0xF9CC9C87, 0xA69D3ED2,
  0xF004C647, 0x0156A37F, 0x9F3D338B, 0x75E41C30, 0xE6BE144B, 0x35F6355B,
  0x81662E13, 0xDB6695B5, 0xCBBD0916, 0xABA4909A, 0x921FF555, 0x8904E655,
  0x64E60EC3, 0x8537997C, 0xFF785ED3, 0x0F77D11C, 0x47E1E82D, 0x7A346190,
  0xD56FC4E6, 0xE9AB0EE4, 0x2F2EA61E, 0x74387C37, 0x735397DB, 0x594CB6DB,
  0x5324753B, 0x0D88768C, 0xE32C2B41, 0x1E94EEBA, 0x175DCF73, 0x1A14F0B6,
};

typedef struct
{
    u32 tag;      // 4 byte value at offset 0xD0 in the PRX file
    u8* key;      // "step1_result" use for XOR step
    u8 code;      // Code for scramble
    u8 codeExtra; // Extra code for ExtraV2Mangle
} TAG_INFO;


// tags and corresponding keys & scramble codes
static const TAG_INFO g_tagInfo[] =
{
    { 0x06000000, (u8*)g_key06, 0x49 }, //1.50 PSAR
    { 0x0E000000, (u8*)g_key0E, 0x51 }, //1.50 PSAR
};

static TAG_INFO const* GetTagInfo(u32 tagFind)
{
    int iTag;
    for (iTag = 0; iTag < sizeof(g_tagInfo)/sizeof(TAG_INFO); iTag++)
        if (g_tagInfo[iTag].tag == tagFind)
            return &g_tagInfo[iTag];
    return NULL; // not found
}

int decrypt_psar(u8* pbIn, u8* out, u32 size, u32 tag){
	TAG_INFO const* pti = GetTagInfo(tag);
    if (!pti)
	{
		printf("Unknown tag 0x%08X.\n", tag);
		return -1;
	}
	
	
	
	u8 bD0[0x80];
	u8 b80[0x50];
	u8 b00[0x80];//elf_info
	u8 b20[0x20];//meta from b0 to d0
	u8 btotal[0x80+0x50+0x80];
	memcpy(b20, pbIn+0xB0, 0x20);
	memcpy(bD0, pbIn+0xD0, 0x80);
	memcpy(b80, pbIn+0x80, 0x50);
	memcpy(b00, pbIn+0x00, 0x80);
	memcpy(btotal, bD0, 0x80);
	memcpy(btotal+0x80, b80, 0x50);
	memcpy(btotal+0x80+0x50, b00, 0x80);
	
	u8 bpartial[0x70+20];
	memcpy(bpartial+20,btotal+0x40,0x70);
	
	int iXOR;
    for (iXOR = 0; iXOR < 0x70; iXOR++)
        bpartial[20+iXOR] = bpartial[20+iXOR] ^ pti->key[0x14+iXOR];
	
	u32* pl = (u32*)(bpartial);
    pl[0] = 5; // number of ulongs in the header
    pl[1] = pl[2] = 0;
    pl[3] = pti->code; // initial seed for PRX
    pl[4] = 0x70; 
	
	
	
	int ret = sceUtilsBufferCopyWithRange(bpartial, 20+0x70, bpartial, 20+0x70, 7);
	
	
	
	if (ret != 0)
	{
		printf("Error in sceUtilsBufferCopyWithRange 0x7 %08x.\n", ret);
		return -1;
	}else{
		//printf("got past kirk 7\n");
	}
	
	for (iXOR = 0; iXOR < 0x70; iXOR++)
		bpartial[iXOR] = bpartial[iXOR] ^ pti->key[0x20+iXOR];
	
	
	
	
	u8 total[0x70+0x20+0x80+(size-0x150)];
	memcpy(total,bpartial,0x70);
	memcpy(total+0x70,b20,0x20);
	memcpy(total+0x90,b00,0x80);
	memcpy(total+0x110,pbIn+0x150,size-0x150);
	
	
	
	
	ret = sceUtilsBufferCopyWithRange(total, size, total, size, 0x1);
	
	
	
	if (ret != 0)
	{
		printf("Error in sceUtilsBufferCopyWithRange 0x1 %08x.\n", ret);
		return -1;
	}
	
	
	
	memcpy(out,total,size-0x150);
	
	
	
	
	
	return size-0x150;
}

uint32_t Demangle(const u8* pIn, u8* pOut, u32 size)
{
	int i;
	u8 buffer150[0x20];
	memcpy(buffer150,pIn+0x150,0x20);
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
	
	u8 buffer0[0x40];
	memcpy(buffer0,pOut,0x40);
	
	u8 retbuf[size];
	memcpy(retbuf,pOut+0x40,0x110);
	memcpy(retbuf+0x110,buffer0,0x40);
	memcpy(retbuf+0x150,buffer150,0x20);
	memcpy(retbuf+0x170,pIn+0x170,size-0x170);
	memcpy(pOut,retbuf,size);
	
	return 0;
}


int jig_decrypt(void *buf, u32 size){
	kirk_init();
	int ret = Demangle(buf, buf, size);
	ret = decrypt_psar(buf,buf,size,*(u32 *)&buf[0xD0]);
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
		WriteFile(argv[2], buffer, res);
	}	
	
	printf("Done.\n");

	return 0;
}
