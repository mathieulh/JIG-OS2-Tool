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

	int read2 = read(fd, buf, size);
	close(fd);

	return read2;
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
    printf("%02hhX%c", ((unsigned char *)data)[i], (i + 1) % 16 ? ' ' : '\n');
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

int decrypt_psar(u8* pbIn, u8* out, u32 size, u32 tag)
{
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
    pl[0] = 5; // mode decrypt
    pl[1] = pl[2] = 0;
    pl[3] = pti->code; // initial seed for PRX
    pl[4] = 0x70; 
	
	
	//hexDump(bpartial, 0x84);
	int ret = sceUtilsBufferCopyWithRange(bpartial, 20+0x70, bpartial, 20+0x70, 7);
	//hexDump(bpartial, 0x84);
	
	
	if (ret != 0)
	{
		printf("Error in sceUtilsBufferCopyWithRange 0x7 %08x.\n", ret);
		return -1;
	}else{
		//printf("got past kirk 7\n");
	}
	
	for (iXOR = 0; iXOR < 0x70; iXOR++)
		bpartial[iXOR] = bpartial[iXOR] ^ pti->key[0x20+iXOR];
	
	//hexDump(bpartial, 0x84);
	
	
	u8 total[0x70+0x20+0x80+(size-0x150)];
	memcpy(total,bpartial,0x70);
	memcpy(total+0x70,b20,0x20);
	memcpy(total+0x90,b00,0x80);
	memcpy(total+0x110,pbIn+0x150,size-0x150);
	int out_size = *(u32 *)(total+0x70);
	
	
	//hexDump(total, 0x200);
	ret = sceUtilsBufferCopyWithRange(total, size, total, size, 0x1);
	
	
	
	if (ret != 0)
	{
		printf("Error in sceUtilsBufferCopyWithRange 0x1 %08x.\n", ret);
		return -1;
	}
	
	
	
	memcpy(out,total,size-0x150);
	
	
	

	return out_size;
}

int encrypt_psar(u8* pbIn, u8* out, u32 size, u32 tag)
{
	int ret, ret1, i;
	
	unsigned int kirk1_data_size;
	
//KIRK1	
	if(size % 0x10 == 0){
		kirk1_data_size =  size;
	}else{
		kirk1_data_size = 0x10 - (size % 0x10) + size;
	}
	
	ret = kirk1_data_size + 0x150;
	memcpy(out, pbIn, ret);

	u8 Padding[] = 
	{
		0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00
	};
	
	u8 PlainText[] = 
	{
		0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
		0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
		0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
		0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
	};
//600
	
	u8 Kirk1Keys[] = 
	{
		0x27, 0xB9, 0x03, 0xA1, 0xF4, 0x70, 0xFD, 0x1E, 0x48, 0xC3, 0x7D, 0xE2, 0x72, 0xC2, 0x31, 0x47,
		0x5D, 0xCC, 0x12, 0x46, 0x56, 0x84, 0xFB, 0xDE, 0x0E, 0xC3, 0x49, 0x50, 0xFB, 0xEE, 0x95, 0x22
	};
	
//500
/*
	u8 Kirk1Keys[] = 
	{
		0xB4, 0x98, 0x38, 0xBB, 0x56, 0x3D, 0xB9, 0xE0, 0xF6, 0x56, 0xE8, 0x9B, 0xBA, 0x8C, 0x96, 0xA2,
		0xDF, 0x72, 0x75, 0xB7, 0xD4, 0x34, 0x95, 0x95, 0xC1, 0x9B, 0x04, 0x9B, 0x76, 0xBB, 0x88, 0x2A
	};
*/
	unsigned int kirk1_blob_offset = 0x40;
	unsigned int kirk1_header_size = 0x90;
	unsigned int kirk1_predata_offset = kirk1_blob_offset + kirk1_header_size;
	unsigned int kirk1_predata_size = 0x80;
	unsigned int kirk1_blob_size = kirk1_header_size + kirk1_data_size + kirk1_predata_size;
	
//	ret = kirk_CMD14(out + kirk1_blob_offset, 0x20); //keys
//	if (ret != 0) return ret;
	memcpy(out + kirk1_blob_offset, Kirk1Keys, 0x20); //fixed keys
	*(unsigned int *)(out + kirk1_blob_offset + 0x60) = 1; //cmd
	*(unsigned int *)(out + kirk1_blob_offset + 0x70) = size; //data size
	*(unsigned int *)(out + kirk1_blob_offset + 0x74) = 0x80; //predata size
	memcpy(out + kirk1_predata_offset, PlainText, 0x40); //predata1 0x40
	memcpy(out + kirk1_predata_offset + 0x40, PlainText, 0x14); //predata2 0x14
	memcpy(out + kirk1_predata_offset + 0x40 + 0x14, PlainText, 0x14); //predata3 0x14
	memcpy(out + kirk1_predata_offset + 0x40 + 0x14 + 0x14, PlainText, 8); //predata4 0x8
	memcpy(out + kirk1_predata_offset + 0x40 + 0x14 + 0x14 + 8, PlainText, 8); //predata5 0x8
	memcpy(out + kirk1_predata_offset + 0x40 + 0x14 + 0x14 + 8 + 8, PlainText, 8); //predata6 0x8
	memcpy(out + kirk1_blob_offset + kirk1_header_size + size + kirk1_predata_size, Padding, kirk1_data_size - size); //padding
	
	ret1 =  kirk_CMD0(out + kirk1_blob_offset, out + kirk1_blob_offset, kirk1_blob_size, 0);
	if (ret1 != 0) return ret1;
	
//KIRK7
	u8 kirk7_buf[0x70+0x14];
	memset(kirk7_buf, 0, 0x70 + 0x14);
	memcpy(kirk7_buf + 0x14, out + kirk1_blob_offset, 0x70);
	
	TAG_INFO const* pti = GetTagInfo(tag);
    if (!pti)
	{
		printf("Unknown tag 0x%08X.\n", tag);
		return -1;
	}
	
	int iXOR;
	for (iXOR = 0; iXOR < 0x70; iXOR++)
		kirk7_buf[iXOR+0x14] = kirk7_buf[iXOR+0x14] ^ pti->key[0x20+iXOR];
	
	u32* pl = (u32*)(kirk7_buf);
    pl[0] = 4; // mode encrypt
    pl[1] = pl[2] = 0;
    pl[3] = pti->code; // initial seed for PRX
    pl[4] = 0x70;
	
	u8* kirk7_buf2 = (u8*) malloc (0x70+20);
	
	ret1 = kirk_CMD4(kirk7_buf2, kirk7_buf, 0x70+20);
	if (ret1 != 0) return ret1;
	
	for (iXOR = 0; iXOR < 0x70; iXOR++)
        kirk7_buf2[iXOR+0x14] = kirk7_buf2[iXOR+0x14] ^ pti->key[0x14+iXOR];
	
	//hexDump(kirk7_buf, 0x70+0x14);

	
	u8 *bufh = (u8*) malloc(0x14C+4);
	u8 *vanity = (u8*) malloc(0x28);
	
	*((u32 *)bufh) = 0x014C;
	
	int size2 = ReadFile("vanity.bin", vanity, 0x28);
	if (size2 < 0)
	{
		printf("Cannot read vanity.bin.\n");
		return -1;
	}



	//hexDump(pti->key, 0x90);
	
	memcpy(bufh+4,pti->key,0x14);
	memcpy(bufh+0x18,vanity,0x28);
	memcpy(bufh+0x40,kirk7_buf2 + 0x14,0x40);
	memcpy(bufh+0x80,kirk7_buf2 + 0x14 + 0x40,0x30);
	memcpy(bufh+0xB0,out + 0xB0, 0x20);
	memcpy(bufh+0xD0,out + 0xD0, 0x80);
	
	if (sceUtilsBufferCopyWithRange(bufh, 0x150, bufh, 0x150, 0x0B) != 0)
	{
		printf("Error in sceUtilsBufferCopyWithRange 0xB.\n");
		return -7;
	}

//final stage
	memcpy(out, out + 0xD0, 0x80);
	memcpy(out + 0x80, kirk7_buf2 + 0x14 + 0x40, 0x30);
	memset(out + 0xD0, 0, 0x40);
	*(unsigned int *)(out + 0xD0) = tag; //tag
	memcpy(out+0xD4,bufh,0x14);
	memcpy(out+0xE8,vanity,0x28);
	
	
	memcpy(out + 0x110, kirk7_buf2 + 0x14, 0x40);

	
	return ret;
}

uint32_t Demangle(const u8* pIn, u8* pOut, u32 size)
{
	int i;
	u8 buffer150[0x20];
	memcpy(buffer150,pIn+0x150,0x20);
	u8 buf[20+0x150];
	/*
	0x17, 0xC8, 0xE8, 0xC8, 0x3D, 0x5B, 0xE2, 0x61, 0x97, 0xAC, 0x84, 0x6D, 0x56, 0xD3, 0xF4, 0xF7
	0xF0, 0xE1, 0x5F, 0x96, 0x4F, 0x33, 0x70, 0xBE, 0x0B, 0xA1, 0xE8, 0x55, 0x4C, 0x65, 0x8D, 0xE3
	*/
	u8 K2[16] = {0x17, 0xC8, 0xE8, 0xC8, 0x3D, 0x5B, 0xE2, 0x61, 0x97, 0xAC, 0x84, 0x6D, 0x56, 0xD3, 0xF4, 0xF7};
	u8 K1[16] = {0xF0, 0xE1, 0x5F, 0x96, 0x4F, 0x33, 0x70, 0xBE, 0x0B, 0xA1, 0xE8, 0x55, 0x4C, 0x65, 0x8D, 0xE3};
	memcpy(buf+20, pIn, 0x150);
	
		
	for ( i = 0; i < 0x150; ++i ) { buf[20+i] ^= K1[i & 0xF]; }
	//hexDump(buf,0x150+20);
	
	u32* pl = (u32*)buf; // first 20 bytes
	pl[0] = 5;
	pl[1] = pl[2] = 0;
	pl[3] = 0x58;
	pl[4] = 0x150;
	
    int ret = sceUtilsBufferCopyWithRange(pOut, 20+0x150, buf, 20+0x150, 0x7);
	
	//hexDump(pOut,0x150);
	
	//printf("%08X\n",ret);
	for ( i = 0; i < 0x150; ++i ) { pOut[i] ^= K2[i & 0xF]; }
	
	//hexDump(pOut,0x150);
	
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

uint32_t Mangle(const u8* pIn, u8* pOut, u32 size)
{
	int i;
	
	u8 K2[16] = {0x17, 0xC8, 0xE8, 0xC8, 0x3D, 0x5B, 0xE2, 0x61, 0x97, 0xAC, 0x84, 0x6D, 0x56, 0xD3, 0xF4, 0xF7};
	u8 K1[16] = {0xF0, 0xE1, 0x5F, 0x96, 0x4F, 0x33, 0x70, 0xBE, 0x0B, 0xA1, 0xE8, 0x55, 0x4C, 0x65, 0x8D, 0xE3};
	
	u8 *buffer150 = (u8*) malloc(0x150);
	memcpy(buffer150,pIn+0x110,0x40);
	memcpy(buffer150+0x40,pIn+0,0x110);
	
	for ( i = 0; i < 0x150; ++i ) { buffer150[i] ^= K2[i & 0xF]; }
	
	u8 *buf = (u8*) malloc(20+0x150);
	
	u32* pl = (u32*)buf; // first 20 bytes
	pl[0] = 4;
	pl[1] = pl[2] = 0;
	pl[3] = 0x58;
	pl[4] = 0x150;
	
	memcpy(buf+20,buffer150,0x150);
	
    int ret = sceUtilsBufferCopyWithRange(buf, 20+0x150, buf, 20+0x150, 0x4);
	
	for ( i = 0; i < 0x150; ++i ) { buf[20+i] ^= K1[i & 0xF]; }
	
	//hexDump(buf+20,0x150);
	
	memcpy(pOut,buf+0x14,0x150);
	
	return 0;
}

int jig_decrypt(void *buf, u32 size){
	kirk_init();
	int ret = Demangle(buf, buf, size);
	ret = decrypt_psar(buf, buf, size, *(u32 *)(buf+0xD0));
	return ret;
}

int jig_encrypt(void *buf, u32 size){
	int ret1, ret2;

	kirk_init();
	ret1 = encrypt_psar(buf, buf, size, 0x6000000);
	ret2 = Mangle(buf, buf, ret1);
	if(ret2 != 0)
		return ret2;

	return ret1;
}

int main(int argc, char** argv)
{	
	int size, res;

	if(argc!=4)
	{
        printf("Usage: %s -d or %s -e in.bin out.bin \n",argv[0],argv[0]);
        return -1;
    }

	memset(buffer, 0, sizeof(buffer));
	
if (!strcmp(argv[1], "-d"))
	{
		size = ReadFile(argv[2], buffer, sizeof(buffer));
		if (size < 0)
		{
			printf("Cannot read file.\n");
			return -1;
		}
	
		res = jig_decrypt(buffer, size);
	}

if (!strcmp(argv[1], "-e"))
	{
		size = ReadFile(argv[2], (buffer + 0x150), sizeof(buffer)-0x150);
		if (size < 0)
		{
			printf("Cannot read file.\n");
			return -1;
		}
	
		res = jig_encrypt(buffer, size);
	}
	
	printf("Res = %d.\n", res);

	if (res >= 0)
	{
		WriteFile(argv[3], buffer, res);
	}	
	
	printf("Done.\n");

	return 0;
}
