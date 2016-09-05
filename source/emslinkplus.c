#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>

#include <libusb-1.0/libusb.h>
#include <openssl/sha.h>

/*
Protocol:
Every command sent to the device via bulk transfer is a total of 0xa bytes. Some commands require a seperate bulk transfer to be sent to the device, right after sending the command header. The format of replies is arbitary.

+0 u8 is the commandID to the device, and +1 u8 is always 0xa5. The rest of the command is the command arguments.

Commands labled here as SPI interface with the savegame SPI, while ones labeled as CARD interface with the ROM hardware.
All SPI commands appear to have the same arguments format, and all CARD commands appear to have the same arguments format.

CARD arguments:
The 8-byte arguments seems to be sent directly to the gamecard bus, where the first u8 argument is the gamecard cmdID. Normally however, the adapter has all of the arguments after the cmdID set to zero.

SPI arguments:
arg+0 is zero, +1 AD3, +2 AD2, +3 AD1, and the 1st cmd byte for the cmdID is determined by the device firmware from the device commandID. AD3 is the low 8-bits, AD2 the next 8-bits, etc. The address is in units of sectors, where each sector is 0x100-bytes. AD3-AD1 are all-zero for non-read/write commands.
u8 arg+4 is always 0x02.
u8 arg+5 is 0x03, orred with 0xa0 for 3DS gamecards.
The last two bytes of the arguments seem to be all-zero.

CARD commands:
Each commandID also matches the gamecard cmdID it's normally used with, however arbitary gamecard commands can be used with each device command.

0x9f: This sends the gamecard cmd, and doesn't read any data from the gamecard. This is normally used for gamecard reset with gamecard cmdID 0x9f.

0x90: This sends the gamecard cmd, and reads 4-bytes from the gamecard. This is normally used for reading the CardID via gamecard cmdID 0x90.

0x00: This sends the gamecard, and reads 0x200-bytes from the gamecard. This is normally used for reading the header via gamecard cmdID 0x00.

SPI commands:
0x9c: Reads the FlashID, the actual FlashID in the read 8-bytes is the 3-bytes located at +2. The rest of the recvbuf is unknown.

0x2c: Reads a 0x200-byte block.

0x7b: Writes a 0x100-byte block.

0x5e: Begin writing a 0x10000-byte chunk, only used for 3DS gamecards.
*/

libusb_device_handle *devh;

void hexdump(void *ptr, int buflen)
{
	unsigned char *buf = (unsigned char*)ptr;
	int i, j;

	for (i=0; i<buflen; i+=16)
	{
		printf("%06x: ", i);
		for (j=0; j<16; j++)
		{ 
			if (i+j < buflen)
			{
				printf("%02x ", buf[i+j]);
			}
			else
			{
				printf("   ");
			}
		}

		printf(" ");

		for (j=0; j<16; j++) 
		{
			if (i+j < buflen)
			{
				printf("%c", (buf[i+j] >= 0x20 && buf[i+j] <= 0x7e) ? buf[i+j] : '.');
			}
		}
		printf("\n");
	}
}

void sha256(void* buf, size_t size, uint8_t* result) {
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, buf, size);
	SHA256_Final(result, &ctx);
}

int transferusb_data(unsigned int endpoint, unsigned char *buffer, unsigned int bufsz)
{
	int ret = 0;
	int total_transferred = 0;

	while(bufsz>0)
	{
		ret = libusb_bulk_transfer(devh, endpoint, buffer, bufsz, &total_transferred, 1000);
		if(ret == LIBUSB_ERROR_TIMEOUT && total_transferred>0)
		{
			buffer+= total_transferred;
			bufsz-= total_transferred;
		}
		else if(ret < 0 || total_transferred != bufsz)
		{
			printf("libusb_bulk_transfer failed: %d, transferred 0x%x of 0x%x bytes.\n", ret, total_transferred, bufsz);
			return ret;
		}

		if(total_transferred == bufsz)bufsz = 0;
	}	

	return 0;
}

int send_cmd(unsigned char *cmdbuf, unsigned int cmdsize, unsigned char *cmdpayload, unsigned int cmdpayload_size, unsigned char *recvbuf, unsigned int recvsize)
{
	int ret = 0;
	struct timespec delay;

	delay.tv_sec = 0;
	delay.tv_nsec = 100000;//1000000;

	ret = transferusb_data(0x02, cmdbuf, cmdsize);
	if(ret < 0)return ret;

	if(cmdpayload)
	{
		ret = transferusb_data(0x02, cmdpayload, cmdpayload_size);
		if(ret < 0)return ret;
	}

	//sleep(1);
	nanosleep(&delay, NULL);

	if(recvbuf == NULL)return 0;

	ret = transferusb_data(0x81, recvbuf, recvsize);
	if(ret < 0)return ret;

	return 0;
}

int get_flashid(unsigned int *flashid)
{
	int i;
	int ret = 0;
	unsigned char cmdbuf[0xa];
	unsigned char recvbuf[0x8];

	memset(cmdbuf, 0, 0xa);
	memset(recvbuf, 0x0, 0x8);

	cmdbuf[0] = 0x9c;
	cmdbuf[1] = 0xa5;
	cmdbuf[6] = 0x02;

	ret = send_cmd(cmdbuf, 0xa, NULL, 0, recvbuf, 0x8);
	if(ret < 0)return ret;

	printf("FlashID CMD reply:\n");
	for(i = 0; i < 0x8; i++)printf("%02x ", recvbuf[i]);
	printf("\n");

	if(recvbuf[0] == 0xff && recvbuf[1] == 0xff)
	{
		printf("Gamecard isn't inserted.\n");
		return -105;
	}

	*flashid = (recvbuf[2]<<16) | (recvbuf[3]<<8) | (recvbuf[4]);

	return 0;
}

int cmd_test()
{
	int i, cmdi;
	int ret = 0;
	unsigned char cmdbuf[2 + 16];
	unsigned char cmd[8] = {0x71, 0xC9, 0x3F, 0xE9, 0xBB, 0x0A, 0x3B, 0x18};
	unsigned char cmd2[8] = {0xF3, 0x2C, 0x92, 0xD8, 0x5C, 0x9D, 0x44};
	unsigned char cmd3[8] = {0x17, 0x8E, 0x42, 0x7C, 0x22, 0xD8, 0x7A};
	unsigned char recvbuf[0x200];

	memset(cmdbuf, 0, 2 + 16);
	memset(recvbuf, 0x0, 0x200);

	cmdbuf[0] = 0x9f;
	cmdbuf[1] = 0xa5;
	cmdbuf[2] = 0x9f;

	ret = send_cmd(cmdbuf, 0xa, NULL, 0x0, NULL, 0x0);
	if(ret < 0)return ret;

	/*cmdbuf[0] = 0x00;
	cmdbuf[1] = 0xa5;
	memcpy(&cmdbuf[2], cmd, 8);

	ret = send_cmd(cmdbuf, 0xa, NULL, 0x0, recvbuf, 0x200);
	if(ret < 0)return ret;*/

	sleep(1);
	/*printf("unk cmd reply: ");
	for(i=0; i<0x200; i++)printf("%02x", recvbuf[i]);
	printf("\n");*/

	/*memset(cmdbuf, 0, 2 + 16);
	cmdbuf[0] = 0x90;
	cmdbuf[1] = 0xa5;
	cmdbuf[2] = 0x90;

	ret = send_cmd(cmdbuf, 0xa, NULL, 0x0, recvbuf, 0x4);
	if(ret < 0)return ret;

	printf("CardID CMD reply:\n");
	for(i = 0; i < 0x4; i++)printf("%02x ", recvbuf[i]);
	printf("\n");*/

	/*cmdbuf[0] = 0x90;
	cmdbuf[1] = 0xa5;
	cmdbuf[2] = 0x90;

	ret = send_cmd(cmdbuf, 0xa, NULL, 0x0, recvbuf, 0x4);
	if(ret < 0)return ret;*/

	/*cmdbuf[0] = 0x90;
	cmdbuf[1] = 0xa5;
	cmdbuf[2] = 0x90;

	ret = send_cmd(cmdbuf, 0xa, NULL, 0x0, recvbuf, 0x4);
	if(ret < 0)return ret;*/

	/*cmdbuf[0] = 0x90;
	cmdbuf[1] = 0xa5;
	cmdbuf[2] = 0xa0;

	ret = send_cmd(cmdbuf, 0xa, NULL, 0x0, recvbuf, 0x4);
	if(ret < 0)return ret;

	printf("CardID2 CMD reply:\n");
	for(i = 0; i < 0x4; i++)printf("%02x ", recvbuf[i]);
	printf("\n");*/

	cmdbuf[0] = 0x00;
	cmdbuf[1] = 0xa5;
	cmdbuf[2] = 0x3e;

	ret = send_cmd(cmdbuf, 0xa, NULL, 0x0, recvbuf, 0x200);
	if(ret < 0)return ret;

	printf("3e reply: ");
	for(i=0; i<0x200; i++)printf("%02x", recvbuf[i]);
	printf("\n");

	cmdbuf[0] = 0x00;
	cmdbuf[1] = 0xa5;
	cmdbuf[2] = 0x82;

	ret = send_cmd(cmdbuf, 2 + 8, NULL, 0, recvbuf, 0x200);
	if(ret < 0)return ret;

	printf("cmd 82 reply: ");
	for(i=0; i<0x200; i++)printf("%02x", recvbuf[i]);
	printf("\n");

	sleep(1);

	cmdbuf[0] = 0x00;
	cmdbuf[1] = 0xa5;
	cmdbuf[2] = 0x00;
	//memcpy(&cmdbuf[2], cmd3, 8);

	for(cmdi=16; cmdi<256; cmdi++)
	{
	cmdbuf[2] = cmdi;
	if(cmdi==0x9f)continue;
	ret = send_cmd(cmdbuf, 2 + 8, NULL, 0, recvbuf, 0x200);
	if(ret < 0)return ret;

	printf("cmd %x reply: ", cmdi);
	for(i=0; i<0x200; i++)printf("%02x", recvbuf[i]);
	printf("\n");
	}

	/*for(cmdi=0; cmdi<256; cmdi++)
	{
	cmdbuf[2] = 0xb2;
	if(cmdi==0x9f)continue;
	ret = send_cmd(cmdbuf, 2 + 8, NULL, 0, recvbuf, 0x200);
	if(ret < 0)return ret;

	printf("cmd2 %x reply: ", cmdi);
	for(i=0; i<0x200; i++)printf("%02x", recvbuf[i]);
	printf("\n");
	}*/

	return 0;
}

int get_cardid(unsigned int *cardid)
{
	int i;
	int ret = 0;
	unsigned char cmdbuf[0xa];
	unsigned char recvbuf[0x4];

	memset(cmdbuf, 0, 0xa);
	memset(recvbuf, 0x0, 0x4);

	cmdbuf[0] = 0x9f;
	cmdbuf[1] = 0xa5;
	cmdbuf[2] = 0x9f;

	ret = send_cmd(cmdbuf, 0xa, NULL, 0x0, NULL, 0x0);
	if(ret < 0)return ret;

	sleep(1);

	cmdbuf[0] = 0x90;
	cmdbuf[1] = 0xa5;
	cmdbuf[2] = 0x90;

	ret = send_cmd(cmdbuf, 0xa, NULL, 0x0, recvbuf, 0x4);
	if(ret < 0)return ret;

	printf("CardID CMD reply:\n");
	for(i = 0; i < 0x4; i++)printf("%02x ", recvbuf[i]);
	printf("\n");

	*cardid = (recvbuf[0]) | (recvbuf[1]<<8) | (recvbuf[2]<<16) | (recvbuf[3]<<24);

	cmdbuf[0] = 0x90;
	cmdbuf[1] = 0xa5;
	cmdbuf[2] = 0xa0;

	ret = send_cmd(cmdbuf, 0xa, NULL, 0x0, recvbuf, 0x4);
	if(ret < 0)return ret;

	printf("CardID2 CMD reply:\n");
	for(i = 0; i < 0x4; i++)printf("%02x ", recvbuf[i]);
	printf("\n");

	return 0;
}

int get_header(unsigned char *header)
{
	int ret = 0;
	unsigned char cmdbuf[0xa];
	char gametitle[13];

	memset(cmdbuf, 0, 0xa);
	memset(gametitle, 0, 13);

	cmdbuf[1] = 0xa5;

	ret = send_cmd(cmdbuf, 0xa, NULL, 0, header, 0x200);
	if(ret < 0)return ret;

	if(header[0]==0xFF)return 0;

	memcpy(gametitle, header, 12);
	printf("NDS header game title: %s\n", gametitle);

	return 0;
}

int read_savblock(int cardtype, unsigned int sector, unsigned char *block)
{
	int i;
	int ret = 0;
	unsigned char cmdbuf[0xa];
	struct timespec delay;

	memset(cmdbuf, 0, 0xa);

	cmdbuf[0] = 0x2c;
	cmdbuf[1] = 0xa5;

	cmdbuf[3] = sector & 0xff;
	cmdbuf[4] = sector >> 8;
	cmdbuf[5] = sector >> 16;
	cmdbuf[6] = 0x02;
	cmdbuf[7] = 0x03;
	if(cardtype)cmdbuf[7] |= 0xa0;

	delay.tv_sec = 0;
	delay.tv_nsec = 250000;//250 milliseconds

	for(i = 0; i < 5; i++)
	{
		ret = send_cmd(cmdbuf, 0xa, NULL, 0, block, 0x200);
		if(ret == 0)break;

		nanosleep(&delay, NULL);
	}

	nanosleep(&delay, NULL);

	return ret;
}

int write_savblock(int cardtype, unsigned int sector, unsigned char *block)
{
	int i;
	int ret = 0;
	unsigned char cmdbuf[0xa];
	struct timespec delay;

	memset(cmdbuf, 0, 0xa);

	cmdbuf[0] = 0x7b;
	cmdbuf[1] = 0xa5;

	cmdbuf[3] = sector & 0xff;
	cmdbuf[4] = sector >> 8;
	cmdbuf[5] = sector >> 16;
	cmdbuf[6] = 0x02;
	cmdbuf[7] = 0x03;
	if(cardtype)cmdbuf[7] |= 0xa0;

	delay.tv_sec = 0;
	delay.tv_nsec = 250000;//250 milliseconds

	for(i = 0; i < 5; i++)
	{
		ret = send_cmd(cmdbuf, 0xa, block, 0x100, NULL, 0);
		if(ret == 0)break;

		nanosleep(&delay, NULL);
	}

	nanosleep(&delay, NULL);

	return ret;
}

int begin_writingblock(unsigned int sector)
{
	int ret = 0;
	unsigned char cmdbuf[0xa];

	memset(cmdbuf, 0, 0xa);

	cmdbuf[0] = 0x5e;
	cmdbuf[1] = 0xa5;

	cmdbuf[3] = sector & 0xff;
	cmdbuf[4] = sector >> 8;
	cmdbuf[5] = sector >> 16;
	cmdbuf[6] = 0x02;
	cmdbuf[7] = 0xa3;

	ret = send_cmd(cmdbuf, 0xa, NULL, 0, NULL, 0);

	return ret;
}

int read_savebuf(unsigned char *buffer, int cardtype, unsigned int savesize)
{
	int ret = 0;
	unsigned int sector = 0, total_sectors = 0;

	total_sectors = savesize >> 8;
	while(sector < total_sectors)
	{
		ret = read_savblock(cardtype, sector, &buffer[sector * 0x100]);
		if(ret < 0)
		{
			printf("Failed to read save block sector %x.\n", sector);
			free(buffer);
			return ret;
		}

		sector+=2;
	}

	return ret;
}

int read_save(char *path, int cardtype, unsigned int savesize)
{
	int ret;
	unsigned char *buffer;
	FILE *fsave;
	
	printf("Reading save...\n");

	buffer = (unsigned char*)malloc(savesize);
	if(buffer==NULL)
	{
		printf("Failed to allocate save buffer.\n");
		return -100;
	}
	memset(buffer, 0, savesize);

	ret = read_savebuf(buffer, cardtype, savesize);
	if(ret!=0)
	{
		free(buffer);
		return ret;
	}

	fsave = fopen(path, "wb");
	if(fsave)
	{
		if(fwrite(buffer, 1, savesize, fsave) != savesize)
		{
			printf("Failed to write save to input file.\n");
			fclose(fsave);
			free(buffer);
			return -101;
		}
		fclose(fsave);
	}
	else
	{
		printf("Failed to open save for writing: %s\n", path);
		free(buffer);
		return -101;
	}

	free(buffer);

	return 0;
}

int write_save(char *path, int cardtype, unsigned int savesize, int fastwrite)
{
	int ret;
	unsigned int sector = 0, total_sectors = 0;
	unsigned char *rdbuffer, *wrbuffer;
	FILE *fsave;
	struct stat savestat;
	uint8_t wrhash[0x20];
	uint8_t rdhash[0x20];
	
	printf("Writing save...\n");

	rdbuffer = (unsigned char*)malloc(savesize);
	wrbuffer = (unsigned char*)malloc(savesize);
	if(rdbuffer==NULL || wrbuffer==NULL)
	{
		printf("Failed to allocate save buffer.\n");
		free(rdbuffer);
		free(wrbuffer);
		return -100;
	}
	memset(rdbuffer, 0, savesize);
	memset(wrbuffer, 0, savesize);

	if(stat(path, &savestat)==-1)
	{
		printf("Failed to stat input save file.\n");
		free(rdbuffer);
		free(wrbuffer);
		return -101;
	}

	if(savestat.st_size != savesize)
	{
		printf("Input save file size doesn't match flash size: %x %x\n", (unsigned int)savestat.st_size, savesize);
		free(rdbuffer);
		free(wrbuffer);
		return -101;
	}

	fsave = fopen(path, "rb");
	if(fsave)
	{
		if(fread(wrbuffer, 1, savesize, fsave) != savesize)
		{
			printf("Failed to read input save file.\n");
			fclose(fsave);
			free(wrbuffer);
			free(rdbuffer);
			return -101;
		}
		fclose(fsave);
	}
	else
	{
		printf("Failed to open save for reading: %s\n", path);
		free(rdbuffer);
		free(wrbuffer);
		return -101;
	}

	if(fastwrite)
	{
		ret = read_savebuf(rdbuffer, cardtype, savesize);
		if(ret!=0)
		{
			free(rdbuffer);
			free(wrbuffer);
			return ret;
		}
	}

	total_sectors = savesize >> 8;
	while(sector < total_sectors)
	{
		if(cardtype && (sector & 0xff) == 0)
		{
			if(fastwrite)
			{
				sha256(&rdbuffer[sector * 0x100], 0x10000, rdhash);
				sha256(&wrbuffer[sector * 0x100], 0x10000, wrhash);

				if(memcmp(rdhash, wrhash, 0x20)==0)
				{
					sector+= 0x100;
					continue;
				}
			}

			ret = begin_writingblock(sector);
			if(ret < 0)
			{
				printf("Failed to begin writing block, with sector 0x%x.\n", sector);
				free(rdbuffer);
				free(wrbuffer);
				return ret;
			}
		}

		ret = write_savblock(cardtype, sector, &wrbuffer[sector * 0x100]);
		if(ret < 0)
		{
			printf("Failed to write save block sector %x.\n", sector);
			free(rdbuffer);
			free(wrbuffer);
			return ret;
		}

		sector++;
	}

	free(rdbuffer);
	free(wrbuffer);

	return 0;
}

unsigned int cardEepromGetSize(int id)//based on the libnds func
{
	int device;
	device = id & 0xffff;

	if ( ((id >> 16) & 0xff) == 0x20 ) { // ST
		switch(device) {

		case 0x4014:
			return 1024*1024;	// 8Mbit(1 meg)
			break;
		case 0x4013:
		case 0x8013: // M25PE40
			return 512*1024;	// 4Mbit(512KByte)
			break;
		case 0x2017:
			return 8*1024*1024;	// 64Mbit(8 meg)
			break;
		}
	}

	if ( ((id >> 16) & 0xff) == 0x62 ) { // Sanyo
		if (device == 0x1100)
			return 512*1024;	// 4Mbit(512KByte)
	}

	if ( ((id >> 16) & 0xff) == 0xC2 ) { // Macronix
		if (device == 0x2211)
			return 128*1024;	// 1Mbit(128KByte) - MX25L1021E
	}

	return 256*1024;	// 2Mbit(256KByte)
}

int main(int argc, char **argv)
{
	int ret = 0, argi = 2;
	unsigned int flashid = 0, cardid = 0, savesize = 0;
	unsigned int alt_savesize = 0;
	int cmdtype = 0;
	int cardtype = 0;
	int hdr_operation = 0;
	int fastwrite = 0;
	FILE *fhdr;

	unsigned char header[0x200];
	char savepath[256];
	char hdrpath[256];

	memset(header, 0, 0x200);
	memset(savepath, 0, 256);
	memset(hdrpath, 0, 256);

	if(argc==1)
	{
		printf("emslinkplus by yellows8\n");
		printf("Tool for using EMS NDS Adapter Plus via libusb.\n");
		printf("Usage:\n");
		printf("emslinkplus <command> <options>\n");
		printf("Commands:\n");
		printf("info: Retrieve info from the gamecard, this is done for all commands.\n");
		printf("read <path>: Read the gamecard savegame and write it to <path>.\n");
		printf("write <path>: Write the gamecard savegame from the savegame located at <path>.\n");
		printf("Options:\n");
		printf("--hdr=<path> Print a hexdump of the header if path isn't specified, otherwise write it to path.");
		printf("--savesize=<hex> Use the specified savesize instead of auto-detecting it via the FlashID.\n");
		printf("--fastwrite For the write savegame command, read the whole image first then only write the blocks which were modified in the input save.\n");

		return 0;
	}

	if(argv[1][0] == '-')return 0;

	if(strcmp(argv[1], "read")==0)
	{
		if(argc<3)return 0;

		cmdtype = 1;
		argi++;
		strncpy(savepath, argv[2], 255);
	}
	else if(strcmp(argv[1], "write")==0)
	{
		if(argc<3)return 0;

		cmdtype = 2;
		argi++;
		strncpy(savepath, argv[2], 255);		
	}
	else if(strcmp(argv[1], "test")==0)
	{
		cmdtype = 3;
	}
	else if(strcmp(argv[1], "info")!=0)
	{
		return 0;
	}

	while(argi < argc)
	{
		if(strncmp(argv[argi], "--hdr", 5)==0)
		{
			if(strlen(argv[argi])==5)
			{
				hdr_operation = 1;
			}
			else if(argv[argi][5] == '=')
			{
				hdr_operation = 2;
				strncpy(hdrpath, &argv[argi][6], 255);
			}
		}

		if(strncmp(argv[argi], "--savesize=", 11)==0)sscanf(&argv[argi][11], "%x", &alt_savesize);
		if(strncmp(argv[argi], "--fastwrite", 11)==0)fastwrite = 1;

		argi++;
	}

	ret = libusb_init(NULL);
	if(ret < 0)
	{
		printf("Failed to initialize libusb.\n");
		return 1;
	}

	devh = libusb_open_device_with_vid_pid(NULL, 0x4670, 0x9394);
	if(devh == NULL)
	{
		printf("Failed to open device.\n");
		goto shutdown;
	}

	ret = libusb_claim_interface(devh, 0);
	if(ret < 0)
	{
		printf("libusb_claim_interface error %d\n", ret);
		goto shutdown_release;
	}
	printf("Claimed interface.\n");

	if(cmdtype==3)
	{
		cmd_test();
		goto shutdown_release;
	}

	ret = get_cardid(&cardid);
	if(ret < 0)
	{
		printf("Failed to retrieve CardID.\n");
		goto shutdown_release;
	}

	printf("CardID: 0x%x\n", cardid);

	ret = get_flashid(&flashid);
	if(ret < 0)
	{
		printf("Failed to retrieve FlashID.\n");
		goto shutdown_release;
	}

	printf("FlashID: 0x%x\n", flashid);

	ret = get_header(header);
	if(ret < 0)
	{
		printf("Failed to retrieve header.\n");
		goto shutdown_release;
	}

	if(header[0] == 0xff)cardtype = 1;
	printf("Gamecard type: %s\n", cardtype==0?"DS":"3DS");

	if(hdr_operation)
	{
		if(hdr_operation==1)
		{
			printf("Header:\n");
			hexdump(header, 0x200);
			printf("\n");
		}
		else if(hdr_operation==2)
		{
			printf("Writing header to file...\n");
			fhdr = fopen(hdrpath, "wb");
			if(fhdr)
			{
				if(fwrite(header, 1, 0x200, fhdr) != 0x200)
				{
					printf("Failed to write header to output file.\n");
				}
				fclose(fhdr);
			}
			else
			{
				printf("Failed to open output header file for writing: %s\n", hdrpath);
			}

			printf("Finished writing header file.\n");
		}
	}

	savesize = alt_savesize;

	if(alt_savesize==0)
	{
		if(cardtype==1)
		{
			savesize = 1 << (flashid & 0xff);
		}
		else if(cardtype==0)
		{
			savesize = cardEepromGetSize(flashid);
		}
	}

	if(savesize)printf("Save size: 0x%x bytes, %d KiB\n", savesize, savesize / 1024);

	if(cardtype==0 && cmdtype!=0)printf("Specify a savesize.\n");

	if(cmdtype!=0 && savesize!=0)
	{
		if(cmdtype==1)read_save(savepath, cardtype, savesize);
		if(cmdtype==2)write_save(savepath, cardtype, savesize, fastwrite);
	}

	shutdown_release:
	libusb_release_interface(devh, 0);

	shutdown:
	libusb_close(devh);
	libusb_exit(NULL);

	return 0;
}

