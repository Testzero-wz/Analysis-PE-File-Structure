#include <stdio.h>
#include<windows.h>
#include<iostream>
#include<String>
#include<vector>

#define CLEN 20
#define ELEN 25
#define NLEN 6
#define DLLNAME "C:\\Users\\windows8.Windows\\Desktop\\CTF\\kernel32.dll"

void showData(const char Chinese[], const char English[],unsigned char * dataAddress, int len);
unsigned long long HexStringToLong(unsigned char * a, int len);
void showDataS(unsigned char * dataAddress, int len);
void showDataH(unsigned char * dataAddress, int len);
void showData1(unsigned char * buf, int len);
long long calcOffset(long long RVA);

using namespace std;

class section {
public:
	int SectionsRVA;
	int PointerToRawData;
	int SizeOFRawData;
	section() {
		SectionsRVA = 0;
		PointerToRawData = 0;
		SizeOFRawData = 0;
	}
	~section() {
	}
	;
};

int NumOfSections = 0; //节表个数
int ExportTableRVA = 0; //导出表RVA
int ExportTablePointer = 0; //导出表文件偏移

vector<section> Sections;
int main() {
	FILE *fp;

	unsigned char buffer[512];
	if ((fp = fopen(DLLNAME,"rb")) != NULL) {
		fread(buffer, sizeof(unsigned char), 0x40, fp);
		/*------------------------------------DOS头-------------------------------------------*/
		printf("DOS头分析:\n");
		showData("PE头偏移", "e_lfanew", &buffer[0x3c], 1);
		//将指针指向PE头开始
		fseek(fp, buffer[0x3c], 0); //当前读取指针指向PE头
		fread(buffer, sizeof(unsigned char), 0x88, fp);
		//showData1(buffer,0x88);
		/*------------------------------------PE头-------------------------------------------*/
		//映像文件头
		printf("映像文件头分析:\n");
		showData("运行环境及平台", "Machine", &buffer[0x4], 2);
		showData("节个数", "NumOfSections", &buffer[0x6], 2);
		NumOfSections = HexStringToLong(&buffer[0x6], 2);
		showData("文件建立时间戳", "TimeDateStamp", &buffer[0x8], 4);
		showData("标志集合", "Characteristics", &buffer[0x16], 2);
		//可选映像头
		printf("可选映像头分析:\n");
		showData("代码入口RVA", "AddressSOfEntryPoint", &buffer[0x28], 4);
		showData("模块首选载入RVA", "ImageBase", &buffer[0x34], 4);
		showData("节内存中对齐", "SectionAlignment", &buffer[0x38], 4);
		showData("节文件中对齐", "FileAlignment", &buffer[0x3c], 4);
		showData("调入内存大小", "SizeOfImage", &buffer[0x50], 4);
		showData("文件头大小之和", "SizeOfHeaders", &buffer[0x54], 4);
		showData("数据目录项项数", "NumberOfRvaAndSizes", &buffer[0x74], 4);
		//数据目录项
		printf("数据目录项分析:\n");
		showData("导出表地址", "ExportTableRVA", &buffer[0x78], 4);
		ExportTableRVA = HexStringToLong(&buffer[0x78], 4);
		showData("导出表大小", "ExportTableSize", &buffer[0x78 + 4], 4);
		showData("导入表地址", "ImportTableRVA", &buffer[0x78 + 8], 4);
		showData("导入表大小", "ImportTableSize", &buffer[0x78 + 12], 4);
		//将指针指向PE头开始
		fseek(fp, 0x70, 1); //当前读取指针指向节表头

		fread(buffer, sizeof(unsigned char), NumOfSections * 0x28, fp);
		/*------------------------------------节表-------------------------------------------*/
		printf("节表分析:\n");
		section Section;
		for (int i = 0; i < NumOfSections; i++) {
			showData("节表名字", "NameOfSectionTable", &buffer[i * 0x28], 0);
			showDataS(&buffer[i * 0x28], 8);

			showData("节表RVA", "VirtualAddress", &buffer[i * 0x28 + 12], 4);
			Section.SectionsRVA = HexStringToLong(&buffer[i * 0x28 + 12], 4);

			showData("文件对齐后尺寸", "SizeOFRawData", &buffer[i * 0x28 + 16], 4);
			Section.SizeOFRawData = HexStringToLong(&buffer[i * 0x28 + 16], 4);

			showData("数据在文件中的位置", "PointerToRawData", &buffer[i * 0x28 + 20],4);
			Section.PointerToRawData = HexStringToLong(&buffer[i * 0x28 + 20],4);

			printf("\t=================================================================\n");
			Sections.push_back(Section);

		}
		//计算导出表文件偏移
		ExportTablePointer = calcOffset(ExportTableRVA);


		/*------------------------------------导出表-------------------------------------------*/
		printf("导出表分析:\n");
		unsigned char buff[512];
		int base = 0; //导出表基数
		int NumOfFunctions = 0; //函数个数
		int NumOfNames = 0; //函数名字个数
		int AddressOfFunctions = 0; //函数RVA
		int AddressOfNames = 0; //函数名字RVA
		int AddressOfNameOrdinals = 0; //函数名字序号RVA

		//跳转到导出表目录头 IMAGE_EXPORT_DIRETORY
		fseek(fp, ExportTablePointer, 0);
		fread(buffer, sizeof(unsigned char), 40, fp);

		showData("DLL名字", "DLLName", &buffer[12], 0);
		fseek(fp, (int) calcOffset(HexStringToLong(&buffer[12], 4)), 0);
		fread(buff, sizeof(unsigned char), sizeof(buff), fp);
		printf("%s\n", buff);
		//showData1(buffer,512);
		showData("基数", "NumOfFunctions", &buffer[16], 4);
		base = HexStringToLong(&buffer[16], 4);
		showData("函数个数", "NumOfFunctions", &buffer[20], 4);
		NumOfFunctions = HexStringToLong(&buffer[20], 4);
		showData("函数名字个数", "NumOfNames", &buffer[24], 4);
		NumOfNames = HexStringToLong(&buffer[24], 4);
		showData("函数RVA", "AddressOfFunctions", &buffer[28], 4);
		AddressOfFunctions = HexStringToLong(&buffer[28], 4);
		showData("函数名字RVA", "AddressOfNames", &buffer[32], 4);
		AddressOfNames = HexStringToLong(&buffer[32], 4);
		showData("函数名字序号RVA", "AddressOfNameOrdinals", &buffer[36], 4);
		AddressOfNameOrdinals = HexStringToLong(&buffer[36], 4);
		printf("导出表函数:\n");
		printf("\n\t%-29s%-28s%s", "序号", "函数名", "函数RVA\n");
		//函数序号
		unsigned char nameBuff[1024];
		unsigned char nameBuffer[1024];
		int count = 0;
		for (int i = 0; i < NumOfNames / 256 + (NumOfNames % 256 != 0); i++) {

			fseek(fp, calcOffset(AddressOfNameOrdinals) + i * sizeof(buffer),0);
			fread(buffer, sizeof(unsigned char), sizeof(buffer), fp);

			fseek(fp, calcOffset(AddressOfNames) + i * sizeof(nameBuffer), 0);
			fread(nameBuffer, sizeof(unsigned char), sizeof(nameBuffer), fp);

			for (int j = 0; j < 512 / 2 && count < NumOfNames; j++) {
				printf("\t%-20X  ",(int) HexStringToLong(&buffer[j * 2], 2) + base);
				fseek(fp,(int) calcOffset(AddressOfFunctions)+ HexStringToLong(&buffer[j * 2], 2) * 4, 0);
				fread(buff, sizeof(unsigned char), 512, fp);

				fseek(fp, calcOffset(HexStringToLong(&nameBuffer[j * 4], 4)),0);
				fread(nameBuff, sizeof(unsigned char), sizeof(nameBuff), fp);
				printf("%-35s", nameBuff);

				showDataH(buff, 4);

				count++;
			}

		}

	}
	fclose(fp);
	return 0;
}

void showData1(unsigned char * buf, int len) {
	for (int i = 0; i < len; i++) {
		printf("%02X", buf[i]);
	}
	printf("\n");
}

long long calcOffset(long long RVA) {

	for (int i = 0; i < NumOfSections; i++) {
		if (Sections[i].SectionsRVA < RVA
				&& RVA < Sections[i].SizeOFRawData + Sections[i].SectionsRVA) {
			return RVA - Sections[i].SectionsRVA + Sections[i].PointerToRawData;
		}

	}
	return 0;

}

void showData(const char Chinese[], const char English[],
		unsigned char * dataAddress, int len) {
	int flag = 0;

	printf("\t%-*s     %-*s=>    ", CLEN, Chinese, ELEN, English);

	for (int i = len - 1; i >= 0; i--) {
		if (flag) {
			printf("%02X", *(dataAddress + i));
		} else if (*(dataAddress + i) != 0) {
			flag = 1;
			printf("%X", *(dataAddress + i));
		}

	}
	if (len != 0) {
		printf("\n");
		if (flag == 0)

			printf("0");
	}
}

void showDataS(unsigned char * dataAddress, int len) {
	printf("%-*.*s\n", len, len, dataAddress);
}

void showDataH(unsigned char * dataAddress, int len) {
	int flag = 0;
	for (int i = len - 1; i >= 0; i--) {
		if (flag) {
			printf("%02X", *(dataAddress + i));
		} else if (*(dataAddress + i) != 0) {
			flag = 1;
			printf("%X", *(dataAddress + i));
		}
	}
	if (len != 0) {
		printf("\n");
		if (flag == 0)

			printf("0");
	}
}

unsigned long long HexStringToLong(unsigned char * a, int len) {
	unsigned long long num = 0, t = 0;
	for (int i = 0; i < len; i++) {
		t = a[i];
		for (int j = i; j > 0; j--) {
			t *= 256;
		}
		num += t;
	}
	return num;
}

