#include<stdio.h>
#include<stdlib.h>
#include<string.h>

typedef unsigned short WORD;
typedef unsigned int DWORD;
typedef unsigned char BYTE;
typedef unsigned long long ULONGLONG;

#define IMAGE_SIZEOF_SHORT_NAME 8
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct _IMAGE_FILE_HEADER {
	WORD  Machine;
	WORD  NumberOfSections;
	DWORD TimeDateStamp;
	DWORD PointerToSymbolTable;
	DWORD NumberOfSymbols;
	WORD  SizeOfOptionalHeader;
	WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_SECTION_HEADER {
	BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		DWORD PhysicalAddress;
		DWORD VirtualSize;
	} Misc;
	DWORD VirtualAddress;
	DWORD SizeOfRawData;
	DWORD PointerToRawData;
	DWORD PointerToRelocations;
	DWORD PointerToLinenumbers;
	WORD  NumberOfRelocations;
	WORD  NumberOfLinenumbers;
	DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	  DWORD VirtualAddress;
	    DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
	WORD                 Magic;
	BYTE                 MajorLinkerVersion;
	BYTE                 MinorLinkerVersion;
	DWORD                SizeOfCode;
	DWORD                SizeOfInitializedData;
	DWORD                SizeOfUninitializedData;
	DWORD                AddressOfEntryPoint;
	DWORD                BaseOfCode;
	ULONGLONG            ImageBase;
	DWORD                SectionAlignment;
	DWORD                FileAlignment;
	WORD                 MajorOperatingSystemVersion;
	WORD                 MinorOperatingSystemVersion;
    WORD                 MajorImageVersion;
	WORD                 MinorImageVersion;
	WORD                 MajorSubsystemVersion;
	WORD                 MinorSubsystemVersion;
	DWORD                Win32VersionValue;
	DWORD                SizeOfImage;
	DWORD                SizeOfHeaders;
	DWORD                CheckSum;
	WORD                 Subsystem;
	WORD                 DllCharacteristics;
	ULONGLONG            SizeOfStackReserve;
	ULONGLONG            SizeOfStackCommit;
	ULONGLONG            SizeOfHeapReserve;
	ULONGLONG            SizeOfHeapCommit;
	DWORD                LoaderFlags;
	DWORD                NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

int main() {
	FILE *input = fopen("pe.exe", "rb");
	fseek(input, 0, SEEK_END);
	unsigned long len = ftell(input);
	rewind(input);

	char *pe = (char*)malloc(len);
	long a = fread(pe, len, 1, input);
	fclose(input);
	
	unsigned int nt_header_offset = *(unsigned int*)(pe + 60);
	unsigned int file_header_offset = nt_header_offset + 4;
	unsigned int optional_header_offset = nt_header_offset + 4 + 20;
	unsigned int section_header_offset = nt_header_offset + 264;
	unsigned int entry_point_offset = optional_header_offset + 16;

	IMAGE_FILE_HEADER *file_header = (IMAGE_FILE_HEADER*)malloc(sizeof(IMAGE_FILE_HEADER));
	memcpy(file_header, pe + file_header_offset, sizeof(IMAGE_FILE_HEADER));
	unsigned short section_num = file_header->NumberOfSections;

	IMAGE_OPTIONAL_HEADER64 *optional_header = (IMAGE_OPTIONAL_HEADER64*)malloc(sizeof(IMAGE_OPTIONAL_HEADER64));
	optional_header = (IMAGE_OPTIONAL_HEADER64*)(pe + optional_header_offset);

	IMAGE_SECTION_HEADER *last_section_header = (IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER));
	memcpy(last_section_header, pe + section_header_offset + (section_num - 1) * sizeof(IMAGE_SECTION_HEADER), sizeof(IMAGE_SECTION_HEADER));
	printf("%x\n", last_section_header->PointerToRawData);
	printf("%x\n", last_section_header->SizeOfRawData);
	printf("%x\n", last_section_header->PointerToRawData + last_section_header->SizeOfRawData);
	printf("%lx\n", len);
	
	IMAGE_SECTION_HEADER *first_section = (IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER));
	memcpy(first_section, pe + section_header_offset, sizeof(IMAGE_SECTION_HEADER));

	unsigned long long image_base = optional_header->ImageBase;
	unsigned int entry_point = optional_header->AddressOfEntryPoint;
	unsigned int section_align = optional_header->SectionAlignment;
	unsigned int file_align = optional_header->FileAlignment;
	unsigned int offset = first_section->PointerToRawData;
	unsigned int section_size = first_section->SizeOfRawData;
	unsigned int vaddr = first_section->VirtualAddress;
	unsigned int vsize = first_section->Misc.VirtualSize;
	
	FILE *fp = fopen("code", "rb");
	fseek(fp, 0, SEEK_END);
	unsigned long code_size = ftell(fp);
	rewind(fp);

	char *code = (char*)malloc(code_size);	
	fread(code, code_size, 1, fp);
	fclose(fp);

	unsigned int start_offset = offset + section_size - code_size;
	unsigned long long start_address = (unsigned long long)entry_point + image_base;
	unsigned long long end_address = (unsigned long long)vsize + (unsigned long long)vaddr + image_base;
	unsigned long long next_section_addr = ((end_address / section_align) + 1) * section_align;
	unsigned long long entry_point_addr = (unsigned long long)entry_point + image_base; 
	unsigned int jmp_address = (unsigned int)(entry_point_addr - next_section_addr);
	unsigned int new_entry_point = (unsigned int)(next_section_addr - (unsigned long long)code_size - image_base);

	/*
	memcpy(code + code_size - 4, (char*)&jmp_address, 4);
	memcpy(pe + start_offset, code, code_size);
	memcpy(pe + entry_point_offset, (char*)&new_entry_point, 4);

	fp = fopen("last_section.exe", "wb");
	fwrite(pe, len, 1, fp);
	fclose(fp);
	*/

	/*
	FILE *fp = fopen("last_section.exe", "wb");
	fwrite(pe, len, 1, fp);
	fclose(fp);
	*/
}
