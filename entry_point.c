#include<stdio.h>
#include<stdlib.h>
#include<string.h>

int main() {
	FILE *input = fopen("pe.exe", "r");	
	fseek(input, 0, SEEK_END);
	unsigned long len = ftell(input);
	rewind(input);
	char *pe = (char*)malloc(len);
	fread(pe, len, 1, input);
	fclose(input);

	unsigned int nt_header_offset = *(unsigned int*)(pe + 60);
	unsigned int optional_header_offset = nt_header_offset + 4 + 20;
	unsigned int entry_point_offset = optional_header_offset + 16;
	unsigned int image_base_offset = optional_header_offset + 24;	
	
	unsigned int entry_point = *(unsigned int*)(pe + entry_point_offset);
	unsigned long image_base = *(unsigned long*)(pe + image_base_offset);

	unsigned long target_address = 0x4015bf;
	unsigned long start_address = image_base + (unsigned long)entry_point;
	unsigned int new_entry_point = entry_point + (unsigned int)(target_address - start_address);

	memcpy(pe + entry_point_offset, (char*)&new_entry_point, sizeof(unsigned int));	
	printf("new entry_point: 0x%x\n", new_entry_point);

	FILE *fp = fopen("entry_point.exe", "wb");
	fwrite(pe, len, 1, fp);
	fclose(fp);
}
