#include <stdio.h>
#include <stdlib.h>

int main() {
	FILE* f = fopen("fake.pak", "wb");
	
	char magic[] = { 0xc0 ^ 0xf7, 0x4a ^ 0xf7, 0xc0 ^ 0xf7, 0xba ^ 0xf7 };
	char version[] = { 0x00 ^ 0xf7, 0x00 ^ 0xf7, 0x00 ^ 0xf7, 0x00 ^ 0xf7 };
	
	fwrite(magic, sizeof(char), sizeof(magic) / sizeof(char), f);
	fwrite(version, sizeof(char), sizeof(version) / sizeof(char), f);
	fprintf(f, "This is the fake data, and of course ,this is not long enough, so I write a bunch of data in it\n");
	fprintf(f, "This is the fake data, and of course ,this is not long enough, so I write a bunch of data in it\n");
	fprintf(f, "This is the fake data, and of course ,this is not long enough, so I write a bunch of data in it\n");
	fprintf(f, "This is the fake data, and of course ,this is not long enough, so I write a bunch of data in it\n");
	fprintf(f, "This is the fake data, and of course ,this is not long enough, so I write a bunch of data in it\n");
	fprintf(f, "This is the fake data, and of course ,this is not long enough, so I write a bunch of data in it\n");
	fprintf(f, "This is the fake data, and of course ,this is not long enough, so I write a bunch of data in it\n");
	fprintf(f, "This is the fake data, and of course ,this is not long enough, so I write a bunch of data in it\n");
	fprintf(f, "This is the fake data, and of course ,this is not long enough, so I write a bunch of data in it\n");
	fprintf(f, "This is the fake data, and of course ,this is not long enough, so I write a bunch of data in it\n");
	fprintf(f, "This is the fake data, and of course ,this is not long enough, so I write a bunch of data in it\n");
	fprintf(f, "This is the fake data, and of course ,this is not long enough, so I write a bunch of data in it\n");
	fprintf(f, "This is the fake data, and of course ,this is not long enough, so I write a bunch of data in it\n");
	fprintf(f, "This is the fake data, and of course ,this is not long enough, so I write a bunch of data in it\n");
	fprintf(f, "This is the fake data, and of course ,this is not long enough, so I write a bunch of data in it\n");
	fprintf(f, "This is the fake data, and of course ,this is not long enough, so I write a bunch of data in it\n");
	fprintf(f, "This is the fake data, and of course ,this is not long enough, so I write a bunch of data in it\n");
	fprintf(f, "This is the fake data, and of course ,this is not long enough, so I write a bunch of data in it\n");
	fprintf(f, "This is the fake data, and of course ,this is not long enough, so I write a bunch of data in it\n");
	fprintf(f, "This is the fake data, and of course ,this is not long enough, so I write a bunch of data in it\n");
	fprintf(f, "This is the fake data, and of course ,this is not long enough, so I write a bunch of data in it\n");
	fprintf(f, "This is the fake data, and of course ,this is not long enough, so I write a bunch of data in it\n");
	fprintf(f, "This is the fake data, and of course ,this is not long enough, so I write a bunch of data in it\n");
	fprintf(f, "This is the fake data, and of course ,this is not long enough, so I write a bunch of data in it\n");
	fclose(f);
	return 0;
}