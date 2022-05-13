
// -------------------------------------------------------------------
// listexport.cpp
// compiler: VisualC++.NET
// 2005/01/15 written by Kenji Aiko (http://ruffnex.oc.to/kenji/)
// special thanks: http://www.chiyoclone.net/
// -------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <stdarg.h>

// �f�o�b�O���ɃR�����g���O���iPrintMsg�֐����L���ɂȂ�j
//#define MYDEBUG

#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif
#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif


typedef unsigned char   BYTE;
typedef unsigned short  WORD;
typedef unsigned long   DWORD;

typedef unsigned char*  PBYTE;
typedef unsigned short* PWORD;
typedef unsigned long*  PDWORD;


// PE�w�b�_�\����
typedef struct {
	DWORD   Signature;
	WORD    Machine;
	WORD    NumberOfSections;
	DWORD   TimeDateStamp;
	DWORD   PointerToSymbolTable;
	DWORD   NumberOfSymbols;
	WORD    SizeOfOptionalHeader;
	WORD    Characteristics;
} FILE_HEADER, *PFILE_HEADER;


// �I�v�V�����w�b�_�\����
typedef struct {
	// �W���t�B�[���h
	WORD    Magic;
	BYTE    MajorLinkerVersion;
	BYTE    MinorLinkerVersion;
	DWORD   SizeOfCode;
	DWORD   SizeOfInitializedData;
	DWORD   SizeOfUninitializedData;
	DWORD   AddressOfEntryPoint;
	DWORD   BaseOfCode;
	DWORD   BaseOfData;
	// Windows�t�B�[���h
	DWORD   ImageBase;
	DWORD   SectionAlignment;
	DWORD   FileAlignment;
	WORD    MajorOperatingSystemVersion;
	WORD    MinorOperatingSystemVersion;
	WORD    MajorImageVersion;
	WORD    MinorImageVersion;
	WORD    MajorSubsystemVersion;
	WORD    MinorSubsystemVersion;
	DWORD   Win32VersionValue;
	DWORD   SizeOfImage;
	DWORD   SizeOfHeaders;
	DWORD   CheckSum;
	WORD    Subsystem;
	WORD    DllCharacteristics;
	DWORD   SizeOfStackReserve;
	DWORD   SizeOfStackCommit;
	DWORD   SizeOfHeapReserve;
	DWORD   SizeOfHeapCommit;
	DWORD   LoaderFlags;
	DWORD   NumberOfRvaAndSizes;
} OPTION_HEADER, *POPTION_HEADER;


// �f�[�^�f�B���N�g��
typedef struct {
	DWORD   VirtualAddress;
	DWORD   Size;
} DATA_DIR, *PDATA_DIR;


// �Z�N�V�����w�b�_
typedef struct {
	BYTE    Name[8];
	DWORD   VirtualSize;
	DWORD   VirtualAddress;
	DWORD   SizeOfRawData;
	DWORD   PointerToRawData;
	DWORD   PointerToRelocations;
	DWORD   PointerToLinenumbers;
	WORD    NumberOfRelocations;
	WORD    NumberOfLinenumbers;
	DWORD   Characteristics;
} SECTION_HEADER, *PSECTION_HEADER;


// �G�N�X�|�[�g�f�B���N�g���e�[�u��
typedef struct {
	DWORD   Characteristics;
	DWORD   TimeDateStamp;
	WORD    MajorVersion;
	WORD    MinorVersion;
	DWORD   Name;
	DWORD   Base;
	DWORD   NumberOfFunctions;
	DWORD   NumberOfNames;
	DWORD   AddressOfFunctions;
	DWORD   AddressOfNames;
	DWORD   AddressOfNameOrdinals;
} EXPORT_DIR, *PEXPORT_DIR;


// printf�Ɏ��������̃��b�Z�[�W�{�b�N�X
DWORD PrintMsg(char *pszFormat, ...)
{
#define MYDEBUG
#ifdef MYDEBUG
	va_list argList;
	va_start(argList, pszFormat);
	char sz[1024];
	vsprintf(sz, pszFormat, argList);
	va_end(argList);
	fprintf(stderr, "%s", sz);
#endif
	return 0;
}


int main(int argc, char *argv[])
{
	// ##########################################
	// �����I�v�V�����擾����
	// ##########################################

	// �����`�F�b�N
	if(argc < 2){
		fprintf(stderr, "Format:\n");
		fprintf(stderr, "C:\\>%s [option] <pe-format file(DLL)> [file name]\n", argv[0]);
		fprintf(stderr, "Example:\n");
		fprintf(stderr, "C:\\>%s kernel32.dll\n", argv[0]);
		fprintf(stderr, "C:\\>%s -stdout kernel32.dll\n", argv[0]);
		fprintf(stderr, "C:\\>%s -file kernel32.dll\n", argv[0]);
		fprintf(stderr, "C:\\>%s -file kernel32.dll _ernel32\n", argv[0]);
		return -1;
	}

	// �I�v�V�����Ȃ��Ȃ��-stdout�Ƃ݂Ȃ�
	char *file_name = argv[1];
	int option_flag = 0;

	// �I�v�V�����`�F�b�N
	if(argc >= 3){
		file_name = argv[2];
		// -no�@�������Ȃ��i�f�o�b�O�p�Ɏg�p�j
		if(!strcmp(argv[1], "-no"))
			option_flag = -1;
		// -stdout�@�W���o�͂ɕ\��
		if(!strcmp(argv[1], "-stdout"))
			option_flag = 0;
		// -file�@�t�@�C���֏o��
		if(!strcmp(argv[1], "-file")){
			if(argc < 4)
				option_flag = 1;
			else
				option_flag = 2;
		}
	}

	// ##########################################
	// DLL�t�@�C���ǂݍ��ݕ���
	// ##########################################

	// �t�@�C���I�[�v��
	FILE *infp = fopen(file_name, "rb");
	if(infp == NULL){
		fprintf(stderr, "�t�@�C���I�[�v���Ɏ��s���܂����F%s\n", file_name);
		return -1;
	}
	PrintMsg("�t�@�C��:%s\n", file_name);

	// 0x3C�ȍ~��4�o�C�g���擾�i"PE\0\0"�̃A�h���X�j
	DWORD offset;
	fseek(infp, 0x3C, SEEK_SET);
	fread(&offset, sizeof(offset), 1, infp);
	fseek(infp, offset, SEEK_SET);
	PrintMsg("PE���ʎq�̃A�h���X:%08X\n", offset);

	// PE�w�b�_�̎擾
	FILE_HEADER file_header;
	fread(&file_header, sizeof(file_header), 1, infp);
	offset += sizeof(file_header);
	fseek(infp, offset, SEEK_SET);
	PrintMsg("PE���ʎq:%08X\n", file_header.Signature);

	// PE�t�H�[�}�b�g�̊m�F
	if(file_header.Signature != 0x00004550){
		fprintf(stderr, "PE�t�H�[�}�b�g�t�@�C���ł͂���܂���Fsignature=%X\n",
			file_header.Signature);
		return -1;
	}

	// PE�w�b�_�ɑ��݂���I�v�V�����w�b�_�T�C�Y�̎擾
	if(file_header.SizeOfOptionalHeader < 96){
		fprintf(stderr, 
			"�I�v�V�����w�b�_�̃T�C�Y������������܂���FSizeOfOptionalHeader=%d\n",
			file_header.SizeOfOptionalHeader);
		return -1;
	}
	PrintMsg("�I�v�V�����w�b�_�̃T�C�Y:%04X\n", file_header.SizeOfOptionalHeader);

	// �I�v�V�����w�b�_�̎擾
	WORD opSize;
	OPTION_HEADER optional_header;
	if(sizeof(optional_header) < file_header.SizeOfOptionalHeader)
		opSize = sizeof(optional_header);
	else
		opSize = file_header.SizeOfOptionalHeader;
	fread(&optional_header, opSize, 1, infp);
	offset += opSize;
	fseek(infp, offset, SEEK_SET);

	//�I�v�V�����w�b�_���̃f�[�^�f�B���N�g���z��̐����擾
	if(optional_header.NumberOfRvaAndSizes < 1){
		fprintf(stderr, 
			"�f�[�^�f�B���N�g���z��̐�������܂���FNumberOfRvaAndSizes=%d\n",
			optional_header.NumberOfRvaAndSizes);
		return -1;
	}
	PrintMsg("�f�[�^�f�B���N�g���z��̐�:%08X\n", optional_header.NumberOfRvaAndSizes);

	// �f�[�^�f�B���N�g���e�[�u���擾
	PDATA_DIR p_data_directory;
	p_data_directory = (PDATA_DIR)malloc(
		sizeof(DATA_DIR) * optional_header.NumberOfRvaAndSizes);
	if(p_data_directory == NULL){
		fprintf(stderr, "�f�[�^�f�B���N�g���p�̃������m�ۂɎ��s���܂���\n");
		return -1;
	}
	fread(p_data_directory, sizeof(DATA_DIR),
		optional_header.NumberOfRvaAndSizes, infp);
	offset += sizeof(DATA_DIR) * optional_header.NumberOfRvaAndSizes;
	fseek(infp, offset, SEEK_SET);

	// �G�N�X�|�[�g�e�[�u���i�f�[�^�f�B���N�g���e�[�u���̈�ԏ�j��
	// ���݂��邩�ǂ����𔻒�
	if(!p_data_directory[0].Size){
		fprintf(stderr, "�G�N�X�|�[�g�e�[�u���̒l������������܂���\n");
		fprintf(stderr, "DLL�t�@�C���ł͂Ȃ��\��������܂�\n");
		return -1;
	}
	PrintMsg("�G�N�X�|�[�g�e�[�u�����z�A�h���X:%08X\n", 
		p_data_directory[0].VirtualAddress);
	PrintMsg("�G�N�X�|�[�g�e�[�u���T�C�Y:%08X\n", 
		p_data_directory[0].Size);

	//�G�N�X�|�[�g����ǂݍ��ރ������̊m�ۂƏ�����
	PBYTE p_export_data = (PBYTE)malloc(p_data_directory[0].Size);
	if(p_export_data == NULL){
		fprintf(stderr, "�G�N�X�|�[�g���p�̃������m�ۂɎ��s���܂���\n");
		return -1;
	}
	memset(p_export_data, '\0', p_data_directory[0].Size);

	//�Z�N�V�����w�b�_�̓ǂݍ���
	PSECTION_HEADER p_section_header;
	p_section_header = (PSECTION_HEADER)malloc(
		sizeof(SECTION_HEADER) * file_header.NumberOfSections);
	if(p_section_header == NULL){
		fprintf(stderr, "�Z�N�V�����w�b�_�p�̃������m�ۂɎ��s���܂���\n");
		return -1;
	}
	fread(p_section_header, sizeof(SECTION_HEADER),
		file_header.NumberOfSections, infp);
	offset += sizeof(SECTION_HEADER) * file_header.NumberOfSections;
	fseek(infp, offset, SEEK_SET);

	// �G�N�X�|�[�g�e�[�u���̍��[�i���z�A�h���X�j�ƉE�[�i���z�A�h���X�{�T�C�Y�j���擾
	DWORD dir_left  = p_data_directory[0].VirtualAddress;
	DWORD dir_right = dir_left + p_data_directory[0].Size;

	//�Z�N�V��������G�N�X�|�[�g��񕔕���ǂݍ���
	for(DWORD i=0; i < file_header.NumberOfSections; i++){

		// �Z�N�V�����̃�������̍��[�i���z�A�h���X�j�ƉE�[�i���z�A�h���X�{�T�C�Y�j���擾
		DWORD sec_left  = p_section_header[i].VirtualAddress;
		DWORD sec_right = sec_left + p_section_header[i].SizeOfRawData;

		// �G�N�X�|�[�g�e�[�u�������Z�N�V�����Ȃ�Έȉ������s
		if(sec_left <= dir_left && dir_right <= sec_right){
			// �Z�N�V��������G�N�X�|�[�g�e�[�u��������ǂݍ���
			offset = dir_left - sec_left + p_section_header[i].PointerToRawData;
			PrintMsg("�G�N�X�|�[�g�e�[�u���̃I�t�Z�b�g:%08X (%08X - %08X + %08X)\n",
				offset, dir_left, sec_left, p_section_header[i].PointerToRawData);
			fseek(infp, offset, SEEK_SET);
			fread(p_export_data, sizeof(BYTE), p_data_directory[0].Size, infp);
			break;
		}
	}
	fclose(infp);

	// ##########################################
	// �G�N�X�|�[�g�f�[�^�擾����
	// ##########################################

	// �G�N�X�|�[�g�f�[�^��EXPORT_DIR�\���̂֕ϊ�
	PEXPORT_DIR p_export_directory = (PEXPORT_DIR)p_export_data;

	// �����p�̃������m�ۂƏ�����
	DWORD func_num = p_export_directory->NumberOfFunctions;
	PWORD p_list_ordinal = (PWORD)malloc(sizeof(WORD) * func_num);
	if(p_list_ordinal == NULL){
		fprintf(stderr, "�����p�̃������m�ۂɎ��s���܂���\n");
		return -1;
	}
	for(DWORD i=0; i < func_num; i++)
		p_list_ordinal[i] = (WORD)(i + p_export_directory->Base);

	// �G�N�X�|�[�g�֐����|�C���^�p�̃������m�ۂƏ�����
	DWORD name_num = p_export_directory->NumberOfNames;
	char **pp_list_name = (char **)malloc(sizeof(char *) * name_num);
	if(pp_list_name == NULL){
		fprintf(stderr, "�֐����|�C���^�p�̃������m�ۂɎ��s���܂���\n");
		return -1;
	}
	memset(pp_list_name, '\0', sizeof(char *) * name_num);

	// �֐����Ə����̐����Ⴄ�Ȃ�Όx��
	if(name_num != func_num){
		fprintf(stderr, "�֐����̐��Ə����̐����Ⴂ�܂�\n");
		fprintf(stderr, "�l�̏��������ɍ��킹�܂�\n");
	}

	// �G�N�X�|�[�g�֐����|�C���^�̎擾
	PDWORD p_export_names = 
		(PDWORD)(p_export_data + p_export_directory->AddressOfNames - dir_left);
	PrintMsg("�G�N�X�|�[�g�֐����|�C���^�̃A�h���X:%08X (%08X + %08X - %08X)\n",
		(offset + p_export_directory->AddressOfNames - dir_left),
		offset, p_export_directory->AddressOfNames, dir_left);
	PWORD p_export_name_ordinal = 
		(PWORD)(p_export_data + p_export_directory->AddressOfNameOrdinals - dir_left);
	PrintMsg("�G�N�X�|�[�g�����̃A�h���X:%08X (%08X + %08X - %08X)\n",
		(offset + p_export_directory->AddressOfNameOrdinals - dir_left),
		offset, p_export_directory->AddressOfNameOrdinals, dir_left);

	//  for(i=0; i < MIN(name_num, func_num); i++){
	for(DWORD i=0; i < /*MIN(*/name_num/*, func_num)*/; i++){
		char *name = (char *)(p_export_data + p_export_names[i] - dir_left);
		pp_list_name[p_export_name_ordinal[i]] = (char *)malloc(strlen(name) + 1);
		if(pp_list_name[p_export_name_ordinal[i]] == NULL){
			printf("�֐����p�̃������m�ۂɎ��s���܂���\n");
			return -1;
		}
		strcpy(pp_list_name[p_export_name_ordinal[i]], name);
	}

	int NONAMECnt = 0;
	for (int i=0; i<func_num; i++)
	{
		if(pp_list_name[i]==NULL)
		{
			pp_list_name[i] = (char*)malloc(50);
			sprintf(pp_list_name[i], "NONAME%u", ++NONAMECnt);
		}
	}

	// ##########################################
	// �f�[�^�o�͕���
	// ##########################################

	// �G�N�X�|�[�g�f�[�^��\���i�o�́j
	if(option_flag == 0){
		//      for(i=0; i < MIN(name_num, func_num); i++)
		//          printf("����: %04X    ���O: %s\n", p_list_ordinal[i], pp_list_name[i]);
		for(DWORD i=0; i < /*MIN(name_num,*/ func_num/*)*/; i++)
			printf("����: %04X    ���O: %s\n", p_list_ordinal[i], pp_list_name[i]);
	}

	// �G�N�X�|�[�g�f�[�^������DLL�\�[�X����
	if(option_flag == 1 || option_flag == 2){

		// �V������������t�@�C�����̎擾�i�f�t�H���g��"dmydll"�j
		char project_name[256];
		if(option_flag == 1)
			strncpy(project_name, "dmydll", sizeof(project_name) - strlen(".cpp") - 1);
		else
			strncpy(project_name, argv[3], sizeof(project_name) - strlen(".cpp") - 1);

		// .cpp�t�@�C���̐���
		strcat(project_name, ".cpp");
		FILE *outfp = fopen(project_name, "wt");
		if(outfp == NULL){
			fprintf(stderr, "�t�@�C���I�[�v���Ɏ��s���܂����F%s\n", project_name);
			return -1;
		}
		// project_name����".cpp"��r��
		project_name[strlen(project_name) - strlen(".cpp")] = '\0';
		// include <windows.h>
		fprintf(outfp, "#include <windows.h>\n");
		// FARPROC p_function
		//      for(i=0; i < MIN(name_num, func_num); i++)
		for(DWORD i=0; i < /*MIN(name_num,*/ func_num/*)*/; i++)
		{
			fprintf(outfp, "FARPROC p_%s;\n", pp_list_name[i]);
		}
		// extern "C"
		fprintf(outfp, "extern \"C\" {\n");
		// __declspec( naked ) void d_function() { _asm{ jmp p_function } }
		// for(i=0; i < MIN(name_num, func_num); i++){
		for(DWORD i=0; i < /*MIN(name_num,*/ func_num/*)*/; i++){
			fprintf(outfp, 
				"__declspec( naked ) void WINAPI d_%s() { _asm{ jmp p_%s } }\n", 
				pp_list_name[i], pp_list_name[i]);
		}
		fprintf(outfp, "}\n");
		// BOOL APIENTRY DllMain...�i"file_name"��DLL�̃t�@�C�����j
		fprintf(outfp, 
			"HINSTANCE h_original;\n"
			"BOOL APIENTRY DllMain(HANDLE hModule,\n" 
			"                      DWORD  ul_reason_for_call,\n"
			"                      LPVOID lpReserved)\n"
			"{\n"
			"    switch(ul_reason_for_call)\n"
			"    {\n"
			"    case DLL_PROCESS_ATTACH:\n"
			"        h_original = LoadLibrary(\"%s\");\n"
			"        if(h_original == NULL)\n"
			"            return FALSE;\n", file_name);
		// p_function = GetProcAddress(h_original, "function");
		//        for(i=0; i < MIN(name_num, func_num); i++){
		//          fprintf(outfp, "        "
		//            "p_%s = GetProcAddress(h_original, \"%s\");\n", 
		//          pp_list_name[i], pp_list_name[i]);
		for(DWORD i=0; i < /*MIN(name_num,*/ func_num/*)*/; i++){
			if(strncmp(pp_list_name[i], "NONAME", 6)==0)
			{
				fprintf(outfp, "        "
					"p_%s = GetProcAddress(h_original, MAKEINTRESOURCE(%u));\n", 
					pp_list_name[i], i+p_export_directory->Base);
			} else {
				fprintf(outfp, "        "
					"p_%s = GetProcAddress(h_original, \"%s\");\n", 
					pp_list_name[i], pp_list_name[i]);
			}
		}
		fprintf(outfp,
			"        break;\n"
			"    case DLL_THREAD_ATTACH:\n"
			"        break;\n"
			"    case DLL_THREAD_DETACH:\n"
			"        break;\n"
			"    case DLL_PROCESS_DETACH:\n"
			"        FreeLibrary(h_original);\n"
			"        break;\n"
			"    default:\n"
			"        break;\n"
			"    }\n"
			"    return TRUE;\n"
			"}\n");
		// ...return TRUE;
		fclose(outfp);

		// .def�t�@�C���̐���
		strcat(project_name, ".def");
		printf(project_name);
		outfp = fopen(project_name, "wt");
		if(outfp == NULL){
			fprintf(stderr, "�t�@�C���I�[�v���Ɏ��s���܂����F%s\n", project_name);
			return -1;
		}
		// project_name����".def"��r��
		project_name[strlen(project_name) - strlen(".def")] = '\0';
		// LIBRARY DLLfile...
		//        fprintf(outfp, "LIBRARY %s\n", project_name);
		fprintf(outfp, "LIBRARY %s ;BASE=%u\n", project_name, p_export_directory->Base);
		fprintf(outfp, "EXPORTS\n");
		// function=d_function @ 1
		//      for(i=0; i < MIN(name_num, func_num); i++)
		//          fprintf(outfp, "    %s=d_%s @ %d\n", pp_list_name[i], pp_list_name[i], i + 1);
		for(DWORD i=0; i < /*MIN(name_num,*/ func_num/*)*/; i++)
			fprintf(outfp, "    %s=d_%s @ %d %s\n", pp_list_name[i], pp_list_name[i], i+p_export_directory->Base/* + 1*/, strncmp(pp_list_name[i], "NONAME", 6)==0?"NONAME":"");
		fclose(outfp);

		printf("�\�[�X�t�@�C�� %s.cpp, %s.def �𐶐����܂���\n", 
			project_name, project_name);
	}

	// �m�ۂ����֐����p�̃����������
	//    for(i=0; i < name_num; i++){
	for(DWORD i=0; i < func_num/*name_num*/; i++){
		if(pp_list_name[i])
			free(pp_list_name[i]);
	}

	// �������̊J��
	// free(pp_list_name);
	free(p_list_ordinal);
	free(p_section_header);
	free(p_export_data);
	free(p_data_directory);

	return 0;
}
