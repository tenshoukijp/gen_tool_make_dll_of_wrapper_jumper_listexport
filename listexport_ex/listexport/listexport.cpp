
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

// デバッグ時にコメントを外す（PrintMsg関数が有効になる）
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


// PEヘッダ構造体
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


// オプションヘッダ構造体
typedef struct {
	// 標準フィールド
	WORD    Magic;
	BYTE    MajorLinkerVersion;
	BYTE    MinorLinkerVersion;
	DWORD   SizeOfCode;
	DWORD   SizeOfInitializedData;
	DWORD   SizeOfUninitializedData;
	DWORD   AddressOfEntryPoint;
	DWORD   BaseOfCode;
	DWORD   BaseOfData;
	// Windowsフィールド
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


// データディレクトリ
typedef struct {
	DWORD   VirtualAddress;
	DWORD   Size;
} DATA_DIR, *PDATA_DIR;


// セクションヘッダ
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


// エクスポートディレクトリテーブル
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


// printfに似た実装のメッセージボックス
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
	// 引数オプション取得部分
	// ##########################################

	// 引数チェック
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

	// オプションなしならば-stdoutとみなす
	char *file_name = argv[1];
	int option_flag = 0;

	// オプションチェック
	if(argc >= 3){
		file_name = argv[2];
		// -no　何もしない（デバッグ用に使用）
		if(!strcmp(argv[1], "-no"))
			option_flag = -1;
		// -stdout　標準出力に表示
		if(!strcmp(argv[1], "-stdout"))
			option_flag = 0;
		// -file　ファイルへ出力
		if(!strcmp(argv[1], "-file")){
			if(argc < 4)
				option_flag = 1;
			else
				option_flag = 2;
		}
	}

	// ##########################################
	// DLLファイル読み込み部分
	// ##########################################

	// ファイルオープン
	FILE *infp = fopen(file_name, "rb");
	if(infp == NULL){
		fprintf(stderr, "ファイルオープンに失敗しました：%s\n", file_name);
		return -1;
	}
	PrintMsg("ファイル:%s\n", file_name);

	// 0x3C以降の4バイトを取得（"PE\0\0"のアドレス）
	DWORD offset;
	fseek(infp, 0x3C, SEEK_SET);
	fread(&offset, sizeof(offset), 1, infp);
	fseek(infp, offset, SEEK_SET);
	PrintMsg("PE識別子のアドレス:%08X\n", offset);

	// PEヘッダの取得
	FILE_HEADER file_header;
	fread(&file_header, sizeof(file_header), 1, infp);
	offset += sizeof(file_header);
	fseek(infp, offset, SEEK_SET);
	PrintMsg("PE識別子:%08X\n", file_header.Signature);

	// PEフォーマットの確認
	if(file_header.Signature != 0x00004550){
		fprintf(stderr, "PEフォーマットファイルではありません：signature=%X\n",
			file_header.Signature);
		return -1;
	}

	// PEヘッダに存在するオプションヘッダサイズの取得
	if(file_header.SizeOfOptionalHeader < 96){
		fprintf(stderr, 
			"オプションヘッダのサイズが正しくありません：SizeOfOptionalHeader=%d\n",
			file_header.SizeOfOptionalHeader);
		return -1;
	}
	PrintMsg("オプションヘッダのサイズ:%04X\n", file_header.SizeOfOptionalHeader);

	// オプションヘッダの取得
	WORD opSize;
	OPTION_HEADER optional_header;
	if(sizeof(optional_header) < file_header.SizeOfOptionalHeader)
		opSize = sizeof(optional_header);
	else
		opSize = file_header.SizeOfOptionalHeader;
	fread(&optional_header, opSize, 1, infp);
	offset += opSize;
	fseek(infp, offset, SEEK_SET);

	//オプションヘッダ内のデータディレクトリ配列の数を取得
	if(optional_header.NumberOfRvaAndSizes < 1){
		fprintf(stderr, 
			"データディレクトリ配列の数が足りません：NumberOfRvaAndSizes=%d\n",
			optional_header.NumberOfRvaAndSizes);
		return -1;
	}
	PrintMsg("データディレクトリ配列の数:%08X\n", optional_header.NumberOfRvaAndSizes);

	// データディレクトリテーブル取得
	PDATA_DIR p_data_directory;
	p_data_directory = (PDATA_DIR)malloc(
		sizeof(DATA_DIR) * optional_header.NumberOfRvaAndSizes);
	if(p_data_directory == NULL){
		fprintf(stderr, "データディレクトリ用のメモリ確保に失敗しました\n");
		return -1;
	}
	fread(p_data_directory, sizeof(DATA_DIR),
		optional_header.NumberOfRvaAndSizes, infp);
	offset += sizeof(DATA_DIR) * optional_header.NumberOfRvaAndSizes;
	fseek(infp, offset, SEEK_SET);

	// エクスポートテーブル（データディレクトリテーブルの一番上）が
	// 存在するかどうかを判定
	if(!p_data_directory[0].Size){
		fprintf(stderr, "エクスポートテーブルの値が正しくありません\n");
		fprintf(stderr, "DLLファイルではない可能性があります\n");
		return -1;
	}
	PrintMsg("エクスポートテーブル仮想アドレス:%08X\n", 
		p_data_directory[0].VirtualAddress);
	PrintMsg("エクスポートテーブルサイズ:%08X\n", 
		p_data_directory[0].Size);

	//エクスポート情報を読み込むメモリの確保と初期化
	PBYTE p_export_data = (PBYTE)malloc(p_data_directory[0].Size);
	if(p_export_data == NULL){
		fprintf(stderr, "エクスポート情報用のメモリ確保に失敗しました\n");
		return -1;
	}
	memset(p_export_data, '\0', p_data_directory[0].Size);

	//セクションヘッダの読み込み
	PSECTION_HEADER p_section_header;
	p_section_header = (PSECTION_HEADER)malloc(
		sizeof(SECTION_HEADER) * file_header.NumberOfSections);
	if(p_section_header == NULL){
		fprintf(stderr, "セクションヘッダ用のメモリ確保に失敗しました\n");
		return -1;
	}
	fread(p_section_header, sizeof(SECTION_HEADER),
		file_header.NumberOfSections, infp);
	offset += sizeof(SECTION_HEADER) * file_header.NumberOfSections;
	fseek(infp, offset, SEEK_SET);

	// エクスポートテーブルの左端（仮想アドレス）と右端（仮想アドレス＋サイズ）を取得
	DWORD dir_left  = p_data_directory[0].VirtualAddress;
	DWORD dir_right = dir_left + p_data_directory[0].Size;

	//セクションからエクスポート情報部分を読み込む
	for(DWORD i=0; i < file_header.NumberOfSections; i++){

		// セクションのメモリ上の左端（仮想アドレス）と右端（仮想アドレス＋サイズ）を取得
		DWORD sec_left  = p_section_header[i].VirtualAddress;
		DWORD sec_right = sec_left + p_section_header[i].SizeOfRawData;

		// エクスポートテーブルを持つセクションならば以下を実行
		if(sec_left <= dir_left && dir_right <= sec_right){
			// セクションからエクスポートテーブル部分を読み込む
			offset = dir_left - sec_left + p_section_header[i].PointerToRawData;
			PrintMsg("エクスポートテーブルのオフセット:%08X (%08X - %08X + %08X)\n",
				offset, dir_left, sec_left, p_section_header[i].PointerToRawData);
			fseek(infp, offset, SEEK_SET);
			fread(p_export_data, sizeof(BYTE), p_data_directory[0].Size, infp);
			break;
		}
	}
	fclose(infp);

	// ##########################################
	// エクスポートデータ取得部分
	// ##########################################

	// エクスポートデータをEXPORT_DIR構造体へ変換
	PEXPORT_DIR p_export_directory = (PEXPORT_DIR)p_export_data;

	// 序数用のメモリ確保と初期化
	DWORD func_num = p_export_directory->NumberOfFunctions;
	PWORD p_list_ordinal = (PWORD)malloc(sizeof(WORD) * func_num);
	if(p_list_ordinal == NULL){
		fprintf(stderr, "序数用のメモリ確保に失敗しました\n");
		return -1;
	}
	for(DWORD i=0; i < func_num; i++)
		p_list_ordinal[i] = (WORD)(i + p_export_directory->Base);

	// エクスポート関数名ポインタ用のメモリ確保と初期化
	DWORD name_num = p_export_directory->NumberOfNames;
	char **pp_list_name = (char **)malloc(sizeof(char *) * name_num);
	if(pp_list_name == NULL){
		fprintf(stderr, "関数名ポインタ用のメモリ確保に失敗しました\n");
		return -1;
	}
	memset(pp_list_name, '\0', sizeof(char *) * name_num);

	// 関数名と序数の数が違うならば警告
	if(name_num != func_num){
		fprintf(stderr, "関数名の数と序数の数が違います\n");
		fprintf(stderr, "値の小さい方に合わせます\n");
	}

	// エクスポート関数名ポインタの取得
	PDWORD p_export_names = 
		(PDWORD)(p_export_data + p_export_directory->AddressOfNames - dir_left);
	PrintMsg("エクスポート関数名ポインタのアドレス:%08X (%08X + %08X - %08X)\n",
		(offset + p_export_directory->AddressOfNames - dir_left),
		offset, p_export_directory->AddressOfNames, dir_left);
	PWORD p_export_name_ordinal = 
		(PWORD)(p_export_data + p_export_directory->AddressOfNameOrdinals - dir_left);
	PrintMsg("エクスポート序数のアドレス:%08X (%08X + %08X - %08X)\n",
		(offset + p_export_directory->AddressOfNameOrdinals - dir_left),
		offset, p_export_directory->AddressOfNameOrdinals, dir_left);

	//  for(i=0; i < MIN(name_num, func_num); i++){
	for(DWORD i=0; i < /*MIN(*/name_num/*, func_num)*/; i++){
		char *name = (char *)(p_export_data + p_export_names[i] - dir_left);
		pp_list_name[p_export_name_ordinal[i]] = (char *)malloc(strlen(name) + 1);
		if(pp_list_name[p_export_name_ordinal[i]] == NULL){
			printf("関数名用のメモリ確保に失敗しました\n");
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
	// データ出力部分
	// ##########################################

	// エクスポートデータを表示（出力）
	if(option_flag == 0){
		//      for(i=0; i < MIN(name_num, func_num); i++)
		//          printf("序数: %04X    名前: %s\n", p_list_ordinal[i], pp_list_name[i]);
		for(DWORD i=0; i < /*MIN(name_num,*/ func_num/*)*/; i++)
			printf("序数: %04X    名前: %s\n", p_list_ordinal[i], pp_list_name[i]);
	}

	// エクスポートデータを元にDLLソース生成
	if(option_flag == 1 || option_flag == 2){

		// 新しく生成するファイル名の取得（デフォルトは"dmydll"）
		char project_name[256];
		if(option_flag == 1)
			strncpy(project_name, "dmydll", sizeof(project_name) - strlen(".cpp") - 1);
		else
			strncpy(project_name, argv[3], sizeof(project_name) - strlen(".cpp") - 1);

		// .cppファイルの生成
		strcat(project_name, ".cpp");
		FILE *outfp = fopen(project_name, "wt");
		if(outfp == NULL){
			fprintf(stderr, "ファイルオープンに失敗しました：%s\n", project_name);
			return -1;
		}
		// project_nameから".cpp"を排除
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
		// BOOL APIENTRY DllMain...（"file_name"はDLLのファイル名）
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

		// .defファイルの生成
		strcat(project_name, ".def");
		printf(project_name);
		outfp = fopen(project_name, "wt");
		if(outfp == NULL){
			fprintf(stderr, "ファイルオープンに失敗しました：%s\n", project_name);
			return -1;
		}
		// project_nameから".def"を排除
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

		printf("ソースファイル %s.cpp, %s.def を生成しました\n", 
			project_name, project_name);
	}

	// 確保した関数名用のメモリを解放
	//    for(i=0; i < name_num; i++){
	for(DWORD i=0; i < func_num/*name_num*/; i++){
		if(pp_list_name[i])
			free(pp_list_name[i]);
	}

	// メモリの開放
	// free(pp_list_name);
	free(p_list_ordinal);
	free(p_section_header);
	free(p_export_data);
	free(p_data_directory);

	return 0;
}
