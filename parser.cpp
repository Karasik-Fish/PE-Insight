#include <iostream>
#include <windows.h>
#include <vector>
#include <fstream>
#include <string>
#include <filesystem>
#include <map>
#include <WinTrust.h>
#include <set>
using namespace std;
namespace fs = filesystem;
#define folder "sessions"

void make_valid_string(string* str)
{
	string sim = "\\/:*?\"<>|";
	for (char& c : *str)
	{
		if (sim.find(c) != string::npos)
		{
			c = '_';
		}
	}
}

template <typename NT, typename ULORD, typename THUNK3264, typename TLS, typename LOAD_CONFIG>
class PEParser
{
public:
	string filePath;
	vector<char>* buffer;
	size_t size_of_file;
	char* pBase;//check_and_make
	PIMAGE_DOS_HEADER pDosHeader;//check_and_make
	NT pNtHeaders;//check_and_make
	string c_cur_folder;//check_and_make
	PIMAGE_SECTION_HEADER pSectionHeader;// section_header
	PIMAGE_DATA_DIRECTORY pData;//data_dir
	IMAGE_IMPORT_DESCRIPTOR* pImportDesc;//import_table
	IMAGE_EXPORT_DIRECTORY* pExportDir; //export_dir
	DWORD* start_of_rsrc; //resourse_table
	PIMAGE_BASE_RELOCATION pReloc; //relocation_table
	TLS* pTLSDir; //tls_table
	PIMAGE_DELAYLOAD_DESCRIPTOR pDelayDesc; //delay_import_table
	IMAGE_DEBUG_DIRECTORY* pDebugDir; //debug_directory
	LOAD_CONFIG* pLoadConfigTable; //load_config_table
	WIN_CERTIFICATE* pSec;
	RUNTIME_FUNCTION* pExc;
	map<ULONGLONG, ULONGLONG> import_map;
	typedef struct
	{
		BYTE Version : 3;
		BYTE Flags : 5;
		BYTE SizeOfProlog;
		BYTE CountOfCodes;
		BYTE FrameRegister : 4;
		BYTE FrameOffset : 4;
	} UNWIND_INFO_HEADER;
	typedef union
	{
		struct
		{
			BYTE CodeOffset;
			BYTE UnwindOp : 4;
			BYTE OpInfo : 4;
		};
		USHORT FrameOffset;
	} UNWIND_CODE;
	PEParser(string filePath, vector<char>* buffer, size_t size) : buffer(buffer), filePath(filePath), size_of_file(size)
	{
		pBase = NULL;
		pDosHeader = NULL;
		pNtHeaders = NULL;
		pSectionHeader = NULL;
		pData = NULL;
		pImportDesc = NULL;
		pExportDir = NULL;
		start_of_rsrc = NULL;
		pReloc = NULL;
		pTLSDir = NULL;
		pDelayDesc = NULL;
		pDebugDir = NULL;
		pLoadConfigTable = NULL;
		pSec = NULL;
		pExc = NULL;
	}
	void parse_it();
	int check_and_make();
	void section_header();
	void data_dir();
	void import_table();
	void export_dir();
	size_t convert_rva_to_raw(DWORD);
	void func_resourse(DWORD*, int, string, string, ofstream*);
	void resourse_table();
	void relocation_table();
	void func_relocation(DWORD, ofstream*);
	void tls_table();
	void func_tls(ULORD);
	void delay_import_table();
	void debug_directory();
	void load_config_table();
	void secutity_table();
	void exception_table();
	void func_exception(int, RUNTIME_FUNCTION*, ofstream*, int, set<DWORD>*);
	size_t get_section_end(DWORD rva);
};
template <typename NT, typename ULORD, typename THUNK3264, typename TLS, typename LOAD_CONFIG>
void PEParser<NT, ULORD, THUNK3264, TLS, LOAD_CONFIG>::parse_it()
{
	if (check_and_make())
	{
		return;
	}
	section_header();
	data_dir();
	import_table();
	export_dir();
	resourse_table();
	relocation_table();
	tls_table();
	delay_import_table();
	debug_directory();
	load_config_table();
	secutity_table();
	exception_table();
}

template <typename NT, typename ULORD, typename THUNK3264, typename TLS, typename LOAD_CONFIG>
int PEParser<NT, ULORD, THUNK3264, TLS, LOAD_CONFIG>::check_and_make()
{
	pBase = (*buffer).data();
	pDosHeader = (PIMAGE_DOS_HEADER)pBase;
	if (sizeof(PIMAGE_DOS_HEADER) > size_of_file)
	{
		cout << "Wrong file" << endl;
		return 1;
	}
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		cout << "net" << endl;
		return 1;
	}
	pNtHeaders = (NT)(pBase + pDosHeader->e_lfanew);
	if (pDosHeader->e_lfanew + sizeof(NT) > size_of_file)
	{
		cout << "Size is too small for NT" << endl;
		return 1;
	}
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		cout << "ne-a" << endl;
		return 1;
	}
	size_t ind = filePath.rfind("\\") + 1;
	if (!fs::exists(folder))
	{
		fs::create_directories(folder);
	}
	if (!fs::exists(folder + string("\\") + filePath.substr(ind, filePath.size() - ind)))
	{
		fs::create_directories(folder + string("\\") + filePath.substr(ind, filePath.size() - ind));
	}
	c_cur_folder = folder + string("\\") + filePath.substr(ind, filePath.size() - ind);
	cout << "----INFO-----" << endl;
	cout << "Machine: " << hex << pNtHeaders->FileHeader.Machine << endl;
	cout << "Number of sections: " << dec << pNtHeaders->FileHeader.NumberOfSections << endl;
	cout << "Size of optional header: " << dec << pNtHeaders->FileHeader.SizeOfOptionalHeader << endl;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((char*)&pNtHeaders->OptionalHeader + pNtHeaders->FileHeader.SizeOfOptionalHeader);
	if ((ULONGLONG)pSectionHeader - (ULONGLONG)pBase + sizeof(IMAGE_SECTION_HEADER) * pNtHeaders->FileHeader.NumberOfSections > size_of_file)
	{
		cout << "There are not enough space for section headers" << endl;
		return 1;
	}
	pData = pNtHeaders->OptionalHeader.DataDirectory;
	if ((ULONGLONG)pData - (ULONGLONG)pBase + sizeof(IMAGE_DATA_DIRECTORY) * pNtHeaders->OptionalHeader.NumberOfRvaAndSizes > size_of_file)
	{
		cout << "Not enough space for Data structs" << endl;
		return 1;
	}
	if (pData[1].VirtualAddress != 0 && pData[1].Size != 0)
	{
		pImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)(pBase + convert_rva_to_raw(pData[1].VirtualAddress));
	}
	if (pData[0].VirtualAddress != 0 && pData[0].Size != 0)
	{
		pExportDir = (IMAGE_EXPORT_DIRECTORY*)(pBase + convert_rva_to_raw(pData[0].VirtualAddress));
	}
	if (pData[2].VirtualAddress != 0 && pData[2].Size != 0)
	{
		start_of_rsrc = (DWORD*)(pBase + convert_rva_to_raw(pData[2].VirtualAddress));
	}
	if (pData[5].VirtualAddress != 0 && pData[5].Size != 0)
	{
		pReloc = (PIMAGE_BASE_RELOCATION)(pBase + convert_rva_to_raw(pData[5].VirtualAddress));
	}
	if (pData[9].VirtualAddress != 0 && pData[9].Size != 0)
	{
		pTLSDir = (TLS*)(pBase + convert_rva_to_raw(pData[9].VirtualAddress));
	}
	if (pData[13].VirtualAddress != 0 && pData[13].Size != 0)
	{
		pDelayDesc = (PIMAGE_DELAYLOAD_DESCRIPTOR)(pBase + convert_rva_to_raw(pData[13].VirtualAddress));
	}
	if (pData[6].VirtualAddress != 0 && pData[6].Size != 0)
	{
		pDebugDir = (IMAGE_DEBUG_DIRECTORY*)(pBase + convert_rva_to_raw(pData[6].VirtualAddress));
	}
	if (pData[10].VirtualAddress != 0 && pData[10].Size != 0)
	{
		pLoadConfigTable = (LOAD_CONFIG*)(pBase + convert_rva_to_raw(pData[10].VirtualAddress));
	}
	if (pData[4].VirtualAddress != 0 && pData[4].Size != 0)
	{
		pSec = (WIN_CERTIFICATE*)(pBase + pData[4].VirtualAddress);
	}
	if (sizeof(THUNK3264) == sizeof(ULONGLONG))
	{
		pExc = (RUNTIME_FUNCTION*)(pBase + convert_rva_to_raw(pData[3].VirtualAddress));
	}
	return 0;
}

template <typename NT, typename ULORD, typename THUNK3264, typename TLS, typename LOAD_CONFIG>
void PEParser<NT, ULORD, THUNK3264, TLS, LOAD_CONFIG>::section_header()
{
	cout << hex << (ULONGLONG)pDosHeader - (ULONGLONG)pBase << endl;
	cout << hex << (ULONGLONG)pNtHeaders - (ULONGLONG)pBase << endl;
	cout << hex << (ULONGLONG)pSectionHeader - (ULONGLONG)pBase << endl;
	cout << "-----IMAGE_SECTION_HEADER-----" << endl;
	for (int i{}; i < pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		char name[9] = { 0 };
		memcpy(name, pSectionHeader[i].Name, 8);

		cout << dec << "Section[" << i + 1 << "] Name: " << name << endl;
		cout << "  Virtual Size: " << pSectionHeader[i].Misc.VirtualSize << endl;
		cout << "  Virtual Address: " << hex << pSectionHeader[i].VirtualAddress << endl;
	}
}

template <typename NT, typename ULORD, typename THUNK3264, typename TLS, typename LOAD_CONFIG>
size_t PEParser<NT, ULORD, THUNK3264, TLS, LOAD_CONFIG>::convert_rva_to_raw(DWORD rva)
{
	for (int i{}; i < pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		if (rva >= pSectionHeader[i].VirtualAddress && rva < (pSectionHeader[i].VirtualAddress + pSectionHeader[i].Misc.VirtualSize))
		{
			if (pSectionHeader[i].SizeOfRawData > (rva - pSectionHeader[i].VirtualAddress))
			{
				return (size_t)(rva - pSectionHeader[i].VirtualAddress + pSectionHeader[i].PointerToRawData);
			}
			else
			{
				return 0;
			}
		}
		
	}
	return 0;
}


template <typename NT, typename ULORD, typename THUNK3264, typename TLS, typename LOAD_CONFIG>
size_t PEParser<NT, ULORD, THUNK3264, TLS, LOAD_CONFIG>::get_section_end(DWORD rva)
{
	for (int i{}; i < pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		if (rva >= pSectionHeader[i].VirtualAddress && rva < (pSectionHeader[i].VirtualAddress + pSectionHeader[i].Misc.VirtualSize))
		{
			size_t pe = pSectionHeader[i].VirtualAddress + pSectionHeader[i].SizeOfRawData;
			size_t ve = pSectionHeader[i].VirtualAddress + pSectionHeader[i].Misc.VirtualSize;

			return (pe < ve) ? pe : ve;
		}
	}
	return 0;
}


template <typename NT, typename ULORD, typename THUNK3264, typename TLS, typename LOAD_CONFIG>
void PEParser<NT, ULORD, THUNK3264, TLS, LOAD_CONFIG>::data_dir()
{
	for (int i{}; i < 16; i++)
	{
		cout << dec << "Data Directory[" << i << "] Virtual Address: " << hex << pData[i].VirtualAddress << ", Size: " << pData[i].Size << endl;
		cout << "  Raw Address: " << hex << convert_rva_to_raw(pData[i].VirtualAddress) << endl;

	}
}

template <typename NT, typename ULORD, typename THUNK3264, typename TLS, typename LOAD_CONFIG>
void PEParser<NT, ULORD, THUNK3264, TLS, LOAD_CONFIG>::import_table()
{
	cout << "-----IMPORT TABLE-----" << endl;
	if ((ULONGLONG)pImportDesc == (ULONGLONG)pBase)
	{
		cout << "Invalid Import address" << endl;
		return;
	}
	if (pImportDesc == 0)
	{
		cout << "Nothing to import (Directory is empty)" << endl;
		return;
	}
	if ((ULONGLONG)pImportDesc - (ULONGLONG)pBase + sizeof(IMAGE_IMPORT_DESCRIPTOR) > size_of_file)
	{
		cout << "There no space for import" << endl;
		return;
	}
	if (pImportDesc->Name == 0)
	{
		cout << "Nothing to import (Empty table)" << endl;
		return;
	}
	if (!fs::exists(c_cur_folder + string("\\import_table")))
	{
		fs::create_directories(c_cur_folder + string("\\import_table")); 
	}
	ofstream out(c_cur_folder + string("\\import_table") + string("\\import_table.txt"));
	if (!out.is_open())
	{
		cout << "Failed to open file for writing: " << c_cur_folder + string("\\import_table") + string("\\import_table.txt") << endl;
	}
	else
	{
		cout << "search through the files" << endl;
		IMAGE_IMPORT_DESCRIPTOR* pImportDesc_copy = pImportDesc;
		ULONGLONG mask1 = 0x80000000;
		ULONGLONG mask2 = 0x7FFFFFFF;
		bool iat_flag = 0;
		if (sizeof(THUNK3264) == 8)
		{
			mask1 = 0x8000000000000000;
			mask2 = 0x7FFFFFFFFFFFFFFF;
			iat_flag = 1;
		}
		while (pImportDesc_copy->Name != 0 && ((ULONGLONG)pImportDesc_copy - (ULONGLONG)pBase + sizeof(IMAGE_IMPORT_DESCRIPTOR) < size_of_file))
		{
			if (convert_rva_to_raw(pImportDesc_copy->Name) == 0 || convert_rva_to_raw(pImportDesc_copy->Name) >= size_of_file)
			{
				cout << "Invalid name address" << endl;
				pImportDesc_copy++;
				continue;
			}
			if (convert_rva_to_raw(pImportDesc_copy->OriginalFirstThunk) == 0 || convert_rva_to_raw(pImportDesc_copy->OriginalFirstThunk) >= size_of_file)
			{
				cout << "Invalid OriginalFirstThunk address" << endl;
				pImportDesc_copy++;
				continue;
			}
			if (convert_rva_to_raw(pImportDesc_copy->FirstThunk) == 0 || convert_rva_to_raw(pImportDesc_copy->FirstThunk) >= size_of_file)
			{
				cout << "Invalid FirstThunk address" << endl;
				pImportDesc_copy++;
				continue;
			}
			size_t raw_dll_name = convert_rva_to_raw(pImportDesc_copy->Name);
			if (raw_dll_name == 0 || raw_dll_name + 1 > size_of_file)
			{
				cout << "Wrong address of name(dll)" << endl;
			}
			else
			{
				int dll_flag = 0;
				for (size_t i{}; i < min(size_of_file - raw_dll_name, 256); i++)
				{
					if ((pBase + raw_dll_name)[i] == '\0')
					{
						dll_flag = 1;
						break;
					}
				}
				if (dll_flag)
					out << (char*)(pBase + convert_rva_to_raw(pImportDesc_copy->Name)) << endl;
				else
					cout << "Detected very strange dll name" << endl;
			}
			DWORD rvaThunk = pImportDesc_copy->OriginalFirstThunk ? pImportDesc_copy->OriginalFirstThunk : pImportDesc_copy->FirstThunk;
			size_t rawThunk = convert_rva_to_raw(rvaThunk);
			if (rawThunk == 0 || rawThunk + sizeof(THUNK3264) > size_of_file)
			{
				cout << "Invalid Thunk address, skipping this DLL" << endl;
				pImportDesc_copy++;
				continue;
			}
			THUNK3264* pThunkData = (THUNK3264*)(pBase + convert_rva_to_raw(rvaThunk));
			ULONGLONG pIAT = pImportDesc_copy->FirstThunk;
			ULONGLONG pILT = rvaThunk;
			while (pThunkData->u1.AddressOfData != 0 && (ULONGLONG)pThunkData - (ULONGLONG)pBase + sizeof(THUNK3264) < size_of_file)
			{
				if (iat_flag)
				{
					import_map[pIAT] = pILT;
					pIAT += sizeof(THUNK3264);
					pILT += sizeof(THUNK3264);
				}
				if ((pThunkData->u1.Ordinal & mask1) != 0)
				{
					out << "import by ordinal: " << dec << ((pThunkData->u1.Ordinal) & mask2) << endl;
				}
				else
				{
					if (convert_rva_to_raw(pThunkData->u1.AddressOfData) == 0 || convert_rva_to_raw(pThunkData->u1.AddressOfData) + sizeof(IMAGE_IMPORT_BY_NAME) > size_of_file)
					{
						cout << "Invalid address of IMAGE_IMPORT_BY_NAME" << endl;
					}
					else
					{
						size_t raw_t = convert_rva_to_raw(pThunkData->u1.AddressOfData);
						if (raw_t == 0 || raw_t + 1 + sizeof(WORD) > size_of_file)
						{
							cout << "Invalid raw address of name" << endl;
						}
						else
						{
							int flag = 0;
							for (size_t i{}; i < min(size_of_file - raw_t, 256); i++)
							{
								if ((pBase + raw_t + sizeof(WORD))[i] == '\0')
								{
									flag = 1;
									break;
								}
							}
							if (flag)
							{
								out << "Import by name: " << ((IMAGE_IMPORT_BY_NAME*)(pBase + raw_t))->Name << endl;
							}
							else
							{
								cout << "Strange name detected" << endl;
							}
						}
					}
				}
				pThunkData++;
			}
			out << endl;
			pImportDesc_copy++;
		}
	}
	out.close();
}

template <typename NT, typename ULORD, typename THUNK3264, typename TLS, typename LOAD_CONFIG>
void PEParser<NT, ULORD, THUNK3264, TLS, LOAD_CONFIG>::export_dir()
{
	cout << "-----EXPORT TABLE-----" << endl;
	if ((ULONGLONG)pExportDir == (ULONGLONG)pBase)
	{
		cout << "Invalid address" << endl;
		return;
	}
	if (pExportDir == 0)
	{
		cout << "Nothing to export (Empty directory)" << endl;
		return;
	}
	if ((ULONGLONG)pExportDir - (ULONGLONG)pBase + sizeof(IMAGE_EXPORT_DIRECTORY) > size_of_file)
	{
		cout << "Wrong size of export" << endl;
		return;
	}
	if (pExportDir->NumberOfFunctions == 0)
	{
		cout << "There are no functions. NumberOfFunctions = 0" << endl;
		return;
	}
	if (!fs::exists(c_cur_folder + string("\\export_table")))
	{
		fs::create_directories(c_cur_folder + string("\\export_table"));
	}
	ofstream out(c_cur_folder + string("\\export_table") + string("\\export_table.txt"));
	if (!out.is_open())
	{
		cout << "Failed to open file for writing: " << c_cur_folder + string("\\export_table") + string("\\export_table.txt") << endl;
	}
	else
	{
		cout << "search through the files" << endl;
		DWORD rawN = convert_rva_to_raw(pExportDir->Name);
		DWORD rawAON = convert_rva_to_raw(pExportDir->AddressOfNames);
		if (rawN != 0 && rawN < size_of_file)
		{
			bool flag_b = 0;
			for (int i{}; i < min(size_of_file - rawN, 256); i++)
			{
				if ((pBase + rawN)[i] == '\0')
				{
					flag_b = 1;
					break;
				}
			}
			if (flag_b)
				out << "Name of lib: " << pBase + rawN << endl;
			else
				cout << "Strange name detected" << endl;
		}
		if (rawAON != 0 && rawAON < size_of_file)
		{
			DWORD* pNames = (DWORD*)(pBase + rawAON);
			for (DWORD i = 0; i < pExportDir->NumberOfNames; i++)
			{
				if (rawAON + sizeof(DWORD) * (i + 1) > size_of_file)
				{
					cout << "Strange size of name_arr" << endl;
					break;
				}
				DWORD rawn = convert_rva_to_raw(pNames[i]);
				if (rawn == 0 || rawn > size_of_file)
				{
					cout << "Strange address of name detected" << endl;
					break;
				}
				bool flag = 0;
				for (int u{}; u < min(size_of_file - rawn, 256); u++)
				{
					if ((pBase + rawn)[u] == '\0')
					{
						flag = 1;
						break;
					}
				}
				if (flag)
				{
					char* funcName = pBase + rawn;
					out << funcName << endl;
				}
				else
					cout << "Strange name detected" << endl;
			}
		}
		
	}
}

template <typename NT, typename ULORD, typename THUNK3264, typename TLS, typename LOAD_CONFIG>
void PEParser<NT, ULORD, THUNK3264, TLS, LOAD_CONFIG>::resourse_table()
{
	cout << "-----RESOURCES-----" << endl;
	if ((ULONGLONG)start_of_rsrc == (ULONGLONG)pBase)
	{
		cout << "Invalid address" << endl;
		return;
	}
	if (start_of_rsrc == 0)
	{
		cout << "No resource data. " << endl;
	}
	if ((ULONGLONG)start_of_rsrc - (ULONGLONG)pBase + sizeof(IMAGE_RESOURCE_DIRECTORY) > size_of_file)
	{
		cout << "Not enough space for dir" << endl;
		return;
	}
	else
	{
		cout << "RAW address to rsrc: " << start_of_rsrc << endl;
		string buffer_temp(256, 0);
		if (!fs::exists(c_cur_folder + string("\\resource_table")))
		{
			fs::create_directories(c_cur_folder + string("\\resource_table"));
		}
		ofstream out(c_cur_folder + string("\\resource_table") + string("\\resource_table.txt"));
		if (!out.is_open())
		{
			cout << "Failed to open file for writing: " << c_cur_folder + string("\\resource_table") + string("\\resource_table.txt") << endl;
		}
		else
		{
			cout << "search through the files" << endl;
			func_resourse(start_of_rsrc, 0, (char*)&(buffer_temp[0]), c_cur_folder + string("\\resource_table"), &out);
		}
		out.close();
	}
}


template <typename NT, typename ULORD, typename THUNK3264, typename TLS, typename LOAD_CONFIG>
void PEParser<NT, ULORD, THUNK3264, TLS, LOAD_CONFIG>::func_resourse(DWORD* pointer, int count, string buffer_temp, string filepath, ofstream* out_p)
{
	if (count > 10)
	{
		return;
	}
	string temp_path = "";
	PIMAGE_RESOURCE_DIRECTORY pResDir = (PIMAGE_RESOURCE_DIRECTORY)pointer;
	if ((ULONGLONG)pResDir - (ULONGLONG)pBase + sizeof(IMAGE_RESOURCE_DIRECTORY) > size_of_file)
	{
		cout << "Not enough space for IMAGE_RESOURCE_DIRECTORY" << endl;
		return;
	}
	WORD numberOfEntries = pResDir->NumberOfIdEntries + pResDir->NumberOfNamedEntries;
	pointer = (DWORD*)((char*)pointer + sizeof(IMAGE_RESOURCE_DIRECTORY));
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pResDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)pointer;
	count++;
	for (WORD i = 0; i < numberOfEntries; i++)
	{
		if ((ULONGLONG)pResDir - (ULONGLONG)pBase + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) * (i + 1) > size_of_file)
		{
			cout << "Not enough space for IMAGE_RESOURCE_DIRECTORY_ENTRY" << endl;
			return;
		}
		*out_p << string(count, '-') << "RAW address of dir: " << (ULONGLONG)pResDirEntry - (ULONGLONG)pBase << " ";
		if (pResDirEntry->NameIsString)
		{
			
			IMAGE_RESOURCE_DIRECTORY_STRING* pResDirString = (IMAGE_RESOURCE_DIRECTORY_STRING*)((char*)start_of_rsrc + pResDirEntry->NameOffset);
			if (((ULONGLONG)pResDirString - (ULONGLONG)pBase + sizeof(WORD) > size_of_file) ||
				((ULONGLONG)pResDirString - (ULONGLONG)pBase + sizeof(WORD) + sizeof(wchar_t) * pResDirString->Length > size_of_file))
			{
				cout << "Not enough space for IMAGE_RESOURCE_DIRECTORY_STRING" << endl;
				string str = "Space error";
				temp_path = str;
				if (count == 1)
				{
					buffer_temp = str;
				}

				*out_p << "Name of string: " << str << endl;
			}
			else
			{
				int size_needed = WideCharToMultiByte(CP_UTF8, 0, (const wchar_t*)pResDirString->NameString, pResDirString->Length, NULL, 0, NULL, NULL);

				string str(size_needed, 0);
				WideCharToMultiByte(CP_UTF8, 0, (const wchar_t*)pResDirString->NameString, pResDirString->Length, (char*)&str[0], size_needed, NULL, NULL);
				temp_path = str;
				if (count == 1)
				{
					buffer_temp = str;
				}
				*out_p << "Name of string: " << str << endl;
			}
		}
		else
		{
			if (count == 1)
			{
				string temp = "#" + to_string(pResDirEntry->Id);
				temp_path = temp;
				buffer_temp = temp;
			}
			else
				temp_path = "#" + to_string(pResDirEntry->Id);

			*out_p << "ID: " << dec << pResDirEntry->Id << endl;
		}
		make_valid_string(&temp_path);
		if (pResDirEntry->DataIsDirectory)
		{
			if (!fs::exists(filepath + "\\" + temp_path))
			{
				fs::create_directories(filepath + "\\" + temp_path);
			}
			func_resourse((DWORD*)((char*)start_of_rsrc + (pResDirEntry->OffsetToDirectory & 0x7FFFFFFF)), count, buffer_temp, filepath + "\\" + temp_path, out_p);
		}
		else
		{
			PIMAGE_RESOURCE_DATA_ENTRY pDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((char*)start_of_rsrc + pResDirEntry->OffsetToData);
			if (sizeof(IMAGE_RESOURCE_DATA_ENTRY) + (ULONGLONG)pDataEntry - (ULONGLONG)pBase > size_of_file)
			{
				cout << "Not enough space for IMAGE_RESOURCE_DATA_ENTRY" << endl;
				return;
			}
			*out_p << string(count, '-') << "RVA of data: " << hex << pDataEntry->OffsetToData << " " << buffer_temp << endl;
			size_t size_of_data = pDataEntry->Size;
			*out_p << string(count, '-') << "Size of data: " << dec << size_of_data << endl;
			size_t rawd = convert_rva_to_raw(pDataEntry->OffsetToData);
			if (rawd == 0 || rawd + size_of_data > size_of_file)
			{
				cout << "Strange address or space of Data" << endl;
				return;
			}
			if (buffer_temp == "#24")
			{
				string temp_str{ (char*)(pBase + rawd), size_of_data };
				const char* p = (const char*)&temp_str[0];
				ofstream out(filepath + "\\" + temp_path + ".txt", ios::binary);
				if (!out.is_open())
				{
					*out_p << "Failed to open file for writing: " << filepath << "\\" << temp_path + ".txt" << endl;
				}
				out.write(p, size_of_data);
				out.close();
			}
			else
			{
				char* pData = pBase + rawd;
				ofstream out(filepath + "\\" + temp_path + ".bin", ios::binary);
				if (!out.is_open())
				{
					*out_p << "Failed to open file for writing: " << filepath << "\\" << temp_path << ".bin" << endl;
				}
				out.write(pData, size_of_data);
				out.close();
			}
		}
		pResDirEntry++;
	}
}

template <typename NT, typename ULORD, typename THUNK3264, typename TLS, typename LOAD_CONFIG>
void PEParser<NT, ULORD, THUNK3264, TLS, LOAD_CONFIG>::relocation_table()
{
	cout << "-----RELOCATION-----" << endl;
	if ((ULONGLONG)pReloc == (ULONGLONG)pBase)
	{
		cout << "Invalid address" << endl;
	}
	else if (pReloc == 0)
	{
		cout << "No relocation data." << endl;
	}
	else if ((ULONGLONG)pReloc - (ULONGLONG)pBase + sizeof(IMAGE_BASE_RELOCATION) > size_of_file)
	{
		cout << "Wrong size of dir" << endl;
		return;
	}
	else
	{
		cout << "search through the files" << endl;
		
		if (!fs::exists(c_cur_folder + string("\\relocation")))
		{
			fs::create_directories(c_cur_folder + string("\\relocation"));
		}
		ofstream out(c_cur_folder + string("\\relocation\\relocation.txt"));
		if (!out.is_open())
		{
			cout << "Failed to open file for writing: " << c_cur_folder + string("\\relocation\\relocation.txt") << endl;
			return;
		}
		func_relocation(pData[5].Size, &out);
		out.close();
	}
}

template <typename NT, typename ULORD, typename THUNK3264, typename TLS, typename LOAD_CONFIG>
void PEParser<NT, ULORD, THUNK3264, TLS, LOAD_CONFIG>::func_relocation(DWORD total_size, ofstream* out)
{
	DWORD cur_size = 0;
	typedef union
	{
		DWORD* dword_ptr;
		ULORD* qword_ptr;
	} pointer;
	pointer p;
	int counter = 0;
	PIMAGE_BASE_RELOCATION pReloc_copy = pReloc;
	while (((ULONGLONG)pReloc_copy - (ULONGLONG)pBase + sizeof(IMAGE_BASE_RELOCATION) <= size_of_file) && 
		(pReloc_copy->VirtualAddress != 0) && (cur_size < total_size))
	{
		if (pReloc_copy->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION))
		{
			cout << "Strange size of block" << endl;
			break;
		}


		counter++;
		int block_size = pReloc_copy->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION);
		
		int n = block_size / sizeof(WORD);
		WORD* shP = (WORD*)(pReloc_copy + 1);
		size_t rawR = convert_rva_to_raw(pReloc_copy->VirtualAddress);
		if (rawR == 0 || rawR > size_of_file)
		{
			cout << "Wrong address" << endl;
			return;
		}
		*out << "Block " << dec << counter << ": " << hex << rawR << endl;
		for (int i{}; i < n; i++)
		{

			if ((*shP >> 12) == 0)
			{

				*out << "	for alignment" << endl;
			}
			else if ((*shP >> 12) == IMAGE_REL_BASED_DIR64)
			{
				p.qword_ptr = (ULORD*)(pBase + convert_rva_to_raw(pReloc_copy->VirtualAddress + (*shP & 0x0FFF)));
				if ((ULONGLONG)p.qword_ptr == (ULONGLONG)pBase || (ULONGLONG)p.qword_ptr - (ULONGLONG)pBase + sizeof(ULONGLONG) > size_of_file)
				{
					cout << "Wrong address" << endl;
				}
				else
				{
					*out << "	addressx64: " << *p.qword_ptr << endl;
				}
			}
			else if ((*shP >> 12) == IMAGE_REL_BASED_HIGHLOW)
			{
				p.dword_ptr = (DWORD*)(pBase + convert_rva_to_raw(pReloc_copy->VirtualAddress + (*shP & 0x0FFF)));
				if ((ULONGLONG)p.qword_ptr == (ULONGLONG)pBase || (ULONGLONG)p.qword_ptr - (ULONGLONG)pBase + sizeof(DWORD) > size_of_file)
				{
					cout << "Wrong address" << endl;
				}
				else
				{
					*out << "	addressx32: " << *p.dword_ptr << endl;
				}
			}
			else
			{
				*out << "	other type of relocation: " << hex << (*shP >> 12) << endl;
			}
			shP++;
		}
		cur_size += pReloc_copy->SizeOfBlock;
		pReloc_copy = (PIMAGE_BASE_RELOCATION)((char*)pReloc_copy + pReloc_copy->SizeOfBlock);
	}
}

template <typename NT, typename ULORD, typename THUNK3264, typename TLS, typename LOAD_CONFIG>
void PEParser<NT, ULORD, THUNK3264, TLS, LOAD_CONFIG>::tls_table()
{
	cout << "-----TLS-----" << endl;
	if ((ULONGLONG)pTLSDir == (ULONGLONG)pBase)
	{
		cout << "Invalid address" << endl;
	}
	else if (pTLSDir == 0)
	{
		cout << "No TLS data." << endl;
	}
	else if ((ULONGLONG)pTLSDir - (ULONGLONG)pBase + sizeof(TLS) > size_of_file)
	{
		cout << "Wrong size of dir" << endl;
	}
	else
	{
		func_tls(pNtHeaders->OptionalHeader.ImageBase);
	}
}

template <typename NT, typename ULORD, typename THUNK3264, typename TLS, typename LOAD_CONFIG>
void PEParser<NT, ULORD, THUNK3264, TLS, LOAD_CONFIG>::func_tls (ULORD ImageBase)
{
	if ((ULONGLONG)pTLSDir - (ULONGLONG)pBase + sizeof(TLS) > size_of_file)
	{
		cout << "Strange size" << endl;
		return;
	}
	if (pTLSDir->AddressOfCallBacks == 0)
	{
		cout << "No callback functions" << endl;
		return;
	}
	if (pTLSDir->AddressOfCallBacks <= ImageBase)
	{
		cout << "Strang va" << endl;
		return;
	}
	ULORD rva = pTLSDir->AddressOfCallBacks - ImageBase;
	size_t rawT = convert_rva_to_raw(rva);
	if (rawT == 0)
	{
		cout << "Strange size of func_arr" << endl;
		return;
	}
	ULORD* pCallback = (ULORD*)(pBase + rawT);
	cout << "ImageBase: " << hex << ImageBase << endl;
	while ((ULONGLONG)pCallback - (ULONGLONG)pBase + sizeof(ULORD) < size_of_file  && *pCallback != 0)
	{
		ULORD rva_func = *pCallback - ImageBase;
		cout << "Callback function RVA: " << hex << rva_func << endl;
		pCallback++;
	}
}

template <typename NT, typename ULORD, typename THUNK3264, typename TLS, typename LOAD_CONFIG>
void PEParser<NT, ULORD, THUNK3264, TLS, LOAD_CONFIG>::delay_import_table()
{
	cout << "-----DELAY IMPORT TABLE-----" << endl;
	if ((ULONGLONG)pDelayDesc == (ULONGLONG)pBase)
	{
		cout << "Invalid address" << endl;
		return;
	}
	if (pDelayDesc == 0)
	{
		cout << "No delay import data.(Directory is empty)" << endl;
		return;
	}
	if (pDelayDesc->DllNameRVA == 0)
	{
		cout << "No delay import data.(Empty table)" << endl;
		return;
	}
	if ((ULONGLONG)pDebugDir - (ULONGLONG)pBase + sizeof(IMAGE_DELAYLOAD_DESCRIPTOR) > size_of_file)
	{
		cout << "Wrong size of dir" << endl;
		return;
	}
	if (!fs::exists(c_cur_folder + string("\\delay_import_table")))
	{
		fs::create_directories(c_cur_folder + string("\\delay_import_table"));
	}
	ofstream out(c_cur_folder + string("\\delay_import_table") + string("\\delay_import_table.txt"));
	if (!out.is_open())
	{
		cout << "Failed to open file for writing: " << c_cur_folder + string("\\delay_import_table") + string("\\delay_import_table.txt") << endl;
		return;
	}
	cout << "search through the files" << endl;
	PIMAGE_DELAYLOAD_DESCRIPTOR temp_p = pDelayDesc;
	while ((ULONGLONG)temp_p - (ULONGLONG)pBase + sizeof(IMAGE_DELAYLOAD_DESCRIPTOR) <= size_of_file && temp_p->DllNameRVA != 0)
	{
		size_t rawN = convert_rva_to_raw(temp_p->DllNameRVA);
		if (rawN == 0 || rawN > size_of_file)
		{
			cout << "Strange name address" << endl;
		}
		else
		{
			bool flag = 0;
			for (int i{}; i < min(size_of_file - rawN, 256); i++)
			{
				if ((pBase + rawN)[i] == '\0')
				{
					flag = 1;
					break;
				}
			}
			if (flag)
				out << "DLL name: " << (pBase + rawN) << endl;
			else
				cout << "Strange name detected" << endl;
		}
		size_t rawT = convert_rva_to_raw(temp_p->ImportNameTableRVA);
		if (rawT == 0 || rawT + sizeof(THUNK3264) > size_of_file)
		{
			cout << "Strange address of THUNK3264" << endl;
			return;
		}
		THUNK3264* pThunkData = (THUNK3264*)(pBase + rawT);
		ULONGLONG mask1 = 0x80000000;
		ULONGLONG mask2 = 0x7FFFFFFF;
		if (sizeof(THUNK3264) == 8)
		{
			mask1 = 0x8000000000000000;
			mask2 = 0x7FFFFFFFFFFFFFFF;
		}
		while ((ULONGLONG)pThunkData - (ULONGLONG)pBase + sizeof(THUNK3264) <= size_of_file && pThunkData->u1.Ordinal != 0)
		{
			if ((pThunkData->u1.Ordinal & mask1) != 0)
			{
				out << "	Import by ordinal: " << dec << (pThunkData->u1.Ordinal & mask2) << endl;
			}
			else
			{
				size_t rawn = convert_rva_to_raw(pThunkData->u1.AddressOfData);
				if (rawn == 0 || rawn + sizeof(WORD) + 1 > size_of_file)
				{
					cout << "Wrong address of f name" << endl;
				}
				else
				{
					IMAGE_IMPORT_BY_NAME* pFN = (IMAGE_IMPORT_BY_NAME*)(pBase + rawn);
					bool flagn = 0;
					for (int i{}; i < min(size_of_file - rawn, 256); i++)
					{
						if ((pFN->Name)[i] == '\0')
						{
							flagn = 1;
							break;
						}
					}
					if (flagn)
						out << "	Import by name: " << (pFN)->Name << endl;
					else
						cout << "Strange name detected(function)" << endl;
				}
			}
			pThunkData++;
		}
		temp_p++;
		out << endl;
	}
	out.close();
}

template <typename NT, typename ULORD, typename THUNK3264, typename TLS, typename LOAD_CONFIG>
void PEParser<NT, ULORD, THUNK3264, TLS, LOAD_CONFIG>::debug_directory()
{
	cout << "-----DEBUG DIRECTORY-----" << endl;
	if ((ULONGLONG)pDebugDir == (ULONGLONG)pBase)
	{
		cout << "Invalid address" << endl;
	}
	if (pDebugDir == 0)
	{
		cout << "No debug data." << endl;
		return;
	}
	size_t debug_size = pData[6].Size;
	if (!fs::exists(c_cur_folder + string("\\debug_dir")))
	{
		fs::create_directories(c_cur_folder + string("\\debug_dir"));
	}
	cout << "search through the files" << endl;
	IMAGE_DEBUG_DIRECTORY* pDebugDir_copy = pDebugDir;
	size_t sizeOfData = 0;
	char* pDataDebug = nullptr;
	map<DWORD, int> count_map = {};
	for (size_t i{}; i < debug_size / sizeof(IMAGE_DEBUG_DIRECTORY); i++)
	{
		//cout << dec << "Debug Directory[" << i + 1 << "] Type: " << pDebugDir_copy->Type << endl;
		if ((ULONGLONG)pDebugDir_copy - (ULONGLONG)pBase + sizeof(IMAGE_DEBUG_DIRECTORY) * (i + 1) > size_of_file)
		{
			cout << "Wrong size of dir" << endl;
			return;
		}

		sizeOfData = pDebugDir_copy->SizeOfData;
		pDataDebug = pBase + pDebugDir_copy->PointerToRawData;
		size_t dataAddr = convert_rva_to_raw(pDebugDir_copy->AddressOfRawData);
		if (dataAddr != pDebugDir_copy->PointerToRawData)
		{
			cout << "There are wrong information about Data address" << endl;
			continue;
		}
		if (pDebugDir_copy->PointerToRawData + sizeOfData > size_of_file)
		{
			cout << "Wrong addr or size of DebugData" << endl;
			continue;
		}
		if (!fs::exists(c_cur_folder + string("\\debug_dir\\type_") + to_string(pDebugDir_copy->Type)))
		{
			fs::create_directories(c_cur_folder + string("\\debug_dir\\type_" + to_string(pDebugDir_copy->Type)));
		}
		if (pDebugDir_copy->Type == 2)
		{
			count_map[2]++;
			ofstream out1(c_cur_folder + string("\\debug_dir\\type_2\\") + to_string(count_map[2]) + string(".bin"), ios::binary);
			ofstream out2(c_cur_folder + string("\\debug_dir\\type_2\\") + to_string(count_map[2]) + string(".txt"));
			if (!out1.is_open() || !out2.is_open())
			{
				cout << "Failed to open file for writing: " << c_cur_folder + string("\\debug_dir\\type_2") + to_string(count_map[2]) + string(".bin or .txt") << endl;
			}
			else
			{
				if ((ULONGLONG)pDataDebug - (ULONGLONG)pBase + sizeof(DWORD) + sizeof(GUID) + sizeof(DWORD) > size_of_file)
				{
					cout << "Wrong size" << endl;
					continue;
				}
				out1.write(pDataDebug, sizeOfData);

				out2 << "Signature: " << pDataDebug[0] << pDataDebug[1] << pDataDebug[2] << pDataDebug[3] << endl;
				if ( *((DWORD*)pDataDebug) == 0x53445352)
				{
					out2 << "GUID" << hex << endl << setfill('0') << setw(8) << *((DWORD*)(pDataDebug + 4)) << "-" << setfill('0') << setw(4) << *((WORD*)(pDataDebug + 8)) << "-" << setfill('0') << setw(4) << *((WORD*)(pDataDebug + 10)) << "-";
					for (int i{}; i < 8; i++)
					{
						out2 << hex << setfill('0') << setw(2) << (int)*((unsigned char*)(pDataDebug + 12 + i));
						if (i == 1)
						{
							out2 << "-";
						}
					}
					out2 << endl << "Age: " << dec << *((DWORD*)(pDataDebug + 20)) << endl;
					bool flag = 0;
					for (int i{}; i < min(size_of_file - (pDebugDir_copy->PointerToRawData + 24), 256); i++)
					{
						if ((pDataDebug + 24)[i] == '\0')
						{
							flag = 1;
							break;
						}
					}
					if (flag)
						out2 << "PDB File Name: " << (char*)(pDataDebug + 24) << endl;
					else
						cout << "Strange name detected" << endl;
				}
				else if (*((DWORD*)pDataDebug) == 0x3031424E)	
				{
					if ((ULONGLONG)pDataDebug - (ULONGLONG)pBase + sizeof(DWORD) + sizeof(DWORD) > size_of_file)
					{
						cout << "Wrong size" << endl;
						continue;
					}
					out2 << "TimeDataStamp: " << *((DWORD*)(pDataDebug + 8)) << endl;
					out2 << "Age: " << *((DWORD*)(pDataDebug + 12)) << endl;

					bool flag = 0;
					for (int i{}; i < min(size_of_file - pDebugDir_copy->PointerToRawData - 16, 256); i++)
					{
						if ((pDataDebug + 16)[i] == '\0')
						{
							flag = 1;
							break;
						}
					}
					if (flag)
						out2 << "PDB File Name: " << (char*)(pDataDebug + 16) << endl;
					else
						cout << "Strange name detected" << endl;
				}
				else
				{
					out2 << "Unknown debug format." << endl;
				}
			}
			out1.close();
			out2.close();
		}
		else if (pDebugDir_copy->Type == 4)
		{
			count_map[4]++;
			PIMAGE_DEBUG_MISC pMisc = (PIMAGE_DEBUG_MISC)(pDataDebug);
			if (12 + (ULONGLONG)pMisc - (ULONGLONG)pBase > size_of_file)
			{
				cout << "No enough space fo Misc" << endl;
				pDebugDir_copy++;
				continue;
			}
			ofstream out1(c_cur_folder + string("\\debug_dir\\type_4\\") + to_string(count_map[4] ) + string(".bin"), ios::binary);
			if (!out1.is_open())
			{
				cout << "Failed to open file for writing: " << c_cur_folder + string("\\debug_dir\\type_4") + to_string(count_map[4]) + string(".bin") << endl;
			}
			else
			{
				out1.write(pDataDebug, sizeOfData);
				out1.close();
			}
			if (pMisc->DataType == 1)
			{
				ofstream out2(c_cur_folder + string("\\debug_dir\\type_4\\") + to_string(count_map[4]) + string(".txt"));
				if (!out2.is_open())
				{
					cout << "Failed to open file for writing: " << c_cur_folder + string("\\debug_dir\\type_4") + to_string(count_map[4]) + string(".txt") << endl;
				}
				else
				{
					if (pMisc->Unicode)
					{
						if (pDebugDir_copy->PointerToRawData + pMisc->Length > size_of_file
							|| pDebugDir_copy->PointerToRawData + pMisc->Length - 12 > 256 * 2 ||
							pMisc->Length <= 13)
						{
							cout << "Strange length of string" << endl;
						}
						else
						{
							size_t size_needed = WideCharToMultiByte(CP_UTF8, 0, (const wchar_t*)pMisc->Data, (pMisc->Length - 12) / 2, NULL, 0, NULL, NULL);
							string str(size_needed, 0);
							WideCharToMultiByte(CP_UTF8, 0, (const wchar_t*)pMisc->Data, (pMisc->Length - 12) / 2, (char*)&str[0], size_needed, NULL, NULL);
							out2 << str << endl;
						}
					}
					else
					{
						bool flag = 0;
						for (int i{}; i < min(min(size_of_file - pDebugDir_copy->PointerToRawData - 12, pMisc->Length - 12), 256); i++)
						{
							if (((char*)pMisc->Data)[i] == '\0')
							{
								flag = 1;
								break;
							}
						}
						if (flag)
							out2 << (char*)pMisc->Data << endl;
						else
							cout << "Detected strange misc name" << endl;
					}
				}
				out2.close();
			}
			else
			{
				ofstream out2(c_cur_folder + string("\\debug_dir\\type_4\\") + to_string(count_map[4]) + string(".txt"));
				out2 << "Unknown DataType";
				out2.close();
			}
		}

		else
		{
			count_map[pDebugDir_copy->Type]++;
			ofstream out(c_cur_folder + string("\\debug_dir\\type_") + to_string(pDebugDir_copy->Type) + string("\\") + to_string(count_map[pDebugDir_copy->Type]) + string(".bin"), ios::binary);
			if (!out.is_open())
			{
				cout << "Failed to open file for writing: " << c_cur_folder + string("\\debug_dir\\type_") + to_string(pDebugDir_copy->Type) + string("\\") + to_string(count_map[pDebugDir_copy->Type] - 1) + string(".bin") << endl;
			}
			else
			{
				out.write(pDataDebug, sizeOfData);
				out.close();
			}
		}
		pDebugDir_copy++;
	}
}
template <typename NT, typename ULORD, typename THUNK3264, typename TLS, typename LOAD_CONFIG>
void PEParser<NT, ULORD, THUNK3264, TLS, LOAD_CONFIG>::load_config_table()
{
	if ((ULONGLONG)pLoadConfigTable == (ULONGLONG)pBase)
	{
		cout << "Invalid address" << endl;
		return;
	}
	if (pLoadConfigTable == 0)
	{
		cout << "No load config data." << endl;
		return;
	}
	if (pData[10].Size < sizeof(DWORD))
	{
		cout << "It's too small" << endl;
		return;
	}
	if (pData[10].Size != pLoadConfigTable->Size)
	{
		cout << "Something strange with the size" << endl;
	}
	size_t size = min(pData[10].Size, pLoadConfigTable->Size);
	cout << "-----LOAD CONFIG TABLE-----" << endl;
	cout << "Size: " << dec << size << endl;
	bool flag_system32 = pNtHeaders->OptionalHeader.Magic == 0x10b;
	//Cookie
	if (offsetof(LOAD_CONFIG, SecurityCookie) + sizeof(ULORD) <= size)
	{
		ULORD va = pLoadConfigTable->SecurityCookie;
		if (va == 0)
		{
			cout << "Security Cookie is NULL" << endl;
		}
		else if (va < pNtHeaders->OptionalHeader.ImageBase)
		{
			cout << "Security Cookie VA address is not avaliable";
		}
		else
		{
			cout << "Security Cookie VA: " << hex << va << endl;
			cout << "Security Cookie RVA: " << hex << va - pNtHeaders->OptionalHeader.ImageBase << endl;
			size_t raw = convert_rva_to_raw(((DWORD)va - pNtHeaders->OptionalHeader.ImageBase));
			if (raw != 0 && (raw + sizeof(ULORD)) <= size_of_file)
			{
				cout << "Security Cookie RAW: " << hex << raw << endl;
				cout << "Security Cookie Value: " << *(ULORD*)(pBase + raw) << endl;
			}
			else
			{
				cout << "Something wrong with cookie" << endl;
			}
		}
	}
	else
	{
		cout << "wrong Cookie offset" << endl;
	}
	if (!fs::exists(c_cur_folder + string("\\load_config_table")))
	{
		fs::create_directories(c_cur_folder + string("\\load_config_table"));
	}
	ofstream out(c_cur_folder + string("\\load_config_table") + string("\\list.txt"));
	if (!out.is_open())
	{
		cout << "Failed to open file for writing: " << c_cur_folder + string("\\load_config_table") + string("\\list.txt") << endl;
		return;
	}

	if (flag_system32)
	{
		if ((offsetof(LOAD_CONFIG, SEHandlerTable) + sizeof(DWORD) > size) || (offsetof(LOAD_CONFIG, SEHandlerCount) + sizeof(DWORD) > size))
		{
			cout << "wrong SEHandlerTable or SEHandlerCount offset" << endl;
		}
		else
		{
			DWORD count = pLoadConfigTable->SEHandlerCount;
			if (pLoadConfigTable->SEHandlerTable == 0 || count == 0)
			{
				cout << "SEHandlerTable or SEHandlerCount == 0" << endl;
			}
			else
			{
				DWORD raw_table = convert_rva_to_raw(pLoadConfigTable->SEHandlerTable - pNtHeaders->OptionalHeader.ImageBase);
				if (raw_table == 0)
				{
					cout << "c_r_t_r error" << endl;
				}
				else
				{
					cout << "SEHandleTable. search through the files" << endl;

					out << "Number of SEHandlerTable functions: " << dec << count << endl;
					if (raw_table + count * 4 > size_of_file)
					{
						out << "But... there are too many function addresses here" << endl;
						for (DWORD i{}; raw_table + i * 4 + 4 <= size_of_file; i++)
						{
							DWORD* rva_func = (DWORD*)(pBase + raw_table + i * sizeof(DWORD));
							out << "	Function RVA: " << hex << *rva_func << endl;
						}
					}
					else
					{
						for (DWORD i{}; i < count; i++)
						{
							DWORD* rva_func = (DWORD*)(pBase + raw_table + i * sizeof(DWORD));
							out << "	Function RVA: " << hex << *rva_func << endl;
						}
					}
				}
			}
		}
	}

	if (offsetof(LOAD_CONFIG, GuardFlags) + sizeof(DWORD) > size)
	{
		cout << "wrong GuardFlags offset" << endl;
	}
	else
	{
		if (pLoadConfigTable->GuardFlags & 0x100)
		{
			if ((offsetof(LOAD_CONFIG, GuardCFFunctionTable) + sizeof(ULORD) > size) || (offsetof(LOAD_CONFIG, GuardCFFunctionCount) + sizeof(ULORD) > size))
			{
				cout << "wrong GuardCFFunctionTable or GuardCFFunctionCount offset" << endl;
			}
			else
			{
				cout << "CFG enabled. search through the files" << endl;
				DWORD functions_count = pLoadConfigTable->GuardCFFunctionCount;
				out << "Number of CFG functions: " << dec << functions_count << endl;
				if (functions_count != 0)
				{
					size_t rawaddr = convert_rva_to_raw(pLoadConfigTable->GuardCFFunctionTable - pNtHeaders->OptionalHeader.ImageBase);
					if (rawaddr == 0 || rawaddr + sizeof(DWORD) > size_of_file)
					{
						cout << "Wrong address of function" << endl;
						return;
					}
					DWORD* pFunctions = (DWORD*)(rawaddr);
					if (pFunctions == 0 || (ULONGLONG)pFunctions + sizeof(DWORD) > size_of_file)
					{
						cout << "Something wrong with CFG functions" << endl;
						out.close();
						return;
					}
					pFunctions = (DWORD*)(pBase + (ULONGLONG)pFunctions);
					int shift = 0;
					if (pLoadConfigTable->GuardFlags & 0x400)
					{
						shift = (pLoadConfigTable->GuardFlags & 0xf0000000) >> 28;
					}
					for (int i{}; (i < functions_count); i++)
					{
						if (((ULONGLONG)pFunctions - (ULONGLONG)pBase) + sizeof(DWORD) + shift > size_of_file)
						{
							out << "Address is too big" << endl;
							break;
						}
						else
						{
							out << "	Function RVA: " << hex << *pFunctions;
							if (shift)
							{
								out << " Extra data: ";
								for (int j{}; j < shift; j++)
								{
									out << hex << setfill('0') << setw(2) << (int)*((unsigned char*)(pFunctions + 1) + j);
								}
							}
							out << endl;
							pFunctions = (DWORD*)((char*)(pFunctions + 1) + shift);
						}
					}
				}
			}
		}
		else
		{
			cout << "  CFG disabled." << endl;
		}
		out.close();
	}
}

template <typename NT, typename ULORD, typename THUNK3264, typename TLS, typename LOAD_CONFIG>
void PEParser<NT, ULORD, THUNK3264, TLS, LOAD_CONFIG>::secutity_table()
{
	cout << "-----SEC TABLE-----" << endl;
	size_t size = pData[4].Size;
	size_t done = 0;
	if ((ULONGLONG)pSec - (ULONGLONG)pBase == 0)
	{
		cout << "There are no Sec table" << endl;
		return;
	}
	
	if ((ULONGLONG)pSec - (ULONGLONG)pBase + size > size_of_file)
	{
		cout << "Something wrong with the address" << endl;
		return;
	}
	cout << dec << "total size(from DataDir): " << size << endl;
	WIN_CERTIFICATE* pSecCopy = pSec;
	if (!fs::exists(c_cur_folder + "\\sec_table"))
	{
		fs::create_directories(c_cur_folder + "\\sec_table");
	}
	int counter = 1;
	while (pSecCopy != 0 && ((ULONGLONG)pSecCopy - (ULONGLONG)pBase + sizeof(WIN_CERTIFICATE) <= size_of_file) && (done + 8 <= size))
	{
		cout << dec << "Length: " << pSecCopy->dwLength << endl;
		if (((ULONGLONG)pSecCopy - (ULONGLONG)pBase + pSecCopy->dwLength > size_of_file) || (done + pSecCopy->dwLength > size))
		{
			cout << "It's too big" << endl;
			break;
		}
		if (pSecCopy->dwLength < 8)
		{
			cout << "Its Length < 8. -break" << endl;
			break;
		}
		cout << hex << "Revision: " << pSecCopy->wRevision << endl;
		cout << hex << "Type: " << pSecCopy->wCertificateType << endl;	
		ofstream out;
		if (pSecCopy->wCertificateType == 0x0002)
		{
			out.open(c_cur_folder + "\\sec_table\\" + to_string(counter) + ".p7b", ios::binary);
		}
		else
		{
			out.open(c_cur_folder + "\\sec_table\\" + to_string(counter) + ".bin", ios::binary);
		}
		if (!out.is_open())
		{
			cout << "Failed to open file for writing: " << c_cur_folder + string("\\sec_table") + string("\\list.") << endl;
			return;
		}
		out.write((const char*)(&pSecCopy->bCertificate), pSecCopy->dwLength - 8);
		int lena = ((ULONGLONG)pSecCopy->dwLength + 7) & ~7;
		done += lena;
		pSecCopy = (WIN_CERTIFICATE*)((char*)pSecCopy + lena);
		counter++;
		out.close();
		cout << endl;
	}
}


template <typename NT, typename ULORD, typename THUNK3264, typename TLS, typename LOAD_CONFIG>
void PEParser<NT, ULORD, THUNK3264, TLS, LOAD_CONFIG>::exception_table()
{
	cout << "-----EXEPTION TABLE-----" << endl;
	if (pExc == NULL)
	{
		cout << "No exeption table. x32" << endl;
		return;
	}
	size_t size = pData[3].Size;
	if (((ULONGLONG)pExc - (ULONGLONG)pBase == 0) || (size == 0))
	{
		cout << "No exeption table" << endl;
		return;
	}
	if ((ULONGLONG)pExc - (ULONGLONG)pBase + size > size_of_file)
	{
		cout << "Something wrong with Exc table" << endl;
		return;
	}
	if (!fs::exists(c_cur_folder + "\\exeption_table"))
	{
		fs::create_directories(c_cur_folder + "\\exeption_table");
	}
	int counter = 0;
	RUNTIME_FUNCTION* pExcCopy = pExc;
	cout << "Size: " << dec << size << endl;
	cout << "Number of RUNTIME_FUNCTION: " << dec << size / sizeof(RUNTIME_FUNCTION) << endl;
	set<DWORD> addresses;
	for (int i{}; i < size; i += sizeof(RUNTIME_FUNCTION))
	{
		addresses.insert(pExcCopy[i / sizeof(RUNTIME_FUNCTION)].UnwindData);
	}
	for (int i{}; i < size; i += sizeof(RUNTIME_FUNCTION))
	{
		counter++;
		if (!fs::exists(c_cur_folder + "\\exeption_table\\" + to_string(counter)))
		{
			fs::create_directories(c_cur_folder + "\\exeption_table\\" + to_string(counter));
		}
		ofstream out_txt(c_cur_folder + "\\exeption_table\\" + to_string(counter) + "\\" + to_string(counter) + ".txt");
		if (!out_txt.is_open())
		{
			cout << "Failed to open file for writing: " << c_cur_folder + "\\exeption_table\\" + to_string(counter) + "\\" + to_string(counter) + ".txt" + ".txt" << endl;
			out_txt.close();
			return;
		}
		func_exception(counter, pExcCopy, &out_txt, 0, &addresses);
		pExcCopy++;
		out_txt.close();
	}
}
template <typename NT, typename ULORD, typename THUNK3264, typename TLS, typename LOAD_CONFIG>
void PEParser<NT, ULORD, THUNK3264, TLS, LOAD_CONFIG>::func_exception(int counter, RUNTIME_FUNCTION* pRun, ofstream* out_txt, int depth, set<DWORD>* addresses)
{
	DWORD imageSize = pNtHeaders->OptionalHeader.SizeOfImage;
	if (pRun->BeginAddress >= imageSize || pRun->UnwindData >= imageSize)
	{
		return; 
	}
	if (pRun->BeginAddress >= pRun->EndAddress || pRun->BeginAddress == 0)
	{
		return;
	}
	if (depth >= 32)
	{
		return;
	}
	*out_txt << "BeginAddress rva: " << pRun->BeginAddress << endl;
	*out_txt << "EndAddress rva: " << pRun->EndAddress << endl;
	*out_txt << "UnwindData rva: " << pRun->UnwindData << endl;
	if (pRun->BeginAddress >= pRun->EndAddress || pRun->BeginAddress == 0)
	{
		return;
	}
	size_t addr = convert_rva_to_raw(pRun->UnwindData);
	if (addr == 0 || addr + sizeof(UNWIND_INFO_HEADER) > size_of_file)
	{
		cout << "Wrong address of UNWIND_INFO_HEADER" << endl;
		cout << "Failed RVA: " << hex << (pRun->UnwindData) << " in function " << dec << counter << endl;
		return;
	}
	UNWIND_INFO_HEADER* pInfo = (UNWIND_INFO_HEADER*)(pBase + addr);
	*out_txt << "UNWIND_INFO:\nFlags: ";
	for (int i{4}; i >= 0; i--)
	{
		*out_txt << ((pInfo->Flags >> i) & 1);
	}
	*out_txt << " SizeOfProlog: " << (int)pInfo->SizeOfProlog;
	*out_txt << " CountOfCodes: " << (int)pInfo->CountOfCodes << endl;
	if (addr + sizeof(UNWIND_INFO_HEADER) + pInfo->CountOfCodes * sizeof(UNWIND_CODE) > size_of_file)
	{
		cout << "Wrong size of UNWIND_INFO(number of UNWIND_CODE)" << endl;
		return;
	}
	unsigned char* pointer = (unsigned char*)pInfo + sizeof(UNWIND_INFO_HEADER) + pInfo->CountOfCodes * sizeof(UNWIND_CODE) + (pInfo->CountOfCodes & 1) * 2;
	if (pInfo->Flags & 0x04)
	{
		ofstream out_bin(c_cur_folder + "\\exeption_table\\" + to_string(counter) + "\\" + to_string(counter) + "_" + to_string(depth) + ".bin");
		if (!out_bin.is_open())
		{
			cout << "Failed to open file for writing: " << c_cur_folder + "\\exeption_table\\" + to_string(counter) + "\\" + to_string(depth + 1) + ".bin" << endl;
			out_bin.close();
			return;
		}
		out_bin.write((const char*)pInfo, 8 + pInfo->CountOfCodes * sizeof(UNWIND_CODE) + (pInfo->CountOfCodes & 1) * 2);
		addr = convert_rva_to_raw(*((ULONG*)pointer));
		if (addr == 0 || addr + sizeof(RUNTIME_FUNCTION) > size_of_file)
		{
			cout << "Wrong address of RUNTIME_FUNCTION in recursion" << endl;
			return;
		}
		func_exception(counter, (RUNTIME_FUNCTION*)(pBase + addr), out_txt, depth + 1, addresses); // FunctionEntry
		out_bin.close();
		return;
	}
	else if (pInfo->Flags == 0)
	{
		ofstream out_bin(c_cur_folder + "\\exeption_table\\" + to_string(counter) + "\\" + to_string(counter) + ".bin");
		if (!out_bin.is_open())
		{
			cout << "Failed to open file for writing: " << c_cur_folder + "\\exeption_table\\" + to_string(counter) + "\\" + to_string(depth + 1) + ".bin" << endl;
			out_bin.close();
			return;
		}
		*out_txt << "No Language Specific Data (LSDA)" << endl;
		out_bin.write((const char*)pInfo, 4 + pInfo->CountOfCodes * sizeof(UNWIND_CODE));
		out_bin.close();
		return;
	}
	else
	{
		ofstream out_bin(c_cur_folder + "\\exeption_table\\" + to_string(counter) + "\\" + to_string(counter) + ".bin");
		if (!out_bin.is_open())
		{
			cout << "Failed to open file for writing: " << c_cur_folder + "\\exeption_table\\" + to_string(counter) + "\\" + to_string(depth + 1) + ".bin" << endl;
			out_bin.close();
			return;
		}
		out_bin.write((const char*)pInfo, 8 + pInfo->CountOfCodes * sizeof(UNWIND_CODE) + (pInfo->CountOfCodes & 1) * 2);
		*out_txt << "Personality Routine rva: " << *((ULONG*)pointer) << endl;
		addr = convert_rva_to_raw(*((ULONG*)pointer));
		if (addr == 0 || addr + 1 > size_of_file)
		{
			cout << "Wrong PR address" << endl;
			return;
		}
		unsigned char* p_text = (unsigned char*)(pBase + addr);
		if (*((WORD*)p_text) == 0x25FF)
		{
			DWORD disp = *((int32_t*)(p_text + 2));
			if ((uint64_t)(p_text + 6 + disp) < 0)
			{
				cout << "Wrong displacement" << endl;
				return;
			}
			ULONGLONG iat_rva = (ULONGLONG)(*((ULONG*)pointer) + 6 + disp);
			ULONGLONG ilt_rva = import_map[iat_rva];

			ULONGLONG iat_raw = convert_rva_to_raw(iat_rva);
			ULONGLONG ilt_raw = convert_rva_to_raw(ilt_rva);
			if (iat_raw == 0 || ilt_raw == 0 || ilt_raw + sizeof(ULONGLONG) > size_of_file || iat_raw + sizeof(ULONGLONG) > size_of_file)
			{
				cout << "Invalid iat or ilt raw address" << endl;
				return;
			}
			THUNK3264* p_iat = (THUNK3264*)(pBase + iat_raw);
			THUNK3264* p_ilt = (THUNK3264*)(pBase + ilt_raw);
			
			if (p_ilt->u1.Ordinal == 0 && p_iat->u1.Ordinal == 0)
			{
				*out_txt << "Only 0" << endl;
				return;
			}
			else if (p_ilt->u1.Ordinal == 0)
			{
				p_ilt = p_iat;
			}

			if (p_ilt->u1.Ordinal & 0x8000000000000000)
			{
				*out_txt << "Know only ordinal: " << (p_ilt->u1.Ordinal & 0x7FFFFFFFFFFFFFFF) << endl;
			}
			else
			{
				ULONGLONG name_rva = p_ilt->u1.AddressOfData;
				ULONGLONG name_raw = convert_rva_to_raw(name_rva);
				if (name_raw == 0 || name_raw >= size_of_file)
				{
					cout << "Invalid name address" << endl;
				}
				PIMAGE_IMPORT_BY_NAME pName = PIMAGE_IMPORT_BY_NAME(pBase + name_raw);
				
				bool flag = 0;
				for (size_t i = 0; i < min(size_of_file - name_raw, 1024); i++)
				{
					if (pName->Name[i] == '\0')
					{
						flag = 1;
						break;
					}
				}
				if (!flag)
				{
					cout << "Very strange name" << endl;
					return;
				}
				*out_txt << "Import by name: " << pName->Name << endl;

				if (string((char*)pName->Name) == "__C_specific_handler")
				{
					size_t scope_count = *((ULONG*)pointer);
					size_t scope_size = 4 + (sizeof(ULONG) * 4 * scope_count);
					out_bin.write((const char*)(pointer + 4), min(scope_size, size_of_file - (ULONGLONG)(pointer + 4) + (ULONGLONG)pBase));
					return;
				}
			}
		}
		size_t sectionEnd = get_section_end(pRun->UnwindData);
		pointer += 4;
		auto it = addresses->upper_bound(pRun->UnwindData);
		size_t lsdaSize = 0;
		if (it != addresses->end())
		{
			if (*it > sectionEnd)
			{
				lsdaSize = sectionEnd;
			}
			else
			{
				lsdaSize = *it;
			}
		}
		else
		{
			lsdaSize = sectionEnd;
		}
		if (lsdaSize <= pRun->UnwindData + ((ULONGLONG)pointer - (ULONGLONG)pInfo))
		{
			cout << "Strange size" << endl;
			return;
		}
		lsdaSize = lsdaSize - pRun->UnwindData - ((ULONGLONG)pointer - (ULONGLONG)pInfo);
		out_bin.write((const char*)pointer, min(lsdaSize, size_of_file - (ULONGLONG)pointer));
		return;
	}
}



int main() {
	string filePath = "C:\\Windows\\System32\\ntdll.dll";
	//string filePath = "C:\\Windows\\SysWOW64\\kernel32.dll";
	//string filePath = "E:\\games\\Tor Browser\\Browser\\firefox.exe";
	//string filePath = "C:\\Windows\\System32\\notepad.exe";
	//string filePath = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
	//string filePath = "C:\\Program Files\\WinRAR\\Rar.exe";
	//start open file
	//string filePath = "E:\\games\\Tor Browser\\Browser\\firefox.exe";

	ifstream file(filePath, ios::binary | ios::ate);
	if (!file.is_open()) {
		cout << "Failed to open file: " << filePath << endl;
		return 1;
	}
	size_t size = file.tellg();
	file.seekg(0, ios::beg);
	vector<char> buffer(size);
	char* p_to_data = buffer.data();
	if (!file.read(buffer.data(), size)) return 1;

	PIMAGE_DOS_HEADER pd = (PIMAGE_DOS_HEADER)p_to_data;
	PIMAGE_NT_HEADERS pnt = (PIMAGE_NT_HEADERS)(p_to_data + pd->e_lfanew);
	if (pnt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		PEParser<PIMAGE_NT_HEADERS64, ULONGLONG, IMAGE_THUNK_DATA64, IMAGE_TLS_DIRECTORY64, IMAGE_LOAD_CONFIG_DIRECTORY64> parser(filePath, &buffer, size);
		parser.parse_it();
		return 0;
	}
	else if (pnt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		PEParser<PIMAGE_NT_HEADERS32, DWORD, IMAGE_THUNK_DATA32, IMAGE_TLS_DIRECTORY32, IMAGE_LOAD_CONFIG_DIRECTORY32> parser(filePath, &buffer, size);
		parser.parse_it();
		return 0;
	}
	else
	{
		cout << "Unknown format." << endl;
		return 1;
	}
}