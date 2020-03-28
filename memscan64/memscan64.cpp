#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <TlHelp32.h>

bool isValidHex4(std::string text, int set_index = 0);
std::string InsertKey(std::string text, std::string Key, int seed = 0);
std::string RemoveKey(std::string text, std::string Key, int seed = 0);

int ReadMemoryInt(HANDLE hProc, DWORD PID, std::wstring moduleName, DWORD base_offset, std::vector<DWORD> offset);
int ReadMemoryInt(std::wstring title, std::wstring moduleName, DWORD base_offset, std::vector<DWORD> offset);
BOOL SetPrivilege(HANDLE hToken, LPCTSTR Privilege, BOOL bEnablePrivilege);
DWORD_PTR GetModuleBaseAddress(std::wstring lpszModuleName, DWORD PID);

std::vector<std::string> Destroy(std::string ctx, std::string delimiter);

std::wstring s2ws(const std::string &s) {
	return std::wstring(s.begin(), s.end());
}

DWORD HS2D(std::string ctx) {
	DWORD x;
	std::stringstream ss;
	ss << std::hex << ctx;
	ss >> x;
	return x;
}

int main(int argc, char * argv[])
{
	HANDLE hToken;
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)) {
		if (GetLastError() == ERROR_NO_TOKEN) {
			if (!ImpersonateSelf(SecurityImpersonation)) return 1;
			if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)) {
				std::cout << "Error: OpenThreadToken\n";
				return 1;
			}
		}
		else return 1;
	}

	if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE)) {
		std::cout << "Error: SetPrivilege\n";
		CloseHandle(hToken);
		return 1;
	}

	std::string buf;
	for (int i = 1; i < argc; i++) {
		if (isValidHex4(argv[i])) {
			std::vector<std::string> res = Destroy(RemoveKey(argv[i], "prockey64", 13), "\\\n");
			int result = 0;

			if (res.size() >= 3) {
				std::wstring title = s2ws(res[0]), modName = s2ws(res[1]);
				DWORD base = atoi(res[2].c_str());
				std::vector<DWORD> offset;
				for (unsigned int i = 3; i < res.size(); i++) {
					offset.push_back(atoi(res[i].c_str()));
				}
				result = ReadMemoryInt(title, modName, base, offset);
			}
			if (result >= -1364536 && result <= -1364531) buf = "0 " + std::to_string(result + 1364537);
			else buf = "1 " + std::to_string(result);
			std::cout << InsertKey(buf, "prockey64", 11) << "\n";
		}
		else std::cout << InsertKey("0 -1", "prockey64", 11) << "\n";
	}
	CloseHandle(hToken);
}

std::vector<std::string> Destroy(std::string ctx, std::string delimiter) {
	std::vector<std::string> res;
	std::size_t pos;
	while ((pos = ctx.find(delimiter)) != std::string::npos) {
		res.push_back(ctx.substr(0, pos));
		ctx = ctx.substr(pos + delimiter.length());
	}
	return res;
}

int ReadMemoryInt(HANDLE hProc, DWORD PID, std::wstring moduleName, DWORD base_offset, std::vector<DWORD> offset) {
	DWORD_PTR BaseAddr = GetModuleBaseAddress(moduleName, PID);
	DWORD_PTR pointer = 0;

	if (!offset.size()) { if (!ReadProcessMemory(hProc, (LPVOID)(BaseAddr + base_offset), &pointer, sizeof(pointer), NULL)) return -1; }
	else {
		if (!ReadProcessMemory(hProc, (LPVOID)(BaseAddr + base_offset), &pointer, sizeof(pointer), NULL)) return -1;
		for (unsigned int i = 0; i < offset.size(); i++) if (!ReadProcessMemory(hProc, (LPVOID)(pointer + offset[i]), &pointer, sizeof(pointer), NULL)) return -1;
	}
	return (int)pointer;
}

int ReadMemoryInt(std::wstring title, std::wstring moduleName, DWORD base_offset, std::vector<DWORD> offset) {

	HWND Wnd = FindWindow(NULL, title.c_str());
	if (Wnd == NULL) {
		return -1364531;
	}
	DWORD PID = 0;
	GetWindowThreadProcessId(Wnd, &PID);

	HANDLE hProc = OpenProcess(PROCESS_VM_READ, 0, PID);
	if (hProc == NULL) {
		return -1364532;
	}

	DWORD_PTR BaseAddr = GetModuleBaseAddress(moduleName, PID);
	DWORD_PTR pointer = 0;
	if (!offset.size()) { if (!ReadProcessMemory(hProc, (LPVOID)(BaseAddr + base_offset), &pointer, sizeof(pointer), NULL)) return -1364533; }
	else {
		if (!ReadProcessMemory(hProc, (LPVOID)(BaseAddr + base_offset), &pointer, sizeof(pointer), NULL)) return -1364534;
		for (unsigned int i = 0; i < offset.size(); i++) if (!ReadProcessMemory(hProc, (LPVOID)(pointer + offset[i]), &pointer, sizeof(pointer), NULL)) return -1364535;
	}
	CloseHandle(hProc);
	return (int)pointer;
}

DWORD_PTR GetModuleBaseAddress(std::wstring lpszModuleName, DWORD PID) {
	DWORD_PTR dwModuleBaseAddress = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);
	MODULEENTRY32 ModuleEntry32 = { 0 };
	ModuleEntry32.dwSize = sizeof(MODULEENTRY32);

	if (Module32First(hSnap, &ModuleEntry32)) {
		do {
			if (std::wstring(ModuleEntry32.szModule) == lpszModuleName) {
				dwModuleBaseAddress = (DWORD_PTR)ModuleEntry32.modBaseAddr;
				break;
			}
		} while (Module32Next(hSnap, &ModuleEntry32));
	}
	CloseHandle(hSnap);
	return dwModuleBaseAddress;
}

BOOL SetPrivilege(HANDLE hToken, LPCTSTR Privilege, BOOL bEnablePrivilege) {
	TOKEN_PRIVILEGES tp = { 0 };
	LUID luid;
	DWORD cb = sizeof(TOKEN_PRIVILEGES);
	if (!LookupPrivilegeValue(NULL, Privilege, &luid)) return FALSE;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege) tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else tp.Privileges[0].Attributes = 0;
	AdjustTokenPrivileges(hToken, FALSE, &tp, cb, NULL, NULL);
	if (GetLastError() != ERROR_SUCCESS) return FALSE;
	return TRUE;
}

bool isValidHex4(std::string text, int set_index) {
	std::string set[2] = { "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-_", "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_" };
	for (unsigned int i = 0; i < text.length(); i++) if (set[set_index].find(text[i]) == std::string::npos) return false;
	return true;
}

std::string toBits(std::string text) {
	std::string buffer = "";
	for (unsigned int i = 0; i < text.length(); i++) {
		for (int j = 7; j >= 0; j--) {
			buffer += (text[i] & (1 << j) ? '1' : '0');
		}
	}
	return buffer;
}

std::string Hex4ToBits(std::string text, int set_index) {
	std::string set[3] = { "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-_", "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_", "0123456789abcdef" };
	std::string buffer = "";
	std::size_t pos;
	for (unsigned int i = 0; i < text.length(); i++) {
		if ((pos = set[set_index].find(text[i])) == std::string::npos) continue;
		for (int j = 5; j >= 0; j--) {
			buffer += (pos & (1 << j) ? '1' : '0');
		}
	}
	return buffer;
}

std::string bitsToANSII(std::string bits) {
	std::string buffer = "";
	int index = 0;
	int size = (int)bits.length();
	while (index <= size - 7) {
		int c = 0;
		for (int i = 0; i < 8 && index + i < size; i++) {
			if (bits[i + index] == '1') c += 1 << (7 - i);
		}
		buffer += char(c);
		index += 8;
	}
	return buffer;
}

std::string bitsToHex4(std::string bits, int set_index = 0) {
	std::string set[3] = { "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-_", "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_", "0123456789abcdef" };
	std::string buffer = "";
	while (bits.length() % 6 != 0) bits += '0';
	int size = (int)bits.length();
	int index = 0;
	while (index < size) {
		unsigned char c = 0;
		for (int i = 0; i < 6; i++) {
			if (bits[i + index] == '1') c += (1 << (5 - i));
		}
		buffer += set[set_index][c%set[set_index].length()];
		index += 6;
	}
	return buffer;
}

std::string toDec(char numb) {
	std::string buffer = "";
	std::string buf = ""; buf += (int)numb;
	int buflength = (int)buf.length();
	while (buflength < 3) { buffer += '0'; buflength++; }
	buffer += (int)numb;
	return buffer;
}

std::string CutKey(std::string Key, int width, int offset = 0, int offsetMultiplier = 1) {
	if (offsetMultiplier == 0) offsetMultiplier = 1;
	std::string buffer = "";
	for (unsigned int i = 0; i < Key.length(); i++) {
		buffer += char((Key[i] + (offset * offsetMultiplier)) % width);
	}
	return buffer;
}

std::string InsertKeyX(std::string text, std::string Key, int seed = 0)
{
	std::string buffer = text;
	std::string bufkey = Key;
	for (unsigned int i = 0; i < buffer.length(); i++) {
		if (i % 2 == 0)
			buffer[i] = unsigned char((buffer[i] + bufkey[i%bufkey.length()]) % 256);
		else buffer[i] = unsigned char((buffer[i] - bufkey[i%bufkey.length()]) % 256);
	}
	bufkey = CutKey(bufkey, 128, seed *(seed + 1), seed);
	for (unsigned int i = 0; i < buffer.length(); i++) {
		buffer[i] = unsigned char((buffer[i] + bufkey[i%bufkey.length()]) % 256);
	}
	bufkey = CutKey(bufkey, 64, seed + 1, seed * seed);
	for (unsigned int i = 0; i < buffer.length(); i++) {
		buffer[i] = unsigned char((buffer[i] + bufkey[i%bufkey.length()]) % 256);
	}
	bufkey = CutKey(bufkey, 32, seed + 1, seed * seed + 62);
	for (unsigned int i = 0; i < buffer.length(); i++) {
		buffer[i] = unsigned char((buffer[i] + bufkey[i%bufkey.length()]) % 256);
	}
	return buffer;
}

std::string RemoveKeyX(std::string text, std::string Key, int seed = 0)
{
	std::string Key_1 = Key;
	std::string Key_2 = CutKey(Key_1, 128, seed *(seed + 1), seed);
	std::string Key_3 = CutKey(Key_2, 64, seed + 1, seed * seed);
	std::string Key_4 = CutKey(Key_3, 32, seed + 1, seed * seed + 62);
	std::string buffer = text;

	for (unsigned int i = 0; i < buffer.length(); i++)
	{
		buffer[i] = unsigned char((buffer[i] - Key_4[i%Key_4.length()]) % 256);
	}
	for (unsigned int i = 0; i < buffer.length(); i++) {
		buffer[i] = unsigned char((buffer[i] - Key_3[i%Key_3.length()]) % 256);
	}
	for (unsigned int i = 0; i < buffer.length(); i++) {
		buffer[i] = unsigned char((buffer[i] - Key_2[i%Key_2.length()]) % 256);
	}
	for (unsigned int i = 0; i < buffer.length(); i++) {
		if (i % 2 == 0)
			buffer[i] = unsigned char((buffer[i] - Key_1[i%Key_1.length()]) % 256);
		else buffer[i] = unsigned char((buffer[i] + Key_1[i%Key_1.length()]) % 256);
	}
	return buffer;
}

std::string InsertKey(std::string text, std::string Key, int seed) {
	text = InsertKeyX(text, Key, seed);
	std::string buffer = toBits(text);
	buffer = bitsToHex4(buffer, 0);
	return buffer;
}

std::string RemoveKey(std::string text, std::string Key, int seed) {
	text = Hex4ToBits(text, 0);
	text = bitsToANSII(text);
	return RemoveKeyX(text, Key, seed);
}