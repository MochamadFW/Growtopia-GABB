// MemomoryRead.cpp : Ten plik zawiera funkcję „main”. W nim rozpoczyna się i kończy wykonywanie programu.
//

#include <Windows.h>
#include <iostream>
#include <conio.h>
#include <vector>
#include <conio.h>
#include <TlHelp32.h>

bool isValidHex4(std::string text, int set_index = 0);
std::string InsertKey(std::string text, std::string Key, int seed = 0);
std::string RemoveKey(std::string text, std::string Key, int seed = 0);

/*int ReadMemoryInt(HANDLE hProc, DWORD PID, std::wstring moduleName, DWORD base_offset, std::vector<DWORD> offset);
int ReadMemoryInt(std::wstring title, std::wstring moduleName, DWORD base_offset, std::vector<DWORD> offset);
BOOL SetPrivilege(HANDLE hToken, LPCTSTR Privilege, BOOL bEnablePrivilege);
DWORD_PTR GetModuleBaseAddress(std::wstring lpszModuleName, DWORD PID);*/

std::string SystemCommand(std::wstring cmd);

std::wstring s2ws(const std::string &s) {
	return std::wstring(s.begin(), s.end());
}

int main() {
	/*HANDLE hToken;
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)) {
		if (GetLastError() == ERROR_NO_TOKEN) {
			if (!ImpersonateSelf(SecurityImpersonation)) return 1;
			if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)) {
				std::cout << "Error: OpenThreadToken\n";
				return 1;
			}
		} else return 1;
	}

	if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE)) {
		std::cout << "Error: SetPrivilege\n";
		CloseHandle(hToken);
		return 1;
	}*/

	while (1) {
		while (_kbhit()) if (_getch() == 'q') break;
		std::cout <<
			RemoveKey(SystemCommand(L"memscan64.exe " + s2ws(InsertKey("Growtopia [1]\\\nGrowtopia.exe\\\n0x003d0f40\\\n0x104\\\n", "prockey64", 13))), "prockey64", 11).c_str() << "\n" << 
			RemoveKey(SystemCommand(L"memscan32.exe " + s2ws(InsertKey("Growtopia [1]\\\nGrowtopia.exe\\\n0x003d0f40\\\n0x104\\\n", "prockey64", 13))), "prockey64", 11).c_str() << "\n";

		//std::cout << ReadMemoryInt(L"Growtopia [1]", L"Growtopia.exe", 0x003D0F40, { 0x104 }) << "\n";
		Sleep(1000);
	}
	return 0;
}

/*int ReadMemoryInt(HANDLE hProc, DWORD PID, std::wstring moduleName, DWORD base_offset, std::vector<DWORD> offset) {
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
		std::cout << "Failed to find window!\n";
		return -1;
	}
	DWORD PID = 0;
	GetWindowThreadProcessId(Wnd, &PID);

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, PID);
	if (hProc == NULL) {
		std::cout << "Failed to open process![" << GetLastError() << "]\n";
		return -1;
	}

	DWORD_PTR BaseAddr = GetModuleBaseAddress(moduleName, PID);
	DWORD_PTR pointer = 0;

	if (!offset.size()) { if (!ReadProcessMemory(hProc, (LPVOID)(BaseAddr + base_offset), &pointer, sizeof(pointer), NULL)) return -2; }
	else {
		if (!ReadProcessMemory(hProc, (LPVOID)(BaseAddr + base_offset), &pointer, sizeof(pointer), NULL)) return -3;
		for (unsigned int i = 0; i < offset.size(); i++) if (!ReadProcessMemory(hProc, (LPVOID)(pointer + offset[i]), &pointer, sizeof(pointer), NULL)) return -4;
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
}*/

struct pipeSet {
	HANDLE g_hChildStd_OUT_Rd = NULL;
	HANDLE g_hChildStd_OUT_Wr = NULL;
	HANDLE g_hChildStd_ERR_Rd = NULL;
	HANDLE g_hChildStd_ERR_Wr = NULL;
};
#define MAX_PIPE_BUFSIZE 4096

bool CreateChildProcess(wchar_t * command, pipeSet &pipes);
std::string ReadFromPipe(pipeSet &pipes);

std::string SystemCommand(std::wstring cmd) {
	pipeSet pipes;
	SECURITY_ATTRIBUTES sa;
	//printf("\n->Start of parent execution.\n");
	// Set the bInheritHandle flag so pipe handles are inherited.
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = TRUE;
	sa.lpSecurityDescriptor = NULL;
	// Create a pipe for the child process's STDERR.
	if (!CreatePipe(&(pipes.g_hChildStd_ERR_Rd), &(pipes.g_hChildStd_ERR_Wr), &sa, 0)) {
		return InsertKey("0 -1", "prockey64", 11);
	}
	// Ensure the read handle to the pipe for STDERR is not inherited.
	if (!SetHandleInformation(pipes.g_hChildStd_ERR_Rd, HANDLE_FLAG_INHERIT, 0)) {
		return InsertKey("0 -2", "prockey64", 11);
	}
	// Create a pipe for the child process's STDOUT.
	if (!CreatePipe(&(pipes.g_hChildStd_OUT_Rd), &(pipes.g_hChildStd_OUT_Wr), &sa, 0)) {
		return InsertKey("0 -3", "prockey64", 11);
	}
	// Ensure the read handle to the pipe for STDOUT is not inherited
	if (!SetHandleInformation(pipes.g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0)) {
		return InsertKey("0 -4", "prockey64", 11);
	}
	// Create the child process.
	wchar_t * comm = new wchar_t[cmd.length() + 1];
	for (unsigned int i = 0; i <= cmd.length(); i++) {
		if (i != cmd.length()) comm[i] = cmd[i];
		else comm[i] = '\0';
	}
	if (!CreateChildProcess(comm, pipes)) {
		return InsertKey("0 -5", "prockey64", 11);
	}

	// Read from pipe that is the standard output for child process.
	std::string result = ReadFromPipe(pipes);

	CloseHandle(pipes.g_hChildStd_ERR_Rd);
	CloseHandle(pipes.g_hChildStd_OUT_Rd);

	return result;
}

bool CreateChildProcess(wchar_t * command, pipeSet &pipes) {
	PROCESS_INFORMATION piProcInfo;
	STARTUPINFO siStartInfo;
	bool bSuccess = FALSE;

	ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));

	ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
	siStartInfo.cb = sizeof(STARTUPINFO);
	siStartInfo.hStdError = pipes.g_hChildStd_ERR_Wr;
	siStartInfo.hStdOutput = pipes.g_hChildStd_OUT_Wr;
	siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

	bSuccess = CreateProcess(NULL, command, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &siStartInfo, &piProcInfo);

	CloseHandle(piProcInfo.hProcess);
	CloseHandle(piProcInfo.hThread);
	CloseHandle(pipes.g_hChildStd_ERR_Wr);
	CloseHandle(pipes.g_hChildStd_OUT_Wr);
	if (!bSuccess) return 0;
	return 1;
}


std::string ReadFromPipe(pipeSet &pipes) {
	DWORD dwRead;
	CHAR chBuf[MAX_PIPE_BUFSIZE];
	bool bSuccess = FALSE;
	std::string out = "", err = "";
	for (;;) {
		bSuccess = ReadFile(pipes.g_hChildStd_OUT_Rd, chBuf, MAX_PIPE_BUFSIZE, &dwRead, NULL);
		if (!bSuccess || dwRead == 0) break;
		out += std::string(chBuf, dwRead);
	}
	dwRead = 0;
	for (;;) {
		bSuccess = ReadFile(pipes.g_hChildStd_ERR_Rd, chBuf, MAX_PIPE_BUFSIZE, &dwRead, NULL);
		if (!bSuccess || dwRead == 0) break;
		err += std::string(chBuf, dwRead);
	}
	if (out.length() == 0) return err;
	return out;
}

BOOL SetPrivilege( HANDLE hToken, LPCTSTR Privilege, BOOL bEnablePrivilege ) {
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