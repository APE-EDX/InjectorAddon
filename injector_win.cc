// injector.cc
#include <Windows.h>
#include <tlhelp32.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")
#define _WIN32_WINNT 0x0501


typedef BOOL (WINAPI *IsWow64Process_t) (HANDLE, PBOOL);
IsWow64Process_t IsWow64Process_g;

DWORD openMode = PROCESS_ALL_ACCESS;

enum ProcessBits {
    PROCESS_32,
    PROCESS_32_64,
    PROCESS_64
};

ProcessBits IsWow64Process(HANDLE handle)
{
    BOOL bIsWow64 = FALSE;

    IsWow64Process_g = (IsWow64Process_t)GetProcAddress(GetModuleHandleA("kernel32"), "IsWow64Process");

    if (NULL != IsWow64Process_g)
    {
        if (!IsWow64Process_g(handle, &bIsWow64))
        {
            return PROCESS_32;
        }
    }
    else
    {
        return PROCESS_32;
    }

	if (bIsWow64)
	{
		return PROCESS_32_64;
	}

	SYSTEM_INFO info;
	GetNativeSystemInfo(&info);
	if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
	{
		return PROCESS_64;
	}

	return PROCESS_32;
}


bool enableDebugPriv()
{
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;
    bool success = false;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
        {
            tkp.PrivilegeCount = 1;
            tkp.Privileges[0].Luid = luid;
            tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            if (AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL))
            {
                success = true;
            }
        }

        CloseHandle(hToken);
    }

    return success;
}

template <typename T> bool startWithPipe(const char* process, T& retval)
{
    bool success = false;
    const size_t stringSize = 1000;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Defaut to -1
    retval = (T)-1;

    // Open pipe
    HANDLE hPipe = CreateNamedPipe(TEXT("\\\\.\\pipe\\APEKernelPipe"), PIPE_ACCESS_DUPLEX | PIPE_TYPE_BYTE | PIPE_READMODE_BYTE, PIPE_WAIT, 1, 1024 * 16, 1024 * 16, NMPWAIT_USE_DEFAULT_WAIT, NULL);
    if (hPipe != INVALID_HANDLE_VALUE)
    {
        // Start the child process.
        if (CreateProcessA(NULL,   // No module name (use command line)
            (LPSTR)process,   // Command line
            NULL,           // Process handle not inheritable
            NULL,           // Thread handle not inheritable
            FALSE,          // Set handle inheritance to FALSE
            0,              // No creation flags
            NULL,           // Use parent's environment block
            NULL,           // Use parent's starting directory
            &si,            // Pointer to STARTUPINFO structure
            &pi)           // Pointer to PROCESS_INFORMATION structure
            )
        {
            if (ConnectNamedPipe(hPipe, NULL) != FALSE)
            {
                uint64_t address;
                DWORD dwRead;
                if (ReadFile(hPipe, (void*)&address, sizeof(uint64_t), &dwRead, NULL) != FALSE)
                {
                    retval = (T)address;
                    success = true;
                }
            }
        }

        // Close pipe
        DisconnectNamedPipe(hPipe);

        // Wait until child process exits.
        WaitForSingleObject(pi.hProcess, INFINITE);

        // Close process and thread handles.
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    return success;
}

bool injectToPID(char* path, char* kernel32Exe, int pid)
{
    openMode = PROCESS_ALL_ACCESS;
    if (!enableDebugPriv())
    {
        openMode = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
    }

    HANDLE hProcess = OpenProcess(openMode, FALSE, pid);
    if (hProcess == NULL)
    {
        return false;
    }

    LPVOID loadLibrary = NULL;
    ProcessBits bits = IsWow64Process(hProcess);
    ProcessBits ownBits = IsWow64Process(GetCurrentProcess());

    const char* arch = (bits == PROCESS_64) ? "64" : "32";
    if (bits != ownBits)
    {
        // Setup correct bits for Kernel32 process call
        int pos = strlen(kernel32Exe);
        while (pos > 0 && kernel32Exe[--pos] != '{') {}
        kernel32Exe[pos] = arch[0]; kernel32Exe[pos + 1] = arch[1];

        if (!startWithPipe(kernel32Exe, loadLibrary))
        {
            CloseHandle(hProcess);
            return false;
        }
    }
    else
    {
        loadLibrary = (LPVOID)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA");
    }

    // Setup correct bits for DLL
    int pos = strlen(path);
    while (pos > 0 && path[--pos] != '{') {}
    path[pos] = arch[0]; path[pos + 1] = arch[1];

    // Alloc size for the path
    const size_t pathLen = strlen(path);
    LPVOID pathAddr = VirtualAllocEx(hProcess, NULL, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pathAddr == NULL)
    {
        CloseHandle(hProcess);
        return false;
    }

    // Write the path
    if (WriteProcessMemory(hProcess, pathAddr, (LPCVOID)path, pathLen, NULL) == 0)
    {
        CloseHandle(hProcess);
        return false;
    }

    // Create the LoadLibraryA thread
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)loadLibrary, pathAddr, 0, NULL);
    if (hThread == NULL)
    {
        CloseHandle(hProcess);
        return false;
    }

    // Wait for the thread and cleanup
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}

void injectDLL(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    // Check the number of arguments passed.
    if (args.Length() < 3)
    {
        // Throw an Error that is passed back to JavaScript
        isolate->ThrowException(Exception::TypeError(
            String::NewFromUtf8(isolate, "Wrong number of arguments")));
        return;
    }

    // Check the argument types
    if (!args[0]->IsString() || !args[1]->IsString() || !args[2]->IsString())
    {
        isolate->ThrowException(Exception::TypeError(
            String::NewFromUtf8(isolate, "Wrong arguments")));
        return;
    }

    // Perform the operation
    v8::String::Utf8Value processV8(args[0]->ToString());
    const char* process = *processV8;

    v8::String::Utf8Value pathV8(args[1]->ToString());
    char* path = *pathV8;

    v8::String::Utf8Value kernel32V8(args[2]->ToString());
    char* kernel32Exe = *kernel32V8;

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (stricmp(entry.szExeFile, process) == 0)
            {
                bool success = injectToPID(path, kernel32Exe, entry.th32ProcessID);
                CloseHandle(snapshot);
                args.GetReturnValue().Set(Boolean::New(isolate, success));
                return;
            }
        }
    }

    CloseHandle(snapshot);
    args.GetReturnValue().Set(Boolean::New(isolate, false));
}

void injectDLLByPID(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    // Check the number of arguments passed.
    if (args.Length() < 3)
    {
        // Throw an Error that is passed back to JavaScript
        isolate->ThrowException(Exception::TypeError(
            String::NewFromUtf8(isolate, "Wrong number of arguments")));
        return;
    }

    // Check the argument types
    if (!args[0]->IsInt32() || !args[1]->IsString() || !args[2]->IsString())
    {
        isolate->ThrowException(Exception::TypeError(
            String::NewFromUtf8(isolate, "Wrong arguments")));
        return;
    }

    int32_t pid = args[0]->Int32Value();

	v8::String::Utf8Value pathV8(args[1]->ToString());
	char* path = *pathV8;

	v8::String::Utf8Value kernel32V8(args[2]->ToString());
	char* kernel32Exe = *kernel32V8;

    bool success = injectToPID(path, kernel32Exe, pid);
    args.GetReturnValue().Set(Boolean::New(isolate, success));
}
