#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <imagehlp.h>
#include "map"
#include "string"
#pragma comment(lib, "user32")
#pragma comment(lib, "ole32")
#pragma comment(lib, "imagehlp")

#define STRCAT(x, y) x##y
#define LOG(x) do { fputs(STRCAT(STRCAT("[DEBUG] ", #x), "\n"), stderr); fflush(stderr); } while (0)
#define ERR(i, x) do { fputs(STRCAT(STRCAT("[ERROR] ", #x), "\n"), stderr); fflush(stderr); return i; } while (0)

#ifndef MOD_NOREPEAT
#define MOD_NOREPEAT 0x4000
#endif

#define VirtualProtect     VirtualProtect_Org
#define ReadProcessMemory  ReadProcessMemory_Org
#define WriteProcessMemory WriteProcessMemory_Org

namespace iat_impl
{
  using namespace std;
  static map <string, void *> IATAddress;
  static map <string, void *> RealAddress;
  static HMODULE hModule;
  static int (__stdcall *VirtualProtect_Org)(const void*, int, int, const void *);
  static int (__stdcall *WriteProcessMemory_Org)(const void*, const void*, const void*, int, const void *);
  static int (__stdcall *ReadProcessMemory_Org)(const void*,const void*, const void*, int, const void *);


  void WriteMemory(const void *addr, const void *start, int size)
  {
    DWORD attr;
    VirtualProtect((void *)addr, size, PAGE_EXECUTE_READWRITE, &attr);
    WriteProcessMemory(GetCurrentProcess(), addr, start, size, 0);
    VirtualProtect((void *)addr, size, attr, 0);
  }
  
  void ReadMemory(const void *dest, const void *src, int size)
  {
    DWORD attr;
    VirtualProtect((void *)src, size, PAGE_EXECUTE_READWRITE, &attr);
    ReadProcessMemory(GetCurrentProcess(), src, dest, size, 0);
    VirtualProtect((void *)src, size, attr, 0);
  }
  
  void ResetTable(HANDLE hd)
  {
    IATAddress.clear();
    RealAddress.clear();
    hModule = (HMODULE) hd;
    if (!VirtualProtect_Org)
    {
      HMODULE hKernel   = LoadLibrary("Kernel32");
      VirtualProtect_Org  = (int (__stdcall *)(const void*, int, int, const void *))GetProcAddress(hKernel, "VirtualProtect");
      ReadProcessMemory_Org   = (int (__stdcall *)(const void*, const void*, const void*, int, const void *))GetProcAddress(hKernel, "ReadProcessMemory");
      WriteProcessMemory_Org  = (int (__stdcall *)(const void*, const void*, const void*, int, const void *))GetProcAddress(hKernel, "WriteProcessMemory");
    }
  }
    
  #define _mem(base, offset, type) ( *(type*)((int)base+(int)offset))
  #define _memint(base, offset) _mem(base, offset, int)
  #define _memuint(base, offset) _mem(base, offset, unsigned int)
    
  void InitTable()
  {
    IMAGE_IMPORT_DESCRIPTOR *pIID;
    DWORD base = (DWORD)hModule;
    DWORD size;
    pIID = (IMAGE_IMPORT_DESCRIPTOR*) ImageDirectoryEntryToData(hModule, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size); 
    while(pIID->FirstThunk != 0){
      char *name1 = (char*) (base+pIID->Name);
      static char modname[1024];
      strncpy(modname, name1, 1024);
      for (char *p = modname; *p; p++) *p = tolower(*p);
      if (strcmp(modname, "common.dll") == 0) {
        IMAGE_THUNK_DATA *piatthunk = (IMAGE_THUNK_DATA*) ( base + pIID->FirstThunk);
        IMAGE_THUNK_DATA *pintthunk = (IMAGE_THUNK_DATA*) ( base + *(DWORD*)pIID ); 
        while(piatthunk->u1.Function != 0) {
          char *name2 = (char*)(((IMAGE_IMPORT_BY_NAME*) (base+pintthunk->u1.AddressOfData))->Name);
          static char out[2048];
          sprintf(out, "%s.%s", modname, name2);
          IATAddress[out]=&piatthunk->u1.Function;
          RealAddress[out]=(void *)piatthunk->u1.Function;
          piatthunk++;
          pintthunk++;
        }
      }
      pIID++;
    }   
  }
  int RedirectFunc(const char *name1, const char* name2)
  {
    map <string, void *> :: iterator it = IATAddress.find(name1);
    if (it == IATAddress.end()) return 0;
    map <string, void *> :: iterator it2 = RealAddress.find(name2);
    if (it2 == RealAddress.end()) return 0;
    int org = *(int *)IATAddress[name1];
    WriteMemory(it->second, &it2->second, sizeof(it2->second));
    return org;
  }
  
  template <typename T>
  int RedirectFunc(const char *name1, T* name2)
  {
    map <string, void *> :: iterator it = IATAddress.find(name1);
    if (it == IATAddress.end()) return 0;
    int org = *(int *)IATAddress[name1];
    WriteMemory(it->second, &name2, sizeof(name2));
    return org;
  }
}

int (*pfn_Camera_IPCServiceMain)();

HANDLE hMutex;

DWORD WINAPI camera_ipc_thread(LPVOID lpParam) {
  LOG(Thread CameraIPC Started);
  ReleaseMutex(hMutex);
  pfn_Camera_IPCServiceMain();
  LOG(Thread CameraIPC Stopped);
  return 0;
}

int hookTime = 0;
int* (*origGetParentDir)(int*, int);
int* GetParentDir(int* out, int in) {
  LOG(Camera.dll Hook Hit);
  hookTime++;
  if (hookTime == 2) {
    iat_impl::RedirectFunc("common.dll.?GetParentDir@FS@Util@@YA?AVCTXStringW@@V3@@Z", origGetParentDir);
    LOG(Camera.dll Hook Uninstalled);
    *out = in;
    return out;
  } else {
    return origGetParentDir(out, in);
  }
}

int main() {
  char* path = getenv("PATH");
  char* newpath = (char*) calloc(strlen(path) + 100, 1);
  strcpy(newpath, "PATH=.\\Bin;\0");
  strcat(newpath, path);
  putenv(newpath);
  free(newpath);

  OleInitialize(NULL);

  LOG(Ready to load Camera.dll);

  HMODULE hCamera = LoadLibrary("Camera.dll");
  if (!hCamera) ERR(1, Cannot load Camera.dll);
  LOG(Camera.dll Loaded);

  iat_impl::ResetTable(hCamera);
  LOG(Camera.dll Hook Reseted);

  iat_impl::InitTable();
  LOG(Camera.dll Hook Inited);

  origGetParentDir = (int *(*)(int *,int))iat_impl::RedirectFunc("common.dll.?GetParentDir@FS@Util@@YA?AVCTXStringW@@V3@@Z", GetParentDir);
  LOG(Camera.dll Hook Installed);

  pfn_Camera_IPCServiceMain = (int (*)()) GetProcAddress(hCamera, "IPCServiceMain");
  if (!pfn_Camera_IPCServiceMain) ERR(2, Cannot locate Camera.dll!IPCServiceMain);
  LOG(Camera.dll!IPCServiceMain Located);

  DWORD dwThreadId;
  hMutex = CreateMutex(NULL, FALSE, NULL);
  HANDLE hThread = CreateThread(NULL, 0, camera_ipc_thread, NULL, 0, &dwThreadId);
  if (!hThread) ERR(3, Cannot create Thread CameraIPC);
  LOG(Thread CameraIPC Created);

  LOG(Waiting for Thread CameraIPC);
  WaitForSingleObject(hMutex, INFINITE);
  LOG(Returned from Thread CameraIPC);

  if (!RegisterHotKey(NULL, 1, MOD_ALT | MOD_CONTROL | MOD_NOREPEAT, 0x41)) ERR(4, Cannot register hotkey!);
  LOG(Registered hotkey Ctrl+Alt+A);

  MSG msg = {0};
  while (GetMessage(&msg, NULL, 0, 0) != 0)
  {
    if (msg.message == WM_HOTKEY)
    {
      LOG(Hotkey triggered);
      PostThreadMessage(dwThreadId, 2024, 0, 0);
    }
  }
  
  OleUninitialize();
  return 0;
}