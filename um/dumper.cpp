#include "dumper.h"
#include "hv.h"

#include <fstream>
#include <cstdio>
#include <cstring>
#include <windows.h>
#include <psapi.h>

static bool enable_debug_privilege() {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
    return false;

  LUID luid{};
  if (!LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &luid)) {
    CloseHandle(token);
    return false;
  }

  TOKEN_PRIVILEGES tp{};
  tp.PrivilegeCount           = 1;
  tp.Privileges[0].Luid       = luid;
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

  AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
  auto const gle = GetLastError();
  CloseHandle(token);
  return gle == ERROR_SUCCESS;
}

static bool name_matches(char const* full_path_or_base, char const* want_name) {
  if (!full_path_or_base || !want_name)
    return false;

  // compare base name only
  char const* base = full_path_or_base;
  for (auto p = full_path_or_base; *p; ++p) {
    if (*p == '\\' || *p == '/')
      base = p + 1;
  }

  // Fast path: exact case-insensitive match (basename vs input)
  if (_stricmp(base, want_name) == 0)
    return true;

  // Normalize both sides: strip a trailing ".sys" (case-insensitive) if present.
  auto strip_sys = [](char* s) {
    size_t const n = strlen(s);
    if (n >= 4 && _stricmp(s + (n - 4), ".sys") == 0)
      s[n - 4] = '\0';
  };

  char base_copy[MAX_PATH] = {};
  char want_copy[MAX_PATH] = {};
  strncpy_s(base_copy, base, _TRUNCATE);
  strncpy_s(want_copy, want_name, _TRUNCATE);

  strip_sys(base_copy);
  strip_sys(want_copy);

  // allow matching "hv" <-> "hv.sys"
  if (_stricmp(base_copy, want_copy) == 0)
    return true;

  return false;
}

struct RTL_PROCESS_MODULE_INFORMATION {
  PVOID  Section;
  PVOID  MappedBase;
  PVOID  ImageBase;
  ULONG  ImageSize;
  ULONG  Flags;
  USHORT LoadOrderIndex;
  USHORT InitOrderIdnex;
  USHORT LoadCount;
  USHORT OffsetToFileName;
  CHAR   FullPathName[0x100];
};

struct RTL_PROCESS_MODULES {
  ULONG                          NumberOfModules;
  RTL_PROCESS_MODULE_INFORMATION Modules[1];
};

// get the image base and image size of a loaded driver
bool find_loaded_driver(char const* const name, void*& imagebase, uint32_t& imagesize) {
  using NtQuerySystemInformationFn = NTSTATUS(NTAPI*)(uint32_t SystemInformationClass,
    PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
  static auto const NtQuerySystemInformation = (NtQuerySystemInformationFn)(
    GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation"));

  imagebase = nullptr;
  imagesize = 0;

  if (!NtQuerySystemInformation || !name)
    return false;

  // best-effort: enable SeDebugPrivilege (often required on Win11 for module lists)
  enable_debug_privilege();

  // 1) Preferred: NtQuerySystemInformation(SystemModuleInformation=0x0B)
  {
    unsigned long length = 0;
    auto st = NtQuerySystemInformation(0x0B, nullptr, 0, &length);
    if (length != 0) {
      auto const raw = new uint8_t[length + 0x200];
      ZeroMemory(raw, length + 0x200);
      auto const info = reinterpret_cast<RTL_PROCESS_MODULES*>(raw);

      st = NtQuerySystemInformation(0x0B, info, length + 0x200, &length);
      if (st >= 0) {
        for (unsigned int i = 0; i < info->NumberOfModules; ++i) {
          auto const& m = info->Modules[i];
          if (!name_matches(m.FullPathName + m.OffsetToFileName, name))
            continue;

          imagebase = m.ImageBase;
          imagesize = m.ImageSize;

          delete[] raw;
          return imagebase != nullptr;
        }
      }

      delete[] raw;
    }
  }

  // 2) Fallback: EnumDeviceDrivers works in many environments where SystemModuleInformation is restricted.
  {
    LPVOID drivers[4096] = {};
    DWORD bytes_needed = 0;
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &bytes_needed))
      return false;

    auto const count = bytes_needed / sizeof(drivers[0]);
    char base_name[MAX_PATH] = {};
    for (DWORD i = 0; i < count; ++i) {
      if (!drivers[i])
        continue;
      ZeroMemory(base_name, sizeof(base_name));
      if (!GetDeviceDriverBaseNameA(drivers[i], base_name, static_cast<DWORD>(sizeof(base_name))))
        continue;
      if (!name_matches(base_name, name))
        continue;

      imagebase = drivers[i];
      imagesize = 0; // unknown via this API
      return true;
    }
  }

  return false;
}

// dump a running driver to a file
bool dump_driver(char const* const name, char const* path) {
  if (!hv::is_hv_running())
    return false;

  hv::shared_queue_session sq;
  if (!sq.open())
    return false;

  void*    imagebase = nullptr;
  uint32_t imagesize = 0;

  if (!find_loaded_driver(name, imagebase, imagesize))
    return false;

  auto const buffer = std::make_unique<uint8_t[]>(imagesize);
  if (imagesize != sq.read_virtual(/*target_cr3=*/0, buffer.get(), imagebase, imagesize))
    return false;

  auto const dos_header = (PIMAGE_DOS_HEADER)&buffer[0];
  auto const nt_header = (PIMAGE_NT_HEADERS)(&buffer[0] + dos_header->e_lfanew);
  auto const sections = (PIMAGE_SECTION_HEADER)(nt_header + 1);

  // fix the imagebase field in the PE header
  nt_header->OptionalHeader.ImageBase = (uintptr_t)imagebase;

  // fix the sections
  for (size_t i = 0; i < nt_header->FileHeader.NumberOfSections; ++i)
    sections[i].PointerToRawData = sections[i].VirtualAddress;

  char file_name[1024] = {};

  if (!path) {
    sprintf_s(file_name, "%s.dump", name);
    path = file_name;
  }

  std::ofstream file(path, std::ios::binary);
  file.write((char const*)buffer.get(), imagesize);

  return true;
}

