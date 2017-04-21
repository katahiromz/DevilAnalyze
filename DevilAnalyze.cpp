// DevilAnalyze - A Windows System Analyzer by Katayama Hirofumi MZ.
// This file is public domain software (PDS).
///////////////////////////////////////////////////////////////////////////////

#define LOGO \
    "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n" \
    "$ DevilAnalyze v1.1 by Katayama Hirofumi MZ $\n" \
    "$            katayama.hirofumi.mz@gmail.com $\n" \
    "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n" \

#if defined(UNICODE) && !defined(_UNICODE)
    #define _UNICODE
#endif
#if !defined(UNICODE) && defined(_UNICODE)
    #define UNICODE
#endif

///////////////////////////////////////////////////////////////////////////////
// Settings

//#define DEVANA_USE_STDOUT     // use standard output
//#define DEVANA_NO_ERROR_POUT  // doesn't write error messages
//#define DEVANA_USE_MSEC       // writes milliseconds
//#define DEVANA_USE_DAYOFWEEK  // writes day of week
//#define DEVANA_DO_SPY         // do spy? (can be illegal in some countries)

///////////////////////////////////////////////////////////////////////////////

#include <windows.h>
#include <imagehlp.h>
#include <shlobj.h>
#include <tchar.h>

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <locale>
#include <clocale>
using namespace std;

#pragma comment(lib, "version.lib")

///////////////////////////////////////////////////////////////////////////////

#ifdef UNICODE
    #error Unicode is not supported yet. Please change the project settings.
#endif

#ifdef UNICODE
    #define tcout       wcout
    #define tcerr       wcerr
    #define tstring     wstring
    #define tofstream   wofstream
#else
    #define tcout       cout
    #define tcerr       cerr
    #define tstring     string
    #define tofstream   ofstream
#endif

#ifdef DEVANA_USE_STDOUT
    #define tfout       tcout
#else
    tofstream           tfout;
#endif

///////////////////////////////////////////////////////////////////////////////

WCHAR *AnsiToWide(const CHAR *pszA)
{
    static WCHAR buffer[256];
    MultiByteToWideChar(CP_ACP, 0, pszA, -1, buffer, 256);
    return buffer;
}
CHAR *WideToAnsi(const WCHAR *pszW)
{
    static CHAR buffer[512];
    WideCharToMultiByte(CP_ACP, 0, pszW, -1, buffer, 512, NULL, NULL);
    return buffer;
}
#define AnsiToAnsi(str)         (str)
#define WideToWide(str)         (str)
#ifdef UNICODE
    #define AnsiToText(str)     AnsiToWide(str)
    #define WideToText(str)     WideToWide(str)
    #define TextToAnsi(str)     WideToAnsi(str)
    #define TextToWide(str)     WideToWide(str)
    #define TextToText(str)     WideToWide(str)
#else
    #define AnsiToText(str)     AnsiToAnsi(str)
    #define WideToText(str)     WideToAnsi(str)
    #define TextToAnsi(str)     AnsiToAnsi(str)
    #define TextToWide(str)     AnsiToWide(str)
    #define TextToText(str)     AnsiToAnsi(str)
#endif

///////////////////////////////////////////////////////////////////////////////

#ifdef UNICODE
    template <typename CharT, typename Traits>
    basic_ostream<CharT, Traits>&
    operator<<(basic_ostream<CharT, Traits>& os, const string& str)
    {
        return os << AnsiToWide(str.c_str());
    }
#else
    template <typename CharT, typename Traits>
    basic_ostream<CharT, Traits>&
    operator<<(basic_ostream<CharT, Traits>& os, const wstring& str)
    {
        return os << WideToAnsi(str.c_str());
    }
#endif

template <typename CharT, typename Traits>
basic_ostream<CharT, Traits>&
operator<<(basic_ostream<CharT, Traits>& os, const ULARGE_INTEGER& x)
{
    return os << x.QuadPart;
}

template <typename CharT, typename Traits>
basic_ostream<CharT, Traits>&
operator<<(basic_ostream<CharT, Traits>& os, const FILETIME& ft)
{
    FILETIME LocalTime;
    SYSTEMTIME st;

    FileTimeToLocalFileTime(&ft, &LocalTime);
    FileTimeToSystemTime(&LocalTime, &st);

    TCHAR szTimeStamp[128];
#ifdef DEVANA_USE_DAYOFWEEK
    static const LPCTSTR Week[] =
    {
        TEXT("Sun"), TEXT("Mon"), TEXT("Tue"),  TEXT("Wed"),
        TEXT("Thr"), TEXT("Fri"), TEXT("Sat")
    };
    #ifdef DEVANA_USE_MSEC
        wsprintf(szTimeStamp, TEXT("%04u-%02u-%02u %02u:%02u:%02u.%04u (%s)"),
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, Week[st.wDayOfWeek]);
    #else
        wsprintf(szTimeStamp, TEXT("%04u-%02u-%02u %02u:%02u:%02u (%s)"),
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond, Week[st.wDayOfWeek]);
    #endif
#else
    #ifdef DEVANA_USE_MSEC
        wsprintf(szTimeStamp, TEXT("%04u-%02u-%02u %02u:%02u:%02u.%04u"),
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    #else
        wsprintf(szTimeStamp, TEXT("%04u-%02u-%02u %02u:%02u:%02u"),
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond);
    #endif
#endif

    return os << szTimeStamp;
}

///////////////////////////////////////////////////////////////////////////////

tstring         g_section;
const TCHAR *   g_selected_section = NULL;

class DLL
{
public:
    HINSTANCE m_hInst;

    DLL(const TCHAR *dll) : m_hInst(LoadLibrary(dll))
    {
    }
    ~DLL()
    {
        FreeLibrary(m_hInst);
    }
    template <typename T>
    bool GetProc(T& fn, const char *name)
    {
        if (m_hInst == NULL)
        {
            fn = NULL;
            return false;
        }
        fn = (T)GetProcAddress(m_hInst, name);
        return fn != NULL;
    }
};

// MapFileAndCheckSumA
typedef DWORD (WINAPI *MAPFILEANDCHECKSUMA)(PSTR, PDWORD, PDWORD);
MAPFILEANDCHECKSUMA pMapFileAndCheckSumA = NULL;

typedef DWORD (WINAPI *MAPFILEANDCHECKSUMW)(PWSTR, PDWORD, PDWORD);
MAPFILEANDCHECKSUMW pMapFileAndCheckSumW = NULL;

#ifdef UNICODE
    #define pMapFileAndCheckSum     pMapFileAndCheckSumW
    typedef MAPFILEANDCHECKSUMW     MAPFILEANDCHECKSUM;
    #define MFACS                   "MapFileAndCheckSumW"
#else
    #define pMapFileAndCheckSum     pMapFileAndCheckSumA
    typedef MAPFILEANDCHECKSUMA     MAPFILEANDCHECKSUM;
    #define MFACS                   "MapFileAndCheckSumA"
#endif


// IsWow64Process
typedef void (WINAPI *ISWOW64PROCESS)(HANDLE, PBOOL);
ISWOW64PROCESS pIsWow64Process = NULL;
#define IW64P "IsWow64Process"

///////////////////////////////////////////////////////////////////////////////

TCHAR *SpecialPath(INT csidl)
{
    static TCHAR s_Path[MAX_PATH];
    LPITEMIDLIST pidl = NULL;
    if (NOERROR == SHGetSpecialFolderLocation(NULL, csidl, &pidl))
    {
        SHGetPathFromIDList(pidl, s_Path);
        CoTaskMemFree(pidl);
        return s_Path;
    }
    return NULL;
}

///////////////////////////////////////////////////////////////////////////////

#ifdef DEVANA_NO_ERROR_POUT
    #define FAIL(name) \
        tcerr << "ERROR: " << g_section << ": " << name << " failed\n";
#else
    #define FAIL(name) \
        tfout << "ERROR: " << g_section << ": " << name << " failed\n"; \
        tcerr << "ERROR: " << g_section << ": " << name << " failed\n";
#endif

bool set_section(const tstring& section)
{
    g_section = section;
    if (g_selected_section == NULL ||
        lstrcmpi(section.c_str(), g_selected_section) == 0)
    {
        tfout << "-----------------------\n";
        return true;
    }
    return false;
}
#define CATEGORY(cat) set_section(TEXT(cat))

#define NOT_STR(type) bool is_str(type) { return false; }
NOT_STR(CHAR);
NOT_STR(BYTE);
NOT_STR(SHORT);
NOT_STR(WORD);
NOT_STR(INT);
NOT_STR(UINT);
NOT_STR(LONG);
NOT_STR(DWORD);
NOT_STR(LONGLONG);
NOT_STR(DWORDLONG);

#define IS_STR(type) bool is_str(type) { return true; }
IS_STR(const CHAR *);
IS_STR(const WCHAR *);
IS_STR(const string&);
IS_STR(const wstring&);
IS_STR(const ULARGE_INTEGER&);
IS_STR(const FILETIME&);

template <size_t len>
IS_STR(const CHAR (&)[len]);
template <size_t len>
IS_STR(const WCHAR (&)[len]);

#define POUT(data) do { \
    tfout << g_section << ": " << #data << ": " << dec; \
    if (is_str(data)) { tfout << "\""; } \
    tfout << data; \
    if (is_str(data)) { tfout << "\""; } \
    if (!is_str(data)) { tfout << hex << " (0x" << data << ")"; } \
    tfout << endl; \
} while (0)

#ifdef DEVANA_NO_ERROR_POUT
    #define PERR(data) do { \
        tcerr << "ERROR: " << g_section << ": " << #data << ": " << dec; \
        if (is_str(data)) { tcerr << "\""; } \
        tcerr << data; \
        if (is_str(data)) { tcerr << "\""; } \
        else { tcerr << hex << " (0x" << data << ")"; } \
        tcerr << endl; \
    } while (0)
#else
    #define PERR(data) do { \
        tfout << "ERROR: " << g_section << ": " << #data << ": " << dec; \
        if (is_str(data)) { tfout << "\""; } \
        tfout << data; \
        if (is_str(data)) { tfout << "\""; } \
        else { tfout << hex << " (0x" << data << ")"; } \
        tfout << endl; \
        tcerr << "ERROR: " << g_section << ": " << #data << ": " << dec; \
        if (is_str(data)) { tcerr << "\""; } \
        cerr << data; \
        if (is_str(data)) { tcerr << "\""; } \
        else { tcerr << hex << " (0x" << data << ")"; } \
        tcerr << endl; \
    } while (0)
#endif

///////////////////////////////////////////////////////////////////////////////

struct TRANS { WORD LangID, CodePage; };

const char *GetSCS(DWORD SCS_)
{
    const char *psz;
#ifndef SCS_64BIT_BINARY
    #define SCS_64BIT_BINARY 6
#endif
    switch (SCS_)
    {
    case SCS_32BIT_BINARY: psz = "SCS_32BIT_BINARY"; break;
    case SCS_DOS_BINARY: psz = "SCS_DOS_BINARY"; break;
    case SCS_WOW_BINARY: psz = "SCS_WOW_BINARY"; break;
    case SCS_PIF_BINARY: psz = "SCS_PIF_BINARY"; break;
    case SCS_POSIX_BINARY: psz = "SCS_POSIX_BINARY"; break;
    case SCS_OS216_BINARY: psz = "SCS_OS216_BINARY"; break;
    case SCS_64BIT_BINARY: psz = "SCS_64BIT_BINARY"; break;
    default: psz = "(unknown binary type)";
    }
    return psz;
}

bool dumpver(const TCHAR *file)
{
    TCHAR *filename = const_cast<TCHAR *>(file);
    DWORD dwHandle;
    DWORD Size = GetFileVersionInfoSize(filename, &dwHandle);
    if (!Size)
    {
        FAIL("GetFileVersionInfoSize");
        return false;
    }
    vector<BYTE> block(Size);
    if (!GetFileVersionInfo(filename, dwHandle, Size, &block[0]))
    {
        FAIL("GetFileVersionInfo");
        return false;
    }
    VS_FIXEDFILEINFO *pFixedFileInfo;
    UINT Len;
    if (!VerQueryValue(&block[0], TEXT("\\"), (void **)&pFixedFileInfo, &Len))
    {
        FAIL("VerQueryValue(\\)");
    }
    TRANS *pTrans;
    if (!VerQueryValue(&block[0], TEXT("\\VarFileInfo\\Translation"), (void **)&pTrans, &Len))
    {
        FAIL("VerQueryValue(\\VarFileInfo\\Translation)");
    }
    else
    {
        POUT(pTrans->LangID);
        POUT(pTrans->CodePage);
        TCHAR SubBlock[256];

#define POUT_SUBBLOCK(subblock) \
        TCHAR *p##subblock = NULL; \
        wsprintf(SubBlock, TEXT("\\StringFileInfo\\%04X%04X\\") TEXT(#subblock), pTrans->LangID, pTrans->CodePage); \
        if (VerQueryValue(&block[0], SubBlock, (void **)&p##subblock, &Len)) \
        { \
            POUT(p##subblock); \
        } \

        POUT_SUBBLOCK(CompanyName);
        POUT_SUBBLOCK(FileDescription);
        POUT_SUBBLOCK(FileVersion);
        POUT_SUBBLOCK(InternalName);
        POUT_SUBBLOCK(LegalCopyright);
        POUT_SUBBLOCK(OriginalFilename);
        POUT_SUBBLOCK(ProductName);
        POUT_SUBBLOCK(ProductVersion);
    }
    POUT(pFixedFileInfo->dwSignature);
    POUT(pFixedFileInfo->dwStrucVersion);
    POUT(pFixedFileInfo->dwFileVersionMS);
    POUT(pFixedFileInfo->dwFileVersionLS);
    POUT(pFixedFileInfo->dwProductVersionMS);
    POUT(pFixedFileInfo->dwProductVersionLS);
    POUT(pFixedFileInfo->dwFileFlagsMask);
    POUT(pFixedFileInfo->dwFileFlags);
    POUT(pFixedFileInfo->dwFileOS);
    POUT(pFixedFileInfo->dwFileType);
    POUT(pFixedFileInfo->dwFileSubtype);
    POUT(pFixedFileInfo->dwFileDateMS);
    POUT(pFixedFileInfo->dwFileDateLS);
    return true;
}

const char *GetMachine(WORD wFileHeaderMachine)
{
    const char *psz = "IMAGE_FILE_MACHINE_UNKNOWN";
    switch (wFileHeaderMachine)
    {
    case IMAGE_FILE_MACHINE_I386: psz = "IMAGE_FILE_MACHINE_I386"; break;
    case IMAGE_FILE_MACHINE_R3000: psz = "IMAGE_FILE_MACHINE_R3000"; break;
    case IMAGE_FILE_MACHINE_R4000: psz = "IMAGE_FILE_MACHINE_R4000"; break;
    case IMAGE_FILE_MACHINE_R10000: psz = "IMAGE_FILE_MACHINE_R10000"; break;
    case IMAGE_FILE_MACHINE_WCEMIPSV2: psz = "IMAGE_FILE_MACHINE_WCEMIPSV2"; break;
    case IMAGE_FILE_MACHINE_ALPHA: psz = "IMAGE_FILE_MACHINE_ALPHA"; break;
    case IMAGE_FILE_MACHINE_POWERPC: psz = "IMAGE_FILE_MACHINE_POWERPC"; break;
    case IMAGE_FILE_MACHINE_SH3: psz = "IMAGE_FILE_MACHINE_SH3"; break;
    case IMAGE_FILE_MACHINE_SH3E: psz = "IMAGE_FILE_MACHINE_SH3E"; break;
    case IMAGE_FILE_MACHINE_SH4: psz = "IMAGE_FILE_MACHINE_SH4"; break;
    case IMAGE_FILE_MACHINE_ARM: psz = "IMAGE_FILE_MACHINE_ARM"; break;
    case IMAGE_FILE_MACHINE_THUMB: psz = "IMAGE_FILE_MACHINE_THUMB"; break;
    case IMAGE_FILE_MACHINE_IA64: psz = "IMAGE_FILE_MACHINE_IA64"; break;
    case IMAGE_FILE_MACHINE_MIPS16: psz = "IMAGE_FILE_MACHINE_MIPS16"; break;
    case IMAGE_FILE_MACHINE_MIPSFPU: psz = "IMAGE_FILE_MACHINE_MIPSFPU"; break;
    case IMAGE_FILE_MACHINE_MIPSFPU16: psz = "IMAGE_FILE_MACHINE_MIPSFPU16"; break;
    case IMAGE_FILE_MACHINE_ALPHA64: psz = "IMAGE_FILE_MACHINE_ALPHA64"; break;
    }
    return psz;
}

bool exeout(const TCHAR *file)
{
    if (!set_section(file))
        return false;

    TCHAR Path[MAX_PATH], *pch;
    if ((INT_PTR)FindExecutable(file, NULL, Path) <= 32)
    {
        FAIL("FindExecutable");
        return false;
    }
    POUT(Path);

    DWORD SCS_;
    if (GetBinaryType(Path, &SCS_))
    {
        tfout << "File '" << Path << "' is " << GetSCS(SCS_) << '\n';
    }
    else
    {
        tfout << "File '" << Path << "' is not an executable\n";
    }

    WIN32_FIND_DATA Find;
    HANDLE hFind = FindFirstFile(Path, &Find);
    if (hFind != INVALID_HANDLE_VALUE)
    {
        POUT(Find.dwFileAttributes);
        POUT(Find.ftLastWriteTime);
        POUT(Find.nFileSizeHigh);
        POUT(Find.nFileSizeLow);
    }
    else
    {
        FAIL("FindFirstFile");
    }

    // check sum
    if (pMapFileAndCheckSum)
    {
        DWORD HeaderSum = 0, CheckSum = 0;
        (*pMapFileAndCheckSum)(Path, &HeaderSum, &CheckSum);
        POUT(HeaderSum);
        POUT(CheckSum);
    }

    return dumpver(file);
}
#define EXEOUT(name)    exeout(TEXT(name))

bool dllout(const TCHAR *file)
{
    if (!set_section(file))
        return false;

    TCHAR Path[MAX_PATH], *pch;
    if (!SearchPath(NULL, file, TEXT(".dll"), MAX_PATH, Path, &pch))
    {
        if (!SearchPath(NULL, file, NULL, MAX_PATH, Path, &pch))
        {
            FAIL("SearchPath");
            return false;
        }
    }
    POUT(Path);

    HINSTANCE hDLLInst = LoadLibraryEx(Path, NULL, LOAD_LIBRARY_AS_DATAFILE);
    if (hDLLInst)
    {
        LPBYTE pb = (LPBYTE)hDLLInst;

        IMAGE_DOS_HEADER *pDOS = (IMAGE_DOS_HEADER *)hDLLInst;
        if (pDOS->e_magic == IMAGE_DOS_SIGNATURE)
        {
            pb += pDOS->e_lfanew;
        }

        IMAGE_NT_HEADERS32 *pNT32 = (IMAGE_NT_HEADERS32 *)pb;
        if (pNT32->Signature == IMAGE_NT_SIGNATURE)
        {
            WORD wFileHeaderMachine = pNT32->FileHeader.Machine;
            const char *FileHeaderMachine = GetMachine(wFileHeaderMachine);
            POUT(FileHeaderMachine);
        }
        FreeLibrary(hDLLInst);
    }
    else
    {
        tcout << "LoadLibraryEx failed\n";
    }

    WIN32_FIND_DATA Find;
    HANDLE hFind = FindFirstFile(Path, &Find);
    if (hFind != INVALID_HANDLE_VALUE)
    {
        POUT(Find.dwFileAttributes);
        POUT(Find.ftLastWriteTime);
        POUT(Find.nFileSizeHigh);
        POUT(Find.nFileSizeLow);
    }
    else
    {
        FAIL("FindFirstFile");
    }

    // check sum
    if (pMapFileAndCheckSum)
    {
        DWORD HeaderSum = 0, CheckSum = 0;
        (*pMapFileAndCheckSum)(Path, &HeaderSum, &CheckSum);
        POUT(HeaderSum);
        POUT(CheckSum);
    }

    return dumpver(file);
}
#define DLLOUT(name)    dllout(TEXT(name))

///////////////////////////////////////////////////////////////////////////////

bool DirList(const TCHAR *dir)
{
    HANDLE hFind;
    WIN32_FIND_DATA find;
    TCHAR CurDir[MAX_PATH], Path[MAX_PATH], *pch;

    if (dir == NULL)
    {
        FAIL("dir == NULL");
        return false;
    }

    GetCurrentDirectory(MAX_PATH, CurDir);
    if (!SetCurrentDirectory(dir))
    {
        FAIL(tstring(dir) + TEXT(": SetCurrentDirectory"));
        return false;
    }

    hFind = FindFirstFile(TEXT("*"), &find);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        FAIL(tstring(dir) + TEXT(": FindFirstFile"));
        return false;
    }

    do
    {
        if (lstrcmp(find.cFileName, TEXT(".")) == 0 ||
            lstrcmp(find.cFileName, TEXT("..")) == 0)
        {
            continue;
        }

        GetFullPathName(find.cFileName, MAX_PATH, Path, &pch);

        ULARGE_INTEGER uli;
        uli.LowPart = find.nFileSizeLow;
        uli.HighPart = find.nFileSizeHigh;

        tfout << Path << "\t0x" << hex << find.dwFileAttributes << "\t" <<
                find.ftLastWriteTime << "\t" << dec << uli.QuadPart << "\n";

        if (find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            DirList(find.cFileName);
        }
    } while (FindNextFile(hFind, &find));

    FindClose(hFind);

    SetCurrentDirectory(CurDir);
    return true;
}

void DumpProcessorArchitecture(WORD wProcessorArchitecture)
{
    const char *Architecture = "PROCESSOR_ARCHITECTURE_UNKNOWN";
    switch (wProcessorArchitecture)
    {
    case PROCESSOR_ARCHITECTURE_INTEL: Architecture = "PROCESSOR_ARCHITECTURE_INTEL"; break;
    case PROCESSOR_ARCHITECTURE_MIPS: Architecture = "PROCESSOR_ARCHITECTURE_MIPS"; break;
    case PROCESSOR_ARCHITECTURE_ALPHA: Architecture = "PROCESSOR_ARCHITECTURE_ALPHA"; break;
    case PROCESSOR_ARCHITECTURE_PPC: Architecture = "PROCESSOR_ARCHITECTURE_PPC"; break;
    case PROCESSOR_ARCHITECTURE_SHX: Architecture = "PROCESSOR_ARCHITECTURE_SHX"; break;
    case PROCESSOR_ARCHITECTURE_ARM: Architecture = "PROCESSOR_ARCHITECTURE_ARM"; break;
    case PROCESSOR_ARCHITECTURE_IA64: Architecture = "PROCESSOR_ARCHITECTURE_IA64"; break;
    case PROCESSOR_ARCHITECTURE_ALPHA64: Architecture = "PROCESSOR_ARCHITECTURE_ALPHA64"; break;
    case PROCESSOR_ARCHITECTURE_MSIL: Architecture = "PROCESSOR_ARCHITECTURE_MSIL"; break;
    }
    POUT(Architecture);
}

void DumpProcessorType(DWORD dwProcessorType)
{
    const char *ProcessorType = "(unknown)";
    switch (dwProcessorType)
    {
    case PROCESSOR_INTEL_386: ProcessorType = "PROCESSOR_INTEL_386"; break;
    case PROCESSOR_INTEL_486: ProcessorType = "PROCESSOR_INTEL_486"; break;
    case PROCESSOR_INTEL_PENTIUM: ProcessorType = "PROCESSOR_INTEL_PENTIUM"; break;
    case PROCESSOR_INTEL_IA64: ProcessorType = "PROCESSOR_INTEL_IA64"; break;
    case PROCESSOR_MIPS_R4000: ProcessorType = "PROCESSOR_MIPS_R4000"; break;
    case PROCESSOR_ALPHA_21064: ProcessorType = "PROCESSOR_ALPHA_21064"; break;
    case PROCESSOR_PPC_601: ProcessorType = "PROCESSOR_PPC_601"; break;
    case PROCESSOR_PPC_603: ProcessorType = "PROCESSOR_PPC_603"; break;
    case PROCESSOR_PPC_604: ProcessorType = "PROCESSOR_PPC_604"; break;
    case PROCESSOR_PPC_620: ProcessorType = "PROCESSOR_PPC_620"; break;
    case PROCESSOR_HITACHI_SH3: ProcessorType = "PROCESSOR_HITACHI_SH3"; break;
    case PROCESSOR_HITACHI_SH3E: ProcessorType = "PROCESSOR_HITACHI_SH3E"; break;
    case PROCESSOR_HITACHI_SH4: ProcessorType = "PROCESSOR_HITACHI_SH4"; break;
    case PROCESSOR_MOTOROLA_821: ProcessorType = "PROCESSOR_MOTOROLA_821"; break;
    case PROCESSOR_SHx_SH3: ProcessorType = "PROCESSOR_SHx_SH3"; break;
    case PROCESSOR_SHx_SH4: ProcessorType = "PROCESSOR_SHx_SH4"; break;
    case PROCESSOR_STRONGARM: ProcessorType = "PROCESSOR_STRONGARM"; break;
    case PROCESSOR_ARM720: ProcessorType = "PROCESSOR_ARM720"; break;
    case PROCESSOR_ARM820: ProcessorType = "PROCESSOR_ARM820"; break;
    case PROCESSOR_ARM920: ProcessorType = "PROCESSOR_ARM920"; break;
    case PROCESSOR_ARM_7TDMI: ProcessorType = "PROCESSOR_ARM_7TDMI"; break;
    case PROCESSOR_OPTIL: ProcessorType = "PROCESSOR_OPTIL"; break;
    }
    POUT(ProcessorType);
}

///////////////////////////////////////////////////////////////////////////////

int main(int argc, char **argv)
{
    ios_base::sync_with_stdio(false);
    setlocale(LC_CTYPE, "");

    DLL ImageHlp(TEXT("imagehlp"));
    if (!ImageHlp.GetProc(pMapFileAndCheckSum, MFACS))
    {
        tcerr << "WARNING: imagehlp.MapFileAndCheckSumA/W is not available\n";
    }

    string filename = "DATA.TXT";

#ifndef DEVANA_USE_STDOUT
    tfout.open(filename.c_str());
    if (!tfout.is_open())
    {
        tcerr << "ERROR: I cannot open the file" << filename << endl;
        return 1;
    }
#endif
    tfout.imbue(locale());

    tfout << LOGO;
    tfout << GetCommandLine() << '\n';

    if (argc >= 2)
    {
        if (GetFileAttributesA(argv[1]) != 0xFFFFFFFF)
        {
            dllout(AnsiToText(argv[1]));
            return 0;
        }
        else
        {
            g_selected_section = AnsiToText(argv[1]);
        }
    }

    if (CATEGORY("version"))
    {
        POUT(GetVersion());

        OSVERSIONINFO osver;
        osver.dwOSVersionInfoSize = sizeof(osver);
        if (GetVersionEx(&osver))
        {
            POUT(osver.dwMajorVersion);
            POUT(osver.dwMinorVersion);
            POUT(osver.dwBuildNumber);
            POUT(osver.dwPlatformId);
            POUT(osver.szCSDVersion);
        }
        else
        {
            FAIL("GetVersionEx");
        }
    }

    if (CATEGORY("system"))
    {
        TCHAR ComputerName[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD size =  MAX_COMPUTERNAME_LENGTH + 1;
        if (!GetComputerName(ComputerName, &size))
        {
            FAIL("GetComputerName");
        }
        else
        {
            POUT(ComputerName);
        }

        SYSTEM_INFO SysInfo;
        GetSystemInfo(&SysInfo);

        POUT(SysInfo.dwOemId);

        POUT(SysInfo.wProcessorArchitecture);
        DumpProcessorArchitecture(SysInfo.wProcessorArchitecture);

        POUT(SysInfo.wReserved);
        POUT(SysInfo.dwPageSize);
        //POUT(SysInfo.lpMinimumApplicationAddress);
        //POUT(SysInfo.lpMaximumApplicationAddress);
        POUT(SysInfo.dwActiveProcessorMask);
        POUT(SysInfo.dwNumberOfProcessors);

        POUT(SysInfo.dwProcessorType);
        DumpProcessorType(SysInfo.dwProcessorType);

        POUT(SysInfo.dwAllocationGranularity);
        POUT(SysInfo.wProcessorLevel);
        POUT(SysInfo.wProcessorRevision);

        {
            DLL kernel32("kernel32");
            if (kernel32.GetProc(pIsWow64Process, IW64P))
            {
                tfout << "IsWow64Process function exists in kernel32.dll.\n";
            }
        }

        TCHAR WinDir[MAX_PATH];
        GetWindowsDirectory(WinDir, MAX_PATH);
        POUT(WinDir);

        TCHAR SysDir[MAX_PATH];
        GetSystemDirectory(SysDir, MAX_PATH);
        POUT(SysDir);

        TCHAR TempPath[MAX_PATH];
        GetTempPath(MAX_PATH, TempPath);
        POUT(TempPath);

        LPTSTR pch;
#define SPECIAL_FOLDER(csidl) \
        pch = SpecialPath(csidl); \
        if (pch) { \
            tfout << g_section << ": " << #csidl << ": " << pch << endl; \
        } else { \
            FAIL(#csidl); \
        }
        SPECIAL_FOLDER(CSIDL_PERSONAL);
        SPECIAL_FOLDER(CSIDL_DESKTOPDIRECTORY);
        SPECIAL_FOLDER(CSIDL_RECENT);
        SPECIAL_FOLDER(CSIDL_STARTMENU);
        SPECIAL_FOLDER(CSIDL_FAVORITES);
        SPECIAL_FOLDER(CSIDL_APPDATA);
    }

    if (CATEGORY("user"))
    {
        TCHAR UserName[256];
        DWORD size = 256;
        if (!GetUserName(UserName, &size))
        {
            FAIL("GetUserName");
        }
        else
        {
            POUT(UserName);
        }
        POUT(GetACP());
        POUT(GetOEMCP());
        POUT(GetUserDefaultLCID());
        POUT(GetUserDefaultLangID());
        POUT(GetSystemDefaultLCID());
        POUT(GetSystemDefaultLangID());
    }

    if (CATEGORY("time"))
    {
        SYSTEMTIME SysTime;
        GetSystemTime(&SysTime);
        POUT(SysTime.wYear);
        POUT(SysTime.wMonth);
        POUT(SysTime.wDayOfWeek);
        POUT(SysTime.wDay);
        POUT(SysTime.wHour);
        POUT(SysTime.wMinute);
        POUT(SysTime.wSecond);
        POUT(SysTime.wMilliseconds);

        SYSTEMTIME LocalTime;
        GetLocalTime(&LocalTime);
        POUT(LocalTime.wYear);
        POUT(LocalTime.wMonth);
        POUT(LocalTime.wDayOfWeek);
        POUT(LocalTime.wDay);
        POUT(LocalTime.wHour);
        POUT(LocalTime.wMinute);
        POUT(LocalTime.wSecond);
        POUT(LocalTime.wMilliseconds);
    }

    if (CATEGORY("disk"))
    {
        BOOL bOK;

        POUT(GetLogicalDrives());

        DWORD SectorsPerCluster;
        DWORD BytesPerSector;
        DWORD NumberOfFreeClusters;
        DWORD TotalNumberOfClusters;

        bOK = GetDiskFreeSpace(NULL,
                               &SectorsPerCluster,
                               &BytesPerSector,
                               &NumberOfFreeClusters,
                               &TotalNumberOfClusters);
        if (bOK)
        {
            POUT(SectorsPerCluster);
            POUT(BytesPerSector);
            POUT(NumberOfFreeClusters);
            POUT(TotalNumberOfClusters);
        }
        else
        {
            FAIL("GetDiskFreeSpace");
        }

        ULARGE_INTEGER FreeBytesAvailableToCaller;
        ULARGE_INTEGER TotalNumberOfBytes;
        ULARGE_INTEGER TotalNumberOfFreeBytes;
        bOK = GetDiskFreeSpaceEx(NULL,
                                 &FreeBytesAvailableToCaller,
                                 &TotalNumberOfBytes,
                                 &TotalNumberOfFreeBytes);
        if (bOK)
        {
            POUT(FreeBytesAvailableToCaller);
            POUT(TotalNumberOfBytes);
            POUT(TotalNumberOfFreeBytes);
        }
        else
        {
            FAIL("GetDiskFreeSpaceEx");
        }
    }

    if (CATEGORY("memory"))
    {
        MEMORYSTATUS MemoryStatus;
        MemoryStatus.dwLength = sizeof(MemoryStatus);
        GlobalMemoryStatus(&MemoryStatus);

        POUT(MemoryStatus.dwMemoryLoad);
        POUT(MemoryStatus.dwTotalPhys);
        POUT(MemoryStatus.dwAvailPhys);
        POUT(MemoryStatus.dwTotalPageFile);
        POUT(MemoryStatus.dwAvailPageFile);
        POUT(MemoryStatus.dwTotalVirtual);
        POUT(MemoryStatus.dwAvailVirtual);
    }

    EXEOUT("notepad");
    EXEOUT("explorer");
    EXEOUT("calc");
    EXEOUT("write");
    EXEOUT("regedit");
    EXEOUT("winhlp32");
    EXEOUT("50comupd");
    EXEOUT("presetup");
    EXEOUT("regsvr32");

    DLLOUT("advapi32");
    DLLOUT("advpack");
    DLLOUT("asycfilt");
    DLLOUT("atl");
    DLLOUT("comcat");
    DLLOUT("comctl32");
    DLLOUT("comdlg32");
    DLLOUT("crypt32");
    DLLOUT("dbghelp");
    DLLOUT("ddraw");
    DLLOUT("dinput");
    DLLOUT("dsound");
    DLLOUT("gdi32");
    DLLOUT("glu32");
    DLLOUT("hlink");
    DLLOUT("hlinkprx");
    DLLOUT("imagehlp");
    DLLOUT("imm32");
    DLLOUT("inloader");
    DLLOUT("kernel32");
    DLLOUT("lz32");
    DLLOUT("mapi32");
    DLLOUT("mfc30");
    DLLOUT("mfc30loc");
    DLLOUT("mfc40");
    DLLOUT("mfc40loc");
    DLLOUT("mfc42");
    DLLOUT("mfc42loc");
    DLLOUT("mfc42u");
    DLLOUT("msi");
    DLLOUT("msimg32");
    DLLOUT("msvcirt");
    DLLOUT("msvcm90");
    DLLOUT("msvcp100");
    DLLOUT("msvcp60");
    DLLOUT("msvcp90");
    DLLOUT("msvcr100");
    DLLOUT("msvcr90");
    DLLOUT("msvcrt");
    DLLOUT("msvcrt10");
    DLLOUT("msvcrt20");
    DLLOUT("msvcrt40");
    DLLOUT("msvfw32");
    DLLOUT("ole32");
    DLLOUT("oleaut32");
    DLLOUT("olepro32");
    DLLOUT("opengl32");
    DLLOUT("riched20");
    DLLOUT("setupapi");
    DLLOUT("shell32");
    DLLOUT("shfolder");
    DLLOUT("shlwapi");
    DLLOUT("stdole2.tlb");
    DLLOUT("url");
    DLLOUT("urlmon");
    DLLOUT("user32");
    DLLOUT("version");
    DLLOUT("w95inf16");
    DLLOUT("w95inf32");
    DLLOUT("wininet");
    DLLOUT("winmm");
    DLLOUT("winspool.drv");
    DLLOUT("ws2_32");
    DLLOUT("wsock32");

#ifdef DEVANA_DO_SPY
    if (argc >= 3 && CATEGORY("tree"))
    {
        DirList(AnsiToText(argv[2]));
    }
    if (argc < 3 && CATEGORY("tree"))
    {
        DirList(TEXT("C:\\"));
    }
#ifndef CSIDL_MYPICTURES
    #define CSIDL_MYPICTURES
#endif
#ifndef CSIDL_MYMUSIC
    #define CSIDL_MYMUSIC   0x000d
#endif
#ifndef CSIDL_MYVIDEO
    #define CSIDL_MYVIDEO   0x000e
#endif
#ifndef CSIDL_FAVORITES
    #define CSIDL_FAVORITES 0x0006
#endif
    if (CATEGORY("documents"))
    {
        DirList(SpecialPath(CSIDL_PERSONAL));
    }
    if (CATEGORY("pictures"))
    {
        DirList(SpecialPath(CSIDL_MYPICTURES));
    }
    if (CATEGORY("music"))
    {
        DirList(SpecialPath(CSIDL_MYMUSIC));
    }
    if (CATEGORY("video"))
    {
        DirList(SpecialPath(CSIDL_MYVIDEO));
    }
    if (CATEGORY("favorites"))
    {
        DirList(SpecialPath(CSIDL_FAVORITES));
    }
#endif  // def DEVANA_DO_SPY

    return 0;
}

///////////////////////////////////////////////////////////////////////////////
