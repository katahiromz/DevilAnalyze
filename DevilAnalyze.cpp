// DevilAnalyze - A Windows System Analyzer by Katayama Hirofumi MZ.
// This file is public domain software (PDS).
///////////////////////////////////////////////////////////////////////////////

#define LOGO \
    "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n" \
    "$ DevilAnalyze v1.0 by Katayama Hirofumi MZ $\n" \
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

bool dllout(const TCHAR *file)
{
    if (!set_section(file))
        return false;

    TCHAR Path[MAX_PATH], *pch;
    if (!SearchPath(NULL, file, TEXT(".dll"), MAX_PATH, Path, &pch))
    {
        SearchPath(NULL, file, NULL, MAX_PATH, Path, &pch);
    }
    POUT(Path);

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
        POUT(SysInfo.wReserved);
        POUT(SysInfo.dwPageSize);
        //POUT(SysInfo.lpMinimumApplicationAddress);
        //POUT(SysInfo.lpMaximumApplicationAddress);
        POUT(SysInfo.dwActiveProcessorMask);
        POUT(SysInfo.dwNumberOfProcessors);
        POUT(SysInfo.dwProcessorType);
        POUT(SysInfo.dwAllocationGranularity);
        POUT(SysInfo.wProcessorLevel);
        POUT(SysInfo.wProcessorRevision);

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

    DLLOUT("kernel32");
    DLLOUT("gdi32");
    DLLOUT("user32");
    DLLOUT("advapi32");
    DLLOUT("comctl32");
    DLLOUT("comdlg32");
    DLLOUT("shell32");
    DLLOUT("shlwapi");
    DLLOUT("imm32");

    DLLOUT("ddraw");
    DLLOUT("dinput");
    DLLOUT("dsound");

    DLLOUT("ole32");
    DLLOUT("oleaut32");
    DLLOUT("opengl32");
    DLLOUT("riched20");
    DLLOUT("winmm");
    DLLOUT("msvfw32");
    DLLOUT("ws2_32");
    DLLOUT("wsock32");
    DLLOUT("msimg32");
    DLLOUT("setupapi");
    DLLOUT("hlink");
    DLLOUT("glu32");
    DLLOUT("dbghelp");
    DLLOUT("imagehlp");
    DLLOUT("lz32");
    DLLOUT("mapi32");
    DLLOUT("msi");
    DLLOUT("shfolder");
    DLLOUT("url");
    DLLOUT("urlmon");
    DLLOUT("version");
    DLLOUT("wininet");
    DLLOUT("winspool.drv");
    DLLOUT("crypt32");

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
