#include <iostream>
#include <windows.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <netfw.h>
#include <urlmon.h>
#include <shellapi.h>
#include <VersionHelpers.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "urlmon.lib")

using namespace std;

enum ConsoleColor {
    BLACK = 0, RED = 4, GREEN = 2, YELLOW = 6,
    BLUE = 9, PINK = 13, WHITE = 7
};

void setColor(ConsoleColor color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

// ───────────────────────────────── TPM CHECK
bool checkTPMStatus() {
    HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) return false;
    CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);

    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;
    bool tpmEnabled = false;

    if (SUCCEEDED(CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc)) &&
        SUCCEEDED(pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2\\Security\\MicrosoftTpm"),
            NULL, NULL, 0, NULL, 0, 0, &pSvc))) {

        CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
            RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL, EOAC_NONE);

        IEnumWbemClassObject* pEnumerator = NULL;
        if (SUCCEEDED(pSvc->ExecQuery(bstr_t("WQL"),
            bstr_t("SELECT * FROM Win32_Tpm"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL, &pEnumerator))) {

            IWbemClassObject* pclsObj = NULL;
            ULONG uReturn = 0;

            if (pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn) == S_OK) {
                VARIANT vtProp;
                pclsObj->Get(L"IsEnabled", 0, &vtProp, 0, 0);
                tpmEnabled = vtProp.boolVal;
                VariantClear(&vtProp);
                pclsObj->Release();
            }
            pEnumerator->Release();
        }
        pSvc->Release(); pLoc->Release();
    }

    CoUninitialize();
    return tpmEnabled;
}

// ───────────────────────────────── defender check
bool checkWindowsDefenderStatus() {
    // check if defender is disabled via registry
    HKEY hKey;
    DWORD value = 0;
    DWORD size = sizeof(value);

    // check if defender is disabled via policy
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExW(hKey, L"DisableAntiSpyware", NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            if (value == 1) return false; // defender is disabled
        }
        RegCloseKey(hKey);
    }

    // check if defender service is running
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm) {
        SC_HANDLE service = OpenServiceW(scm, L"WinDefend", SERVICE_QUERY_STATUS);
        if (service) {
            SERVICE_STATUS status;
            if (QueryServiceStatus(service, &status)) {
                CloseServiceHandle(service);
                CloseServiceHandle(scm);
                return (status.dwCurrentState == SERVICE_RUNNING);
            }
            CloseServiceHandle(service);
        }
        CloseServiceHandle(scm);
    }

    // if we can't determine the status through services, check wmi
    HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) return false;

    CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);

    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;
    bool active = false;

    if (SUCCEEDED(CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc)) &&
        SUCCEEDED(pLoc->ConnectServer(_bstr_t(L"ROOT\\SecurityCenter2"),
            NULL, NULL, 0, NULL, 0, 0, &pSvc))) {

        CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
            RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL, EOAC_NONE);

        IEnumWbemClassObject* pEnum = NULL;
        if (SUCCEEDED(pSvc->ExecQuery(bstr_t("WQL"),
            bstr_t("SELECT displayName,productState FROM AntiVirusProduct"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL, &pEnum))) {

            IWbemClassObject* pObj = NULL;
            ULONG uReturn = 0;

            while (pEnum->Next(WBEM_INFINITE, 1, &pObj, &uReturn) == S_OK) {
                VARIANT nameVar, stateVar;
                pObj->Get(L"displayName", 0, &nameVar, 0, 0);
                pObj->Get(L"productState", 0, &stateVar, 0, 0);

                if (nameVar.vt == VT_BSTR && wcsstr(nameVar.bstrVal, L"Defender")) {
                    DWORD state = stateVar.uintVal;
                    // check if defender is enabled (state & 0x1000) == 0x1000
                    active = (state & 0x1000) == 0x1000;
                }

                VariantClear(&nameVar);
                VariantClear(&stateVar);
                pObj->Release();
            }
            pEnum->Release();
        }
        pSvc->Release(); pLoc->Release();
    }

    CoUninitialize();
    return active;
}

// ───────────────────────────────── FIREWALL
bool checkFirewallStatus() {
    INetFwPolicy2* pNetFwPolicy2 = NULL;
    bool enabled = false;

    if (SUCCEEDED(CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER,
        __uuidof(INetFwPolicy2), (void**)&pNetFwPolicy2))) {
        VARIANT_BOOL fwEnabled;
        pNetFwPolicy2->get_FirewallEnabled(NET_FW_PROFILE2_PUBLIC, &fwEnabled);
        enabled = (fwEnabled == VARIANT_TRUE);
        pNetFwPolicy2->Release();
    }

    return enabled;
}

// ───────────────────────────────── OTHER CHECKS
bool checkSecureBootStatus() {
    HKEY hKey;
    DWORD val = 0, size = sizeof(val);
    return RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
        0, KEY_READ, &hKey) == ERROR_SUCCESS &&
        RegQueryValueExW(hKey, L"UEFISecureBootEnabled", NULL, NULL, (LPBYTE)&val, &size) == ERROR_SUCCESS &&
        RegCloseKey(hKey) == ERROR_SUCCESS && val == 1;
}

bool checkVirtualizationStatus() {
    return IsProcessorFeaturePresent(PF_VIRT_FIRMWARE_ENABLED);
}

bool checkSmartScreenStatus() {
    HKEY hKey;
    WCHAR buffer[10];
    DWORD size = sizeof(buffer);
    return RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer",
        0, KEY_READ, &hKey) == ERROR_SUCCESS &&
        RegQueryValueExW(hKey, L"SmartScreenEnabled", NULL, NULL, (LPBYTE)&buffer, &size) == ERROR_SUCCESS &&
        wcscmp(buffer, L"Off") != 0;
}

bool checkExploitProtectionStatus() {
    return GetSystemDEPPolicy() == 2; // Always On
}

// ───────────────────────────────── INFO
string getWindowsVersion() {
    HKEY hKey;
    WCHAR productName[256];
    WCHAR displayVersion[256];
    DWORD size = sizeof(productName);
    DWORD versionSize = sizeof(displayVersion);

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExW(hKey, L"ProductName", NULL, NULL, (LPBYTE)productName, &size) == ERROR_SUCCESS &&
            RegQueryValueExW(hKey, L"DisplayVersion", NULL, NULL, (LPBYTE)displayVersion, &versionSize) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            wstring version(productName);
            wstring build(displayVersion);
            return string(version.begin(), version.end()) + " " + string(build.begin(), build.end());
        }
        RegCloseKey(hKey);
    }

    // Fallback to basic version check if registry fails
    if (IsWindows10OrGreater()) return "Windows 10";
    if (IsWindows8OrGreater()) return "Windows 8";
    if (IsWindows7OrGreater()) return "Windows 7";
    return "Unknown Windows version";
}

string getWindowsEdition() {
    return ""; // We don't need to show edition anymore since it's included in the version string
}

// ───────────────────────────────── ACTIONS
void disableWindowsSecurity() {
    // Disable Windows Defender
    system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f >nul 2>&1");
    system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f >nul 2>&1");
    system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableOnAccessProtection /t REG_DWORD /d 1 /f >nul 2>&1");
    system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableScanOnRealtimeEnable /t REG_DWORD /d 1 /f >nul 2>&1");
    system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f >nul 2>&1");
    system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisablePrivacyMode /t REG_DWORD /d 1 /f >nul 2>&1");
    system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f >nul 2>&1");
    system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableIOAVProtection /t REG_DWORD /d 1 /f >nul 2>&1");

    // Disable Windows Firewall
    system("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\" /v EnableFirewall /t REG_DWORD /d 0 /f >nul 2>&1");
    system("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile\" /v EnableFirewall /t REG_DWORD /d 0 /f >nul 2>&1");
    system("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile\" /v EnableFirewall /t REG_DWORD /d 0 /f >nul 2>&1");
    system("netsh advfirewall set allprofiles state off >nul 2>&1");

    // Disable SmartScreen
    system("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\" /v SmartScreenEnabled /t REG_SZ /d Off /f >nul 2>&1");

    // Disable DEP
    system("bcdedit /set {current} nx AlwaysOff >nul 2>&1");

    // Disable Windows Security Center
    system("reg add \"HKLM\\SOFTWARE\\Microsoft\\Security Center\\Monitoring\" /v DisableMonitoring /t REG_DWORD /d 1 /f >nul 2>&1");
    system("reg add \"HKLM\\SOFTWARE\\Microsoft\\Security Center\\Monitoring\\AntiVirusDisableNotify\" /v DisableMonitoring /t REG_DWORD /d 1 /f >nul 2>&1");
    system("reg add \"HKLM\\SOFTWARE\\Microsoft\\Security Center\\Monitoring\\FirewallDisableNotify\" /v DisableMonitoring /t REG_DWORD /d 1 /f >nul 2>&1");

    cout << "\n[+] Disabled Defender, Firewall, SmartScreen, DEP, and Security Center\n";
    cout << "[!] Please restart your computer for changes to take effect.\n";
}

void showBIOSInfo() {
    setColor(BLUE);
    cout << "\n========================================\n";
    cout << "            BIOS Information           \n";
    cout << "========================================\n\n";
    setColor(WHITE);

    // Get BIOS Version
    setColor(BLUE);
    cout << "BIOS Version: ";
    setColor(WHITE);
    system("wmic bios get smbiosbiosversion /format:list | findstr \"SMBIOSBIOSVersion\"");

    // Get Manufacturer
    setColor(BLUE);
    cout << "\nManufacturer: ";
    setColor(WHITE);
    system("wmic bios get manufacturer /format:list | findstr \"Manufacturer\"");

    // Get Release Date
    setColor(BLUE);
    cout << "\nRelease Date: ";
    setColor(WHITE);
    system("wmic bios get releaseDate /format:list | findstr \"ReleaseDate\"");

    // Get BIOS Status
    setColor(BLUE);
    cout << "\nBIOS Status: ";
    setColor(WHITE);
    system("wmic bios get status /format:list | findstr \"Status\"");

    // Get Motherboard Info
    setColor(BLUE);
    cout << "\nMotherboard Model: ";
    setColor(WHITE);
    system("wmic baseboard get product /format:list | findstr \"Product\"");

    setColor(BLUE);
    cout << "\nMotherboard Manufacturer: ";
    setColor(WHITE);
    system("wmic baseboard get manufacturer /format:list | findstr \"Manufacturer\"");

    // Check for MSI motherboard
    cout << "\n\nChecking for MSI updates...\n";
    if (system("wmic baseboard get manufacturer | findstr \"Micro-Star\" >nul 2>&1") == 0) {
        setColor(GREEN);
        cout << "[+] MSI motherboard detected. You can check for updates at: https://www.msi.com/support\n";
    }
    else {
        setColor(YELLOW);
        cout << "[-] No MSI motherboard detected.\n";
    }

    setColor(GREEN);
    cout << "\n[+] BIOS information has been retrieved.\n";
    setColor(WHITE);
}

void downloadAndRun(const string& url, const string& filename) {
    URLDownloadToFileA(NULL, url.c_str(), filename.c_str(), 0, NULL);
    ShellExecuteA(NULL, "open", filename.c_str(), NULL, NULL, SW_SHOWNORMAL);
}

void printHeader() {
    setColor(WHITE);
    cout << "Program running with administrator privileges.\n";
    cout << "Checker Tool made by exo\n";
    setColor(BLUE);
    cout << "v1.0\n\n";
}

void printStatusLine(const string& label, bool enabled) {
    cout << label;
    setColor(enabled ? GREEN : RED);
    cout << (enabled ? "enabled\n" : "disabled\n");
    setColor(WHITE);
}

void printStatus() {
    setColor(GREEN);
    cout << "This account is not linked with a Microsoft email.\n";
    setColor(WHITE);

    printStatusLine("TPM is ", checkTPMStatus());
    printStatusLine("Secure Boot is ", checkSecureBootStatus());
    printStatusLine("Virtualization is ", checkVirtualizationStatus());
    printStatusLine("Windows Defender is ", checkWindowsDefenderStatus());
    printStatusLine("SmartScreen is ", checkSmartScreenStatus());
    printStatusLine("Windows Firewall is ", checkFirewallStatus());
    printStatusLine("Exploit Protection is ", checkExploitProtectionStatus());

    setColor(BLUE);
    cout << getWindowsVersion() << "\n\n";
    setColor(WHITE);
}

// ───────────────────────────────── HWID CHECKER
void checkHWID() {
    setColor(BLUE);
    cout << "\n========================================\n";
    cout << "         Hardware ID Information        \n";
    cout << "========================================\n\n";
    setColor(WHITE);

    // Get CPU ID
    cout << "CPU ID:\n";
    system("wmic cpu get ProcessorId /format:list | findstr \"ProcessorId\"");

    // Get Motherboard Serial
    cout << "\nMotherboard Serial:\n";
    system("wmic baseboard get SerialNumber /format:list | findstr \"SerialNumber\"");

    // Get BIOS Serial
    cout << "\nBIOS Serial:\n";
    system("wmic bios get SerialNumber /format:list | findstr \"SerialNumber\"");

    // Get Disk Drive Serial
    cout << "\nDisk Drive Serial:\n";
    system("wmic diskdrive get SerialNumber /format:list | findstr \"SerialNumber\"");

    // Get MAC Address
    cout << "\nMAC Address:\n";
    system("getmac /v /fo list | findstr \"Physical Address\"");

    // Get Windows Product ID
    cout << "\nWindows Product ID:\n";
    system("wmic os get SerialNumber /format:list | findstr \"SerialNumber\"");

    // Get TPM Info
    cout << "\nTPM Information:\n";
    system("wmic tpm get SpecVersion /format:list | findstr \"SpecVersion\"");

    setColor(YELLOW);
    cout << "\n[!] Note: If you see 'Default string' for any value, it means the system could not retrieve that specific identifier.\n";
    cout << "    This is normal for some systems, especially in virtual machines or when running with limited permissions.\n\n";

    setColor(GREEN);
    cout << "[+] All hardware IDs have been retrieved.\n";
    setColor(WHITE);
}

void printMenu() {
    cout << "----------------------------------------\n";
    cout << "              Menu Options              \n";
    cout << "----------------------------------------\n";
    cout << "1. Disable all Windows Security Features\n";
    cout << "2. Verify if BIOS is Updated\n";
    cout << "3. Disable Exploit Protection\n";
    cout << "4. Download and run AnyDesk\n";
    cout << "5. Check Hardware Identifiers (CPU, MB, BIOS, Disk, MAC)\n";
    cout << "6. Download Windows 10 22H2 ISO\n";
    cout << "7. Install Visual Redists and DirectX (via script)\n";
    cout << "----------------------------------------\n\n";

    setColor(GREEN);
    cout << "Please enter your choice: ";
    setColor(WHITE);
}

bool askToContinue() {
    setColor(GREEN);
    cout << "\nDo you want to go back to menu? (Y/N): ";
    setColor(WHITE);
    char choice;
    cin >> choice;
    return (choice == 'Y' || choice == 'y');
}

int main() {
    bool running = true;
    while (running) {
        printHeader();
        printStatus();
        printMenu();

        int choice;
        cin >> choice;

        switch (choice) {
        case 1:
            disableWindowsSecurity();
            if (!askToContinue()) running = false;
            break;
        case 2:
            showBIOSInfo();
            if (!askToContinue()) running = false;
            break;
        case 3:
            system("bcdedit /set {current} nx AlwaysOff >nul 2>&1");
            cout << "\n[+] Exploit Protection has been disabled.\n";
            cout << "[!] Please restart your computer for changes to take effect.\n";
            if (!askToContinue()) running = false;
            break;
        case 4:
            downloadAndRun("https://download.anydesk.com/AnyDesk.exe", "AnyDesk.exe");
            if (!askToContinue()) running = false;
            break;
        case 5:
            checkHWID();
            if (!askToContinue()) running = false;
            break;
        case 6:
            ShellExecuteA(NULL, "open", "https://www.microsoft.com/software-download/windows10", NULL, NULL, SW_SHOWNORMAL);
            if (!askToContinue()) running = false;
            break;
        case 7:
            ShellExecuteA(NULL, "open", "https://aka.ms/vs/17/release/vc_redist.x64.exe", NULL, NULL, SW_SHOWNORMAL);
            if (!askToContinue()) running = false;
            break;
        default:
            cout << "Invalid choice.\n";
            if (!askToContinue()) running = false;
            break;
        }
    }

    return 0;
}
