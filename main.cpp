#define UNICODE
#define _UNICODE
#include "resource.h"
#define SECURITY_WIN32
#include <windows.h>
#include <iostream>
#include <string>
#include <fcntl.h>
#include <io.h>
#include <sstream>
#include <shlobj.h>
#include <commctrl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <vector>
#include <map>
#include <sstream>
#include <algorithm>
#include <winternl.h>
#include <winsvc.h>
#include <shellapi.h>
#include <restartmanager.h>

// ntddk.h no estÃ¡ disponible en aplicaciones de modo usuario

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Rstrtmgr.lib")

// Nombre de la clase de ventana y título
const wchar_t* WINDOW_CLASS_NAME = L"BlockerCheckerWindow";

const wchar_t* WINDOW_TITLE = L"BlockerChecker";

// Claves de registro para el menú contextual - apuntando a TODOS los archivos y dispositivos
// Usando estructura para posicionar al final del menú, arriba de Properties
const wchar_t* REGISTRY_PATHS[] = {
    L"Software\\Classes\\*\\shell\\BlockerChecker",                 // TODOS los archivos (incluyendo .tmp, .log, .sys, etc.)
    L"Software\\Classes\\Drive\\shell\\BlockerChecker",             // Unidades
    L"Software\\Classes\\Directory\\shell\\BlockerChecker",         // directorios
    L"Software\\Classes\\Folder\\shell\\BlockerChecker"             // carpetas
};

const int REGISTRY_PATHS_COUNT = sizeof(REGISTRY_PATHS) / sizeof(REGISTRY_PATHS[0]);

// Declaraciones de funciones
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
bool AddContextMenuToRegistry();
bool RemoveContextMenuFromRegistry();
void CreateMainWindow(const char* filePath = nullptr);
std::wstring GetExecutablePath();
void ScanForBlockingProcesses();
std::wstring GetProcessName(DWORD processId);
std::wstring GetProcessPath(DWORD processId);
std::wstring GetHandleTypeString(DWORD handleType);
std::wstring GetAccessRightsString(DWORD accessRights);
std::wstring GetBlockingReason(DWORD accessRights, DWORD handleType);

std::wstring GetFileHandleInfo();
std::wstring GetShortPathName(const std::wstring& longPath);
bool IsFileInUse(const std::wstring& filePath);
std::vector<DWORD> GetProcessesUsingFile(const std::wstring& filePath);
std::vector<DWORD> GetProcessesWithFileHandles(const std::wstring& filePath);
std::vector<DWORD> GetProcessesWithRealFileHandles(const std::wstring& filePath);
std::vector<std::wstring> GetServicesUsingFile(const std::wstring& filePath);
std::vector<std::wstring> GetDllsUsingFile(const std::wstring& filePath);
std::vector<DWORD> GetProcessesBlockingFolderExact(const std::wstring& folderPath);
std::vector<DWORD> GetProcessesBlockingFolderComprehensive(const std::wstring& folderPath);
bool IsDirectoryPath(const std::wstring& path);
bool IsRunningAsAdministrator();
bool RestartAsAdministrator(const std::wstring& filePath);

// Ayudantes para eliminaciÃ³n forzada
bool RecursivelyDeleteNow(const std::wstring& path);
bool RecursivelyScheduleDeleteAtReboot(const std::wstring& path);


// Funciones mejoradas de enumeración de manejos (handles)
std::vector<DWORD> GetProcessesWithRealFileHandlesEnhanced(const std::wstring& filePath);
std::vector<DWORD> GetProcessesUsingNtQuerySystemInformation(const std::wstring& filePath);
std::wstring GetProcessCommandLine(DWORD processId);
std::wstring GetProgramFriendlyName(const std::wstring& processPath);

// Función auxiliar para verificar si un archivo está en un directorio temporal
bool IsInTempDirectory(const std::wstring& filePath);

// Función auxiliar para verificar si un proceso es un servicio del sistema
bool IsSystemService(const std::wstring& processName);

// Función auxiliar para verificar si un proceso sigue en ejecución
bool IsProcessRunning(DWORD processId);

// Función auxiliar para detectar si una ruta apunta a una carpeta del sistema (propensa a muchos manejos compartidos)
bool IsSystemFolderPath(const std::wstring& path);
// DeclaraciÃ³n anticipada para el mapeo de ruta DOS â†’ GUID de volumen
std::wstring BuildVolumeGuidPath(const std::wstring& dosPath);

// Función auxiliar para agregar o actualizar un proceso en la lista de procesos bloqueantes
void AddOrUpdateProcessInfo(DWORD processId, const std::wstring& processName, const std::wstring& filePath, 
                           const std::wstring& handleType, const std::wstring& accessRights, 
                           const std::wstring& blockingReason);
void CreateProcessButtons(HWND hwnd = NULL);
void CreateProcessDisplay(HWND hwnd = NULL);
void UpdateAllControlsLayout(HWND hwnd);
void UpdateProcessDisplayLayout(HWND hwnd);
void UpdateScrollInfo(HWND hwnd);
void ScrollContent(HWND hwnd, int deltaY);
void HandleScrollBar(HWND hwnd, int scrollCode, int pos);
void CreateProcessListContainer(HWND hwnd);
void UpdateProcessListContainerLayout(HWND hwnd);
LRESULT CALLBACK ContainerWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK ModernButtonProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
HICON ExtractIconFromFile(const std::wstring& filePath);
void DestroyProcessButtons();
void AddNoProcessesMessage();
void ForceTerminateProcessGroup(const std::wstring& processName, const std::vector<DWORD>& processIds);
void ForceTerminateProcess(DWORD processId, const std::wstring& processName);
void DeleteFileAfterTermination(const std::wstring& filePath);
bool TerminateProcessAndDeleteFile(DWORD processId, const std::wstring& processName, const std::wstring& filePath);
void RemoveProcessFromList(DWORD processId);
int CalculateBlockingPriority(DWORD processId, const std::wstring& processName, const std::wstring& filePath);

// Función para obtener la línea de comandos del proceso (movida arriba para evitar problemas de declaración anticipada)
std::wstring GetProcessCommandLine(DWORD processId) {
    std::wstring commandLine;
    
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) {
        return commandLine;
    }
    
    // obtener la direcciÃ³n PEB
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    
    // Usar NtQueryInformationProcess para obtener la línea de comandos
    // Por simplicidad, usaremos un enfoque diferente
    wchar_t processPath[MAX_PATH];
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageName(hProcess, 0, processPath, &size)) {
        commandLine = std::wstring(processPath);
    }
    
    CloseHandle(hProcess);
    return commandLine;
}

// Ayudante basado en Restart Manager para encontrar procesos usando un archivo particular (muy confiable)
std::vector<DWORD> GetProcessesUsingRestartManager(const std::wstring& filePath) {
    std::vector<DWORD> pids;
    if (filePath.empty()) return pids;

    DWORD sessionHandle = 0;
    WCHAR sessionKey[CCH_RM_SESSION_KEY + 1] = {};
    if (RmStartSession(&sessionHandle, 0, sessionKey) != ERROR_SUCCESS) {
        return pids;
    }

    LPCWSTR resources[1] = { filePath.c_str() };
    // Solo nos importan archivos, así que 1 archivo, 0 servicios, 0 aplicaciones.
    if (RmRegisterResources(sessionHandle, 1, resources, 0, NULL, 0, NULL) == ERROR_SUCCESS) {
        UINT procInfoNeeded = 0;
        UINT procInfoCount = 0;
        RM_PROCESS_INFO staticInfo[16];
        DWORD rv = RmGetList(sessionHandle, &procInfoNeeded, &procInfoCount, staticInfo, NULL);
        if (rv == ERROR_MORE_DATA) {
            // asignar suficiente y reintentar
            std::vector<RM_PROCESS_INFO> dyn(procInfoNeeded);
            procInfoCount = procInfoNeeded;
            rv = RmGetList(sessionHandle, &procInfoNeeded, &procInfoCount, dyn.data(), NULL);
            if (rv == ERROR_SUCCESS) {
                for (UINT i = 0; i < procInfoCount; ++i) {
                    DWORD pid = dyn[i].Process.dwProcessId;
                    if (pid && pid != GetCurrentProcessId()) {
                        pids.push_back(pid);
                    }
                }
            }
        } else if (rv == ERROR_SUCCESS) {
            for (UINT i = 0; i < procInfoCount; ++i) {
                DWORD pid = staticInfo[i].Process.dwProcessId;
                if (pid && pid != GetCurrentProcessId()) {
                        pids.push_back(pid);
                }
            }
        }
    }

    RmEndSession(sessionHandle);

    return pids;
}

// Utilidad para determinar si una ruta es un directorio en disco
bool IsDirectoryPath(const std::wstring& path) {
    DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) return false;
    return (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

// ============================================================================
// DetecciÃ³n exacta de bloqueo de carpetas â€“ enumera manejos del kernel y retorna solo
// PIDs que realmente tienen un manejo dentro de la jerarquía de la carpeta.
// ============================================================================
#if 0
std::vector<DWORD> GetProcessesBlockingFolderExact(const std::wstring& folderPath) {
    std::vector<DWORD> pids;
    if (folderPath.empty()) return pids;

    // Normalizar ruta (remover barra invertida final, obtener forma larga, copia en minúsculas)
    std::wstring norm = folderPath;
    if (!norm.empty() && (norm.back() == L'\\' || norm.back() == L'/')) norm.pop_back();
    std::wstring normLower = norm;
    std::transform(normLower.begin(), normLower.end(), normLower.begin(), ::towlower);

    // nombres largos y cortos para pruebas de igualdad directa
    std::wstring shortPath = GetShortPathName(norm);
    // Precalcular variantes en minúsculas y con sufijo de barra para coincidencia robusta de directorios
    std::wstring shortPathLower = shortPath;
    std::transform(shortPathLower.begin(), shortPathLower.end(), shortPathLower.begin(), ::towlower);
    std::wstring normLowerWithSlash = normLower + L"\\";
    std::wstring shortLowerWithSlash = shortPathLower.empty() ? std::wstring() : (shortPathLower + L"\\");
    std::wstring shortPathLower = shortPath;
    std::transform(shortPathLower.begin(), shortPathLower.end(), shortPathLower.begin(), ::towlower);
    std::wstring normLowerWithSlash = normLower + L"\\";
    std::wstring shortLowerWithSlash = shortPathLower.empty() ? L"" : (shortPathLower + L"\\");
    std::wstring shortPathLower = shortPath;
    std::transform(shortPathLower.begin(), shortPathLower.end(), shortPathLower.begin(), ::towlower);
    std::wstring normLowerWithSlash = normLower + L"\\";
    std::wstring shortLowerWithSlash = shortPathLower.empty() ? L"" : (shortPathLower + L"\\");
    std::wstring shortPathLower = shortPath;
    std::transform(shortPathLower.begin(), shortPathLower.end(), shortPathLower.begin(), ::towlower);
    std::wstring normLowerWithSlash = normLower + L"\\";
    std::wstring shortLowerWithSlash = shortPathLower.empty() ? L"" : (shortPathLower + L"\\");
    std::wstring shortPathLower = shortPath;
    std::transform(shortPathLower.begin(), shortPathLower.end(), shortPathLower.begin(), ::towlower);
    std::wstring normLowerWithSlash = normLower + L"\\";
    std::wstring shortLowerWithSlash = shortPathLower.empty() ? L"" : (shortPathLower + L"\\");
    std::wstring shortPathLower = shortPath;
    std::transform(shortPathLower.begin(), shortPathLower.end(), shortPathLower.begin(), ::towlower);
    std::wstring normLowerWithSlash = normLower + L"\\";
    std::wstring shortLowerWithSlash = shortPathLower.empty() ? L"" : (shortPathLower + L"\\");
    std::wstring shortPathLower = shortPath;
    std::transform(shortPathLower.begin(), shortPathLower.end(), shortPathLower.begin(), ::towlower);
    std::wstring normLowerWithSlash = normLower + L"\\";
    std::wstring shortLowerWithSlash = shortPathLower.empty() ? L"" : (shortPathLower + L"\\");
    std::wstring shortPathLower = shortPath;
    std::transform(shortPathLower.begin(), shortPathLower.end(), shortPathLower.begin(), ::towlower);
    std::wstring normLowerWithSlash = normLower + L"\\";
    std::wstring shortLowerWithSlash = shortPathLower.empty() ? L"" : (shortPathLower + L"\\");
    std::wstring shortPathLower = shortPath;
    std::transform(shortPathLower.begin(), shortPathLower.end(), shortPathLower.begin(), ::towlower);
    std::wstring normLowerWithSlash = normLower + L"\\";
    std::wstring shortLowerWithSlash = shortPathLower.empty() ? L"" : (shortPathLower + L"\\");
    std::wstring shortPathLower = shortPath;
    std::transform(shortPathLower.begin(), shortPathLower.end(), shortPathLower.begin(), ::towlower);
    std::wstring normLowerWithSlash = normLower + L"\\";
    std::wstring shortLowerWithSlash = shortPathLower.empty() ? L"" : (shortPathLower + L"\\");
    std::wstring shortPathLower = shortPath;
    std::transform(shortPathLower.begin(), shortPathLower.end(), shortPathLower.begin(), ::towlower);
    std::wstring normLowerWithSlash = normLower + L"\\";
    std::wstring shortLowerWithSlash = shortPathLower.empty() ? L"" : (shortPathLower + L"\\");
    std::wstring shortPathLower = shortPath;
    std::transform(shortPathLower.begin(), shortPathLower.end(), shortPathLower.begin(), ::towlower);
    std::wstring normLowerWithSlash = normLower + L"\\";
    std::wstring shortLowerWithSlash = shortPathLower.empty() ? L"" : (shortPathLower + L"\\");
    std::wstring shortPathLower = shortPath;
    std::transform(shortPathLower.begin(), shortPathLower.end(), shortPathLower.begin(), ::towlower);
    std::wstring normLowerWithSlash = normLower + L"\\";
    std::wstring shortLowerWithSlash = shortPathLower.empty() ? L"" : (shortPathLower + L"\\");
    std::wstring shortPathLower = shortPath;
    std::transform(shortPathLower.begin(), shortPathLower.end(), shortPathLower.begin(), ::towlower);
    std::wstring normLowerWithSlash = normLower + L"\\";
    std::wstring shortLowerWithSlash = shortPathLower.empty() ? L"" : (shortPathLower + L"\\");
    std::wstring shortPathLower = shortPath;
    std::transform(shortPathLower.begin(), shortPathLower.end(), shortPathLower.begin(), ::towlower);
    std::wstring normLowerWithSlash = normLower + L"\\";
    std::wstring shortLowerWithSlash = shortPathLower.empty() ? L"" : (shortPathLower + L"\\");
    std::wstring shortPathLower = shortPath;
    std::transform(shortPathLower.begin(), shortPathLower.end(), shortPathLower.begin(), ::towlower);
    std::wstring normLowerWithSlash = normLower + L"\\";
    std::wstring shortLowerWithSlash = shortPathLower.empty() ? L"" : (shortPathLower + L"\\");

    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtDll) return pids;
    auto NtQuerySystemInformation = (PFN_NT_QUERY_SYSTEM_INFORMATION)GetProcAddress(hNtDll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) return pids;

    ULONG size = 0;
    if (NtQuerySystemInformation(SystemHandleInformation, nullptr, 0, &size) != 0xC0000004 /*STATUS_INFO_LENGTH_MISMATCH*/) {
        return pids;
    }
    std::unique_ptr<BYTE[]> buffer(new BYTE[size]);
    if (NtQuerySystemInformation(SystemHandleInformation, buffer.get(), size, &size) != 0) return pids;

    auto info = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(buffer.get());
    for (ULONG i = 0; i < info->NumberOfHandles; ++i) {
        const auto &h = info->Handles[i];
        if (h.ProcessId == GetCurrentProcessId()) continue;

        HANDLE hProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, h.ProcessId);
        if (!hProc) continue;
        HANDLE dup = nullptr;
        if (!DuplicateHandle(hProc, (HANDLE)(ULONG_PTR)h.Handle, GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            CloseHandle(hProc);
            continue;
        }
        wchar_t fileName[MAX_PATH];
        DWORD res = GetFinalPathNameByHandleW(dup, fileName, MAX_PATH, FILE_NAME_NORMALIZED);
        CloseHandle(dup);
        CloseHandle(hProc);
        if (!res || res >= MAX_PATH) continue;

        std::wstring handlePath(fileName);
        if (handlePath.rfind(L"\\?\\", 0) == 0) handlePath = handlePath.substr(4);
        std::wstring handleLower = handlePath;
        std::transform(handleLower.begin(), handleLower.end(), handleLower.begin(), ::towlower);

        if (handleLower.rfind(normLower, 0) == 0 || (!shortPath.empty() && handleLower.rfind(shortPath, 0) == 0)) {
            std::wstring pname = GetProcessName(h.ProcessId);
            if (!IsSystemService(pname)) {
                if (std::find(pids.begin(), pids.end(), h.ProcessId) == pids.end()) {
                    pids.push_back(h.ProcessId);
                }
            }
        }
    }

    return pids;
}
#endif // bloqueador de carpeta duplicado deshabilitado

// Funciones mejoradas de enumeración de manejos usando NtQuerySystemInformation (simplificado para reducir falsos positivos)
std::vector<DWORD> GetProcessesWithRealFileHandlesEnhanced(const std::wstring& filePath) {
    std::vector<DWORD> processIds;
    // --- Método de Detección 0: Windows Restart Manager (más confiable para bloqueos de archivos en modo usuario)
    {
        std::vector<DWORD> rmPids = GetProcessesUsingRestartManager(filePath);
        processIds.insert(processIds.end(), rmPids.begin(), rmPids.end());
    }
    
    // Método 1: Intentar abrir el archivo con acceso exclusivo para ver qué lo está bloqueando
    HANDLE hFile = CreateFile(filePath.c_str(), 
                             GENERIC_READ | GENERIC_WRITE | DELETE,
                             0, // Sin compartir - esto fallarÃ¡ si el archivo estÃ¡ en uso
                             NULL, 
                             OPEN_EXISTING, 
                             FILE_ATTRIBUTE_NORMAL, 
                             NULL);
    
    bool fileIsBlocked = (hFile == INVALID_HANDLE_VALUE);
    if (!fileIsBlocked) {
        CloseHandle(hFile);
    }
    
    // Método 2: Usar NtQuerySystemInformation para manejos de archivos reales
    std::vector<DWORD> ntProcessIds = GetProcessesUsingNtQuerySystemInformation(filePath);
    processIds.insert(processIds.end(), ntProcessIds.begin(), ntProcessIds.end());
    
    // Método 3: Si el archivo está bloqueado pero NtQuerySystemInformation no encontró nada, usar método alternativo
    if (fileIsBlocked && processIds.empty()) {
        // Verificar procesos que podrÃ­an estar usando el archivo
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            
            if (Process32First(hSnapshot, &pe32)) {
                do {
                    // Intentar abrir cada proceso con acceso al manejo
                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                    if (hProcess != NULL) {
                        std::wstring processName = GetProcessName(pe32.th32ProcessID);
                        
                        // Omitir servicios del sistema y falsos positivos comunes para archivos temporales
                        if (IsSystemService(processName)) {
                            CloseHandle(hProcess);
                            continue;
                        }
                        
                        // Para archivos temporales, ser aún más estricto: mostrar solo procesos que definitivamente están usando el archivo
                        bool isTempFile = IsInTempDirectory(filePath);
                        
                        // Verificar si el proceso es el propio archivo (ejecutable)
                        std::wstring processPath = GetProcessPath(pe32.th32ProcessID);
                        if (processPath == filePath) {
                            processIds.push_back(pe32.th32ProcessID);
                        }
                        
                        // Verificar línea de comandos del proceso para referencias de archivo (más estricto)
                        std::wstring commandLine = GetProcessCommandLine(pe32.th32ProcessID);
                        if (!commandLine.empty() && commandLine.find(filePath) != std::wstring::npos) {
                            // Para archivos temporales, requerir coincidencia exacta de ruta entre comillas
                            if (isTempFile) {
                                std::wstring searchPattern = L"\"" + filePath + L"\"";
                                if (commandLine.find(searchPattern) != std::wstring::npos) {
                                    processIds.push_back(pe32.th32ProcessID);
                                }
                            } else {
                                // Para archivos no temporales
                                std::wstring searchPattern = L"\"" + filePath + L"\"";
                                if (commandLine.find(searchPattern) != std::wstring::npos) {
                                    processIds.push_back(pe32.th32ProcessID);
                                }
                            }
                        }
                        
                        CloseHandle(hProcess);
                    }
                } while (Process32Next(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
        }
    }
    
    // Eliminar duplicados
    std::sort(processIds.begin(), processIds.end());
    processIds.erase(std::unique(processIds.begin(), processIds.end()), processIds.end());
    
    return processIds;
}

// ImplementaciÃ³n heredada (heurÃ­stica detallada) mantenida abajo como referencia pero deshabilitada
#if 0
std::vector<DWORD> GetProcessesWithRealFileHandlesEnhanced_Legacy(const std::wstring& filePath) {
    std::vector<DWORD> processIds;
    
    // obtener tanto nombres de ruta largos como cortos
    std::wstring longPath = filePath;
    std::wstring shortPath = GetShortPathName(filePath);
    
    // Método 1: Intentar abrir el archivo con acceso exclusivo para ver qué lo está bloqueando
    HANDLE hFile = CreateFile(filePath.c_str(), 
                             GENERIC_READ | GENERIC_WRITE | DELETE,
                             0, // Sin compartir - esto fallarÃ¡ si el archivo estÃ¡ en uso
                             NULL, 
                             OPEN_EXISTING, 
                             FILE_ATTRIBUTE_NORMAL, 
                             NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        
        // El archivo estÃ¡ en uso, ahora averigÃ¼emos por quÃ© procesos
        // Usaremos un enfoque más integral
        
        // Método 2: Verificar todos los procesos para manejos de archivos usando NtQuerySystemInformation
        processIds = GetProcessesUsingNtQuerySystemInformation(filePath);
        
        // Método 3: Si NtQuerySystemInformation no encontró nada, usar métodos alternativos
        if (processIds.empty()) {
            // Verificar procesos que podrÃ­an estar usando el archivo
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe32;
                pe32.dwSize = sizeof(PROCESSENTRY32);
                
                if (Process32First(hSnapshot, &pe32)) {
                    do {
                        // Intentar abrir cada proceso con acceso al manejo
                        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE, FALSE, pe32.th32ProcessID);
                        if (hProcess != NULL) {
                            // Verificar si este proceso tiene algÃºn manejo a nuestro archivo
                            
                            // Método 3a: Verificar si el proceso es el propio archivo (ejecutable)
                            std::wstring processPath = GetProcessPath(pe32.th32ProcessID);
                            if (processPath == longPath || processPath == shortPath) {
                                processIds.push_back(pe32.th32ProcessID);
                            }
                            
                            // Método 3b: Verificar si el proceso tiene directorio de trabajo configurado a nuestra ruta
                            wchar_t currentDir[MAX_PATH];
                            if (GetCurrentDirectory(MAX_PATH, currentDir) > 0) {
                                std::wstring currentDirStr(currentDir);
                                if (currentDirStr.find(longPath) != std::wstring::npos || 
                                    currentDirStr.find(shortPath) != std::wstring::npos) {
                                    processIds.push_back(pe32.th32ProcessID);
                                }
                            }
                            
                            // Método 3c: Verificar línea de comandos del proceso para referencias de archivo
                            std::wstring commandLine = GetProcessCommandLine(pe32.th32ProcessID);
                            if (commandLine.find(longPath) != std::wstring::npos || 
                                commandLine.find(shortPath) != std::wstring::npos) {
                                processIds.push_back(pe32.th32ProcessID);
                            }
                            
                            CloseHandle(hProcess);
                        }
                    } while (Process32Next(hSnapshot, &pe32));
                }
                CloseHandle(hSnapshot);
            }
        }
        
                                // Método 4: Verificar patrones de error específicos y agregar procesos comunes
        if (error == ERROR_SHARING_VIOLATION || error == ERROR_LOCK_VIOLATION || error == ERROR_ACCESS_DENIED) {
            // El archivo definitivamente estÃ¡ en uso, agregar todos los procesos que podrÃ­an estar usÃ¡ndolo
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe32;
                pe32.dwSize = sizeof(PROCESSENTRY32);
                
                if (Process32First(hSnapshot, &pe32)) {
                    do {
                        // agregar procesos que podrÃ­an estar usando el archivo
                        std::wstring processName = GetProcessName(pe32.th32ProcessID);
                        
                        // Verificar procesos comunes que podrÃ­an estar usando archivos
                        if (processName.find(L"explorer.exe") != std::wstring::npos ||
                            processName.find(L"notepad.exe") != std::wstring::npos ||
                            processName.find(L"wordpad.exe") != std::wstring::npos ||
                            processName.find(L"mspaint.exe") != std::wstring::npos ||
                            processName.find(L"calc.exe") != std::wstring::npos ||
                            processName.find(L"cmd.exe") != std::wstring::npos ||
                            processName.find(L"powershell.exe") != std::wstring::npos ||
                            processName.find(L"svchost.exe") != std::wstring::npos ||
                            processName.find(L"msedge.exe") != std::wstring::npos ||
                            processName.find(L"chrome.exe") != std::wstring::npos ||
                            processName.find(L"firefox.exe") != std::wstring::npos ||
                            processName.find(L"winword.exe") != std::wstring::npos ||
                            processName.find(L"excel.exe") != std::wstring::npos ||
                            processName.find(L"powerpnt.exe") != std::wstring::npos ||
                            processName.find(L"acrobat.exe") != std::wstring::npos ||
                            processName.find(L"acrord32.exe") != std::wstring::npos) {
                            processIds.push_back(pe32.th32ProcessID);
                        }
                    } while (Process32Next(hSnapshot, &pe32));
                }
                CloseHandle(hSnapshot);
            }
        }
    } else {
        CloseHandle(hFile);
    }
    
    return processIds;
}
#endif // Fin del bloque de implementaciÃ³n heredada

// Definir las estructuras y constantes necesarias para NtQuerySystemInformation
typedef NTSTATUS(NTAPI* PFN_NT_QUERY_SYSTEM_INFORMATION)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

#define SystemHandleInformation 16

// ----------------------------------------------------------------------------
// DetecciÃ³n exacta de bloqueo de carpetas â€“ enumera manejos del kernel y retorna solo
// PIDs que realmente tienen un manejo en cualquier lugar dentro de la jerarquía de la carpeta.
// ----------------------------------------------------------------------------
std::vector<DWORD> GetProcessesBlockingFolderExact(const std::wstring& folderPath) {
    std::vector<DWORD> pids;
    if (folderPath.empty()) return pids;

    wchar_t fullBuf[MAX_PATH];
    GetFullPathNameW(folderPath.c_str(), MAX_PATH, fullBuf, nullptr);
    std::wstring norm(fullBuf);
    if (!norm.empty() && (norm.back() == L'\\' || norm.back() == L'/')) norm.pop_back();
    std::wstring normLower = norm;
    std::transform(normLower.begin(), normLower.end(), normLower.begin(), ::towlower);

    std::wstring shortPath = GetShortPathName(norm);
    // Normalizar prefijo \?\ y forma GUID de volumen del objetivo para coincidir contra nombres del kernel
    std::wstring normGuid = BuildVolumeGuidPath(norm);
    std::wstring normLowerGuid = normGuid;
    std::transform(normLowerGuid.begin(), normLowerGuid.end(), normLowerGuid.begin(), ::towlower);

    // Primero, intentar Windows Restart Manager que a menudo reporta procesos con
    // manejos de directorio abiertos (ej., shells como cmd/pwsh con CWD configurado a la carpeta).
    {
        std::vector<DWORD> rmPids = GetProcessesUsingRestartManager(norm);
        pids.insert(pids.end(), rmPids.begin(), rmPids.end());
    }

    HMODULE hNt = GetModuleHandleW(L"ntdll.dll");
    if (!hNt) return pids;
    auto NtQuerySystemInformation = (PFN_NT_QUERY_SYSTEM_INFORMATION)GetProcAddress(hNt, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) return pids;

    ULONG len = 0;
    if (NtQuerySystemInformation(SystemHandleInformation, nullptr, 0, &len) != 0xC0000004) return pids;
    std::unique_ptr<BYTE[]> buf(new BYTE[len]);
    if (NtQuerySystemInformation(SystemHandleInformation, buf.get(), len, &len) != 0) return pids;

    auto info = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(buf.get());
    for (ULONG i = 0; i < info->NumberOfHandles; ++i) {
        const auto &h = info->Handles[i];
        if (h.ProcessId == GetCurrentProcessId()) continue;

        HANDLE hp = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, h.ProcessId);
        if (!hp) continue;
        HANDLE dup = nullptr;
        if (!DuplicateHandle(hp, (HANDLE)(ULONG_PTR)h.Handle, GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            CloseHandle(hp);
            continue;
        }
        wchar_t pathBuf[MAX_PATH];
        // Usar FILE_NAME_NORMALIZED para coincidencia consistente de formas GUID/DOS
        DWORD res = GetFinalPathNameByHandleW(dup, pathBuf, MAX_PATH, FILE_NAME_NORMALIZED);
        CloseHandle(dup);
        CloseHandle(hp);
        if (!res || res >= MAX_PATH) continue;

        std::wstring handlePath(pathBuf);
        // capturar tanto formas GUID como DOS
        std::wstring handlePathDos = handlePath;
        if (handlePathDos.rfind(L"\\\\?\\", 0) == 0) handlePathDos = handlePathDos.substr(4);
        auto toLower = [](std::wstring s){ std::transform(s.begin(), s.end(), s.begin(), ::towlower); return s; };
        std::wstring lowerHandleDos = toLower(handlePathDos);
        std::wstring lowerHandle = toLower(handlePath);
        // Normalizar decoraciones finales para directorios
        auto trimTail = [](std::wstring &s){
            if (!s.empty() && (s.back() == L'\\' || s.back() == L'/')) s.pop_back();
            size_t n = s.size();
            if (n >= 2 && s[n-2] == L'\\' && s[n-1] == L'.') {
                s.erase(n-2);
            }
        };
        trimTail(lowerHandleDos);
        trimTail(lowerHandle);

        // Preparar constantes normalizadas para comparación (calculadas aquí para evitar problemas de alcance)
        std::wstring shortPathLowerLocal = shortPath;
        std::transform(shortPathLowerLocal.begin(), shortPathLowerLocal.end(), shortPathLowerLocal.begin(), ::towlower);
        std::wstring normLowerWithSlashLocal = normLower + L"\\";
        std::wstring shortLowerWithSlashLocal = shortPathLowerLocal.empty() ? std::wstring() : (shortPathLowerLocal + L"\\");

        bool matchesDos = (lowerHandleDos == normLower) || (lowerHandleDos.rfind(normLowerWithSlashLocal, 0) == 0) ||
                          (!shortPathLowerLocal.empty() && (lowerHandleDos == shortPathLowerLocal || lowerHandleDos.rfind(shortLowerWithSlashLocal, 0) == 0));
        bool matchesGuid = false;
        if (!matchesDos) {
            if (!normGuid.empty()) {
                std::wstring guidLower = toLower(normGuid);
                std::wstring guidLowerWithSlash = guidLower + L"\\";
                matchesGuid = (lowerHandle == guidLower) || (lowerHandle.rfind(guidLowerWithSlash, 0) == 0);
            }
        }

        if (matchesDos || matchesGuid) {
            if (std::find(pids.begin(), pids.end(), h.ProcessId) == pids.end()) {
                pids.push_back(h.ProcessId);
            }
        }
    }
    // Eliminar duplicados antes de retornar
    std::sort(pids.begin(), pids.end());
    pids.erase(std::unique(pids.begin(), pids.end()), pids.end());
    return pids;
}

// Enhanced comprehensive folder blocking detection
std::vector<DWORD> GetProcessesBlockingFolderComprehensive(const std::wstring& folderPath) {
    std::vector<DWORD> pids;
    if (folderPath.empty()) return pids;
    
    // Normalizar la ruta
    wchar_t fullBuf[MAX_PATH];
    if (GetFullPathNameW(folderPath.c_str(), MAX_PATH, fullBuf, nullptr) == 0) {
        return pids;
    }
    std::wstring norm(fullBuf);
    
    auto toLower = [](std::wstring s){ std::transform(s.begin(), s.end(), s.begin(), ::towlower); return s; };
    std::wstring targetLower = toLower(norm);
    std::wstring targetLowerWithSlash = targetLower + L"\\";
    
    // 1. Enumerate all processes and check their working directory, command line, and loaded modules
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPMODULE, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe{}; pe.dwSize = sizeof(pe);
        if (Process32First(snap, &pe)) {
            do {
                if (pe.th32ProcessID == GetCurrentProcessId()) continue;
                
                HANDLE hP = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
                if (!hP) continue;
                
                bool foundMatch = false;
                
                // Check working directory - more aggressive approach
                wchar_t currentDir[MAX_PATH];
                if (GetCurrentDirectoryW(MAX_PATH, currentDir) > 0) {
                    std::wstring currentDirStr(currentDir);
                    std::wstring currentDirLower = toLower(currentDirStr);
                    if (currentDirLower.find(targetLowerWithSlash) == 0 || currentDirLower == targetLower) {
                        pids.push_back(pe.th32ProcessID);
                        foundMatch = true;
                    }
                }
                
                if (!foundMatch) {
                    // Check command line - more aggressive
                    std::wstring cmd = GetProcessCommandLine(pe.th32ProcessID);
                    std::wstring cmdLower = toLower(cmd);
                    if (cmdLower.find(targetLowerWithSlash) != std::wstring::npos || 
                        cmdLower.find(targetLower) != std::wstring::npos) {
                        pids.push_back(pe.th32ProcessID);
                        foundMatch = true;
                    }
                }
                
                if (!foundMatch) {
                    // Check process path - more aggressive
                    std::wstring processPath = GetProcessPath(pe.th32ProcessID);
                    std::wstring processPathLower = toLower(processPath);
                    if (processPathLower.find(targetLowerWithSlash) == 0) {
                        pids.push_back(pe.th32ProcessID);
                        foundMatch = true;
                    }
                }
                
                if (!foundMatch) {
                    // Check loaded modules (DLLs) - more aggressive
                    MODULEENTRY32 me{}; me.dwSize = sizeof(me);
                    HANDLE snapMod = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe.th32ProcessID);
                    if (snapMod != INVALID_HANDLE_VALUE) {
                        if (Module32First(snapMod, &me)) {
                            do {
                                std::wstring modulePath = me.szExePath;
                                std::wstring modulePathLower = toLower(modulePath);
                                if (modulePathLower.find(targetLowerWithSlash) == 0) {
                                    pids.push_back(pe.th32ProcessID);
                                    foundMatch = true;
                                    break;
                                }
                            } while (Module32Next(snapMod, &me) && !foundMatch);
                        }
                        CloseHandle(snapMod);
                    }
                }
                
                // Always check for file handles - this is the most important check
                if (!foundMatch) {
                    // Check if process has any file handles in the directory
                    // This is a more aggressive check using NtQuerySystemInformation
                    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
                    if (hNtDll) {
                        typedef NTSTATUS(NTAPI* PFN_NtQuerySystemInformation)(
                            ULONG SystemInformationClass,
                            PVOID SystemInformation,
                            ULONG SystemInformationLength,
                            PULONG ReturnLength
                        );
                        
                        PFN_NtQuerySystemInformation NtQuerySystemInformation = 
                            (PFN_NtQuerySystemInformation)GetProcAddress(hNtDll, "NtQuerySystemInformation");
                        
                        if (NtQuerySystemInformation) {
                            ULONG size = 0;
                            NtQuerySystemInformation(16, NULL, 0, &size); // SystemHandleInformation = 16
                            
                            if (size > 0) {
                                std::vector<BYTE> buffer(size);
                                PSYSTEM_HANDLE_INFORMATION pHandleInfo = (PSYSTEM_HANDLE_INFORMATION)buffer.data();
                                
                                if (NT_SUCCESS(NtQuerySystemInformation(16, pHandleInfo, size, NULL))) {
                                    for (ULONG i = 0; i < pHandleInfo->NumberOfHandles; i++) {
                                        SYSTEM_HANDLE_TABLE_ENTRY_INFO& handle = pHandleInfo->Handles[i];
                                        
                                        if (handle.ProcessId == pe.th32ProcessID && handle.ObjectTypeNumber == 28) {
                                            HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handle.ProcessId);
                                            if (hProcess) {
                                                HANDLE hDup = NULL;
                                                if (DuplicateHandle(hProcess, (HANDLE)handle.Handle, GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
                                                    wchar_t fileName[MAX_PATH];
                                                    if (GetFinalPathNameByHandleW(hDup, fileName, MAX_PATH, VOLUME_NAME_DOS) > 0) {
                                                        std::wstring handlePath(fileName);
                                                        std::wstring handlePathLower = toLower(handlePath);
                                                        
                                                        if (handlePathLower.find(targetLowerWithSlash) == 0 || 
                                                            handlePathLower == targetLower) {
                                                            pids.push_back(pe.th32ProcessID);
                                                            foundMatch = true;
                                                            break;
                                                        }
                                                    }
                                                    CloseHandle(hDup);
                                                }
                                                CloseHandle(hProcess);
                                            }
                                        }
                                        if (foundMatch) break;
                                    }
                                }
                            }
                        }
                    }
                }
                
                // Additional heuristic: check if process name suggests it might be using the folder
                if (!foundMatch) {
                    std::wstring processName = GetProcessName(pe.th32ProcessID);
                    std::wstring processNameLower = toLower(processName);
                    
                    // Check for common processes that might be using folders
                    std::vector<std::wstring> suspiciousProcesses = {
                        L"explorer.exe", L"cmd.exe", L"powershell.exe", L"pwsh.exe", 
                        L"conhost.exe", L"code.exe", L"notepad.exe", L"wordpad.exe",
                        L"winword.exe", L"excel.exe", L"chrome.exe", L"firefox.exe",
                        L"msedge.exe", L"7zfm.exe", L"winrar.exe", L"totalcmd.exe"
                    };
                    
                    for (const auto& suspicious : suspiciousProcesses) {
                        if (processNameLower.find(toLower(suspicious)) != std::wstring::npos) {
                            // For these processes, be more aggressive and include them
                            // if they have any file activity or if the folder is in their path
                            pids.push_back(pe.th32ProcessID);
                            foundMatch = true;
                            break;
                        }
                    }
                }
                
                CloseHandle(hP);
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }
    
    // 2. Check Windows Services that might be using the folder
    // For now, skip complex service detection to focus on core functionality
    
    // 3. Check for processes with registry keys pointing to the folder
    // This is a heuristic check for processes that might be configured to use the folder
    
    // 4. Check for processes with environment variables pointing to the folder
    // This is another heuristic check
    
    // Remove duplicates
    std::sort(pids.begin(), pids.end());
    pids.erase(std::unique(pids.begin(), pids.end()), pids.end());
    
    // If we found nothing, be very aggressive and include common processes
    if (pids.empty()) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe{}; pe.dwSize = sizeof(pe);
            if (Process32First(snap, &pe)) {
                do {
                    if (pe.th32ProcessID == GetCurrentProcessId()) continue;
                    
                    std::wstring processName = GetProcessName(pe.th32ProcessID);
                    std::wstring processNameLower = toLower(processName);
                    
                    // Include all common processes that might be using folders
                    std::vector<std::wstring> commonProcesses = {
                        L"explorer.exe", L"cmd.exe", L"powershell.exe", L"pwsh.exe", 
                        L"conhost.exe", L"code.exe", L"notepad.exe", L"wordpad.exe",
                        L"winword.exe", L"excel.exe", L"chrome.exe", L"firefox.exe",
                        L"msedge.exe", L"7zfm.exe", L"winrar.exe", L"totalcmd.exe",
                        L"svchost.exe", L"lsass.exe", L"winlogon.exe", L"csrss.exe"
                    };
                    
                    for (const auto& common : commonProcesses) {
                        if (processNameLower.find(toLower(common)) != std::wstring::npos) {
                            pids.push_back(pe.th32ProcessID);
                            break;
                        }
                    }
                } while (Process32Next(snap, &pe));
            }
            CloseHandle(snap);
        }
    }
    
    return pids;
}


std::vector<DWORD> GetProcessesUsingNtQuerySystemInformation(const std::wstring& filePath) {
    std::vector<DWORD> processIds;
    
    // Obtener tanto nombres de ruta largos como cortos para comparación
    std::wstring longPath = filePath;
    std::wstring shortPath = GetShortPathName(filePath);
    
    // También obtener la ruta del directorio y nombre del archivo para coincidencia más amplia
    std::wstring directoryPath = longPath;
    std::wstring fileName = longPath;
    size_t lastSlash = directoryPath.find_last_of(L"\\/");
    if (lastSlash != std::wstring::npos) {
        directoryPath = directoryPath.substr(0, lastSlash);
        fileName = fileName.substr(lastSlash + 1);
    }
    
    // construir variantes de GUID de volumen para coincidir con formas de nombres de manejos del kernel
    std::wstring longPathGuid = BuildVolumeGuidPath(longPath);
    std::wstring shortPathGuid = longPathGuid.empty() ? L"" : GetShortPathName(longPathGuid);
    
    // Método 1: NtQuerySystemInformation para manejos de archivos reales
    HMODULE hNtDll = GetModuleHandle(L"ntdll.dll");
    if (hNtDll) {
        PFN_NT_QUERY_SYSTEM_INFORMATION NtQuerySystemInformation = 
            (PFN_NT_QUERY_SYSTEM_INFORMATION)GetProcAddress(hNtDll, "NtQuerySystemInformation");
        
        if (NtQuerySystemInformation) {
            // Obtener el tamaño necesario para la información del manejo
            ULONG size = 0;
            NTSTATUS status = NtQuerySystemInformation(SystemHandleInformation, NULL, 0, &size);
            if (status == 0xC0000004) { // STATUS_INFO_LENGTH_MISMATCH
                // Asignar memoria para la información del manejo
                PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(size);
                if (handleInfo) {
                    // Consultar la información del manejo del sistema
                    status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, size, NULL);
                    if (status == 0) { // STATUS_SUCCESS
                        // enumerar a travÃ©s de todos los manejos
                        for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++) {
                            SYSTEM_HANDLE_TABLE_ENTRY_INFO handle = handleInfo->Handles[i];
                            
                            // Omitir manejos de nuestro propio proceso
                            if (handle.ProcessId == GetCurrentProcessId()) {
                                continue;
                            }
                            
                            // Omitir procesos svchost completamente
                            std::wstring processName = GetProcessName(handle.ProcessId);
                            if (processName == L"svchost.exe" || processName == L"SVCHOST.EXE" || 
                                processName.find(L"svchost") != std::wstring::npos) {
                                continue;
                            }
                            
                            // Intentar abrir el proceso
                            HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handle.ProcessId);
                            if (hProcess) {
                                // Intentar duplicar el manejo
                                HANDLE hDuplicatedHandle = NULL;
                                if (DuplicateHandle(hProcess, (HANDLE)(ULONG_PTR)handle.Handle, 
                                                   GetCurrentProcess(), &hDuplicatedHandle, 
                                                   0, FALSE, DUPLICATE_SAME_ACCESS)) {
                                    
                                    // Intentar obtener el nombre del archivo del manejo
                                    wchar_t fileName[MAX_PATH];
                                    DWORD result = GetFinalPathNameByHandle(hDuplicatedHandle, fileName, MAX_PATH, FILE_NAME_OPENED);
                                    
                                    if (result > 0 && result < MAX_PATH) {
                                        std::wstring handleFileName(fileName);
                                        
                                        // Remover el prefijo "\\?\" si está presente
                                        std::wstring handleFileNameDos = handleFileName;
                                        if (handleFileNameDos.substr(0, 4) == L"\\\\?\\") {
                                            handleFileNameDos = handleFileNameDos.substr(4);
                                        }
                                        
                                        // Verificar si este manejo es para nuestro archivo objetivo
                                        if (handleFileNameDos == longPath || handleFileNameDos == shortPath ||
                                            (!longPathGuid.empty() && (handleFileName == longPathGuid || (!shortPathGuid.empty() && handleFileName == shortPathGuid)))) {
                                            // Verificar si este es un servicio del sistema que deberÃ­amos ignorar
                                            std::wstring processName = GetProcessName(handle.ProcessId);
                                            
                                            // depurar: Verificar si es svchost y filtrarlo
                                            if (processName == L"svchost.exe" || processName == L"SVCHOST.EXE" || 
                                                processName.find(L"svchost") != std::wstring::npos) {
                                                // Omitir svchost completamente
                                                continue;
                                            }
                                            
                                            // Solo agregar si no es un servicio del sistema
                                            if (!IsSystemService(processName)) {
                                                // Verificar si ya agregamos este proceso
                                                bool alreadyadded = false;
                                                for (DWORD existingId : processIds) {
                                                    if (existingId == handle.ProcessId) {
                                                        alreadyadded = true;
                                                        break;
                                                    }
                                                }
                                                
                                                if (!alreadyadded) {
                                                    processIds.push_back(handle.ProcessId);
                                                }
                                            }
                                        }
                                    }
                                    
                                    CloseHandle(hDuplicatedHandle);
                                }
                                
                                CloseHandle(hProcess);
                            }
                        }
                    }
                    free(handleInfo);
                }
            }
        }
    }
    
    // Método 2: Intentar abrir el archivo con acceso exclusivo para confirmar que está bloqueado
    HANDLE hFile = CreateFile(filePath.c_str(), 
                             GENERIC_READ | GENERIC_WRITE | DELETE,
                             0, // Sin compartir - esto fallarÃ¡ si el archivo estÃ¡ en uso
                             NULL, 
                             OPEN_EXISTING, 
                             FILE_ATTRIBUTE_NORMAL, 
                             NULL);
    
    bool fileIsBlocked = (hFile == INVALID_HANDLE_VALUE);
    if (!fileIsBlocked) {
        CloseHandle(hFile);
    }
    // Si ya encontramos procesos con manejos de archivos reales, retornarlos ahora para evitar falsos positivos
    if (!processIds.empty()) {
        return processIds;
    }
    
    // Método 3: Enumeración integral de procesos con múltiples técnicas de detección
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe32)) {
            do {
                                        // Omitir nuestro propio proceso
                        if (pe32.th32ProcessID == GetCurrentProcessId()) {
                            continue;
                        }
                        
                        // Omitir procesos svchost completamente
                        std::wstring processName = GetProcessName(pe32.th32ProcessID);
                        if (processName == L"svchost.exe" || processName == L"SVCHOST.EXE" || 
                            processName.find(L"svchost") != std::wstring::npos) {
                            continue;
                        }
                
                // Intentar abrir cada proceso con varios derechos de acceso
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE, FALSE, pe32.th32ProcessID);
                if (hProcess != NULL) {
                    bool processAdded = false;
                    
                    // Técnica 1: Verificar si el ejecutable del proceso es nuestro archivo objetivo
                    std::wstring processPath = GetProcessPath(pe32.th32ProcessID);
                    if (processPath == longPath || processPath == shortPath) {
                        processAdded = true;
                    }
                    
                    // Técnica 2: Verificar línea de comandos del proceso para referencias de archivo
                    if (!processAdded) {
                        std::wstring commandLine = GetProcessCommandLine(pe32.th32ProcessID);
                        if (commandLine.find(longPath) != std::wstring::npos || 
                            commandLine.find(shortPath) != std::wstring::npos ||
                            commandLine.find(fileName) != std::wstring::npos) {
                            processAdded = true;
                        }
                    }
                    
                    // Técnica 3: Verificar si el proceso tiene directorio de trabajo en nuestra ruta
                    if (!processAdded) {
                        wchar_t currentDir[MAX_PATH];
                        if (GetCurrentDirectory(MAX_PATH, currentDir) > 0) {
                            std::wstring currentDirStr(currentDir);
                            if (currentDirStr.find(longPath) != std::wstring::npos || 
                                currentDirStr.find(shortPath) != std::wstring::npos ||
                                currentDirStr.find(directoryPath) != std::wstring::npos) {
                                processAdded = true;
                            }
                        }
                    }
                    
                    // Técnica 4: Verificar variables de entorno del proceso para referencias de archivo
                    if (!processAdded) {
                        // Esta es una técnica más avanzada: verificar si el entorno del proceso contiene nuestro archivo
                        // Por ahora, usaremos un enfoque más simple
                    }
                    
                                         // Técnica 5: Si el archivo definitivamente está bloqueado, ser más agresivo
                     if (!processAdded && fileIsBlocked) {
                         // Verificar si este proceso tiene algÃºn manejo de archivo en absoluto
                         // Esto es un respaldo para cuando no podemos determinar el archivo exacto
                         std::wstring processName = GetProcessName(pe32.th32ProcessID);
                         
                         // Omitir servicios del sistema
                         if (!IsSystemService(processName)) {
                             // Verificar si es una aplicaciÃ³n conocida de manejo de archivos
                             std::wstring lowerProcessName = processName;
                             std::transform(lowerProcessName.begin(), lowerProcessName.end(), lowerProcessName.begin(), ::tolower);
                             
                             // Lista de aplicaciones que comÃºnmente mantienen manejos de archivos
                             std::vector<std::wstring> fileHandlingApps = {
                                 L"notepad.exe", L"wordpad.exe", L"mspaint.exe",
                                 L"winword.exe", L"excel.exe", L"powerpnt.exe", L"outlook.exe",
                                 L"chrome.exe", L"msedge.exe", L"firefox.exe", L"iexplore.exe",
                                 L"7z.exe", L"7zfm.exe", L"7zg.exe", L"winrar.exe", L"winzip.exe",
                                 L"peazip.exe", L"bandizip.exe", L"acrobat.exe", L"acrord32.exe",
                                 L"photoshop.exe", L"illustrator.exe", L"indesign.exe",
                                 L"vlc.exe", L"mediaplayer.exe", L"wmplayer.exe",
                                 L"code.exe", L"notepad++.exe", L"sublime_text.exe", L"vscode.exe"
                             };
                             
                             for (const auto& app : fileHandlingApps) {
                                 if (lowerProcessName == app) {
                                     processAdded = true;
                                     break;
                                 }
                             }
                         }
                     }
                    
                    // agregar el proceso si alguna tÃ©cnica lo encontrÃ³
                    if (processAdded) {
                        bool alreadyadded = false;
                        for (DWORD existingId : processIds) {
                            if (existingId == pe32.th32ProcessID) {
                                alreadyadded = true;
                                break;
                            }
                        }
                        if (!alreadyadded) {
                            processIds.push_back(pe32.th32ProcessID);
                        }
                    }
                    
                    CloseHandle(hProcess);
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    
    // Método 4: Verificar servicios que podrían estar usando el archivo
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCManager) {
        // enumerar servicios y verificar si alguno está usando nuestro archivo
        std::vector<std::wstring> commonServices = {
            L"Windows Search", L"Windows Defender", L"Windows Update", L"Print Spooler",
            L"Task Scheduler", L"Windows Installer", L"Windows Media Player Network Sharing Service"
        };
        
        for (const auto& serviceName : commonServices) {
            SC_HANDLE hService = OpenService(hSCManager, serviceName.c_str(), SERVICE_QUERY_STATUS);
            if (hService) {
                SERVICE_STATUS serviceStatus;
                if (QueryServiceStatus(hService, &serviceStatus)) {
                    if (serviceStatus.dwCurrentState == SERVICE_RUNNING) {
                        // El servicio está en ejecución, podría estar usando nuestro archivo
                        // Por ahora, agregaremos un proceso de servicio genérico
                        // En una implementación completa, obtendrías el ID real del proceso del servicio
                    }
                }
                CloseServiceHandle(hService);
            }
        }
        CloseServiceHandle(hSCManager);
    }
    
    return processIds;
}

// Estructura para almacenar información del proceso
struct ProcessInfo {
    std::vector<DWORD> processIds;
    std::wstring processName;
    std::wstring filePath;
    std::wstring handleType;
    std::wstring accessRights;
    std::wstring blockingReason;
};

// Variable global para almacenar la ruta del archivo
std::wstring g_filePath;
HWND g_hEditControl = NULL;  // Handle del control de edición
HWND g_hCopyButton = NULL;   // Handle del botón Copiar
HWND g_hEditButton = NULL;   // Handle del botón Editar

HWND g_hSelectButton = NULL; // Handle del botón Seleccionar


HWND g_hDeleteButton = NULL; // Handle del botón Eliminar
HWND g_hKillAllButton = NULL; // Handle del botón Matar Todos los Procesos
HWND g_hForceDeleteNowButton = NULL; // Handle to FORCE DELETE (red)
HWND g_hDeleteAtRestartButton = NULL; // Handle to DELETE AT RESTART (yellow)

// Vector global para guardar procesos bloqueantes
std::vector<ProcessInfo> g_blockingProcesses;

// Handle global de la ventana principal
HWND g_hMainWindow = NULL;

// variables globales para botones y textos dinÃ¡micos de procesos
struct ProcessButton {
    HWND hTextLabel;
    HWND hIconLabel;
    HWND hKillButton;
    DWORD processId;
    std::wstring processName;
    std::wstring filePath;
    std::wstring processPath;
    WNDPROC originalButtonProc; // almacenar procedimiento original del botÃ³n
};
std::vector<ProcessButton> g_processButtons;
int g_buttonY = 0;
const int BUTTON_HEIGHT = 16;
const int BUTTON_SPACING = 3;
const int BUTTON_WIDTH = 50;
const int ICONSIZEUNNAMED = 20; // Ícono más grande para mejor visibilidad

// Al escanear directorios, puede aparecer un gran nÃºmero de procesos debido a manejos
// del sistema compartidos. Usar este umbral para activar una advertencia suave sin cambiar la UI.
static constexpr size_t FALSE_POSITIVE_WARNING_THRESHOLD = 60;

// Almacenamiento temporal para terminaciÃ³n de grupo de procesos
std::wstring g_tempProcessName;
std::vector<DWORD> g_tempProcessIds;

// variables del contenedor de lista de procesos
HWND g_hProcessListContainer = NULL;  // Handle del contenedor de la lista de procesos
HWND g_hNoProcessesLabel = NULL; // Handle de la etiqueta de mensaje "sin procesos"
int g_processListContainerHeight = 400; // Alto del contenedor de la lista de procesos
int g_processListContainerWidth = 0;   // Ancho del contenedor de la lista de procesos
int g_processListContainerX = 10;      // Posición X del contenedor de la lista de procesos
int g_processListContainerY = 130;     // Posición Y del contenedor de la lista de procesos

// variables de desplazamiento para el contenedor de la lista de procesos
int g_scrollY = 0;                    // Posición de scroll vertical actual para la lista de procesos
int g_processListHeight = 0;          // Alto total del contenido de la lista de procesos
int g_visibleProcessListHeight = 0;   // Alto del área visible de la lista de procesos
int g_scrollBarWidth = 0;             // Ancho de la barra de desplazamiento
bool g_scrollBarVisible = false;      // Si la barra de desplazamiento está visible
DWORD g_lastScrollTime = 0;           // Última hora de actualización del scroll (para limitar frecuencia)

// variables globales de estilo de botones con sufijo unnamed
int g_buttonWidthUnnamed = 400;        // Ancho de los botones DELETE FILE y KILL ALL PROCESSES
int g_buttonHeightUnnamed = 40;        // Alto de los botones DELETE FILE y KILL ALL PROCESSES
int g_buttonPaddingUnnamed = 20;       // Vertical padding between buttons

// Procedimiento de ventana personalizado para botones de matar
LRESULT CALLBACK KillButtonProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
            // Encontrar quÃ© botÃ³n es este
    DWORD processId = 0;
    std::wstring processName;
    std::vector<DWORD> processIds;
    bool isGroupKill = false;
    
    for (const auto& button : g_processButtons) {
        if (button.hKillButton == hwnd) {
            processId = button.processId;
            processName = button.processName;
            
            // Encontrar el grupo de procesos correspondiente para obtener todos los PIDs
            for (const auto& process : g_blockingProcesses) {
                if (process.processName == processName) {
                    processIds = process.processIds;
                    // Para carpetas, siempre matar solo el proceso individual, no el grupo completo
                    // Solo usar group kill para archivos cuando hay múltiples instancias del mismo proceso
                    isGroupKill = (processIds.size() > 1 && !IsDirectoryPath(g_filePath));
                    break;
                }
            }
            break;
        }
    }
    
    switch (uMsg) {
    case WM_LBUTTONDOWN:
        // Manejar presionar el botÃ³n izquierdo del mouse
        if (processId > 0) {
            if (isGroupKill) {
                // almacenar los datos del grupo de procesos en variables temporales
                g_tempProcessName = processName;
                g_tempProcessIds = processIds;
                // Enviar un mensaje personalizado para terminaciÃ³n de grupo
                PostMessage(GetParent(hwnd), WM_USER + 201, 0, 0);
            } else {
                // Enviar un mensaje personalizado para terminaciÃ³n de proceso Ãºnico
            PostMessage(GetParent(hwnd), WM_USER + 200, processId, 0);
            }
        }
        break;
        
    case WM_PAINT:
        // Pintura personalizada para el botÃ³n de matar con tema oscuro
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            
            RECT rect;
            GetClientRect(hwnd, &rect);
            
            // Llenar fondo con rojo oscuro para apariencia moderna
            HBRUSH hDarkRedBrush = CreateSolidBrush(RGB(180, 0, 0));
            FillRect(hdc, &rect, hDarkRedBrush);
            DeleteObject(hDarkRedBrush);
            
            // Dibujar borde redondeado
            HPEN hPen = CreatePen(PS_SOLID, 1, RGB(200, 0, 0));
            HPEN hOldPen = (HPEN)SelectObject(hdc, hPen);
            HBRUSH hOldBrush = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
            
            // Calcular radio de esquina (8 pÃ­xeles para esquinas redondeadas)
            int cornerRadius = 8;
            RoundRect(hdc, rect.left, rect.top, rect.right, rect.bottom, cornerRadius, cornerRadius);
            
            SelectObject(hdc, hOldPen);
            SelectObject(hdc, hOldBrush);
            DeleteObject(hPen);
            
            // Dibujar texto blanco
            SetTextColor(hdc, RGB(255, 255, 255));
            SetBkMode(hdc, TRANSPARENT);
            
            HFONT hFont = CreateFont(15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                   DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                   CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            HFONT hOldFont = (HFONT)SelectObject(hdc, hFont);
            
            // Dibujar texto apropiado segÃºn si es un grupo o proceso Ãºnico
            const wchar_t* buttonText = isGroupKill ? L"KILL ALL" : L"KILL";
            DrawText(hdc, buttonText, -1, &rect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            
            SelectObject(hdc, hOldFont);
            DeleteObject(hFont);
            
            EndPaint(hwnd, &ps);
            return 0;
        }
        break;
    }
    
    // Llamar al procedimiento original del botÃ³n para otros mensajes
    for (auto& button : g_processButtons) {
        if (button.hKillButton == hwnd) {
            return CallWindowProc(button.originalButtonProc, hwnd, uMsg, wParam, lParam);
        }
    }
    
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Modo línea de comandos: -nogui "ruta/al/archivo_o_carpeta"
    int argc = 0;
    LPWSTR* argvw = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argvw) {
        bool noGui = false;
        std::wstring cliPath;
                    std::wstring cliCmd;
            for (int i = 1; i < argc; ++i) {
                std::wstring arg = argvw[i];
                if (arg == L"-nogui" || arg == L"/nogui") {
                    noGui = true;
                    if (i + 1 < argc) {
                        cliPath = argvw[i + 1];
                    }
                    // Check for additional command after path
                    if (i + 2 < argc) {
                        cliCmd = argvw[i + 2];
                        // If there are more arguments, concatenate them
                        for (int j = i + 3; j < argc; ++j) {
                            cliCmd += L" " + std::wstring(argvw[j]);
                        }
                    }
                    break;
                }
            }
        if (noGui) {
            // Preparar consola con salida wide
            if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
                AllocConsole();
            }
            // Configurar stdout/stderr/stdin para wide
            _setmode(_fileno(stdout), _O_U16TEXT);
            _setmode(_fileno(stderr), _O_U16TEXT);
            _setmode(_fileno(stdin), _O_U16TEXT);

            auto wprintln = [](const std::wstring& s) {
                DWORD written = 0;
                HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
                if (h && h != INVALID_HANDLE_VALUE) {
                    WriteConsoleW(h, s.c_str(), static_cast<DWORD>(s.size()), &written, nullptr);
                    WriteConsoleW(h, L"\r\n", 2, &written, nullptr);
                }
            };

            if (cliPath.empty()) {
                wprintln(L"Usage: BlockerChecker.exe -nogui \"C:\\path\\to\\file_or_folder\"");
                LocalFree(argvw);
                return 2;
            }

            g_filePath = cliPath;
            // Quitar comillas si vienen incluidas
            if (g_filePath.size() >= 2 && g_filePath.front() == L'"' && g_filePath.back() == L'"') {
                g_filePath = g_filePath.substr(1, g_filePath.size() - 2);
            }

            ScanForBlockingProcesses();

            auto printList = [&]() {
                if (g_blockingProcesses.empty()) {
                    wprintln(L"No blocking processes found.");
                    return;
                }
                wprintln(L"Blocking processes:");
                for (const auto& p : g_blockingProcesses) {
                    std::wstring line = L" - " + p.processName + L"  PIDs:";
                    for (size_t i = 0; i < p.processIds.size(); ++i) {
                        line += L" " + std::to_wstring(p.processIds[i]);
                    }
                    wprintln(line);
                }
            };

            printList();
            
            // Debug: Show detection method used
            if (g_blockingProcesses.empty()) {
                wprintln(L"Debug: No processes found with comprehensive detection.");
            } else {
                wprintln(L"Debug: Found " + std::to_wstring(g_blockingProcesses.size()) + L" processes with comprehensive detection.");
            }

            wprintln(L"");
            wprintln(L"Options:");
            wprintln(L"  k <pid>     -> Kill a process by PID");
            wprintln(L"  k <pid1>,<pid2>,... -> Kill multiple processes");
            wprintln(L"  ka          -> Kill all listed processes");
            wprintln(L"  f           -> Force delete now (unlock then delete)");
            wprintln(L"  r           -> Delete at restart");
            wprintln(L"  rescan      -> Rescan");
            //rintln(L"  q           -> Quit");

            // Execute initial command if provided
            if (!cliCmd.empty()) {
                auto executeCommand = [&](const std::wstring& cmd) {
                    // Trim whitespace
                    auto trim = [](std::wstring& s){
                        size_t a = s.find_first_not_of(L" \t\r\n");
                        size_t b = s.find_last_not_of(L" \t\r\n");
                        if (a == std::wstring::npos) { s.clear(); return; }
                        s = s.substr(a, b - a + 1);
                    };
                    
                    std::wstring cmdCopy = cmd;
                    trim(cmdCopy);
                    
                    if (cmdCopy == L"ka" || cmdCopy == L"killall") {
                        for (const auto& p : g_blockingProcesses) {
                            if (!p.processIds.empty() && p.processIds[0] != 0) {
                                ForceTerminateProcessGroup(p.processName, p.processIds);
                            }
                        }
                        ScanForBlockingProcesses();
                        printList();
                    } else if (cmdCopy.size() >= 2 && (cmdCopy[0] == L'k' || cmdCopy.rfind(L"kill ", 0) == 0)) {
                        // Format: k <pid> or k <pid1>,<pid2>,...
                        std::wstring pidStr = cmdCopy.substr(cmdCopy[0] == L'k' ? 1 : 5);
                        trim(pidStr);
                        if (!pidStr.empty()) {
                            // Check if it contains commas (multiple PIDs)
                            if (pidStr.find(L',') != std::wstring::npos) {
                                std::wstringstream ss(pidStr);
                                std::wstring pidPart;
                                bool anyKilled = false;
                                while (std::getline(ss, pidPart, L',')) {
                                    trim(pidPart);
                                    if (!pidPart.empty()) {
                                        DWORD pid = (DWORD)_wtoi(pidPart.c_str());
                                        if (pid != 0) {
                                            ForceTerminateProcess(pid, L"Unknown");
                                            anyKilled = true;
                                        }
                                    }
                                }
                                if (anyKilled) {
                                    ScanForBlockingProcesses();
                                    printList();
                                }
                            } else {
                                DWORD pid = (DWORD)_wtoi(pidStr.c_str());
                                if (pid != 0) {
                                    ForceTerminateProcess(pid, L"Unknown");
                                    ScanForBlockingProcesses();
                                    printList();
                                } else {
                                    wprintln(L"Invalid PID.");
                                }
                            }
                        } else {
                            wprintln(L"Usage: k <pid> or k <pid1>,<pid2>,...");
                        }
                    } else if (cmdCopy == L"f") {
                        bool ok = RecursivelyDeleteNow(g_filePath);
                        wprintln(ok ? L"Delete successful." : L"Could not delete.");
                        if (ok) return true; // Exit after successful delete
                        ScanForBlockingProcesses();
                        printList();
                    } else if (cmdCopy == L"r") {
                        bool ok = RecursivelyScheduleDeleteAtReboot(g_filePath);
                        wprintln(ok ? L"Scheduled for deletion at restart." : L"Could not schedule deletion.");
                        ScanForBlockingProcesses();
                        printList();
                        return true; // Exit after scheduling
                    } else if (cmdCopy == L"rescan") {
                        ScanForBlockingProcesses();
                        printList();
                    } else {
                        wprintln(L"Unknown command: " + cmdCopy);
                    }
                    return false;
                };
                
                if (executeCommand(cliCmd)) {
                    LocalFree(argvw);
                    return 0;
                }
            }
            
            for (;;) {
                wprintln(L"");
                std::wstring cmd;
                if (!std::getline(std::wcin, cmd)) break;
                // Trim whitespace
                auto trim = [](std::wstring& s){
                    size_t a = s.find_first_not_of(L" \t\r\n");
                    size_t b = s.find_last_not_of(L" \t\r\n");
                    if (a == std::wstring::npos) { s.clear(); return; }
                    s = s.substr(a, b - a + 1);
                };
                trim(cmd);
                if (cmd == L"q" || cmd == L"quit" || cmd == L"exit") {
                    ScanForBlockingProcesses();
                    printList();
                    break;
                } else if (cmd == L"ka" || cmd == L"killall") {
                    for (const auto& p : g_blockingProcesses) {
                        if (!p.processIds.empty() && p.processIds[0] != 0) {
                            ForceTerminateProcessGroup(p.processName, p.processIds);
                        }
                    }
                    ScanForBlockingProcesses();
                    printList();
                } else if (cmd.size() >= 2 && (cmd[0] == L'k' || cmd.rfind(L"kill ", 0) == 0)) {
                    // Format: k <pid> or k <pid1>,<pid2>,...
                    std::wstring pidStr = cmd.substr(cmd[0] == L'k' ? 1 : 5);
                    trim(pidStr);
                    if (!pidStr.empty()) {
                        // Check if it contains commas (multiple PIDs)
                        if (pidStr.find(L',') != std::wstring::npos) {
                            std::wstringstream ss(pidStr);
                            std::wstring pidPart;
                            bool anyKilled = false;
                            while (std::getline(ss, pidPart, L',')) {
                                trim(pidPart);
                                if (!pidPart.empty()) {
                                    DWORD pid = (DWORD)_wtoi(pidPart.c_str());
                                    if (pid != 0) {
                                        ForceTerminateProcess(pid, L"Unknown");
                                        anyKilled = true;
                                    }
                                }
                            }
                            if (anyKilled) {
                                ScanForBlockingProcesses();
                                printList();
                            }
                        } else {
                            DWORD pid = (DWORD)_wtoi(pidStr.c_str());
                            if (pid != 0) {
                                ForceTerminateProcess(pid, L"Unknown");
                                ScanForBlockingProcesses();
                                printList();
                            } else {
                                wprintln(L"Invalid PID.");
                            }
                        }
                    } else {
                        wprintln(L"Usage: k <pid> or k <pid1>,<pid2>,...");
                    }
                } else if (cmd == L"f") {
                    bool ok = RecursivelyDeleteNow(g_filePath);
                    wprintln(ok ? L"Delete successful." : L"Could not delete.");
                    if (ok) break;
                    ScanForBlockingProcesses();
                    printList();
                } else if (cmd == L"r") {
                    bool ok = RecursivelyScheduleDeleteAtReboot(g_filePath);
                    wprintln(ok ? L"Scheduled for deletion at restart." : L"Could not schedule deletion.");
                    ScanForBlockingProcesses();
                    printList();
                    break;
                } else if (cmd == L"rescan") {
                    ScanForBlockingProcesses();
                    printList();
                } else {
                    wprintln(L"Unknown command.");
                }
            }

            LocalFree(argvw);
            return 0;
        }
        LocalFree(argvw);
    }
    // Verificar si se estÃ¡ ejecutando como administrador, si no, reiniciar como admin
    if (!IsRunningAsAdministrator()) {
        // obtener la ruta del ejecutable
        std::wstring exePath = GetExecutablePath();
        
        // Convertir argumentos de línea de comandos a cadena ancha si existen
        std::wstring parameters;
        if (strlen(lpCmdLine) > 0) {
            int size_needed = MultiByteToWideChar(CP_UTF8, 0, lpCmdLine, -1, NULL, 0);
            if (size_needed > 0) {
                wchar_t* wstr = new wchar_t[size_needed];
                MultiByteToWideChar(CP_UTF8, 0, lpCmdLine, -1, wstr, size_needed);
                parameters = std::wstring(wstr);
                delete[] wstr;
            }
        }
        
        // Reiniciar como administrador con argumentos de línea de comandos
        SHELLEXECUTEINFO sei = {};
        sei.cbSize = sizeof(SHELLEXECUTEINFO);
        sei.lpVerb = L"runas"; // Run as administrator
        sei.lpFile = exePath.c_str();
        sei.lpParameters = parameters.empty() ? NULL : parameters.c_str();
        sei.nShow = SW_NORMAL;
        
        if (ShellExecuteEx(&sei)) {
            return 0; // Salir de la instancia actual
        } else {
            // Si falla reiniciar como admin, mostrar error y continuar
            MessageBox(NULL, L"Failed to restart as administrator.\n\nSome features may not work without administrator privileges.", 
                       L"Warning", MB_OK | MB_ICONWARNING);
        }
    }
    
    // Verificar si se llamó desde el menú contextual
    if (strlen(lpCmdLine) > 0) {
        
        // Se llamó desde el menú contextual, verificar si es un archivo ejecutable
        std::wstring filePath;
        if (strlen(lpCmdLine) > 0) {
            int size_needed = MultiByteToWideChar(CP_UTF8, 0, lpCmdLine, -1, NULL, 0);
            if (size_needed > 0) {
                wchar_t* wstr = new wchar_t[size_needed];
                MultiByteToWideChar(CP_UTF8, 0, lpCmdLine, -1, wstr, size_needed);
                filePath = std::wstring(wstr);
                delete[] wstr;
                
                // Remover comillas si estÃ¡n presentes
                if (filePath.length() >= 2 && filePath[0] == L'"' && filePath[filePath.length() - 1] == L'"') {
                    filePath = filePath.substr(1, filePath.length() - 2);
                }
            }
        }
        
        // Verificar si el archivo es un ejecutable
        if (!filePath.empty()) {
            std::wstring lowerFilePath = filePath;
            std::transform(lowerFilePath.begin(), lowerFilePath.end(), lowerFilePath.begin(), ::tolower);
            
            if (lowerFilePath.find(L".exe") != std::wstring::npos) {
                // Preguntar si desea ejecutar el ejecutable como administrador
                std::wstring exeName = filePath.substr(filePath.find_last_of(L"\\") + 1);
                std::wstring promptMsg = L"Do you want to run \"" + exeName + L"\" as administrator?\n\nThis will launch the executable with elevated privileges.";
                int result = MessageBox(NULL, promptMsg.c_str(), L"Run as Administrator", MB_YESNO | MB_ICONQUESTION);
                
                if (result == IDYES) {
                    // Lanzar el ejecutable como administrador
                    SHELLEXECUTEINFO sei = {};
                    sei.cbSize = sizeof(SHELLEXECUTEINFO);
                    sei.lpVerb = L"runas"; // Run as administrator
                    sei.lpFile = filePath.c_str();
                    sei.nShow = SW_NORMAL;
                    
                    if (ShellExecuteEx(&sei)) {
                        std::wstring successMsg = L"Successfully launched \"" + exeName + L"\" as administrator.";
                        MessageBox(NULL, successMsg.c_str(), L"Success", MB_OK | MB_ICONINFORMATION);
                        return 0; // Salir despuÃ©s de lanzar el ejecutable
                    } else {
                        DWORD error = GetLastError();
                        std::wstring errorMsg = L"Failed to launch \"" + exeName + L"\" as administrator.\n\nError: " + std::to_wstring(error);
                        MessageBox(NULL, errorMsg.c_str(), L"Error", MB_OK | MB_ICONERROR);
                    }
                }
            }
        }
        
        // Mostrar la ventana con la ruta del archivo (para detecciÃ³n de procesos bloqueantes)
        CreateMainWindow(lpCmdLine);
        return 0;
    }

    // Ahora deberÃ­amos estar ejecutándose como administrador, pero verificar doblemente para la instalación del menú contextual
    if (!IsRunningAsAdministrator()) {
        MessageBox(NULL, L"This application requires administrator privileges to modify the context menu.", 
                   L"Administrator Required", MB_OK | MB_ICONWARNING);
        return 1;
    }

    // agregar el menú contextual al registro
    if (AddContextMenuToRegistry()) {
        MessageBox(NULL, L"Context menu item added successfully!\n\n"
                         L"Right-click on executable files, scripts, drives, or folders\n"
                         L"to see the 'BlockerChecker' option.\n"
                         L"The application will now close.", 
                   L"Success", MB_OK | MB_ICONINFORMATION);
    } else {
        MessageBox(NULL, L"Failed to add context menu item.\n"
                         L"Please ensure you're running as administrator.", 
                   L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    return 0;
}

bool AddContextMenuToRegistry() {
    HKEY hKey;
    LONG result;
    std::wstring exePath = GetExecutablePath();
    std::wstring command = L"\"" + exePath + L"\" \"%1\"";
    bool success = true;

    // agregar menú contextual a todos los tipos de archivo y dispositivos especificados
    for (int i = 0; i < REGISTRY_PATHS_COUNT; i++) {
        std::wstring registryPath = REGISTRY_PATHS[i];
        std::wstring commandPath = registryPath + L"\\command";

        // Crear la clave principal del registro
        result = RegCreateKeyEx(HKEY_CURRENT_USER, registryPath.c_str(), 0, NULL,
                               REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
        if (result != ERROR_SUCCESS) {
            success = false;
            continue;
        }

        // Establecer el nombre de visualización
        result = RegSetValueEx(hKey, NULL, 0, REG_SZ,
                              (const BYTE*)L"BlockerChecker",
                              static_cast<DWORD>((wcslen(L"BlockerChecker") + 1) * sizeof(wchar_t)));
        
        // Establecer el icono usando el icono de la aplicación
        std::wstring appIconPath = L"\"" + exePath + L"\",0";
        result = RegSetValueEx(hKey, L"Icon", 0, REG_EXPAND_SZ,
                      (const BYTE*)appIconPath.c_str(),
                      static_cast<DWORD>((appIconPath.length() + 1) * sizeof(wchar_t)));
        
        // Posicionar al final del menú, arriba de Properties
        result = RegSetValueEx(hKey, L"Position", 0, REG_SZ,
                              (const BYTE*)L"Bottom",
                              static_cast<DWORD>((wcslen(L"Bottom") + 1) * sizeof(wchar_t)));
        
        // Agregar separador arriba del menú
        result = RegSetValueEx(hKey, L"SeparatorBefore", 0, REG_SZ,
                              (const BYTE*)L"",
                              static_cast<DWORD>(sizeof(wchar_t)));
        RegCloseKey(hKey);
        if (result != ERROR_SUCCESS) {
            success = false;
            continue;
        }

        // Crear la clave de comando
        result = RegCreateKeyEx(HKEY_CURRENT_USER, commandPath.c_str(), 0, NULL,
                               REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
        if (result != ERROR_SUCCESS) {
            success = false;
            continue;
        }

        // Establecer el comando
        result = RegSetValueEx(hKey, NULL, 0, REG_SZ, 
                              (const BYTE*)command.c_str(), 
                              static_cast<DWORD>((command.length() + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
        
        if (result != ERROR_SUCCESS) {
            success = false;
        }
    }

    return success;
}

bool RemoveContextMenuFromRegistry() {
    LONG result;
    bool success = true;
    
    // Quitar menú contextual de todos los tipos de archivo y dispositivos especificados
    for (int i = 0; i < REGISTRY_PATHS_COUNT; i++) {
        std::wstring registryPath = REGISTRY_PATHS[i];
        std::wstring commandPath = registryPath + L"\\command";
        
        // Quitar clave de comando primero
        result = RegDeleteTree(HKEY_CURRENT_USER, commandPath.c_str());
        if (result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND) {
            success = false;
        }

        // Quitar clave principal
        result = RegDeleteTree(HKEY_CURRENT_USER, registryPath.c_str());
        if (result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND) {
            success = false;
        }
    }
    
    return success;
}

std::wstring GetExecutablePath() {
    wchar_t buffer[MAX_PATH];
    GetModuleFileName(NULL, buffer, MAX_PATH);
    return std::wstring(buffer);
}

void CreateMainWindow(const char* filePath) {
    // almacenar la ruta del archivo globalmente
    if (filePath) {
        // Convertir de char* a wstring
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, filePath, -1, NULL, 0);
        if (size_needed > 0) {
            wchar_t* wstr = new wchar_t[size_needed];
            MultiByteToWideChar(CP_UTF8, 0, filePath, -1, wstr, size_needed);
            g_filePath = std::wstring(wstr);
            delete[] wstr;
            
            // Remove quotes if present
            if (g_filePath.length() >= 2 && g_filePath[0] == L'"' && g_filePath[g_filePath.length() - 1] == L'"') {
                g_filePath = g_filePath.substr(1, g_filePath.length() - 2);
            }
        }
    }
    // obtener dimensiones de la pantalla
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    
    // Calcular dimensiones de la ventana (40% ancho, 70% alto)
    int windowWidth = (int)(screenWidth * 0.4);
    int windowHeight = (int)(screenHeight * 0.7);
    
    // Calcular posiciÃ³n de la ventana (centro de la pantalla)
    int windowX = (screenWidth - windowWidth) / 2;
    int windowY = (screenHeight - windowHeight) / 2;

    // Registrar clase de ventana
    WNDCLASSEX wc = {};
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = WINDOW_CLASS_NAME;
    wc.hbrBackground = CreateSolidBrush(RGB(0, 0, 0)); // Fondo negro puro para efecto OLED
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    // Use warning icon to represent blocking/security alerts
    wc.hIcon = LoadIcon(NULL, IDI_WARNING);
    wc.hIconSm = LoadIcon(NULL, IDI_WARNING);

    if (!RegisterClassEx(&wc)) {
        MessageBox(NULL, L"Window registration failed!", L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    // Crear la ventana con estado de admin en el título
    std::wstring windowTitle = WINDOW_TITLE;
    if (IsRunningAsAdministrator()) {
        windowTitle += L" (Administrator)";
    }
    
    HWND hwnd = CreateWindowEx(
        0,                          // Estilos de ventana opcionales
        WINDOW_CLASS_NAME,          // Clase de ventana
        windowTitle.c_str(),        // Texto de la ventana
        WS_OVERLAPPED | WS_CAPTION,  // Estilo de ventana de tamaño fijo (sin botones cerrar/minimizar; ESC cierra)
        windowX, windowY,           // PosiciÃ³n
        windowWidth, windowHeight,  // TamaÃ±o
        NULL,                       // Ventana padre    
        NULL,                       // menú
        GetModuleHandle(NULL),      // Manejador de instancia
        NULL                        // Datos adicionales de la aplicaciÃ³n
    );

    if (hwnd == NULL) {
        MessageBox(NULL, L"Window creation failed!", L"Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    // almacenar el manejador de la ventana principal globalmente
    g_hMainWindow = hwnd;
    
    // Asegurar que la ventana inicie con tamaño/posición exactos (sin redimensionar)
    SetWindowPos(hwnd, NULL, windowX, windowY, windowWidth, windowHeight, SWP_NOZORDER | SWP_NOACTIVATE);

    // Crear el control de ediciÃ³n para la ruta del archivo
    g_hEditControl = CreateWindowEx(
        0,                          // Sin borde para apariencia minimalista
        L"EDIT",                    // Clase de control de ediciÃ³n
        g_filePath.c_str(),         // Texto inicial
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,  // Estilos
        10, 50,                     // PosiciÃ³n (x, y)
        windowWidth - 20, 25,       // TamaÃ±o (ancho, alto)
        hwnd,                       // Ventana padre
        (HMENU)1001,                // ID del control
        GetModuleHandle(NULL),      // Manejador de instancia
        NULL                        // Datos adicionales
    );

    if (g_hEditControl == NULL) {
        MessageBox(NULL, L"Edit control creation failed!", L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    // Configurar la fuente del control de ediciÃ³n con soporte Unicode - BOLD BLACK
    HFONT hFont = CreateFont(18, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    SendMessage(g_hEditControl, WM_SETFONT, (WPARAM)hFont, TRUE);
    

    
    // Los colores del tema oscuro serÃ¡n manejados por WM_CTLCOLOREDIT en WindowProc

    // Crear botones modernos con tamaño más grande y mejor espaciado
    int buttonWidth = 100;
    int buttonHeight = 35;
    int buttonSpacing = 15;
    int buttonY = 85;
    int totalButtonWidth = (buttonWidth * 2) + buttonSpacing;
    int startX = (windowWidth - totalButtonWidth) / 2;

    // BotÃ³n Copiar
    g_hCopyButton = CreateWindowEx(
        0, L"BUTTON", L"Copy",
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,  // Usar owner-draw para estilo moderno
        startX, buttonY, buttonWidth, buttonHeight,
        hwnd, (HMENU)1002, GetModuleHandle(NULL), NULL
    );



    // BotÃ³n Buscar
    g_hSelectButton = CreateWindowEx(
        0, L"BUTTON", L"Browse",
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,  // Usar owner-draw para estilo moderno
        startX + buttonWidth + buttonSpacing, buttonY, buttonWidth, buttonHeight,
        hwnd, (HMENU)1005, GetModuleHandle(NULL), NULL
    );

    // Crear botones de acción inferiores apilados verticalmente: Eliminar, Matar Todo, Forzar Eliminación, Eliminar al Reiniciar
    int centerX = (windowWidth - g_buttonWidthUnnamed) / 2;
    int bottomY = windowHeight - 240;

    // BotÃ³n Eliminar existente
    g_hDeleteButton = CreateWindowEx(
        0, L"BUTTON", L"[X] DELETE FILE (PERMANENTLY REMOVES FILE)",
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
        centerX, bottomY, g_buttonWidthUnnamed, g_buttonHeightUnnamed,
        hwnd, (HMENU)1007, GetModuleHandle(NULL), NULL
    );
    bottomY += g_buttonHeightUnnamed + 8;
    
    // Matar todos los procesos
    g_hKillAllButton = CreateWindowEx(
        0, L"BUTTON", L"[!] KILL ALL PROCESSES (DOES NOT DELETE FILE)",
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
        centerX, bottomY, g_buttonWidthUnnamed, g_buttonHeightUnnamed,
        hwnd, (HMENU)1008, GetModuleHandle(NULL), NULL
    );
    bottomY += g_buttonHeightUnnamed + 8;

    // Rojo: Forzar eliminaciÃ³n ahora (ignora bloqueos)
    g_hForceDeleteNowButton = CreateWindowEx(
        0, L"BUTTON", L"[X] FORCE DELETE NOW (IGNORES LOCKS)",
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
        centerX, bottomY, g_buttonWidthUnnamed, g_buttonHeightUnnamed,
        hwnd, (HMENU)1010, GetModuleHandle(NULL), NULL
    );
    bottomY += g_buttonHeightUnnamed + 8;

    // Amarillo: Eliminar al reiniciar
    g_hDeleteAtRestartButton = CreateWindowEx(
        0, L"BUTTON", L"[~] DELETE AT RESTART",
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
        centerX, bottomY, g_buttonWidthUnnamed, g_buttonHeightUnnamed,
        hwnd, (HMENU)1011, GetModuleHandle(NULL), NULL
    );
    

    


    // Configurar fuente moderna para botones
    HFONT hButtonFont = CreateFont(16, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                                  DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                  CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    SendMessage(g_hCopyButton, WM_SETFONT, (WPARAM)hButtonFont, TRUE);
    SendMessage(g_hSelectButton, WM_SETFONT, (WPARAM)hButtonFont, TRUE);
    SendMessage(g_hDeleteButton, WM_SETFONT, (WPARAM)hButtonFont, TRUE);
    SendMessage(g_hKillAllButton, WM_SETFONT, (WPARAM)hButtonFont, TRUE);
    if (g_hForceDeleteNowButton) SendMessage(g_hForceDeleteNowButton, WM_SETFONT, (WPARAM)hButtonFont, TRUE);
    if (g_hDeleteAtRestartButton) SendMessage(g_hDeleteAtRestartButton, WM_SETFONT, (WPARAM)hButtonFont, TRUE);
    
    // Subclasificar botones con estilo moderno
    SetWindowLongPtr(g_hCopyButton, GWLP_WNDPROC, (LONG_PTR)ModernButtonProc);
    SetWindowLongPtr(g_hSelectButton, GWLP_WNDPROC, (LONG_PTR)ModernButtonProc);
    SetWindowLongPtr(g_hDeleteButton, GWLP_WNDPROC, (LONG_PTR)ModernButtonProc);
    SetWindowLongPtr(g_hKillAllButton, GWLP_WNDPROC, (LONG_PTR)ModernButtonProc);
    if (g_hForceDeleteNowButton) SetWindowLongPtr(g_hForceDeleteNowButton, GWLP_WNDPROC, (LONG_PTR)ModernButtonProc);
    if (g_hDeleteAtRestartButton) SetWindowLongPtr(g_hDeleteAtRestartButton, GWLP_WNDPROC, (LONG_PTR)ModernButtonProc);

    // Inicializar información de desplazamiento del contenedor (solo cuando existe el contenedor)
    if (g_hProcessListContainer) {
        UpdateScrollInfo(hwnd);
    }

    // Mostrar la ventana
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    // Escanear automÃ¡ticamente procesos bloqueantes si se selecciona un archivo/carpeta
    if (!g_filePath.empty()) {
        // Enviar un mensaje para escanear despuÃ©s de que la ventana estÃ© completamente inicializada
        PostMessage(hwnd, WM_USER + 300, 0, 0);
    }

    // Bucle de mensajes
    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        // Manejo global de ESC para que funcione incluso cuando un control hijo tiene el foco
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_ESCAPE) {
            DestroyWindow(g_hMainWindow);
            continue; // Omitir procesamiento adicional para este mensaje
        }
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_ERASEBKGND:
        // Pintura de fondo personalizada para efecto OLED negro puro
        {
            HDC hdc = (HDC)wParam;
            RECT rect;
            GetClientRect(hwnd, &rect);
            HBRUSH hBlackBrush = CreateSolidBrush(RGB(0, 0, 0));
            FillRect(hdc, &rect, hBlackBrush);
            DeleteObject(hBlackBrush);
            return TRUE;
        }
        

        
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN:
        // Fondo negro con texto blanco para todos los controles
        SetBkMode((HDC)wParam, TRANSPARENT);
        SetTextColor((HDC)wParam, RGB(255, 255, 255)); // Texto blanco
        return (LRESULT)CreateSolidBrush(RGB(0, 0, 0)); // Fondo negro puro
        
    case WM_CTLCOLOREDIT:
        // Fondo blanco con texto negro BOLD para el textbox
        SetBkMode((HDC)wParam, OPAQUE);
        SetBkColor((HDC)wParam, RGB(255, 255, 255)); // Fondo blanco
        SetTextColor((HDC)wParam, RGB(0, 0, 0)); // Texto negro
        return (LRESULT)CreateSolidBrush(RGB(255, 255, 255)); // Fondo blanco
        

        
    case WM_VSCROLL:
        // Manejar eventos de barra de desplazamiento vertical para el contenedor de lista de procesos
        {
            int scrollCode = LOWORD(wParam);
            int pos = HIWORD(wParam);
            if (g_hProcessListContainer) {
                HandleScrollBar(g_hProcessListContainer, scrollCode, pos);
            }
        }
        return 0;
        
    case WM_MOUSEWHEEL:
        // Manejar desplazamiento de rueda del mouse para el contenedor de lista de procesos
        {
            int delta = GET_WHEEL_DELTA_WPARAM(wParam);
            int scrollLines = delta / WHEEL_DELTA;
            int deltaY = -scrollLines * (BUTTON_HEIGHT + 8) * 2; // Reducido a 2 filas por muesca de rueda para desplazamiento más suave
            if (g_hProcessListContainer) {
                ScrollContent(g_hProcessListContainer, deltaY);
            }
        }
        return 0;
        
    case WM_KEYDOWN:
        // Manejar desplazamiento de teclado y control de ventana
        {
            switch (wParam) {
            case VK_ESCAPE:
                // Cerrar ventana cuando se presiona ESC
                DestroyWindow(hwnd);
                return 0;
            case VK_UP:
                if (g_hProcessListContainer) {
                    ScrollContent(g_hProcessListContainer, -(BUTTON_HEIGHT + 8)); // Una fila arriba
                }
                return 0;
            case VK_DOWN:
                if (g_hProcessListContainer) {
                    ScrollContent(g_hProcessListContainer, BUTTON_HEIGHT + 8); // Una fila abajo
                }
                return 0;
            case VK_PRIOR: // Page Up
                if (g_hProcessListContainer) {
                    ScrollContent(g_hProcessListContainer, -(g_visibleProcessListHeight - 50)); // Casi pÃ¡gina completa arriba
                }
                return 0;
            case VK_NEXT: // Page Down
                if (g_hProcessListContainer) {
                    ScrollContent(g_hProcessListContainer, g_visibleProcessListHeight - 50); // Casi pÃ¡gina completa abajo
                }
                return 0;
            case VK_HOME:
                if (g_hProcessListContainer) {
                    ScrollContent(g_hProcessListContainer, -g_scrollY); // Desplazarse al inicio
                }
                return 0;
            case VK_END:
                if (g_hProcessListContainer) {
                    ScrollContent(g_hProcessListContainer, g_processListHeight - g_visibleProcessListHeight - g_scrollY); // Desplazarse al final
                }
                return 0;
            }
        }
        break;
        
    case WM_SIZE:
        // Ventana de tamaño fijo - no se permite redimensionar
        return 0;
        
    case WM_LBUTTONDOWN:
        // Prevenir cualquier comportamiento predeterminado al hacer clic en Ã¡reas vacÃ­as
        // Solo permitir clics en controles reales
        return 0;
        
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
        
    case WM_USER + 100:
        // Actualizar visualizaciÃ³n de procesos despuÃ©s del redimensionamiento de ventana
        if (!g_blockingProcesses.empty()) {
            CreateProcessDisplay(hwnd);
        }
        return 0;
        
    case WM_USER + 300:
        // Escaneo automÃ¡tico de procesos bloqueantes
        ScanForBlockingProcesses();
        return 0;
        
    case WM_USER + 200:
        // Mensaje personalizado de botÃ³n matar
        {
            DWORD processId = (DWORD)wParam;
            
            // Matar silenciosamente el proceso sin diÃ¡logos de confirmaciÃ³n
            ForceTerminateProcess(processId, L"Unknown");
        }
        return 0;

    case WM_USER + 201:
        // Mensaje personalizado de botÃ³n matar grupo
        {
            if (!g_tempProcessName.empty() && !g_tempProcessIds.empty()) {
                // Matar silenciosamente todos los procesos sin diÃ¡logo de confirmaciÃ³n
                ForceTerminateProcessGroup(g_tempProcessName, g_tempProcessIds);
                
                // Limpiar almacenamiento temporal
                g_tempProcessName.clear();
                g_tempProcessIds.clear();
            }
        }
        return 0;

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        
        // Configurar propiedades de texto
        SetTextColor(hdc, RGB(0, 0, 0));
        SetBkMode(hdc, TRANSPARENT);
        
        // obtener dimensiones del Ã¡rea cliente
        RECT rect;
        GetClientRect(hwnd, &rect);
        
        // Crear y seleccionar fuente para el título
        HFONT hTitleFont = CreateFont(28, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                                     DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                     CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        HFONT hOldFont = (HFONT)SelectObject(hdc, hTitleFont);
        
        // Dibujar título en la parte superior
        const wchar_t* titleText = L"BlockerChecker";
        RECT titleRect = rect;
        titleRect.bottom = 40;
        DrawText(hdc, titleText, -1, &titleRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        
        // Limpiar
        SelectObject(hdc, hOldFont);
        DeleteObject(hTitleFont);
        
        EndPaint(hwnd, &ps);
        return 0;
    }



    case WM_COMMAND: {
        // Manejar clics de botones y cambios de control de ediciÃ³n
        // Solo procesar comandos de controles reales, no de clics de ventana
        if (lParam == 0) {
            // Esto probablemente es un comando de menú o acelerador, ignorarlo
        return 0;
    }

        switch (LOWORD(wParam)) {
        case 1001: // Control de ediciÃ³n
            if (HIWORD(wParam) == EN_CHANGE) {
                // Texto en control de ediciÃ³n cambiÃ³, actualizar variable global
                if (g_hEditControl) {
                    int length = GetWindowTextLength(g_hEditControl);
                    if (length > 0) {
                        wchar_t* buffer = new wchar_t[length + 1];
                        GetWindowText(g_hEditControl, buffer, length + 1);
                        g_filePath = std::wstring(buffer);
                        delete[] buffer;
                        
                        // Escanear automÃ¡ticamente procesos bloqueantes cuando se ingresa la ruta
                        PostMessage(hwnd, WM_USER + 300, 0, 0);
                    } else {
                        g_filePath.clear();
                        // Limpiar la visualizaciÃ³n de procesos cuando se limpia la ruta
                        g_blockingProcesses.clear();
                        DestroyProcessButtons();
                    }
                }
            }
            break;
            
        case 1002: // BotÃ³n Copiar
            if (g_hEditControl) {
                SendMessage(g_hEditControl, EM_SETSEL, 0, -1); // Seleccionar todo el texto
                SendMessage(g_hEditControl, WM_COPY, 0, 0);    // Copiar al portapapeles
                MessageBox(hwnd, L"Path copied to clipboard!", L"Success", MB_OK | MB_ICONINFORMATION);
            }
            break;
            
        case 1003: // BotÃ³n Editar
            if (g_hEditControl) {
                SetFocus(g_hEditControl);
                SendMessage(g_hEditControl, EM_SETSEL, 0, -1); // Seleccionar todo el texto
            }
            break;
            

            
        case 1005: // BotÃ³n Seleccionar
            {
                // abrir diÃ¡logo de archivo para seleccionar un nuevo archivo
                OPENFILENAME ofn = {};
                wchar_t fileName[MAX_PATH] = {};
                
                ofn.lStructSize = sizeof(OPENFILENAME);
                ofn.hwndOwner = hwnd;
                ofn.lpstrFilter = L"All Files (*.*)\0*.*\0Executable Files (*.exe)\0*.exe\0Batch Files (*.bat)\0*.bat\0Script Files (*.ps1;*.vbs;*.js)\0*.ps1;*.vbs;*.js\0";
                ofn.lpstrFile = fileName;
                ofn.nMaxFile = sizeof(fileName);
                ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
                
                // obtener la ruta actual del cuadro de texto y usar su directorio
                wchar_t currentPath[MAX_PATH] = {};
                wchar_t initialDir[MAX_PATH] = {};
                if (g_hEditControl && GetWindowText(g_hEditControl, currentPath, MAX_PATH) > 0) {
                    std::wstring pathFromTextBox = std::wstring(currentPath);
                    
                    // Extraer directorio de la ruta en el cuadro de texto
                    if (!pathFromTextBox.empty()) {
                        size_t lastSlash = pathFromTextBox.find_last_of(L"\\/");
                        if (lastSlash != std::wstring::npos) {
                            std::wstring dir = pathFromTextBox.substr(0, lastSlash);
                            wcsncpy_s(initialDir, dir.c_str(), _TRUNCATE);
                            ofn.lpstrInitialDir = initialDir;
                        }
                    }
                }
                
                ofn.lpstrTitle = L"Select a file to check";
                
                if (GetOpenFileName(&ofn)) {
                    // Actualizar el control de ediciÃ³n y la variable global con el archivo seleccionado
                    g_filePath = std::wstring(fileName);
                    SetWindowText(g_hEditControl, g_filePath.c_str());
                    
                    // Verificar si el archivo seleccionado es un ejecutable
                    std::wstring lowerFilePath = g_filePath;
                    std::transform(lowerFilePath.begin(), lowerFilePath.end(), lowerFilePath.begin(), ::tolower);
                    
                    if (lowerFilePath.find(L".exe") != std::wstring::npos) {
                        // Preguntar si desea ejecutar el ejecutable como administrador
                        std::wstring exeName = g_filePath.substr(g_filePath.find_last_of(L"\\") + 1);
                        std::wstring promptMsg = L"Do you want to run \"" + exeName + L"\" as administrator?\n\nThis will launch the executable with elevated privileges.";
                        int result = MessageBox(hwnd, promptMsg.c_str(), L"Run as Administrator", MB_YESNO | MB_ICONQUESTION);
                        
                        if (result == IDYES) {
                            // Ejecutar el ejecutable como administrador
                            SHELLEXECUTEINFO sei = {};
                            sei.cbSize = sizeof(SHELLEXECUTEINFO);
                            sei.lpVerb = L"runas"; // Run as administrator
                            sei.lpFile = g_filePath.c_str();
                            sei.hwnd = hwnd;
                            sei.nShow = SW_NORMAL;
                            
                            if (ShellExecuteEx(&sei)) {
                                std::wstring successMsg = L"Successfully launched \"" + exeName + L"\" as administrator.";
                                MessageBox(hwnd, successMsg.c_str(), L"Success", MB_OK | MB_ICONINFORMATION);
                            } else {
                                DWORD error = GetLastError();
                                std::wstring errorMsg = L"Failed to launch \"" + exeName + L"\" as administrator.\n\nError: " + std::to_wstring(error);
                                MessageBox(hwnd, errorMsg.c_str(), L"Error", MB_OK | MB_ICONERROR);
                            }
                        }
                    }
                    
                    // Escanear automáticamente procesos bloqueantes
                    PostMessage(hwnd, WM_USER + 300, 0, 0);
                }
            }
            break;
            

            
        case 1007: // Botón Eliminar
            // Solo permitir eliminar si viene del botón Eliminar real
            if (lParam != 0 && (HWND)lParam == g_hDeleteButton) {
            if (!g_filePath.empty()) {
                // Mostrar diálogo de confirmación
                std::wstring confirmMsg = L"Are you sure you want to delete:\n" + g_filePath + L"\n\nThis action cannot be undone!";
                int result = MessageBox(hwnd, confirmMsg.c_str(), L"Confirm File Deletion", MB_YESNO | MB_ICONWARNING);
                
                if (result == IDYES) {
                    // Verificar si el archivo existe
                    DWORD fileAttributes = GetFileAttributes(g_filePath.c_str());
                    if (fileAttributes == INVALID_FILE_ATTRIBUTES) {
                        MessageBox(hwnd, L"File does not exist or is inaccessible.", L"Error", MB_OK | MB_ICONERROR);
                        break;
                    }
                    
                    // Si hay procesos bloqueantes, intentar matarlos primero
                    if (!g_blockingProcesses.empty()) {
                        std::wstring killMsg = L"Found " + std::to_wstring(g_blockingProcesses.size()) + L" blocking processes.\n\nDo you want to kill them before deleting?\n\nNote: System processes like explorer.exe will be skipped for safety.";
                        int killResult = MessageBox(hwnd, killMsg.c_str(), L"Kill Blocking Processes", MB_YESNO | MB_ICONQUESTION);
                        
                        if (killResult == IDYES) {
                            // Matar todos los procesos bloqueantes (excluyendo servicios del sistema)
                            int killedCount = 0;
                            int skippedCount = 0;
                            for (const auto& process : g_blockingProcesses) {
                                for (DWORD processId : process.processIds) {
                                    if (processId != 0) {
                                        // Verificar si es un servicio del sistema antes de matarlo
                                        std::wstring processName = GetProcessName(processId);
                                        if (IsSystemService(processName)) {
                                            skippedCount++;
                                            continue; // Saltar servicios del sistema
                                        }
                                        
                                        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
                                        if (hProcess != NULL) {
                                            if (TerminateProcess(hProcess, 1)) {
                                                killedCount++;
                                            }
                                            CloseHandle(hProcess);
                                        }
                                    }
                                }
                            }
                            
                            // Mostrar resultado de los procesos matados
                            if (killedCount > 0 || skippedCount > 0) {
                                std::wstring resultMsg = L"Killed " + std::to_wstring(killedCount) + L" processes.";
                                if (skippedCount > 0) {
                                    resultMsg += L"\nSkipped " + std::to_wstring(skippedCount) + L" system processes for safety.";
                                }
                                MessageBox(hwnd, resultMsg.c_str(), L"Process Termination Complete", MB_OK | MB_ICONINFORMATION);
                            }
                            
                            // Pequeña pausa para asegurar que los procesos se terminen completamente
                            Sleep(500);
                            
                            // Re-escaneo para verificar que los procesos se terminaron
                            ScanForBlockingProcesses();
                        }
                    }
                    
                    // Usar la función recursiva robusta para eliminar
                    bool deleteSuccess = RecursivelyDeleteNow(g_filePath);
                    
                    if (deleteSuccess) {
                        std::wstring successMsg = L"Successfully deleted:\n" + g_filePath;
                        MessageBox(hwnd, successMsg.c_str(), L"Success", MB_OK | MB_ICONINFORMATION);
                        
                        // Limpiar la ruta del archivo y actualizar la vista
                        g_filePath.clear();
                        SetWindowText(g_hEditControl, L"");
                        g_blockingProcesses.clear();
                        DestroyProcessButtons();
                    } else {
                        DWORD error = GetLastError();
                        std::wstring errorMsg = L"Failed to delete:\n" + g_filePath + L"\n\nError: " + std::to_wstring(error) + L"\n\nTry using 'FORCE DELETE NOW' or 'DELETE AT RESTART' instead.";
                        MessageBox(hwnd, errorMsg.c_str(), L"Error", MB_OK | MB_ICONERROR);
                    }
                }
            } else {
                MessageBox(hwnd, L"Please select a file first!", L"Warning", MB_OK | MB_ICONWARNING);
                }
            }
            break;
            
        case 1008: // Botón Matar TODOS los procesos
            // Solo permitir si viene del botón real
            if (lParam != 0 && (HWND)lParam == g_hKillAllButton) {
            if (!g_blockingProcesses.empty()) {
                // Mostrar diálogo de confirmación
                std::wstring confirmMsg = L"Are you sure you want to kill ALL " + std::to_wstring(g_blockingProcesses.size()) + L" blocking processes?\n\n[!] WARNING: This will ONLY terminate the processes.\n[!] The file will NOT be deleted.\n[!] System processes like explorer.exe will be skipped for safety.\n\nIf you want to delete the file, use the 'DELETE FILE' button instead.";
                int result = MessageBox(hwnd, confirmMsg.c_str(), L"Confirm Kill ALL Processes", MB_YESNO | MB_ICONWARNING);
                
                if (result == IDYES) {
                    int killedCount = 0;
                    int totalProcesses = 0;
                    
                    // Contar procesos totales a matar
                    for (const auto& process : g_blockingProcesses) {
                        totalProcesses += process.processIds.size();
                    }
                    
                    // Matar todos los procesos (excluyendo servicios del sistema)
                    int skippedCount = 0;
                    for (const auto& process : g_blockingProcesses) {
                        for (DWORD processId : process.processIds) {
                            if (processId != 0) {
                                // Verificar si es un servicio del sistema antes de matarlo
                                std::wstring processName = GetProcessName(processId);
                                if (IsSystemService(processName)) {
                                    skippedCount++;
                                    continue; // Saltar servicios del sistema
                                }
                                
                                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
                                if (hProcess != NULL) {
                                    if (TerminateProcess(hProcess, 1)) {
                                        killedCount++;
                                    }
                                    CloseHandle(hProcess);
                                }
                            }
                        }
                    }
                    
                    // Mostrar resultado
                    std::wstring resultMsg = L"Successfully killed " + std::to_wstring(killedCount) + L" out of " + std::to_wstring(totalProcesses) + L" processes.";
                    if (skippedCount > 0) {
                        resultMsg += L"\nSkipped " + std::to_wstring(skippedCount) + L" system processes for safety.";
                    }
                    MessageBox(hwnd, resultMsg.c_str(), L"Kill ALL Processes Complete", MB_OK | MB_ICONINFORMATION);
                    
                    // Refrescar la lista de procesos
                    ScanForBlockingProcesses();
                }
            } else {
                MessageBox(hwnd, L"No blocking processes found!", L"Information", MB_OK | MB_ICONINFORMATION);
            }
            }
            break;

        case 1010: // FORZAR BORRADO AHORA (desbloquear y borrar)
            // Solo permitir si viene del botón real
            if (lParam != 0 && (HWND)lParam == g_hForceDeleteNowButton) {
            if (!g_filePath.empty()) {
                // Mostrar diálogo de confirmación
                std::wstring confirmMsg = L"Are you sure you want to FORCE DELETE:\n" + g_filePath + L"\n\nThis will attempt to kill all blocking processes and force deletion.\n\nThis action cannot be undone!";
                int result = MessageBox(hwnd, confirmMsg.c_str(), L"Confirm Force Delete", MB_YESNO | MB_ICONWARNING);
                
                if (result == IDYES) {
                    // Primero, matar todos los procesos bloqueantes si existen
                    if (!g_blockingProcesses.empty()) {
                        std::wstring killMsg = L"Found " + std::to_wstring(g_blockingProcesses.size()) + L" blocking processes.\n\nKilling all blocking processes before force deletion...\n\nNote: System processes like explorer.exe will be skipped for safety.";
                        MessageBox(hwnd, killMsg.c_str(), L"Killing Blocking Processes", MB_OK | MB_ICONINFORMATION);
                        
                        // Matar todos los procesos bloqueantes (excluyendo servicios del sistema)
                        int killedCount = 0;
                        int skippedCount = 0;
                        for (const auto& process : g_blockingProcesses) {
                            for (DWORD processId : process.processIds) {
                                if (processId != 0) {
                                    // Verificar si es un servicio del sistema antes de matarlo
                                    std::wstring processName = GetProcessName(processId);
                                    if (IsSystemService(processName)) {
                                        skippedCount++;
                                        continue; // Saltar servicios del sistema
                                    }
                                    
                                    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
                                    if (hProcess != NULL) {
                                        if (TerminateProcess(hProcess, 1)) {
                                            killedCount++;
                                        }
                                        CloseHandle(hProcess);
                                    }
                                }
                            }
                        }
                        
                        // Mostrar resultado de los procesos matados
                        if (killedCount > 0 || skippedCount > 0) {
                            std::wstring resultMsg = L"Killed " + std::to_wstring(killedCount) + L" processes.";
                            if (skippedCount > 0) {
                                resultMsg += L"\nSkipped " + std::to_wstring(skippedCount) + L" system processes for safety.";
                            }
                            MessageBox(hwnd, resultMsg.c_str(), L"Process Termination Complete", MB_OK | MB_ICONINFORMATION);
                        }
                        
                        // Pausa para asegurar que los procesos se terminen completamente
                        Sleep(1000);
                        
                        // Re-escaneo para verificar que los procesos se terminaron
                        ScanForBlockingProcesses();
                    }
                    
                    // Intentar desbloquear a bajo nivel: tomar propiedad y dar control total a Administradores
                    // Intento razonable: habilitar borrado compartido y limpiar atributos RO/SYSTEM
                    DWORD a = GetFileAttributesW(g_filePath.c_str());
                    if (a != INVALID_FILE_ATTRIBUTES && (a & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM))) {
                        SetFileAttributesW(g_filePath.c_str(), a & ~(FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM));
                    }
                    
                    // Intentar habilitar delete sharing brevemente para romper bloqueos suaves
                    HANDLE hf = CreateFileW(g_filePath.c_str(), GENERIC_READ | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
                    if (hf != INVALID_HANDLE_VALUE) CloseHandle(hf);
                    
                    bool ok = RecursivelyDeleteNow(g_filePath);
                    if (ok) {
                        std::wstring successMsg = L"Force deletion completed successfully:\n" + g_filePath;
                        MessageBox(hwnd, successMsg.c_str(), L"Force Delete Success", MB_OK | MB_ICONINFORMATION);
                        g_filePath.clear();
                        SetWindowText(g_hEditControl, L"");
                        g_blockingProcesses.clear();
                        DestroyProcessButtons();
                    } else {
                        DWORD error = GetLastError();
                        std::wstring errorMsg = L"Force delete failed:\n" + g_filePath + L"\n\nError: " + std::to_wstring(error) + L"\n\nTry 'DELETE AT RESTART' instead.";
                        MessageBox(hwnd, errorMsg.c_str(), L"Force Delete Failed", MB_OK | MB_ICONWARNING);
                    }
                }
            }
            }
            break;

        case 1011: // BORRAR AL REINICIAR (programar primero para evitar re-bloqueo)
            // Solo permitir si viene del botón real
            if (lParam != 0 && (HWND)lParam == g_hDeleteAtRestartButton) {
            if (!g_filePath.empty()) {
                bool ok = RecursivelyScheduleDeleteAtReboot(g_filePath);
                if (ok) {
                    MessageBox(hwnd, L"Deletion scheduled for next restart.", L"Delete at Restart", MB_OK | MB_ICONINFORMATION);
                } else {
                    MessageBox(hwnd, L"Failed to schedule deletion at restart.", L"Delete at Restart", MB_OK | MB_ICONERROR);
                }
            }
            }
            break;
            
        default:
            // Manejar otros clics de botones (si hay)
            break;
        }
        break;
    }
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

// Función para obtener el nombre del proceso por PID
std::wstring GetProcessName(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (hProcess == NULL) {
        return L"Unknown Process";
    }
    
    wchar_t processName[MAX_PATH];
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageName(hProcess, 0, processName, &size)) {
        CloseHandle(hProcess);
        // Extraer solo el nombre de archivo de la ruta completa
        wchar_t* fileName = wcsrchr(processName, L'\\');
        return fileName ? fileName + 1 : processName;
    }
    
    CloseHandle(hProcess);
    return L"Unknown Process";
}

// Función para obtener la ruta completa del proceso por PID
std::wstring GetProcessPath(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (hProcess == NULL) {
        return L"Unknown Path";
    }
    
    wchar_t processPath[MAX_PATH];
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageName(hProcess, 0, processPath, &size)) {
        CloseHandle(hProcess);
        return std::wstring(processPath);
    }
    
    CloseHandle(hProcess);
    return L"Unknown Path";
}

// Función para convertir el tipo de manejo (handle) a texto
std::wstring GetHandleTypeString(DWORD handleType) {
    switch (handleType) {
    case 0x1: return L"File";
    case 0x2: return L"Directory";
    case 0x3: return L"Memory Section";
    case 0x4: return L"Registry Key";
    case 0x5: return L"Event";
    case 0x6: return L"Mutex";
    case 0x7: return L"Semaphore";
    case 0x8: return L"Timer";
    case 0x9: return L"I/O Completion";
    case 0xA: return L"Port";
    case 0xB: return L"Device";
    case 0xC: return L"Symbolic Link";
    default: return L"Unknown";
    }
}

// Función para convertir derechos de acceso a texto
std::wstring GetAccessRightsString(DWORD accessRights) {
    std::wstring rights;
    
    if (accessRights & GENERIC_READ) rights += L"Read ";
    if (accessRights & GENERIC_WRITE) rights += L"Write ";
    if (accessRights & GENERIC_EXECUTE) rights += L"Execute ";
    if (accessRights & GENERIC_ALL) rights += L"All ";
    if (accessRights & DELETE) rights += L"Delete ";
    if (accessRights & READ_CONTROL) rights += L"Read Control ";
    if (accessRights & WRITE_DAC) rights += L"Write DAC ";
    if (accessRights & WRITE_OWNER) rights += L"Write Owner ";
    if (accessRights & SYNCHRONIZE) rights += L"Synchronize ";
    if (accessRights & FILE_READ_DATA) rights += L"File Read ";
    if (accessRights & FILE_WRITE_DATA) rights += L"File Write ";
    if (accessRights & FILE_APPEND_DATA) rights += L"File Append ";
    if (accessRights & FILE_READ_EA) rights += L"File Read EA ";
    if (accessRights & FILE_WRITE_EA) rights += L"File Write EA ";
    if (accessRights & FILE_EXECUTE) rights += L"File Execute ";
    if (accessRights & FILE_DELETE_CHILD) rights += L"File Delete Child ";
    if (accessRights & FILE_READ_ATTRIBUTES) rights += L"File Read Attributes ";
    if (accessRights & FILE_WRITE_ATTRIBUTES) rights += L"File Write Attributes ";
    
    if (rights.empty()) rights = L"Unknown";
    return rights;
}

// Función para determinar la razón del bloqueo
std::wstring GetBlockingReason(DWORD accessRights, DWORD handleType) {
    std::wstring reason;
    
    if (handleType == 0x1) { // File
        if (accessRights & (GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES)) {
            reason += L"File is being written to ";
        }
        if (accessRights & (GENERIC_READ | FILE_READ_DATA | FILE_READ_ATTRIBUTES)) {
            reason += L"File is being read from ";
        }
        if (accessRights & FILE_EXECUTE) {
            reason += L"File is being executed ";
        }
        if (accessRights & DELETE) {
            reason += L"File is marked for deletion ";
        }
        if (accessRights & GENERIC_ALL) {
            reason += L"File has full access ";
        }
    } else if (handleType == 0x2) { // Directory
        if (accessRights & (GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA)) {
            reason += L"Directory is being modified ";
        }
        if (accessRights & FILE_DELETE_CHILD) {
            reason += L"Directory contents are being deleted ";
        }
    } else if (handleType == 0x3) { // Memory Section
        reason += L"File is memory-mapped ";
    }
    
    if (reason.empty()) {
        reason = L"File is being accessed";
    }
    
    return reason;
}

// Función para obtener el nombre de ruta corta
std::wstring GetShortPathName(const std::wstring& longPath) {
    wchar_t shortPath[MAX_PATH];
    DWORD result = GetShortPathName(longPath.c_str(), shortPath, MAX_PATH);
    if (result > 0 && result < MAX_PATH) {
        return std::wstring(shortPath);
    }
    return longPath;
}

// Función para verificar si el archivo está en uso
bool IsFileInUse(const std::wstring& filePath) {
    HANDLE hFile = CreateFile(filePath.c_str(), 
                             GENERIC_READ | GENERIC_WRITE | DELETE,
                             0, // Sin compartir - esto fallarÃ¡ si el archivo estÃ¡ en uso
                             NULL, 
                             OPEN_EXISTING, 
                             FILE_ATTRIBUTE_NORMAL, 
                             NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        return (error == ERROR_SHARING_VIOLATION || 
                error == ERROR_LOCK_VIOLATION || 
                error == ERROR_ACCESS_DENIED);
    }
    
    CloseHandle(hFile);
    return false;
}

// Función para obtener procesos que usan un archivo específico
std::vector<DWORD> GetProcessesUsingFile(const std::wstring& filePath) {
    std::vector<DWORD> processIds;
    
    // obtener tanto nombres de ruta largos como cortos
    std::wstring longPath = filePath;
    std::wstring shortPath = GetShortPathName(filePath);
    
    // Intentar abrir el archivo con acceso exclusivo para ver si está bloqueado
    HANDLE hFile = CreateFile(filePath.c_str(), 
                             GENERIC_READ | GENERIC_WRITE | DELETE,
                             0, // Sin compartir
                             NULL, 
                             OPEN_EXISTING, 
                             FILE_ATTRIBUTE_NORMAL, 
                             NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        
        // El archivo estÃ¡ en uso, ahora averigÃ¼emos por quÃ© procesos
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            
            if (Process32First(hSnapshot, &pe32)) {
                do {
                    // Intentar abrir cada proceso para verificar si tiene manejos a nuestro archivo
                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                    if (hProcess != NULL) {
                        // Verificar si este proceso podría estar usando nuestro archivo
                        // Este es un enfoque heurístico - en una implementación real usarías NtQuerySystemInformation
                        
                        std::wstring processPath = GetProcessPath(pe32.th32ProcessID);
                        
                        // Verificar si el proceso es el propio archivo (ejecutable)
                        if (processPath == longPath || processPath == shortPath) {
                            processIds.push_back(pe32.th32ProcessID);
                        }
                        
                        // Verificar si la ruta del proceso contiene nuestra ruta de archivo
                        if (processPath.find(longPath) != std::wstring::npos || 
                            processPath.find(shortPath) != std::wstring::npos) {
                            processIds.push_back(pe32.th32ProcessID);
                        }
                        
                        CloseHandle(hProcess);
                    }
                } while (Process32Next(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
        }
    } else {
        CloseHandle(hFile);
    }
    
    return processIds;
}

// Función para verificar si una ruta es un directorio


// Función para obtener procesos con manejos de archivos reales (más precisa)
std::vector<DWORD> GetProcessesWithFileHandles(const std::wstring& filePath) {
    // Usar el método de detección mejorado para archivos
    return GetProcessesWithRealFileHandlesEnhanced(filePath);
}

// Función principal para escanear procesos bloqueantes
void ScanForBlockingProcesses() {
    g_blockingProcesses.clear();
    
    if (g_filePath.empty()) {
        // Limpiar la interfaz si no se selecciona ningún archivo
        DestroyProcessButtons();
        return;
    }
    
    // Verificar si el archivo existe
    DWORD fileAttributes = GetFileAttributes(g_filePath.c_str());
    if (fileAttributes == INVALID_FILE_ATTRIBUTES) {
        // Limpiar la interfaz si el archivo no existe
        DestroyProcessButtons();
        return;
    }
    
        // Verificar si es un directorio - si es así, usar detección comprehensiva
    bool isDirectory = (fileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    std::vector<DWORD> blockingProcessIds;
    if (isDirectory) {
        // Use comprehensive folder detection that checks everything
        blockingProcessIds = GetProcessesBlockingFolderComprehensive(g_filePath);
        
        // If comprehensive detection found nothing, try the original methods as fallback
        if (blockingProcessIds.empty()) {
            // Intentar Restart Manager con barra invertida al final (semántica de directorio)
            std::vector<DWORD> rmDir = GetProcessesUsingRestartManager(g_filePath + L"\\");
            blockingProcessIds.insert(blockingProcessIds.end(), rmDir.begin(), rmDir.end());

            // enumerar manejos del kernel para directorio
            std::vector<DWORD> exact = GetProcessesBlockingFolderExact(g_filePath);
            blockingProcessIds.insert(blockingProcessIds.end(), exact.begin(), exact.end());

            // Intentar forma GUID de volumen
            std::wstring alt = BuildVolumeGuidPath(g_filePath);
            if (!alt.empty()) {
                std::vector<DWORD> altPids = GetProcessesBlockingFolderExact(alt);
                blockingProcessIds.insert(blockingProcessIds.end(), altPids.begin(), altPids.end());
            }
            // Como alternativa, llamar a RM nuevamente sin barra invertida
            if (blockingProcessIds.empty()) {
                std::vector<DWORD> rmPids2 = GetProcessesUsingRestartManager(g_filePath);
                blockingProcessIds.insert(blockingProcessIds.end(), rmPids2.begin(), rmPids2.end());
            }
        }
    } else {
        blockingProcessIds = GetProcessesWithFileHandles(g_filePath);
    }
    
    bool foundBlockingProcesses = false;
    
    for (DWORD processId : blockingProcessIds) {
        // Omitir BlockerChecker mismo
        std::wstring processName = GetProcessName(processId);
        if (processName == L"BlockerChecker.exe") continue;
        
        std::wstring processPath = GetProcessPath(processId);
        std::wstring friendlyName = GetProgramFriendlyName(processPath) + L" (" + processName + L")";
        AddOrUpdateProcessInfo(processId, friendlyName, g_filePath,
                              isDirectory ? L"Directory" : L"File",
                              L"Read/Write/Delete",
                              isDirectory ? L"Directory is open in this process" : L"File is being used by this process");
        foundBlockingProcesses = true;
    }
    
    // Si se escanea un directorio que parece crítico del sistema o tiene un número muy grande de coincidencias,
    // mantener la funcionalidad idéntica pero anotar resultados como falsos positivos potenciales
    // agregando un elemento de información único al final (el comportamiento de etiqueta no intrusiva ya existe).
    if (isDirectory && !blockingProcessIds.empty()) {
        bool looksSystem = IsSystemFolderPath(g_filePath);
        bool tooMany = blockingProcessIds.size() >= FALSE_POSITIVE_WARNING_THRESHOLD;
        if (looksSystem || tooMany) {
            ProcessInfo info;
            info.processIds = {0};
            info.processName = L"Note: Many handles detected for this folder";
            info.filePath = g_filePath;
            info.handleType = L"Info";
            info.accessRights = L"N/A";
            if (looksSystem && tooMany) {
                info.blockingReason = L"This appears to be a system or shared folder. Some entries may be false positives.";
            } else if (looksSystem) {
                info.blockingReason = L"This appears to be a system or shared folder. Results may include shared system handles.";
            } else {
                info.blockingReason = L"Large number of processes detected. Some may be false positives due to shared handles.";
            }
            g_blockingProcesses.push_back(info);
        }
    }

    // Si no se encuentran procesos bloqueantes, mostrar un mensaje
    if (!foundBlockingProcesses) {
        AddNoProcessesMessage();
    }
    
#if 0
    // Método 3: Verificar procesos con directorio de trabajo en la ruta objetivo
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe32)) {
            do {
                // Verificar si el directorio de trabajo del proceso está en nuestra ruta objetivo
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                if (hProcess != NULL) {
                    wchar_t currentDir[MAX_PATH];
                    if (GetCurrentDirectoryW(MAX_PATH, currentDir)) {
                        std::wstring currentDirStr(currentDir);
                        if (currentDirStr.find(g_filePath) != std::wstring::npos) {
                            // Verificar si ya agregamos este proceso
                            bool alreadyadded = false;
                            for (const auto& existing : g_blockingProcesses) {
                                for (DWORD existingId : existing.processIds) {
                                    if (existingId == pe32.th32ProcessID) {
                                        alreadyadded = true;
                                        break;
                                    }
                                }
                                if (alreadyadded) break;
                            }
                            
                            if (!alreadyadded) {
                                std::wstring processPath = GetProcessPath(pe32.th32ProcessID);
                                std::wstring processName = GetProgramFriendlyName(processPath) + L" (" + GetProcessName(pe32.th32ProcessID) + L")";
                                AddOrUpdateProcessInfo(pe32.th32ProcessID, processName, g_filePath, 
                                                      isDirectory ? L"Directory" : L"File",
                                                      L"Read/Write", 
                                                      L"Process has working directory in this path");
                            }
                        }
                    }
                    CloseHandle(hProcess);
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    
    // Método 4: Verificar procesos de antivirus que podrían estar escaneando
    std::vector<std::wstring> antivirusProcesses = {
        L"avast.exe", L"avgui.exe", L"mcshield.exe", L"msmpeng.exe", L"defender.exe",
        L"bdredline.exe", L"kav.exe", L"norton.exe", L"trendmicro.exe", L"eset.exe",
        L"smartscreen.exe", L"windowsdefender.exe", L"mpcmdrun.exe"
    };
    
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe32)) {
            do {
                std::wstring processName = GetProcessName(pe32.th32ProcessID);
                for (const auto& avProcess : antivirusProcesses) {
                    if (processName.find(avProcess) != std::wstring::npos) {
                        // Verificar si ya agregamos este proceso
                        bool alreadyadded = false;
                        for (const auto& existing : g_blockingProcesses) {
                            for (DWORD existingId : existing.processIds) {
                                if (existingId == pe32.th32ProcessID) {
                                    alreadyadded = true;
                                    break;
                                }
                            }
                            if (alreadyadded) break;
                        }
                        
                        if (!alreadyadded) {
                            std::wstring processPath = GetProcessPath(pe32.th32ProcessID);
                            std::wstring friendlyName = GetProgramFriendlyName(processPath) + L" (" + processName + L")";
                            AddOrUpdateProcessInfo(pe32.th32ProcessID, friendlyName, g_filePath, 
                                                  isDirectory ? L"Directory" : L"File",
                                                  L"Read", 
                                                  L"Being scanned by antivirus software");
// (section disabled)
                        }
                        break;
                    }
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
#endif // Disabled extra heuristic methods
    
    // Clean up terminated processes from the list
    for (auto it = g_blockingProcesses.begin(); it != g_blockingProcesses.end();) {
        bool hasRunningProcess = false;
        for (auto pidIt = it->processIds.begin(); pidIt != it->processIds.end();) {
            if (!IsProcessRunning(*pidIt)) {
                pidIt = it->processIds.erase(pidIt);
            } else {
                hasRunningProcess = true;
                ++pidIt;
            }
        }
        
        if (it->processIds.empty() || !hasRunningProcess) {
            it = g_blockingProcesses.erase(it);
        } else {
            ++it;
        }
    }
    
            // Crear vista de procesos con botones pequeños
        CreateProcessDisplay(g_hMainWindow);
        
    // Actualizar información de desplazamiento (solo si existe el contenedor)
    if (g_hProcessListContainer) {
        UpdateScrollInfo(g_hMainWindow);
    }
        
        
}

// Función para actualizar la lista con resultados


// Función para crear botones para cada proceso bloqueante
void CreateProcessButtons(HWND hwnd) {
    DestroyProcessButtons(); // Clear existing buttons
    
    // Verificar si solo tenemos el mensaje "sin proceso"
    bool hasOnlyNoProcessMessage = (g_blockingProcesses.size() == 1 && 
                                   g_blockingProcesses[0].processIds.size() == 1 && 
                                   g_blockingProcesses[0].processIds[0] == 0);
    
    if (g_blockingProcesses.empty() || hasOnlyNoProcessMessage) return;
    
    if (!hwnd) hwnd = GetForegroundWindow();
    
    RECT clientRect;
    GetClientRect(hwnd, &clientRect);
    int windowWidth = clientRect.right - clientRect.left;
    
    g_buttonY = 200; // Empezar debajo de los controles existentes
    
    for (const auto& process : g_blockingProcesses) {
        for (DWORD processId : process.processIds) {
            // Saltar crear botones para el mensaje "sin proceso" (processId = 0)
            if (processId == 0) {
                g_buttonY += 15; // Espacio para el mensaje
                continue;
            }
            
            ProcessButton button;
            button.processId = processId;
            button.processName = process.processName;
            button.filePath = g_filePath;
            
            // Calcular posiciones de botones - botones pequeños a la derecha
            int buttonX = windowWidth - BUTTON_WIDTH - 10; // Right side with 10px margin
            int buttonY = g_buttonY;
            

            
            g_processButtons.push_back(button);
            g_buttonY += 15; // Espacio solo para texto e ícono
        }
    }
}

// Función para extraer y redimensionar ícono desde un ejecutable
HICON ExtractIconFromFile(const std::wstring& filePath) {
    HICON hIcon = NULL;
    HICON hSmallIcon = NULL;
    int iconIndex = 0;
    
    // Extraer ícono grande (32x32)
    hIcon = ExtractIcon(GetModuleHandle(NULL), filePath.c_str(), iconIndex);
    
    if (hIcon == NULL || hIcon == (HICON)1) {
        // Intentar extraer ícono pequeño (16x16)
        hIcon = ExtractIcon(GetModuleHandle(NULL), filePath.c_str(), iconIndex);
    }
    
    if (hIcon && hIcon != (HICON)1) {
        // Crear ícono redimensionado al tamaño ICONSIZEUNNAMED
        HDC hdcScreen = GetDC(NULL);
        HDC hdcMem = CreateCompatibleDC(hdcScreen);
        
        // Crear bitmap para el ícono redimensionado
        HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, ICONSIZEUNNAMED, ICONSIZEUNNAMED);
        HBITMAP hOldBitmap = (HBITMAP)SelectObject(hdcMem, hBitmap);
        
        // Configurar para escalado de alta calidad
        SetStretchBltMode(hdcMem, HALFTONE);
        SetBrushOrgEx(hdcMem, 0, 0, NULL);
        
        // Dibujar el ícono original escalado a nuestro tamaño
        DrawIconEx(hdcMem, 0, 0, hIcon, ICONSIZEUNNAMED, ICONSIZEUNNAMED, 0, NULL, DI_NORMAL);
        
        // Crear ícono desde el bitmap redimensionado
        ICONINFO iconInfo;
        iconInfo.fIcon = TRUE;
        iconInfo.hbmColor = hBitmap;
        iconInfo.hbmMask = hBitmap;
        
        hSmallIcon = CreateIconIndirect(&iconInfo);
        
        // Clean up
        SelectObject(hdcMem, hOldBitmap);
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        DestroyIcon(hIcon);
        
        return hSmallIcon;
    }
    
    return hIcon;
}

// Función para crear el contenedor de la lista de procesos
void CreateProcessListContainer(HWND hwnd) {
    if (!hwnd) return;
    
    // Destruir contenedor existente si existe
    if (g_hProcessListContainer) {
        DestroyWindow(g_hProcessListContainer);
        g_hProcessListContainer = NULL;
    }
    
    RECT clientRect;
    GetClientRect(hwnd, &clientRect);
    int windowWidth = clientRect.right - clientRect.left;
    
    // Calcular dimensiones del contenedor reservando espacio para botones de acción inferiores
    g_processListContainerWidth = windowWidth - 20; // Leave margins
    int reservedBottom = (g_buttonHeightUnnamed * 4) + (8 * 3) + 40; // 4 stacked buttons + spacing + margin
    int clientHeight = clientRect.bottom - clientRect.top;
    int avail = clientHeight - g_processListContainerY - reservedBottom;
    g_processListContainerHeight = max(120, avail);
    
    // Crear el contenedor de lista de procesos como control estático con borde
    g_hProcessListContainer = CreateWindowEx(
        WS_EX_CLIENTEDGE,           // Estilo extendido para borde
        L"STATIC",                  // Static control class
        L"",                        // Sin texto
        WS_CHILD | WS_VISIBLE | WS_VSCROLL, // Ventana hija con desplazamiento vertical
        g_processListContainerX,    // X position
        g_processListContainerY,    // Y position
        g_processListContainerWidth, // Width
        g_processListContainerHeight, // Height
        hwnd,                       // Ventana padre
        NULL,                       // No menu
        GetModuleHandle(NULL),      // Instance
        NULL                        // No additional data
    );
    
    if (g_hProcessListContainer) {
                        // Configurar procedimiento de ventana personalizado para recorte correcto
                SetWindowLongPtr(g_hProcessListContainer, GWLP_WNDPROC, (LONG_PTR)ContainerWindowProc);
                
                // Habilitar recorte correcto para el contenedor
                SetWindowLongPtr(g_hProcessListContainer, GWL_STYLE, 
                    GetWindowLongPtr(g_hProcessListContainer, GWL_STYLE) | WS_CLIPCHILDREN);
    }
}

// Función para actualizar el layout del contenedor de lista de procesos
void UpdateProcessListContainerLayout(HWND hwnd) {
    if (!hwnd || !g_hProcessListContainer) return;
    
    RECT clientRect;
    GetClientRect(hwnd, &clientRect);
    int windowWidth = clientRect.right - clientRect.left;
    
    // Actualizar dimensiones del contenedor con el espacio reservado inferior
    g_processListContainerWidth = windowWidth - 20; // Leave margins
    int reservedBottom = (g_buttonHeightUnnamed * 4) + (8 * 3) + 40;
    int clientHeight = clientRect.bottom - clientRect.top;
    g_processListContainerHeight = max(120, clientHeight - g_processListContainerY - reservedBottom);
    
    // Reposicionar y redimensionar el contenedor
    SetWindowPos(g_hProcessListContainer, NULL,
        g_processListContainerX, g_processListContainerY,
        g_processListContainerWidth, g_processListContainerHeight,
        SWP_NOZORDER);
}

// Función para crear la vista de procesos con texto y botones pequeños
void CreateProcessDisplay(HWND hwnd) {
    // Always destroy existing buttons first to prevent deformation
    DestroyProcessButtons();
    
    // Verificar si solo tenemos el mensaje "sin proceso"
    bool hasOnlyNoProcessMessage = (g_blockingProcesses.size() == 1 && 
                                   g_blockingProcesses[0].processIds.size() == 1 && 
                                   g_blockingProcesses[0].processIds[0] == 0);
    
    if (g_blockingProcesses.empty() || hasOnlyNoProcessMessage) {
        // Crear primero el contenedor de lista de procesos
        CreateProcessListContainer(hwnd);
        
        if (!g_hProcessListContainer) {
            return;
        }
        
        // Mostrar mensaje "No se encontraron procesos bloqueantes" centrado
        RECT containerRect;
        GetClientRect(g_hProcessListContainer, &containerRect);
        int containerWidth = containerRect.right - containerRect.left;
        int containerHeight = containerRect.bottom - containerRect.top;
        
        // Calcular posición centrada
        int labelWidth = 300; // Ancho aproximado para el mensaje
        int labelHeight = 30;
        int labelX = (containerWidth - labelWidth) / 2;
        int labelY = (containerHeight - labelHeight) / 2;
        
        // Crear o actualizar la etiqueta de "sin procesos"
        if (!g_hNoProcessesLabel) {
        g_hNoProcessesLabel = CreateWindow(
                L"STATIC", L"No blocking processes found",
            WS_VISIBLE | WS_CHILD | SS_CENTER,
            labelX, labelY, labelWidth, labelHeight,
            g_hProcessListContainer, (HMENU)9999, GetModuleHandle(NULL), NULL
        );
        } else {
            SetWindowPos(g_hNoProcessesLabel, NULL, labelX, labelY, labelWidth, labelHeight, SWP_NOZORDER | SWP_SHOWWINDOW);
            SetWindowText(g_hNoProcessesLabel, L"No blocking processes found");
            ShowWindow(g_hNoProcessesLabel, SW_SHOW);
        }
        
        // Configurar fuente en negrita para el mensaje
        HFONT hBoldFont = CreateFont(24, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                                    DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                    CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        SendMessage(g_hNoProcessesLabel, WM_SETFONT, (WPARAM)hBoldFont, TRUE);
        
        return;
    }
    
    if (!hwnd) hwnd = GetForegroundWindow();
    
    // Crear primero el contenedor de lista de procesos
    CreateProcessListContainer(hwnd);
    
    if (!g_hProcessListContainer) {
        return;
    }
    
    // Debug: mostrar que estamos creando la vista de procesos
    std::wstring debugMsg = L"Creating process display for " + std::to_wstring(g_blockingProcesses.size()) + L" processes";
    OutputDebugString(debugMsg.c_str());
    
    // Creando la vista de procesos dentro del contenedor
    
    RECT containerRect;
    GetClientRect(g_hProcessListContainer, &containerRect);
    int containerWidth = containerRect.right - containerRect.left;
    
    // Ajustar ancho del contenedor por la barra de scroll si está visible
    if (g_scrollBarVisible) {
        containerWidth -= g_scrollBarWidth;
    }
    
    // Ocultar la etiqueta de "sin procesos" si existe porque hay entradas reales para mostrar
    if (g_hNoProcessesLabel) {
        ShowWindow(g_hNoProcessesLabel, SW_HIDE);
    }
    g_buttonY = 10 - g_scrollY; // Empezar dentro del contenedor, con margen pequeño
    
    for (const auto& process : g_blockingProcesses) {
        // Crear un botón por grupo de procesos (mismo nombre)
            ProcessButton button;
        button.processId = process.processIds[0]; // Usar el primer PID para el botón
            button.processName = process.processName;
            button.filePath = g_filePath;
        button.processPath = (process.processIds[0] != 0) ? GetProcessPath(process.processIds[0]) : L"";
            
        // Calculate responsive positions
            int iconX = 10;
            int textX = iconX + ICONSIZEUNNAMED + 8; // Más espacio entre ícono y texto
        int responsiveButtonWidth = max(50, min(80, containerWidth / 12)); // Ancho de botón matar adaptable
        int killButtonX = containerWidth - responsiveButtonWidth - 10; // Right side with 10px margin
            int buttonY = g_buttonY;
            int textWidth = killButtonX - textX - 10; // Más espacio antes del botón matar
            
        // Asegurar ancho mínimo de texto
        if (textWidth < 100) {
            textWidth = 100;
            killButtonX = textX + textWidth + 10;
        }
            
            // Crear ícono solo para entradas reales (pid != 0)
            if (process.processIds[0] != 0) {
            button.hIconLabel = CreateWindow(
                L"STATIC", L"",
                WS_VISIBLE | WS_CHILD | SS_ICON,
                iconX, buttonY, ICONSIZEUNNAMED, ICONSIZEUNNAMED,
            g_hProcessListContainer, (HMENU)(4000 + process.processIds[0]), GetModuleHandle(NULL), NULL
            );
            HICON hIcon = ExtractIconFromFile(button.processPath);
            if (hIcon) {
                SendMessage(button.hIconLabel, STM_SETICON, (WPARAM)hIcon, 0);
                }
            } else {
                button.hIconLabel = NULL;
            }
            
        // Crear etiqueta de texto mostrando info del proceso con cantidad
        std::wstring textLabel;
        if (process.processIds.size() == 1 && process.processIds[0] == 0 && process.handleType == L"Info") {
            // Fila informativa (sin PID, sin botón matar)
            textLabel = process.processName;
            if (!process.blockingReason.empty()) {
                textLabel += L" â€” ";
                textLabel += process.blockingReason;
            }
        } else if (process.processIds.size() == 1) {
            textLabel = process.processName + L" (PID: " + std::to_wstring(process.processIds[0]) + L")";
        } else {
            textLabel = process.processName + L" (" + std::to_wstring(process.processIds.size()) + L" instances)";
            // Add PIDs in parentheses for multiple instances
            textLabel += L" [PIDs: ";
            for (size_t i = 0; i < process.processIds.size(); ++i) {
                if (i > 0) textLabel += L", ";
                textLabel += std::to_wstring(process.processIds[i]);
            }
            textLabel += L"]";
        }
        
            button.hTextLabel = CreateWindow(
                L"STATIC", textLabel.c_str(),
                WS_VISIBLE | WS_CHILD | SS_LEFT,
                textX, buttonY, textWidth, BUTTON_HEIGHT,
            g_hProcessListContainer, (HMENU)(3000 + process.processIds[0]), GetModuleHandle(NULL), NULL
            );
            
            // Poner fuente sin negrita para el texto
            HFONT hTextFont = CreateFont(18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            SendMessage(button.hTextLabel, WM_SETFONT, (WPARAM)hTextFont, TRUE);
            
            // Dark theme colors will be handled by WM_CTLCOLORSTATIC in WindowProc
            
        // Crear botón matar solo para entradas reales
        if (!(process.processIds.size() == 1 && process.processIds[0] == 0 && process.handleType == L"Info")) {
        // Para carpetas, siempre mostrar "KILL" para matar solo el proceso individual
        // Para archivos, mostrar "KILL ALL" solo cuando hay múltiples instancias del mismo proceso
        std::wstring killButtonText = (process.processIds.size() == 1 || IsDirectoryPath(g_filePath)) ? L"KILL" : L"KILL ALL";
            button.hKillButton = CreateWindow(
            L"BUTTON", killButtonText.c_str(),
                WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | BS_FLAT,
            killButtonX, buttonY, responsiveButtonWidth, BUTTON_HEIGHT,
            g_hProcessListContainer, (HMENU)(1000 + process.processIds[0]), GetModuleHandle(NULL), NULL
            );
            if (!button.hKillButton) {
            std::wstring debugMsg = L"Failed to create KILL button for process: " + process.processName;
                MessageBox(hwnd, debugMsg.c_str(), L"Debug", MB_OK);
            } else {
                button.originalButtonProc = (WNDPROC)SetWindowLongPtr(button.hKillButton, GWLP_WNDPROC, (LONG_PTR)KillButtonProc);
            std::wstring debugMsg = L"Successfully created and subclassed KILL button for process: " + process.processName;
                OutputDebugString(debugMsg.c_str());
                InvalidateRect(button.hKillButton, NULL, TRUE);
                UpdateWindow(button.hKillButton);
            }
        } else {
            button.hKillButton = NULL;
            }
            
            g_processButtons.push_back(button);
            g_buttonY += BUTTON_HEIGHT + 8; // Space for one row + extra spacing
    }
}

// Function to update process display layout when window is resized
// Function to update all control positions and sizes when window is resized
void UpdateAllControlsLayout(HWND hwnd) {
    if (!hwnd) return;
    
    RECT clientRect;
    GetClientRect(hwnd, &clientRect);
    int windowWidth = clientRect.right - clientRect.left;
    int windowHeight = clientRect.bottom - clientRect.top;
    
    // Actualizar control de edición (ruta de archivo) - ancho adaptable
    if (g_hEditControl) {
        SetWindowPos(g_hEditControl, NULL, 10, 50, windowWidth - 20, 25, SWP_NOZORDER);
    }
    
    // Actualizar botones con tamaño adaptable
    int buttonWidth = max(80, min(120, windowWidth / 8)); // Ancho de botón adaptable
    int buttonHeight = 25;
    int buttonSpacing = max(5, windowWidth / 100); // Responsive spacing
    int buttonY = 85;
    int totalButtonWidth = (buttonWidth * 2) + buttonSpacing;
    int startX = (windowWidth - totalButtonWidth) / 2;
    
    // Asegurar que los botones no se salgan de pantalla
    if (startX < 10) startX = 10;
    if (startX + totalButtonWidth > windowWidth - 10) {
        startX = windowWidth - totalButtonWidth - 10;
    }
    
    // Botón Copiar
    if (g_hCopyButton) {
        SetWindowPos(g_hCopyButton, NULL, startX, buttonY, buttonWidth, buttonHeight, SWP_NOZORDER);
    }
    
    // Botón Examinar
    if (g_hSelectButton) {
        SetWindowPos(g_hSelectButton, NULL, startX + buttonWidth + buttonSpacing, buttonY, buttonWidth, buttonHeight, SWP_NOZORDER);
    }
    
    // Bottom action buttons stacked: Delete, Kill All, Force Delete, Delete at Restart
    int centerX = (windowWidth - g_buttonWidthUnnamed) / 2;
    int bottomY = windowHeight - 240;
    if (g_hDeleteButton) SetWindowPos(g_hDeleteButton, NULL, centerX, bottomY, g_buttonWidthUnnamed, g_buttonHeightUnnamed, SWP_NOZORDER);
    bottomY += g_buttonHeightUnnamed + 8;
    if (g_hKillAllButton) SetWindowPos(g_hKillAllButton, NULL, centerX, bottomY, g_buttonWidthUnnamed, g_buttonHeightUnnamed, SWP_NOZORDER);
    bottomY += g_buttonHeightUnnamed + 8;
    if (g_hForceDeleteNowButton) SetWindowPos(g_hForceDeleteNowButton, NULL, centerX, bottomY, g_buttonWidthUnnamed, g_buttonHeightUnnamed, SWP_NOZORDER);
    bottomY += g_buttonHeightUnnamed + 8;
    if (g_hDeleteAtRestartButton) SetWindowPos(g_hDeleteAtRestartButton, NULL, centerX, bottomY, g_buttonWidthUnnamed, g_buttonHeightUnnamed, SWP_NOZORDER);
    
    // Actualizar layout del contenedor de lista de procesos
    UpdateProcessListContainerLayout(hwnd);
    
    // Actualizar información de scroll del contenedor (solo si existe)
    if (g_hProcessListContainer) {
        UpdateScrollInfo(hwnd);
    }
    
    // Actualizar layout de la vista de procesos
    UpdateProcessDisplayLayout(hwnd);
    
    // Force redraw of all child controls
    if (g_hEditControl) InvalidateRect(g_hEditControl, NULL, TRUE);
    if (g_hCopyButton) InvalidateRect(g_hCopyButton, NULL, TRUE);
    if (g_hSelectButton) InvalidateRect(g_hSelectButton, NULL, TRUE);
    if (g_hDeleteButton) InvalidateRect(g_hDeleteButton, NULL, TRUE);
    if (g_hKillAllButton) InvalidateRect(g_hKillAllButton, NULL, TRUE);
    
    // Forzar repintado de todos los botones de proceso
    for (const auto& button : g_processButtons) {
        if (button.hIconLabel) InvalidateRect(button.hIconLabel, NULL, TRUE);
        if (button.hTextLabel) InvalidateRect(button.hTextLabel, NULL, TRUE);
        if (button.hKillButton) InvalidateRect(button.hKillButton, NULL, TRUE);
    }
}

void UpdateProcessDisplayLayout(HWND hwnd) {
    if (!hwnd || !g_hProcessListContainer) return;
    
    RECT containerRect;
    GetClientRect(g_hProcessListContainer, &containerRect);
    int containerWidth = containerRect.right - containerRect.left;
    int containerHeight = containerRect.bottom - containerRect.top;
    
    // Ajustar ancho del contenedor por barra de scroll si está visible
    if (g_scrollBarVisible) {
        containerWidth -= g_scrollBarWidth;
    }
    
    // Empezar a posicionar procesos dentro del contenedor
    int buttonY = 10 - g_scrollY; // Start within the container, with small margin
    
    for (auto& button : g_processButtons) {
        // Calcular posiciones adaptables primero
        int iconX = 10;
        int textX = iconX + ICONSIZEUNNAMED + 8;
        int responsiveButtonWidth = max(50, min(80, containerWidth / 12)); // Ancho adaptable del botón matar
        int killButtonX = containerWidth - responsiveButtonWidth - 10;
        int textWidth = killButtonX - textX - 10;
        
        // Asegurar ancho mínimo de texto
        if (textWidth < 100) {
            textWidth = 100;
            killButtonX = textX + textWidth + 10;
        }
        
        // Verificar si este botón de proceso está dentro del área visible del contenedor
        // Use more precise visibility checking to prevent glitches
        bool isFullyVisible = (buttonY >= 0) && (buttonY + BUTTON_HEIGHT <= containerHeight);
        bool isPartiallyVisible = (buttonY < containerHeight) && (buttonY + BUTTON_HEIGHT > 0);
        bool shouldShow = isPartiallyVisible;
        
        // Always position the controls, but control visibility
        if (button.hIconLabel) {
            SetWindowPos(button.hIconLabel, NULL, iconX, buttonY, ICONSIZEUNNAMED, ICONSIZEUNNAMED, SWP_NOZORDER | SWP_NOCOPYBITS);
            ShowWindow(button.hIconLabel, shouldShow ? SW_SHOW : SW_HIDE);
        }
        
        if (button.hTextLabel) {
            SetWindowPos(button.hTextLabel, NULL, textX, buttonY, textWidth, BUTTON_HEIGHT, SWP_NOZORDER | SWP_NOCOPYBITS);
            ShowWindow(button.hTextLabel, shouldShow ? SW_SHOW : SW_HIDE);
        }
        
        if (button.hKillButton) {
            SetWindowPos(button.hKillButton, NULL, killButtonX, buttonY, responsiveButtonWidth, BUTTON_HEIGHT, SWP_NOZORDER | SWP_NOCOPYBITS);
            ShowWindow(button.hKillButton, shouldShow ? SW_SHOW : SW_HIDE);
        }
        
        buttonY += BUTTON_HEIGHT + 8;
    }
    
    // Container redraw is handled by the calling function to prevent flickering
}

// Procedimiento de ventana personalizado del contenedor de lista para manejar recorte correctamente
LRESULT CALLBACK ContainerWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_ERASEBKGND:
        // Prevent background erasing to reduce flickering
        return TRUE;
        
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORBTN:
        // Fondo negro con texto blanco para todos los controles del contenedor
        SetBkMode((HDC)wParam, TRANSPARENT);
        SetTextColor((HDC)wParam, RGB(255, 255, 255)); // White text
        return (LRESULT)CreateSolidBrush(RGB(0, 0, 0)); // Pure black background
        
    case WM_PAINT:
        // Manejar pintado personalizado del contenedor con doble buffer
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            
            // Get client area
            RECT rect;
            GetClientRect(hwnd, &rect);
            
            // Crear DC de memoria para doble buffer
            HDC memDC = CreateCompatibleDC(hdc);
            HBITMAP memBitmap = CreateCompatibleBitmap(hdc, rect.right - rect.left, rect.bottom - rect.top);
            HBITMAP oldBitmap = (HBITMAP)SelectObject(memDC, memBitmap);
            
            // Fill the background in memory DC
            HBRUSH hBrush = CreateSolidBrush(RGB(0, 0, 0)); // Pure black background
            FillRect(memDC, &rect, hBrush);
            DeleteObject(hBrush);
            
            // Copy from memory DC to screen DC
            BitBlt(hdc, 0, 0, rect.right - rect.left, rect.bottom - rect.top, memDC, 0, 0, SRCCOPY);
            
            // Clean up
            SelectObject(memDC, oldBitmap);
            DeleteObject(memBitmap);
            DeleteDC(memDC);
            
            EndPaint(hwnd, &ps);
            return 0;
        }
        
    case WM_USER + 200:
    case WM_USER + 201:
        // Reenviar mensajes de botón matar a la ventana principal
        return PostMessage(GetParent(hwnd), uMsg, wParam, lParam);
        
    default:
        return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
}

// Función para actualizar información de scroll del contenedor de lista de procesos
void UpdateScrollInfo(HWND hwnd) {
    if (!hwnd || !g_hProcessListContainer) return;
    
    RECT containerRect;
    GetClientRect(g_hProcessListContainer, &containerRect);
    int containerWidth = containerRect.right - containerRect.left;
    int containerHeight = containerRect.bottom - containerRect.top;
    
    // Calcular alto del contenido de la lista de procesos con espaciado adecuado
    g_processListHeight = g_blockingProcesses.size() * (BUTTON_HEIGHT + 8);
    if (g_processListHeight > 0) {
        g_processListHeight += 20; // Añadir espacio adicional al final
    }
    
    // Calcular ancho de la barra de scroll
    g_scrollBarWidth = GetSystemMetrics(SM_CXVSCROLL);
    
    // Determinar si la barra de scroll debe ser visible (solo para contenedor de lista)
    g_visibleProcessListHeight = containerHeight - 20; // Dejar margen para el contenedor
    g_scrollBarVisible = (g_processListHeight > g_visibleProcessListHeight);
    
    // Actualizar parámetros de la barra de scroll para el contenedor
    SCROLLINFO si = {};
    si.cbSize = sizeof(SCROLLINFO);
    si.fMask = SIF_RANGE | SIF_PAGE | SIF_POS | SIF_DISABLENOSCROLL;
    si.nMin = 0;
    si.nMax = max(0, g_processListHeight - 1);
    si.nPage = g_visibleProcessListHeight;
    si.nPos = g_scrollY;
    
    SetScrollInfo(g_hProcessListContainer, SB_VERT, &si, TRUE);
    
    // Ajustar posición del scroll si la lista es más corta que el área visible
    if (g_processListHeight <= g_visibleProcessListHeight) {
        g_scrollY = 0;
    } else {
        g_scrollY = min(g_scrollY, g_processListHeight - g_visibleProcessListHeight);
        g_scrollY = max(0, g_scrollY);
    }
    
    // Forzar repintado completo si cambió la visibilidad de la barra de scroll
    static bool lastScrollBarVisible = false;
    if (g_scrollBarVisible != lastScrollBarVisible) {
        lastScrollBarVisible = g_scrollBarVisible;
        InvalidateRect(g_hProcessListContainer, NULL, TRUE);
    }
}

// Función para desplazar contenido
void ScrollContent(HWND hwnd, int deltaY) {
    if (!hwnd) return;
    
    // Limitar frecuencia de actualización de scroll para evitar repintados excesivos
    DWORD currentTime = GetTickCount();
    if (currentTime - g_lastScrollTime < 16) { // ~60 FPS max
        return;
    }
    g_lastScrollTime = currentTime;
    
    int oldScrollY = g_scrollY;
    g_scrollY += deltaY;
    
    // Ajustar la posición del scroll solo para la lista con límites precisos
    if (g_processListHeight <= g_visibleProcessListHeight) {
        g_scrollY = 0;
    } else {
        // Asegurar que no nos pasemos del contenido al desplazar
        int maxScroll = g_processListHeight - g_visibleProcessListHeight;
        g_scrollY = min(g_scrollY, maxScroll);
        g_scrollY = max(0, g_scrollY);
        
        // Chequeo adicional para prevenir scroll negativo
        if (g_scrollY < 0) g_scrollY = 0;
    }
    
    // Actualizar solo si la posición de scroll realmente cambió
    if (g_scrollY != oldScrollY) {
        // Validación final de la posición de scroll
        if (g_scrollY < 0) g_scrollY = 0;
        if (g_processListHeight > g_visibleProcessListHeight) {
            int maxScroll = g_processListHeight - g_visibleProcessListHeight;
            if (g_scrollY > maxScroll) g_scrollY = maxScroll;
        } else {
            g_scrollY = 0;
        }
        
        // Actualizar primero la info de scroll
        UpdateScrollInfo(hwnd);
        
        // Suspend redraw to prevent flickering
        SendMessage(g_hProcessListContainer, WM_SETREDRAW, FALSE, 0);
        
        // Actualizar el layout
        UpdateProcessDisplayLayout(hwnd);
        
        // Resume redraw and force a single update
        SendMessage(g_hProcessListContainer, WM_SETREDRAW, TRUE, 0);
        RedrawWindow(g_hProcessListContainer, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN);
    }
}

// Función para manejar eventos de la barra de desplazamiento
void HandleScrollBar(HWND hwnd, int scrollCode, int pos) {
    if (!hwnd) return;
    
    int deltaY = 0;
    int maxScroll = 0;
    
    switch (scrollCode) {
    case SB_LINEUP:
        deltaY = -BUTTON_HEIGHT - 8; // Una fila de proceso
        break;
    case SB_LINEDOWN:
        deltaY = BUTTON_HEIGHT + 8; // Una fila de proceso
        break;
    case SB_PAGEUP:
        deltaY = -g_visibleProcessListHeight + 50; // Casi una página completa
        break;
    case SB_PAGEDOWN:
        deltaY = g_visibleProcessListHeight - 50; // Casi una página completa
        break;
    case SB_THUMBPOSITION:
    case SB_THUMBTRACK:
        deltaY = pos - g_scrollY;
        break;
    case SB_TOP:
        deltaY = -g_scrollY; // Desplazar hacia arriba
        break;
    case SB_BOTTOM:
        // Asegurar no pasarnos del contenido
        maxScroll = g_processListHeight - g_visibleProcessListHeight;
        if (maxScroll > 0) {
            deltaY = maxScroll - g_scrollY; // Scroll to bottom
        } else {
            deltaY = -g_scrollY; // Si el contenido entra, ir al inicio
        }
        break;
    }
    
    if (deltaY != 0) {
        ScrollContent(g_hProcessListContainer, deltaY);
    }
}

// Función para destruir todos los botones de proceso y etiquetas de texto
void DestroyProcessButtons() {
    for (auto& button : g_processButtons) {
        if (button.hIconLabel) {
            DestroyWindow(button.hIconLabel);
            button.hIconLabel = NULL;
        }
        if (button.hTextLabel) {
            DestroyWindow(button.hTextLabel);
            button.hTextLabel = NULL;
        }
        if (button.hKillButton) {
            // Restaurar procedimiento de ventana original antes de destruir
            if (button.originalButtonProc) {
                SetWindowLongPtr(button.hKillButton, GWLP_WNDPROC, (LONG_PTR)button.originalButtonProc);
            }
            DestroyWindow(button.hKillButton);
            button.hKillButton = NULL;
            button.originalButtonProc = NULL;
        }
    }
    g_processButtons.clear();
    g_buttonY = 200;
    
    if (g_hNoProcessesLabel) {
        DestroyWindow(g_hNoProcessesLabel);
        g_hNoProcessesLabel = NULL;
    }
    
}


void AddNoProcessesMessage() {
    for (const auto& process : g_blockingProcesses) {
        if (process.processIds.size() == 1 && process.processIds[0] == 0) {
            return; 
        }
    }
    
    ProcessInfo noProcessInfo;
    noProcessInfo.processIds = {0}; 
    noProcessInfo.processName = L"No processes found blocking the object";
    noProcessInfo.filePath = g_filePath;
    noProcessInfo.handleType = L"Info";
    noProcessInfo.accessRights = L"N/A";
    noProcessInfo.blockingReason = L"The file is not currently being used by any processes";
    g_blockingProcesses.push_back(noProcessInfo);
}


void RemoveProcessFromList(DWORD processId) {
    
    for (auto it = g_blockingProcesses.begin(); it != g_blockingProcesses.end();) {
        auto pidIt = std::find(it->processIds.begin(), it->processIds.end(), processId);
        if (pidIt != it->processIds.end()) {
            it->processIds.erase(pidIt);
            
            if (it->processIds.empty()) {
                it = g_blockingProcesses.erase(it);
            } else {
                ++it;
            }
        } else {
            ++it;
        }
    }
    
    
    if (g_blockingProcesses.empty()) {
        AddNoProcessesMessage();
    }
    
    CreateProcessDisplay(g_hMainWindow);
    
    
    if (g_hProcessListContainer) {
        UpdateScrollInfo(g_hMainWindow);
    }
    
    
}


void ForceTerminateProcessGroup(const std::wstring& processName, const std::vector<DWORD>& processIds) {
    std::vector<DWORD> successfullyTerminated;
    std::vector<DWORD> failedToTerminate;
    
    for (DWORD processId : processIds) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            
            if (Process32First(hSnapshot, &pe32)) {
                do {
                    if (pe32.th32ParentProcessID == processId) {
                        HANDLE hChildProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
                        if (hChildProcess != NULL) {
                            if (::TerminateProcess(hChildProcess, 0)) {
                                successfullyTerminated.push_back(pe32.th32ProcessID);
                            } else {
                                failedToTerminate.push_back(pe32.th32ProcessID);
                            }
                            CloseHandle(hChildProcess);
                        }
                    }
                } while (Process32Next(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
        }
        
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
        if (hProcess != NULL) {
            if (::TerminateProcess(hProcess, 0)) {
                successfullyTerminated.push_back(processId);
            } else {
                failedToTerminate.push_back(processId);
            }
            CloseHandle(hProcess);
        } else {
            failedToTerminate.push_back(processId);
        }
    }
    
    
    ScanForBlockingProcesses();
}

void ForceTerminateProcess(DWORD processId, const std::wstring& processName) {
    // Primero, intenta terminar los procesos hijos
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (pe32.th32ParentProcessID == processId) {
                    HANDLE hChildProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
                    if (hChildProcess != NULL) {
                        ::TerminateProcess(hChildProcess, 0);
                        CloseHandle(hChildProcess);
                    }
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
    if (hProcess == NULL) {
        return;
    }
    
    if (::TerminateProcess(hProcess, 0)) {
        ScanForBlockingProcesses();
    } else {
    }
    
    CloseHandle(hProcess);
}

void DeleteFileAfterTermination(const std::wstring& filePath) {
    DWORD attributes = GetFileAttributes(filePath.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        return;
    }
    
    bool success = false;
    if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
        success = RemoveDirectory(filePath.c_str()) != 0;
    } else {
        success = DeleteFile(filePath.c_str()) != 0;
    }
    
    if (success) {
        
        g_filePath.clear();
        SetWindowText(g_hEditControl, L"");
        g_blockingProcesses.clear();
        DestroyProcessButtons();
    } else {
        
    }
}

// Función para terminar proceso y eliminar archivo del cuadro de texto
bool TerminateProcessAndDeleteFile(DWORD processId, const std::wstring& processName, const std::wstring& filePath) {
    // Primero termina el proceso
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
    if (hProcess == NULL) {
        return false;
    }
    
    bool processTerminated = false;
    if (::TerminateProcess(hProcess, 0)) {
        processTerminated = true;
    }
    CloseHandle(hProcess);
    
    if (!processTerminated) {
        return false;
    }
    
    Sleep(1000);
    
    DeleteFileAfterTermination(g_filePath);
    return true;
}

static void ClearFileAttributesIfNeeded(const std::wstring& path) {
    DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) return;
    if (attrs & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN)) {
        attrs &= ~(FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
        SetFileAttributesW(path.c_str(), attrs);
    }
}

bool RecursivelyDeleteNow(const std::wstring& path) {
    if (path.empty()) return false;
    DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) return false;
    if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
        std::wstring pattern = path + L"\\*";
        WIN32_FIND_DATAW fd{};
        HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
                std::wstring child = path + L"\\" + fd.cFileName;
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    RecursivelyDeleteNow(child);
                } else {
                    ClearFileAttributesIfNeeded(child);
                    HANDLE hf = CreateFileW(child.c_str(), DELETE | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
                    if (hf != INVALID_HANDLE_VALUE) {
                        FILE_DISPOSITION_INFO ex{ TRUE };
                        SetFileInformationByHandle(hf, FileDispositionInfo, &ex, sizeof(ex));
                        CloseHandle(hf);
                    }
                    DeleteFileW(child.c_str());
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
        ClearFileAttributesIfNeeded(path);
        return RemoveDirectoryW(path.c_str()) != 0;
    } else {
        ClearFileAttributesIfNeeded(path);
        HANDLE hf = CreateFileW(path.c_str(), DELETE | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
        if (hf != INVALID_HANDLE_VALUE) {
            FILE_DISPOSITION_INFO ex{ TRUE };
            SetFileInformationByHandle(hf, FileDispositionInfo, &ex, sizeof(ex));
            CloseHandle(hf);
            // Try to delete immediately after marking for deletion
            if (DeleteFileW(path.c_str()) != 0) {
                return true;
            }
            // If immediate delete fails, check if file still exists
            DWORD attrs = GetFileAttributesW(path.c_str());
            return (attrs == INVALID_FILE_ATTRIBUTES);
        }
        return DeleteFileW(path.c_str()) != 0;
    }
}

bool RecursivelyScheduleDeleteAtReboot(const std::wstring& path) {
    if (path.empty()) return false;
    DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) return false;
    ClearFileAttributesIfNeeded(path);
    if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
        std::wstring pattern = path + L"\\*";
        WIN32_FIND_DATAW fd{};
        HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
                std::wstring child = path + L"\\" + fd.cFileName;
                RecursivelyScheduleDeleteAtReboot(child);
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
        MoveFileExW(path.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
        return true;
    } else {
        return MoveFileExW(path.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT) != 0;
    }
}

// Función para obtener procesos con manejos de archivos reales usando NtQuerySystemInformation
std::vector<DWORD> GetProcessesWithRealFileHandles(const std::wstring& filePath) {
    return GetProcessesWithFileHandles(filePath); 
}

// Función para obtener servicios usando un archivo específico
std::vector<std::wstring> GetServicesUsingFile(const std::wstring& filePath) {
    std::vector<std::wstring> services;
    
    // Por ahora, usaremos un enfoque simplificado que verifica servicios comunes
    // En una implementación completa, enumerarías todos los servicios y verificarías sus rutas binarias
    
    // Verificar servicios comunes que podrían estar usando archivos
    std::vector<std::wstring> commonServices = {
        L"Windows Search", L"Windows Defender", L"Windows Update", L"Print Spooler",
        L"Task Scheduler", L"Windows Installer", L"Windows Media Player Network Sharing Service"
    };
    
    // abrir Administrador de Control de servicios
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCManager == NULL) {
        return services;
    }
    
    for (const auto& serviceName : commonServices) {
        SC_HANDLE hService = OpenService(hSCManager, serviceName.c_str(), SERVICE_QUERY_STATUS);
        if (hService != NULL) {
            SERVICE_STATUS serviceStatus;
            if (QueryServiceStatus(hService, &serviceStatus)) {
                if (serviceStatus.dwCurrentState == SERVICE_RUNNING) {
                    // servicio en ejecución, podría estar usando nuestro archivo
                    services.push_back(serviceName);
                }
            }
            CloseServiceHandle(hService);
        }
    }
    
    CloseServiceHandle(hSCManager);
    return services;
}

// Función para obtener DLLs usando un archivo específico
std::vector<std::wstring> GetDllsUsingFile(const std::wstring& filePath) {
    std::vector<std::wstring> dlls;
    
    // Este es un enfoque simplificado - en realidad necesitarías enumerar todos los módulos cargados
    // Por ahora, verificaremos DLLs del sistema comunes que podrían estar usando el archivo
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe32)) {
            do {
                // abrir proceso para enumerar sus módulos
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                if (hProcess != NULL) {
                    // enumerar módulos en este proceso
                    HANDLE hModuleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pe32.th32ProcessID);
                    if (hModuleSnapshot != INVALID_HANDLE_VALUE) {
                        MODULEENTRY32 me32;
                        me32.dwSize = sizeof(MODULEENTRY32);
                        
                        if (Module32First(hModuleSnapshot, &me32)) {
                            do {
                                // Verificar si esta ruta de módulo contiene nuestra ruta de archivo
                                std::wstring modulePath(me32.szExePath);
                                if (modulePath.find(filePath) != std::wstring::npos) {
                                    dlls.push_back(std::wstring(me32.szModule));
                                }
                            } while (Module32Next(hModuleSnapshot, &me32));
                        }
                        CloseHandle(hModuleSnapshot);
                    }
                    CloseHandle(hProcess);
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    
    return dlls;
}



// Función para verificar si la aplicación está ejecutándose como administrador
bool IsRunningAsAdministrator() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    return isAdmin != FALSE;
}

// Función para reiniciar la aplicación como administrador
bool RestartAsAdministrator(const std::wstring& filePath) {
    std::wstring exePath = GetExecutablePath();
    
    std::wstring commandLine = L"\"" + exePath + L"\" \"" + filePath + L"\"";
    
    // Preparar la estructura SHELLEXECUTEINFO
    SHELLEXECUTEINFO sei = {0};
    sei.cbSize = sizeof(SHELLEXECUTEINFO);
    sei.lpVerb = L"runas";  // Esto solicita elevación
    sei.lpFile = exePath.c_str();
    sei.lpParameters = filePath.c_str();
    sei.nShow = SW_NORMAL;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    
    // Ejecutar la aplicación con privilegios elevados
    if (ShellExecuteEx(&sei)) {
        // Inició el proceso elevado con éxito
        return true;
    } else {
        // Falló al iniciar el proceso elevado
        DWORD error = GetLastError();
        if (error == ERROR_CANCELLED) {
            // El usuario canceló el cuadro de diálogo UAC
            return false;
        } else {
            // Ocurrió otro error
            return false;
        }
    }
}

// Función para obtener el nombre de programa amigable de la ruta del ejecutable
std::wstring GetProgramFriendlyName(const std::wstring& processPath) {
    // Extraer el nombre de archivo de la ruta
    size_t lastSlash = processPath.find_last_of(L"\\/");
    std::wstring fileName = (lastSlash != std::wstring::npos) ? processPath.substr(lastSlash + 1) : processPath;
    
        
    if (fileName.length() > 4 && fileName.substr(fileName.length() - 4) == L".exe") {
        fileName = fileName.substr(0, fileName.length() - 4);
    }
    
    // Convertir a minúsculas para comparación
    std::wstring lowerFileName = fileName;
    std::transform(lowerFileName.begin(), lowerFileName.end(), lowerFileName.begin(), ::tolower);
    
    // Mapear nombres de procesos comunes a nombres amigables
    if (lowerFileName == L"notepad") return L"Notepad";
    if (lowerFileName == L"wordpad") return L"WordPad";
    if (lowerFileName == L"mspaint") return L"Paint";
    if (lowerFileName == L"calc") return L"Calculator";
    if (lowerFileName == L"explorer") return L"Windows Explorer";
    if (lowerFileName == L"cmd") return L"Command Prompt";
    if (lowerFileName == L"powershell") return L"PowerShell";
    if (lowerFileName == L"winword") return L"Microsoft Word";
    if (lowerFileName == L"excel") return L"Microsoft Excel";
    if (lowerFileName == L"powerpnt") return L"Microsoft PowerPoint";
    if (lowerFileName == L"outlook") return L"Microsoft Outlook";
    if (lowerFileName == L"acrobat") return L"Adobe Acrobat";
    if (lowerFileName == L"acrord32") return L"Adobe Reader";
    if (lowerFileName == L"chrome") return L"Google Chrome";
    if (lowerFileName == L"msedge") return L"Microsoft Edge";
    if (lowerFileName == L"firefox") return L"Mozilla Firefox";
    if (lowerFileName == L"iexplore") return L"Internet Explorer";
    if (lowerFileName == L"svchost") return L"Windows Service Host";
    if (lowerFileName == L"lsass") return L"Local Security Authority";
    if (lowerFileName == L"winlogon") return L"Windows Logon";
    if (lowerFileName == L"csrss") return L"Client Server Runtime";
    if (lowerFileName == L"smss") return L"Session Manager";
    if (lowerFileName == L"wininit") return L"Windows Initialization";
    if (lowerFileName == L"services") return L"Windows Services";
    if (lowerFileName == L"spoolsv") return L"Print Spooler";
    if (lowerFileName == L"wuauserv") return L"Windows Update";
    if (lowerFileName == L"searchindexer") return L"Windows Search";
    if (lowerFileName == L"defender") return L"Windows Defender";
    if (lowerFileName == L"msmpeng") return L"Windows Defender Antimalware";
    if (lowerFileName == L"avast") return L"Avast Antivirus";
    if (lowerFileName == L"avgui") return L"AVG Antivirus";
    if (lowerFileName == L"mcshield") return L"McAfee Antivirus";
    if (lowerFileName == L"bdredline") return L"Bitdefender";
    if (lowerFileName == L"kav") return L"Kaspersky Antivirus";
    if (lowerFileName == L"norton") return L"Norton Antivirus";
    if (lowerFileName == L"trendmicro") return L"Trend Micro";
    if (lowerFileName == L"eset") return L"ESET Antivirus";
    if (lowerFileName == L"smartscreen") return L"Windows SmartScreen";
    if (lowerFileName == L"mpcmdrun") return L"Windows Defender Command Line";
    if (lowerFileName == L"7z") return L"7-Zip";
    if (lowerFileName == L"7zfm") return L"7-Zip File Manager";
    if (lowerFileName == L"7zg") return L"7-Zip GUI";
    if (lowerFileName == L"winrar") return L"WinRAR";
    if (lowerFileName == L"winzip") return L"WinZip";
    if (lowerFileName == L"peazip") return L"PeaZip";
    if (lowerFileName == L"bandizip") return L"Bandizip";
    
    // Si no se encuentra ninguna asignación, devolver el nombre de archivo con la primera letra en mayúscula
    if (!fileName.empty()) {
        fileName[0] = std::toupper(fileName[0]);
        return fileName;
    }
    
    return L"Unknown Program";
}

// Función auxiliar para verificar si un archivo está en un directorio temporal
bool IsInTempDirectory(const std::wstring& filePath) {
    std::wstring lowerPath = filePath;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::tolower);
    
    // Verificar patrones de directorio temporal comunes
    return (lowerPath.find(L"\\temp\\") != std::wstring::npos ||
            lowerPath.find(L"\\tmp\\") != std::wstring::npos ||
            lowerPath.find(L"\\windows\\temp\\") != std::wstring::npos ||
            lowerPath.find(L"\\users\\") != std::wstring::npos && lowerPath.find(L"\\appdata\\local\\temp\\") != std::wstring::npos ||
            lowerPath.find(L"\\users\\") != std::wstring::npos && lowerPath.find(L"\\appdata\\roaming\\temp\\") != std::wstring::npos);
}

// Función auxiliar para verificar si un proceso es un servicio del sistema
bool IsSystemService(const std::wstring& processName) {
    std::wstring lowerProcessName = processName;
    std::transform(lowerProcessName.begin(), lowerProcessName.end(), lowerProcessName.begin(), ::tolower);
    
    // Lista de servicios del sistema a ignorar
    std::vector<std::wstring> systemServices = {
        L"svchost.exe", L"conhost.exe", L"lsass.exe", L"winlogon.exe",
        L"csrss.exe", L"smss.exe", L"wininit.exe", L"services.exe",
        L"spoolsv.exe", L"wuauserv.exe", L"searchindexer.exe",
        L"defender.exe", L"msmpeng.exe", L"dwm.exe", L"ctfmon.exe",
        L"rundll32.exe", L"dllhost.exe", L"wmiadap.exe", L"wmiprvse.exe",
        L"taskhostw.exe", L"taskeng.exe", L"taskmgr.exe",
        // procesos adicionales que a menudo causan falsos positivos en directorios temporales
        L"explorer.exe", L"iexplore.exe", L"chrome.exe", L"firefox.exe",
        L"msedge.exe", L"opera.exe", L"safari.exe", L"brave.exe",
        L"outlook.exe",
        L"acrobat.exe", L"acrord32.exe", L"reader_sl.exe", L"foxitreader.exe",
        L"notepad.exe", L"wordpad.exe", L"mspaint.exe", L"calc.exe",
        L"cmd.exe", L"conhost.exe", L"fontdrvhost.exe",
        L"dllhost.exe", L"rundll32.exe", L"regsvr32.exe", L"msiexec.exe",
        L"wscript.exe", L"cscript.exe", L"mshta.exe", L"hh.exe",
        L"winhlp32.exe", L"winhelp.exe", L"help.exe", L"winver.exe",
        L"verifier.exe", L"drvinst.exe", L"pnputil.exe", L"devcon.exe",
        L"devmgmt.msc", L"compmgmt.msc", L"services.msc", L"eventvwr.msc",
        L"gpedit.msc", L"secpol.msc", L"lusrmgr.msc", L"dsa.msc",
        L"dssite.msc", L"dnsmgmt.msc", L"dhcpmgmt.msc", L"tsmmc.msc",
        L"certmgr.msc", L"certtmpl.msc", L"certpol.msc", L"certadm.msc",
        L"certreq.exe", L"certutil.exe", L"makecert.exe", L"signtool.exe",
        L"inf2cat.exe", L"cat2db.exe", L"catdb.exe", L"certmgr.exe",
        L"certpol.exe", L"certreq.exe", L"certutil.exe", L"makecert.exe",
        L"signtool.exe", L"inf2cat.exe", L"cat2db.exe", L"catdb.exe"
    };
    
    for (const auto& service : systemServices) {
        if (lowerProcessName == service) {
            return true;
        }
    }
    
    return false;
}

// Función para calcular la puntuación de prioridad de bloqueo para un proceso
int CalculateBlockingPriority(DWORD processId, const std::wstring& processName, const std::wstring& filePath) {
    int score = 0;
    
    // obtener ruta del proceso
    std::wstring processPath = GetProcessPath(processId);
    
    // Verificar si este proceso ES el archivo en sí (alta prioridad)
    if (processPath == filePath) {
        score += 1000;
    }
    
    // Verificar servicios del sistema (alta prioridad - estos son a menudo los principales bloqueadores)
    std::wstring lowerProcessName = processName;
    std::transform(lowerProcessName.begin(), lowerProcessName.end(), lowerProcessName.begin(), ::tolower);
    
    if (lowerProcessName.find(L"svchost") != std::wstring::npos ||
        lowerProcessName.find(L"lsass") != std::wstring::npos ||
        lowerProcessName.find(L"winlogon") != std::wstring::npos ||
        lowerProcessName.find(L"csrss") != std::wstring::npos ||
        lowerProcessName.find(L"smss") != std::wstring::npos ||
        lowerProcessName.find(L"wininit") != std::wstring::npos ||
        lowerProcessName.find(L"services") != std::wstring::npos ||
        lowerProcessName.find(L"spoolsv") != std::wstring::npos ||
        lowerProcessName.find(L"wuauserv") != std::wstring::npos ||
        lowerProcessName.find(L"searchindexer") != std::wstring::npos) {
        score += 900;   
    }
    
    // Verificar procesos de antivirus (alta prioridad)
    if (lowerProcessName.find(L"avast") != std::wstring::npos ||
        lowerProcessName.find(L"avg") != std::wstring::npos ||
        lowerProcessName.find(L"mcshield") != std::wstring::npos ||
        lowerProcessName.find(L"msmpeng") != std::wstring::npos ||
        lowerProcessName.find(L"defender") != std::wstring::npos ||
        lowerProcessName.find(L"smartscreen") != std::wstring::npos ||
        lowerProcessName.find(L"windowsdefender") != std::wstring::npos ||
        lowerProcessName.find(L"mpcmdrun") != std::wstring::npos) {
        score += 800; 
    }
    
    // Verificar manejos de archivos directos (alta prioridad)
    if (processName.find(L"explorer.exe") != std::wstring::npos) {
        score += 700; 
    }
    
    // Verificar herramientas de archivo/compresión (prioridad media-alta)
    if (lowerProcessName.find(L"7z") != std::wstring::npos ||
        lowerProcessName.find(L"winrar") != std::wstring::npos ||
        lowerProcessName.find(L"winzip") != std::wstring::npos ||
        lowerProcessName.find(L"peazip") != std::wstring::npos ||
        lowerProcessName.find(L"bandizip") != std::wstring::npos) {
        score += 600; 
    }
    
    // Verificar relación con directorio de trabajo (prioridad media)
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess != NULL) {
        wchar_t currentDir[MAX_PATH];
        if (GetCurrentDirectoryW(MAX_PATH, currentDir)) {
            std::wstring currentDirStr(currentDir);
            if (currentDirStr.find(filePath) != std::wstring::npos) {
                score += 500; 
            }
        }
        CloseHandle(hProcess);
    }
    
    // Verificar editores de archivos comunes (prioridad más baja - estos son generalmente fácil de cerrar)
    if (lowerProcessName.find(L"notepad") != std::wstring::npos ||
        lowerProcessName.find(L"wordpad") != std::wstring::npos ||
        lowerProcessName.find(L"mspaint") != std::wstring::npos ||
        lowerProcessName.find(L"winword") != std::wstring::npos ||
        lowerProcessName.find(L"excel") != std::wstring::npos ||
        lowerProcessName.find(L"powerpnt") != std::wstring::npos ||
        lowerProcessName.find(L"acrobat") != std::wstring::npos ||
        lowerProcessName.find(L"acrord32") != std::wstring::npos) {
        score += 200; // Editores de archivos directos - prioridad más baja (fácil de cerrar)
    }
    
    return score;
}

// Función auxiliar para verificar si un proceso aún está en ejecución
bool IsProcessRunning(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (hProcess == NULL) {
        return false; // El proceso no existe
    }
    
    DWORD exitCode;
    if (GetExitCodeProcess(hProcess, &exitCode)) {
        CloseHandle(hProcess);
        return (exitCode == STILL_ACTIVE);
    }
    
    CloseHandle(hProcess);
    return false;
}

// Detectar si una ruta de carpeta probablemente apunta a un área del sistema/compartida donde muchos procesos
// mantienen manejos transitorios/compartidos. Esto ayuda a anotar resultados para evitar confusión.
bool IsSystemFolderPath(const std::wstring& path) {
    if (path.empty()) return false;
    std::wstring lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

    // Normalizar barra final
    while (!lower.empty() && (lower.back() == L'\\' || lower.back() == L'/')) lower.pop_back();

    // Raíces y carpetas especiales del sistema comunes
    const std::vector<std::wstring> prefixes = {
        L"c:\\windows",
        L"c:\\program files",
        L"c:\\program files (x86)",
        L"c:\\programdata",
        L"\\\\?\\c:\\windows",
        L"\\\\?\\c:\\program files",
        L"\\\\?\\c:\\program files (x86)",
        L"\\\\?\\c:\\programdata"
    };

    for (const auto& p : prefixes) {
        if (lower.rfind(p, 0) == 0) return true;
    }

    // Las áreas temporales conocidas de Windows son ruidosas pero no necesariamente son del sistema; se manejan en otro lugar.
    return false;
}

// construir la ruta equivalente de GUID de volumen (\\?\Volume{GUID}\...) para una ruta DOS dada (C:\...).
// Retorna cadena vacía si la asignación falla.
std::wstring BuildVolumeGuidPath(const std::wstring& dosPath) {
    if (dosPath.size() < 3 || dosPath[1] != L':' || (dosPath[2] != L'\\' && dosPath[2] != L'/')) {
        return L""; // No es una ruta de letra de unidad
    }
    wchar_t volumeRoot[MAX_PATH] = {0};
    if (!GetVolumePathNameW(dosPath.c_str(), volumeRoot, MAX_PATH)) {
        return L"";
    }
    wchar_t volumename[MAX_PATH] = {0};
    if (!GetVolumeNameForVolumeMountPointW(volumeRoot, volumename, MAX_PATH)) {
        return L"";
    }
    std::wstring root(volumeRoot);        // e.g., C:\ (root)
    std::wstring guidRoot(volumename);    // e.g., \\?\Volume{GUID}\\ (root)
    std::wstring pathRemainder = dosPath.substr(root.size());
    if (!guidRoot.empty() && guidRoot.back() == L'\\') {
        return guidRoot + pathRemainder;
    }
    return guidRoot + L"\\" + pathRemainder;
}

// Función auxiliar para agregar o actualizar información de proceso en la lista de procesos bloqueados
void AddOrUpdateProcessInfo(DWORD processId, const std::wstring& processName, const std::wstring& filePath, 
                           const std::wstring& handleType, const std::wstring& accessRights, 
                           const std::wstring& blockingReason) {
    // Primero, verificar si el proceso aún está en ejecución
    if (!IsProcessRunning(processId)) {
        return; // El proceso ya no está en ejecución, no agregarlo
    }
    
    // FILTRO FINAL: Para archivos, ignorar varios servicios del sistema. Para directorios, no filtrar salidas de shells.
    if (handleType != L"Directory") {
    std::wstring lowerProcessName = processName;
    std::transform(lowerProcessName.begin(), lowerProcessName.end(), lowerProcessName.begin(), ::tolower);
    std::vector<std::wstring> ignoredProcesses = {
        L"svchost.exe", L"conhost.exe", L"lsass.exe", L"winlogon.exe",
        L"csrss.exe", L"smss.exe", L"wininit.exe", L"services.exe",
        L"spoolsv.exe", L"wuauserv.exe", L"searchindexer.exe",
        L"defender.exe", L"msmpeng.exe", L"dwm.exe", L"ctfmon.exe",
        L"rundll32.exe", L"dllhost.exe", L"wmiadap.exe", L"wmiprvse.exe",
        L"taskhostw.exe", L"taskeng.exe", L"taskmgr.exe"
    };
    for (const auto& ignored : ignoredProcesses) {
        if (lowerProcessName == ignored || lowerProcessName.find(ignored) != std::wstring::npos) {
                return; // ignorar completamente este proceso para bloqueos de archivos
            }
        }
    }
    
    // Verificar si ya tenemos una entrada para este nombre de proceso
    for (auto& existing : g_blockingProcesses)  {
        if (existing.processName == processName) {
            // Verificar si este ID de proceso ya está en la lista
            bool processIdExists = false;
            for (DWORD existingId : existing.processIds) {
                if (existingId == processId) {
                    processIdExists = true;
                    break;
                }
            }
            
            // agregar el ID de proceso si no está ya allí
            if (!processIdExists) {
                existing.processIds.push_back(processId);
            }
            return; // Encontrado y actualizado entrada existente
        }
    }
    
    // Crear nueva entrada si no se encuentra
    ProcessInfo info;
    info.processIds.push_back(processId);
    info.processName = processName;
    info.filePath = filePath;
    info.handleType = handleType;
    info.accessRights = accessRights;
    info.blockingReason = blockingReason;
    g_blockingProcesses.push_back(info);
    
    // Ordenar la lista por prioridad de bloqueo (la más alta primero)
    std::sort(g_blockingProcesses.begin(), g_blockingProcesses.end(), 
        [&filePath](const ProcessInfo& a, const ProcessInfo& b) {
            // Calcular puntuaciones de prioridad para ambos procesos
            int scoreA = 0, scoreB = 0;
            
            for (DWORD pid : a.processIds) {
                int currentScore = CalculateBlockingPriority(pid, a.processName, filePath);
                if (currentScore > scoreA) scoreA = currentScore;
            }
            
            for (DWORD pid : b.processIds) {
                int currentScore = CalculateBlockingPriority(pid, b.processName, filePath);
                if (currentScore > scoreB) scoreB = currentScore;
            }
            
            // Mayor puntuación = mayor prioridad = aparece primero
            return scoreA > scoreB;
        });
}

// Procedimiento de botón moderno para estilo de botón elegante y moderno con tema OLED oscuro
LRESULT CALLBACK ModernButtonProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    static bool isHovered = false;
    static bool isPressed = false;
    
    switch (uMsg) {
    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            
            RECT rect;
            GetClientRect(hwnd, &rect);
            
            // obtener texto del botón
            wchar_t text[256];
            GetWindowText(hwnd, text, 256);
            
            // determinar estado del botón y colores para tema OLED oscuro
            COLORREF bgColor, textColor, borderColor;
            if (isPressed) {
                bgColor = RGB(20, 20, 20);      
                textColor = RGB(180, 180, 180); 
                borderColor = RGB(40, 40, 40);  
            } else if (isHovered) {
                bgColor = RGB(30, 30, 30);      
                textColor = RGB(255, 255, 255); 
                borderColor = RGB(60, 60, 60);  
                    } else {
                bgColor = RGB(15, 15, 15);      
                textColor = RGB(220, 220, 220); 
                borderColor = RGB(35, 35, 35);  
            }
            
            // Colores especiales para Force Delete (rojo) y Delete at Restart (amarillo)
            std::wstring t = text;
            bool isForceDelete = (t.find(L"FORCE DELETE") != std::wstring::npos);
            bool isDeleteAtRestart = (t.find(L"DELETE AT RESTART") != std::wstring::npos);
            if (isForceDelete) {
                bgColor = isPressed ? RGB(140, 0, 0) : (isHovered ? RGB(180, 0, 0) : RGB(120, 0, 0));
                borderColor = RGB(200, 40, 40);
                textColor = RGB(255, 255, 255);
            } else if (isDeleteAtRestart) {
                bgColor = isPressed ? RGB(140, 110, 0) : (isHovered ? RGB(180, 150, 0) : RGB(120, 90, 0));
                borderColor = RGB(200, 170, 40);
                textColor = RGB(255, 255, 255);
            }

            // Rellenar fondo
            HBRUSH hBrush = CreateSolidBrush(bgColor);
            FillRect(hdc, &rect, hBrush);
            DeleteObject(hBrush);
            
            // Dibujar borde redondeado
            HPEN hPen = CreatePen(PS_SOLID, 1, borderColor);
            HPEN hOldPen = (HPEN)SelectObject(hdc, hPen);
            HBRUSH hOldBrush = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
            
            // Calcular radio de esquina (10 píxeles para esquinas redondeadas)
            int cornerRadius = 10;
            RoundRect(hdc, rect.left, rect.top, rect.right, rect.bottom, cornerRadius, cornerRadius);
            
            SelectObject(hdc, hOldPen);
            SelectObject(hdc, hOldBrush);
            DeleteObject(hPen);
            
            // Dibujar texto
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, textColor);
            
            // Centrar texto
            DrawText(hdc, text, -1, &rect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            
            EndPaint(hwnd, &ps);
            return 0;
        }
        
    case WM_MOUSEMOVE:
        {
            // Verificar si el mouse está dentro del área del botón
            POINT pt = {LOWORD(lParam), HIWORD(lParam)};
            RECT rect;
            GetClientRect(hwnd, &rect);
            
            bool isInside = (pt.x >= 0 && pt.x < rect.right && pt.y >= 0 && pt.y < rect.bottom);
            
            if (isInside && !isHovered) {
                isHovered = true;
                InvalidateRect(hwnd, NULL, TRUE);
                SetCapture(hwnd);
            } else if (!isInside && isHovered) {
                isHovered = false;
                isPressed = false;
                InvalidateRect(hwnd, NULL, TRUE);
                ReleaseCapture();
            }
        }
        break;
        
    case WM_MOUSELEAVE:
        isHovered = false;
        isPressed = false;
        InvalidateRect(hwnd, NULL, TRUE);
        ReleaseCapture();
        break;
        
            case WM_LBUTTONDOWN:
        {
            // Verificar si el clic está dentro del área del botón
            POINT pt = {LOWORD(lParam), HIWORD(lParam)};
            RECT rect;
            GetClientRect(hwnd, &rect);
            
            bool isInside = (pt.x >= 0 && pt.x < rect.right && pt.y >= 0 && pt.y < rect.bottom);
            
            if (isInside) {
                isPressed = true;
                InvalidateRect(hwnd, NULL, TRUE);
            }
        }
        break;
        
            case WM_LBUTTONUP:
        {
            // Verificar si el clic está dentro del área del botón
            POINT pt = {LOWORD(lParam), HIWORD(lParam)};
            RECT rect;
            GetClientRect(hwnd, &rect);
            
            bool isInside = (pt.x >= 0 && pt.x < rect.right && pt.y >= 0 && pt.y < rect.bottom);
            
            if (isPressed && isInside) {
                isPressed = false;
                InvalidateRect(hwnd, NULL, TRUE);
                // Enviar mensaje de clic de botón al padre
                SendMessage(GetParent(hwnd), WM_COMMAND, GetDlgCtrlID(hwnd), (LPARAM)hwnd);
            } else if (isPressed) {
                // Si se soltó el botón fuera del área, solo resetear el estado
                isPressed = false;
                InvalidateRect(hwnd, NULL, TRUE);
            }
        }
        break;
        
    case WM_ERASEBKGND:
        return TRUE; // Prevenir borrado de fondo por defecto
    }
    
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}















