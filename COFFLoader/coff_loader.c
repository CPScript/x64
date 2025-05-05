#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winhttp.h>

// Include the COFF loader header
#include "coff_loader.h"

// Download a COFF file from a URL directly into memory
BOOL DownloadToMemory(const char* url, uint8_t** outBuffer, size_t* outSize) {
    BOOL result = FALSE;
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    DWORD bufferSize = 0;
    DWORD downloadSize = 0;
    DWORD bytesRead = 0;
    URL_COMPONENTS urlComp = {0};
    char hostName[256] = {0};
    char urlPath[2048] = {0};
    
    *outBuffer = NULL;
    *outSize = 0;
    
    // Initialize URL_COMPONENTS structure
    urlComp.dwStructSize = sizeof(URL_COMPONENTS);
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = sizeof(hostName);
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = sizeof(urlPath);
    
    // Crack the URL
    if (!WinHttpCrackUrl(url, 0, 0, &urlComp)) {
        printf("Error: Failed to parse URL\n");
        return FALSE;
    }
    
    // Initialize WinHTTP
    hSession = WinHttpOpen(L"COFF Loader/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                          WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        printf("Error: Failed to initialize WinHTTP\n");
        return FALSE;
    }
    
    // Connect to server
    hConnect = WinHttpConnect(hSession, hostName, urlComp.nPort, 0);
    if (!hConnect) {
        printf("Error: Failed to connect to server\n");
        goto cleanup;
    }
    
    // Create request handle
    hRequest = WinHttpOpenRequest(hConnect, L"GET", urlPath,
                                 NULL, WINHTTP_NO_REFERER,
                                 WINHTTP_DEFAULT_ACCEPT_TYPES,
                                 (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        printf("Error: Failed to create request\n");
        goto cleanup;
    }
    
    // Send request
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                           WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        printf("Error: Failed to send request\n");
        goto cleanup;
    }
    
    // Receive response
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        printf("Error: Failed to receive response\n");
        goto cleanup;
    }
    
    // Get content length
    DWORD contentLength = 0;
    DWORD headerSize = sizeof(contentLength);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
                       WINHTTP_HEADER_NAME_BY_INDEX, &contentLength, &headerSize, WINHTTP_NO_HEADER_INDEX);
    
    // Allocate buffer for the file (use a reasonable default if content length is not available)
    bufferSize = contentLength > 0 ? contentLength : 1024 * 1024; // 1MB default
    *outBuffer = (uint8_t*)malloc(bufferSize);
    if (!*outBuffer) {
        printf("Error: Memory allocation failed\n");
        goto cleanup;
    }
    
    // Read data
    do {
        // Check if we need to expand the buffer
        if (downloadSize + 8192 > bufferSize) {
            bufferSize *= 2;
            uint8_t* newBuffer = (uint8_t*)realloc(*outBuffer, bufferSize);
            if (!newBuffer) {
                printf("Error: Memory reallocation failed\n");
                free(*outBuffer);
                *outBuffer = NULL;
                goto cleanup;
            }
            *outBuffer = newBuffer;
        }
        
        // Read data from the HTTP response
        if (!WinHttpReadData(hRequest, *outBuffer + downloadSize, 8192, &bytesRead)) {
            printf("Error: Failed to read data\n");
            free(*outBuffer);
            *outBuffer = NULL;
            goto cleanup;
        }
        
        downloadSize += bytesRead;
    } while (bytesRead > 0);
    
    // Shrink buffer to actual size
    if (downloadSize > 0) {
        uint8_t* newBuffer = (uint8_t*)realloc(*outBuffer, downloadSize);
        if (newBuffer) {
            *outBuffer = newBuffer;
        }
        *outSize = downloadSize;
        result = TRUE;
    } else {
        free(*outBuffer);
        *outBuffer = NULL;
    }
    
cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    
    return result;
}

// Extended symbol resolver that maps function names to procedures
void* AdvancedSymbolResolver(const char* symbolName) {
    // First check common Windows DLLs
    void* address = DefaultSymbolResolver(symbolName);
    if (address) {
        return address;
    }
    
    // Define custom function mappings
    static struct {
        const char* name;
        void* address;
    } customFunctions[] = {
        // Add your custom function mappings here
        // Example: {"MyCustomFunction", (void*)&MyCustomFunctionImpl}
        {NULL, NULL}
    };
    
    // Look for a matching custom function
    for (int i = 0; customFunctions[i].name != NULL; i++) {
        if (strcmp(symbolName, customFunctions[i].name) == 0) {
            return customFunctions[i].address;
        }
    }
    
    // Handle DLL loading by name (e.g., "MYDLL.dll!FunctionName")
    char* delim = strchr(symbolName, '!');
    if (delim) {
        // Extract the DLL name and function name
        size_t dllNameLen = delim - symbolName;
        char* dllName = (char*)malloc(dllNameLen + 1);
        if (dllName) {
            strncpy(dllName, symbolName, dllNameLen);
            dllName[dllNameLen] = '\0';
            
            // Load the DLL
            HMODULE hModule = LoadLibraryA(dllName);
            free(dllName);
            
            if (hModule) {
                // Get the function address
                return GetProcAddress(hModule, delim + 1);
            }
        }
    }
    
    printf("Warning: Unresolved external symbol: %s\n", symbolName);
    return NULL;
}

// Example of full in-memory execution with no file I/O
int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <url_to_coff_file> [args...]\n", argv[0]);
        return 1;
    }
    
    uint8_t* buffer = NULL;
    size_t bufferSize = 0;
    
    // Download the COFF file directly into memory
    if (!DownloadToMemory(argv[1], &buffer, &bufferSize)) {
        printf("Error: Failed to download the COFF file\n");
        return 1;
    }
    
    printf("Successfully downloaded %zu bytes\n", bufferSize);
    
    // Load the COFF module from memory
    PCOFF_MODULE module = CoffLoadModule(buffer, bufferSize);
    if (!module) {
        printf("Error: Failed to load COFF module\n");
        free(buffer);
        return 1;
    }
    
    // Relocate the module using our advanced resolver
    if (!CoffRelocateModule(module, AdvancedSymbolResolver)) {
        printf("Error: Failed to relocate COFF module\n");
        CoffUnloadModule(module);
        free(buffer);
        return 1;
    }
    
    // Free the buffer as it's no longer needed
    free(buffer);
    
    // Execute the COFF module
    printf("Executing COFF module...\n");
    int result = CoffExecuteModule(module, argc - 1, &argv[1]);
    printf("Execution completed with result: %d\n", result);
    
    // Unload the module
    CoffUnloadModule(module);
    
    return 0;
}