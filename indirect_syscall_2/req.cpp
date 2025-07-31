#include <windows.h>
#include <winhttp.h>
#include <iostream>

#pragma comment(lib, "winhttp.lib")

int main() {
    // Open WinHTTP session
    HINTERNET hSession = WinHttpOpen(L"Example/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    if (!hSession) {
        std::cerr << "WinHttpOpen failed: " << GetLastError() << std::endl;
        return 1;
    }

    // Connect to server
    HINTERNET hConnect = WinHttpConnect(hSession, L"example.com",
        INTERNET_DEFAULT_HTTP_PORT, 0);

    if (!hConnect) {
        std::cerr << "WinHttpConnect failed: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hSession);
        return 1;
    }

    // Open HTTP request
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/",
        NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0);

    if (!hRequest) {
        std::cerr << "WinHttpOpenRequest failed: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return 1;
    }

    // Send the request
    if (!WinHttpSendRequest(hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0,
        0, 0)) {
        std::cerr << "WinHttpSendRequest failed: " << GetLastError() << std::endl;
    }

    // Receive response
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        std::cerr << "WinHttpReceiveResponse failed: " << GetLastError() << std::endl;
    }
    else {
        DWORD dwSize = 0;
        do {
            DWORD dwDownloaded = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                break;

            if (!dwSize)
                break;

            char* buffer = new char[dwSize + 1];
            ZeroMemory(buffer, dwSize + 1);

            if (WinHttpReadData(hRequest, (LPVOID)buffer, dwSize, &dwDownloaded))
                std::cout << buffer;

            delete[] buffer;
        } while (dwSize > 0);
    }

    // Cleanup
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return 0;
}
