#pragma once

#include <windows.h>
#include <bcrypt.h>
#include <wchar.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>

#define STATUS_SUCCESS ((NTSTATUS)0x00000000)

#pragma comment(linker,"/export:BCryptAddContextFunction=c:\\windows\\system32\\bcrypt.BCryptAddContextFunction,@1")
#pragma comment(linker,"/export:BCryptAddContextFunctionProvider=c:\\windows\\system32\\bcrypt.BCryptAddContextFunctionProvider,@2")
#pragma comment(linker,"/export:BCryptCloseAlgorithmProvider=c:\\windows\\system32\\bcrypt.BCryptCloseAlgorithmProvider,@3")
#pragma comment(linker,"/export:BCryptConfigureContext=c:\\windows\\system32\\bcrypt.BCryptConfigureContext,@4")
#pragma comment(linker,"/export:BCryptConfigureContextFunction=c:\\windows\\system32\\bcrypt.BCryptConfigureContextFunction,@5")
#pragma comment(linker,"/export:BCryptCreateContext=c:\\windows\\system32\\bcrypt.BCryptCreateContext,@6")
#pragma comment(linker,"/export:BCryptCreateHash=c:\\windows\\system32\\bcrypt.BCryptCreateHash,@7")
#pragma comment(linker,"/export:BCryptCreateMultiHash=c:\\windows\\system32\\bcrypt.BCryptCreateMultiHash,@8")
#pragma comment(linker,"/export:BCryptDecrypt=c:\\windows\\system32\\bcrypt.BCryptDecrypt,@9")
#pragma comment(linker,"/export:BCryptDeleteContext=c:\\windows\\system32\\bcrypt.BCryptDeleteContext,@10")
#pragma comment(linker,"/export:BCryptDeriveKey=c:\\windows\\system32\\bcrypt.BCryptDeriveKey,@11")
#pragma comment(linker,"/export:BCryptDeriveKeyCapi=c:\\windows\\system32\\bcrypt.BCryptDeriveKeyCapi,@12")
#pragma comment(linker,"/export:BCryptDeriveKeyPBKDF2=c:\\windows\\system32\\bcrypt.BCryptDeriveKeyPBKDF2,@13")
#pragma comment(linker,"/export:BCryptDestroyHash=c:\\windows\\system32\\bcrypt.BCryptDestroyHash,@14")
#pragma comment(linker,"/export:BCryptDestroyKey=c:\\windows\\system32\\bcrypt.BCryptDestroyKey,@15")
#pragma comment(linker,"/export:BCryptDestroySecret=c:\\windows\\system32\\bcrypt.BCryptDestroySecret,@16")
#pragma comment(linker,"/export:BCryptDuplicateHash=c:\\windows\\system32\\bcrypt.BCryptDuplicateHash,@17")
#pragma comment(linker,"/export:BCryptDuplicateKey=c:\\windows\\system32\\bcrypt.BCryptDuplicateKey,@18")
// #pragma comment(linker,"/export:BCryptEncrypt=c:\\windows\\system32\\bcrypt.BCryptEncrypt,@19")
#pragma comment(linker,"/export:BCryptEnumAlgorithms=c:\\windows\\system32\\bcrypt.BCryptEnumAlgorithms,@20")
#pragma comment(linker,"/export:BCryptEnumContextFunctionProviders=c:\\windows\\system32\\bcrypt.BCryptEnumContextFunctionProviders,@21")
#pragma comment(linker,"/export:BCryptEnumContextFunctions=c:\\windows\\system32\\bcrypt.BCryptEnumContextFunctions,@22")
#pragma comment(linker,"/export:BCryptEnumContexts=c:\\windows\\system32\\bcrypt.BCryptEnumContexts,@23")
#pragma comment(linker,"/export:BCryptEnumProviders=c:\\windows\\system32\\bcrypt.BCryptEnumProviders,@24")
#pragma comment(linker,"/export:BCryptEnumRegisteredProviders=c:\\windows\\system32\\bcrypt.BCryptEnumRegisteredProviders,@25")
#pragma comment(linker,"/export:BCryptExportKey=c:\\windows\\system32\\bcrypt.BCryptExportKey,@26")
#pragma comment(linker,"/export:BCryptFinalizeKeyPair=c:\\windows\\system32\\bcrypt.BCryptFinalizeKeyPair,@27")
// #pragma comment(linker,"/export:BCryptFinishHash=c:\\windows\\system32\\bcrypt.BCryptFinishHash,@28")
#pragma comment(linker,"/export:BCryptFreeBuffer=c:\\windows\\system32\\bcrypt.BCryptFreeBuffer,@29")
// #pragma comment(linker,"/export:BCryptGenRandom=c:\\windows\\system32\\bcrypt.BCryptGenRandom,@30")
#pragma comment(linker,"/export:BCryptGenerateKeyPair=c:\\windows\\system32\\bcrypt.BCryptGenerateKeyPair,@31")
// #pragma comment(linker,"/export:BCryptGenerateSymmetricKey=c:\\windows\\system32\\bcrypt.BCryptGenerateSymmetricKey,@32")
#pragma comment(linker,"/export:BCryptGetFipsAlgorithmMode=c:\\windows\\system32\\bcrypt.BCryptGetFipsAlgorithmMode,@33")
#pragma comment(linker,"/export:BCryptGetProperty=c:\\windows\\system32\\bcrypt.BCryptGetProperty,@34")
#pragma comment(linker,"/export:BCryptHash=c:\\windows\\system32\\bcrypt.BCryptHash,@35")
#pragma comment(linker,"/export:BCryptHashData=c:\\windows\\system32\\bcrypt.BCryptHashData,@36")
#pragma comment(linker,"/export:BCryptImportKey=c:\\windows\\system32\\bcrypt.BCryptImportKey,@37")
#pragma comment(linker,"/export:BCryptImportKeyPair=c:\\windows\\system32\\bcrypt.BCryptImportKeyPair,@38")
#pragma comment(linker,"/export:BCryptKeyDerivation=c:\\windows\\system32\\bcrypt.BCryptKeyDerivation,@39")
#pragma comment(linker,"/export:BCryptOpenAlgorithmProvider=c:\\windows\\system32\\bcrypt.BCryptOpenAlgorithmProvider,@40")
#pragma comment(linker,"/export:BCryptProcessMultiOperations=c:\\windows\\system32\\bcrypt.BCryptProcessMultiOperations,@41")
#pragma comment(linker,"/export:BCryptQueryContextConfiguration=c:\\windows\\system32\\bcrypt.BCryptQueryContextConfiguration,@42")
#pragma comment(linker,"/export:BCryptQueryContextFunctionConfiguration=c:\\windows\\system32\\bcrypt.BCryptQueryContextFunctionConfiguration,@43")
#pragma comment(linker,"/export:BCryptQueryContextFunctionProperty=c:\\windows\\system32\\bcrypt.BCryptQueryContextFunctionProperty,@44")
#pragma comment(linker,"/export:BCryptQueryProviderRegistration=c:\\windows\\system32\\bcrypt.BCryptQueryProviderRegistration,@45")
#pragma comment(linker,"/export:BCryptRegisterConfigChangeNotify=c:\\windows\\system32\\bcrypt.BCryptRegisterConfigChangeNotify,@46")
#pragma comment(linker,"/export:BCryptRegisterProvider=c:\\windows\\system32\\bcrypt.BCryptRegisterProvider,@47")
#pragma comment(linker,"/export:BCryptRemoveContextFunction=c:\\windows\\system32\\bcrypt.BCryptRemoveContextFunction,@48")
#pragma comment(linker,"/export:BCryptRemoveContextFunctionProvider=c:\\windows\\system32\\bcrypt.BCryptRemoveContextFunctionProvider,@49")
#pragma comment(linker,"/export:BCryptResolveProviders=c:\\windows\\system32\\bcrypt.BCryptResolveProviders,@50")
#pragma comment(linker,"/export:BCryptSecretAgreement=c:\\windows\\system32\\bcrypt.BCryptSecretAgreement,@51")
#pragma comment(linker,"/export:BCryptSetAuditingInterface=c:\\windows\\system32\\bcrypt.BCryptSetAuditingInterface,@52")
#pragma comment(linker,"/export:BCryptSetContextFunctionProperty=c:\\windows\\system32\\bcrypt.BCryptSetContextFunctionProperty,@53")
#pragma comment(linker,"/export:BCryptSetProperty=c:\\windows\\system32\\bcrypt.BCryptSetProperty,@54")
#pragma comment(linker,"/export:BCryptSignHash=c:\\windows\\system32\\bcrypt.BCryptSignHash,@55")
#pragma comment(linker,"/export:BCryptUnregisterConfigChangeNotify=c:\\windows\\system32\\bcrypt.BCryptUnregisterConfigChangeNotify,@56")
#pragma comment(linker,"/export:BCryptUnregisterProvider=c:\\windows\\system32\\bcrypt.BCryptUnregisterProvider,@57")
#pragma comment(linker,"/export:BCryptVerifySignature=c:\\windows\\system32\\bcrypt.BCryptVerifySignature,@58")

typedef NTSTATUS(WINAPI* BCryptEncrypt_Type)(
    BCRYPT_KEY_HANDLE hKey,
    PUCHAR pbInput,
    ULONG cbInput,
    VOID* pPaddingInfo,
    PUCHAR pbIV,
    ULONG cbIV,
    PUCHAR pbOutput,
    ULONG cbOutput,
    ULONG* pcbResult,
    ULONG dwFlags
);

typedef NTSTATUS(WINAPI* BCryptGenerateSymmetricKey_Type)(
    BCRYPT_ALG_HANDLE hAlgorithm,
    BCRYPT_KEY_HANDLE* phKey,
    PUCHAR pbKeyObject,
    ULONG cbKeyObject,
    PUCHAR pbSecret,
    ULONG cbSecret,
    ULONG dwFlags
);

typedef NTSTATUS(WINAPI* BCryptGenRandom_Type)(
    BCRYPT_ALG_HANDLE hAlgorithm,
    PUCHAR pbBuffer,
    ULONG cbBuffer,
    ULONG dwFlags
);

typedef NTSTATUS(WINAPI* BCryptFinishHash_Type)(
    BCRYPT_HASH_HANDLE hHash,
    PUCHAR pbOutput,
    ULONG cbOutput,
    ULONG dwFlags
);

typedef NTSTATUS(WINAPI* BCryptGetProperty_Type)(
    BCRYPT_HANDLE hObject,
    LPCWSTR pszProperty,
    PUCHAR pbBuffer,
    ULONG cbBuffer,
    ULONG* pcbResult,
    ULONG dwFlags
);

typedef NTSTATUS(WINAPI* BCryptExportKey_Type)(
    BCRYPT_KEY_HANDLE hKey,
    BCRYPT_KEY_HANDLE hExportKey,
    LPCWSTR pszBlobType,
    PUCHAR pbOutput,
    ULONG cbOutput,
    ULONG* pcbResult,
    ULONG dwFlags
);

HMODULE g_hModule = NULL;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        g_hModule = LoadLibrary(L"c:\\windows\\system32\\bcrypt.dll");
        if (g_hModule == NULL) {
            MessageBox(NULL, L"Failed to load bcrypt.dll", L"Error", MB_OK);
            return FALSE;
        }
        break;
    case DLL_PROCESS_DETACH:
        if (g_hModule) FreeLibrary(g_hModule);
        break;
    }

    return TRUE;
}

// Utility function to convert binary data to hexadecimal string
void BinaryToHex(const void* data, size_t size, wchar_t* output, size_t outputSize) {
    const unsigned char* bytes = (const unsigned char*)data;
    for (size_t i = 0; i < size && i < outputSize / 3; i++) {
        swprintf(output + (i * 3), outputSize - (i * 3), L"%02X ", bytes[i]);
    }
}

void LogKeyProperties(BCRYPT_KEY_HANDLE hKey, FILE* logFile) {
    BCryptGetProperty_Type BCryptGetProperty = (BCryptGetProperty_Type)GetProcAddress(g_hModule, "BCryptGetProperty");
    BCryptExportKey_Type BCryptExportKey = (BCryptExportKey_Type)GetProcAddress(g_hModule, "BCryptExportKey");

    NTSTATUS status;
    ULONG cbData;

    // Retrieve the algorithm name
    WCHAR algorithmName[256];
    ULONG cbAlgorithmName = sizeof(algorithmName);

    status = BCryptGetProperty(hKey, BCRYPT_ALGORITHM_NAME, (PUCHAR)algorithmName, cbAlgorithmName * sizeof(WCHAR), &cbData, 0);
    if (status == STATUS_SUCCESS) {
        fwprintf(logFile, L"Algorithm: %s\n", algorithmName);
    }
    else {
        fwprintf(logFile, L"Algorithm: failed to retrieve algorithm name (0x%08X)\n", status);
    }

    // Export the key value
    DWORD keyBlobSize = 0;
    status = BCryptExportKey(hKey, NULL, BCRYPT_KEY_DATA_BLOB, NULL, 0, &keyBlobSize, 0);
    if (status != STATUS_SUCCESS) {
        fwprintf(logFile, L"KEY: failed to determine key blob size (0x%08X)\n", status);
        return;
    }

    PUCHAR keyBlob = (PUCHAR)malloc(keyBlobSize);
    if (!keyBlob) {
        fwprintf(logFile, L"KEY: failed the memory allocation for key blob.\n");
        return;
    }

    status = BCryptExportKey(hKey, NULL, BCRYPT_KEY_DATA_BLOB, keyBlob, keyBlobSize, &keyBlobSize, 0);
    if (status == STATUS_SUCCESS) {
        fwprintf(logFile, L"KEY (%lu bytes): ", keyBlobSize);
        for (ULONG i = sizeof(BCRYPT_KEY_DATA_BLOB_HEADER); i < keyBlobSize; i++) {
            fwprintf(logFile, L"%02X ", keyBlob[i]);
        }
        fwprintf(logFile, L"\n");
    }
    else {
        fwprintf(logFile, L"KEY: failed to export key value (0x%08X)\n", status);
    }

    free(keyBlob);
}

void LogParameters(const wchar_t* functionName,
    BCRYPT_KEY_HANDLE hKey,
    PUCHAR pbInput, ULONG cbInput,
    VOID* pPaddingInfo,
    PUCHAR pbIV, ULONG cbIV,
    PUCHAR pbOutput, ULONG cbOutput,
    ULONG* pcbResult,
    ULONG dwFlags, NTSTATUS status) {

    FILE* logFile;
    _wfopen_s(&logFile, L"C:\\bcryptlogger\\logs.txt", L"a+");
    if (logFile) {
        wchar_t hexInput[512];
        wchar_t hexOutput[512];
        wchar_t hexIV[512];

        BinaryToHex(pbInput, cbInput, hexInput, sizeof(hexInput) / sizeof(hexInput[0]));
        BinaryToHex(pbOutput, cbOutput, hexOutput, sizeof(hexOutput) / sizeof(hexOutput[0]));
        BinaryToHex(pbIV, cbIV, hexIV, sizeof(hexIV) / sizeof(hexIV[0]));

        fwprintf(logFile, L"%s called.\n", functionName);
        fwprintf(logFile, L"Input: %s\n", hexInput);
        fwprintf(logFile, L"Output: %s\n", hexOutput);
        fwprintf(logFile, L"IV: %s\n", hexIV);

        LogKeyProperties(hKey, logFile);

        fwprintf(logFile, L"\n");
        fclose(logFile);
    }
}

NTSTATUS WINAPI ProxyBCryptEncrypt(
    BCRYPT_KEY_HANDLE hKey,
    PUCHAR pbInput,
    ULONG cbInput,
    VOID* pPaddingInfo,
    PUCHAR pbIV,
    ULONG cbIV,
    PUCHAR pbOutput,
    ULONG cbOutput,
    ULONG* pcbResult,
    ULONG dwFlags
) { 
    BCryptEncrypt_Type Original_BCryptEncrypt = (BCryptEncrypt_Type)GetProcAddress(g_hModule, "BCryptEncrypt");
    if (!Original_BCryptEncrypt) {
        MessageBox(NULL, L"Failed to locate BCryptEncrypt", L"Error", MB_OK);
        return STATUS_DLL_NOT_FOUND;
    }

    NTSTATUS status = Original_BCryptEncrypt(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags);
    LogParameters(L"BCryptEncrypt", hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags, status);

    return status;
}

NTSTATUS WINAPI ProxyBCryptGenerateSymmetricKey(
    BCRYPT_ALG_HANDLE hAlgorithm,
    BCRYPT_KEY_HANDLE* phKey,
    PUCHAR pbKeyObject,
    ULONG cbKeyObject,
    PUCHAR pbSecret,
    ULONG cbSecret,
    ULONG dwFlags
) {
    BCryptGenerateSymmetricKey_Type Original_BCryptGenerateSymmetricKey = (BCryptGenerateSymmetricKey_Type)GetProcAddress(g_hModule, "BCryptGenerateSymmetricKey");
    if (!Original_BCryptGenerateSymmetricKey) {
        MessageBox(NULL, L"Failed to locate BCryptGenerateSymmetricKey", L"Error", MB_OK);
        return STATUS_DLL_NOT_FOUND;
    }

    FILE* logFile;
    _wfopen_s(&logFile, L"C:\\bcryptlogger\\logs.txt", L"a+");
    if (logFile) {
        fwprintf(logFile, L"BCryptGenerateSymmetricKey called.\n");
        fwprintf(logFile, L"hAlgorithm: 0x%p\n", hAlgorithm);
        fwprintf(logFile, L"phKey: 0x%p\n", phKey);
        fwprintf(logFile, L"pbKeyObject: ");
        for (ULONG i = 0; i < cbKeyObject; i++) {
            fwprintf(logFile, L"%02X ", pbKeyObject[i]);
        }
        fwprintf(logFile, L"\n");
        fwprintf(logFile, L"pbSecret: ");
        for (ULONG i = 0; i < cbSecret; i++) {
            fwprintf(logFile, L"%02X ", pbSecret[i]);
        }
        fwprintf(logFile, L"\n");
        fwprintf(logFile, L"cbKeyObject: %lu bytes\n", cbKeyObject);
        fwprintf(logFile, L"cbSecret: %lu bytes\n", cbSecret);
        fwprintf(logFile, L"dwFlags: 0x%08X\n", dwFlags);
        fwprintf(logFile, L"\n");
        fclose(logFile);
    }

    return Original_BCryptGenerateSymmetricKey(hAlgorithm, phKey, pbKeyObject, cbKeyObject, pbSecret, cbSecret, dwFlags);
}

NTSTATUS WINAPI ProxyBCryptGenRandom(
    BCRYPT_ALG_HANDLE hAlgorithm,
    PUCHAR pbBuffer,
    ULONG cbBuffer,
    ULONG dwFlags
) {
    BCryptGenRandom_Type Original_BCryptGenRandom = (BCryptGenRandom_Type)GetProcAddress(g_hModule, "BCryptGenRandom");
    if (!Original_BCryptGenRandom) {
        MessageBox(NULL, L"Failed to locate BCryptGenRandom", L"Error", MB_OK);
        return STATUS_DLL_NOT_FOUND;
    }

    NTSTATUS status = Original_BCryptGenRandom(hAlgorithm, pbBuffer, cbBuffer, dwFlags);

    FILE* logFile;
    _wfopen_s(&logFile, L"C:\\bcryptlogger\\logs.txt", L"a+");

    if (logFile) {
        fwprintf(logFile, L"BCryptGenRandom called.\n");
        fwprintf(logFile, L"hAlgorithm: 0x%p\n", hAlgorithm);
        fwprintf(logFile, L"cbBuffer: %lu\n", cbBuffer);
        fwprintf(logFile, L"dwFlags: 0x%08X\n", dwFlags);
        if (status == STATUS_SUCCESS) {
            fwprintf(logFile, L"GENERATED: ");
            for (ULONG i = 0; i < cbBuffer; i++) {
                fwprintf(logFile, L"%02X ", pbBuffer[i]);
            }
            fwprintf(logFile, L"\n");
        }
        else {
            fwprintf(logFile, L"BCryptGenRandom failed with status: 0x%08X\n", status);
        }

        fwprintf(logFile, L"\n");
        fclose(logFile);
    }

    return status;
}

NTSTATUS WINAPI ProxyBCryptFinishHash(
    BCRYPT_HASH_HANDLE hHash,
    PUCHAR pbOutput,
    ULONG cbOutput,
    ULONG dwFlags
) {
    BCryptFinishHash_Type Original_BCryptFinishHash = (BCryptFinishHash_Type)GetProcAddress(g_hModule, "BCryptFinishHash");

    if (!Original_BCryptFinishHash) {
        MessageBox(NULL, L"Failed to locate BCryptFinishHash", L"Error", MB_OK);
        return STATUS_DLL_NOT_FOUND;
    }

    NTSTATUS status = Original_BCryptFinishHash(hHash, pbOutput, cbOutput, dwFlags);

    FILE* logFile;
    _wfopen_s(&logFile, L"C:\\bcryptlogger\\logs.txt", L"a+");
    
    if (logFile) {
        fwprintf(logFile, L"Called BCryptFinishHash.\n");
        fwprintf(logFile, L"hHash: 0x%p\n", hHash);
        fwprintf(logFile, L"cbOutput: %lu\n", cbOutput);
        fwprintf(logFile, L"dwFlags: 0x%08X\n", dwFlags);

        if (status == STATUS_SUCCESS) {
            fwprintf(logFile, L"Hash Output: ");
            for (ULONG i = 0; i < cbOutput; i++) {
                fwprintf(logFile, L"%02X ", pbOutput[i]);
            }
            fwprintf(logFile, L"\n");
        }
        else {
            fwprintf(logFile, L"BCryptFinishHash failed with status: 0x%08X\n", status);
        }

        fwprintf(logFile, L"\n");
        fclose(logFile);
    }

    return status;
}
