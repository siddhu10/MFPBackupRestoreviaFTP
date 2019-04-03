#include "pch.h"
#include "OpenSSLWrapper.h"
#include <openssl/evp.h>
using namespace std;

using namespace OpenSSLWinRTComponent;
using namespace Platform;

static unsigned char cbc_key[16] = { 0x5e,0x71,0xd9,0xb8,0xc2,0xd8,0x37,0xb8,0x2a,0x74,0x62,0x30,0x68,0x24,0x6b,0x32 };

static unsigned char cbc_iv[16] = { 0x43,0xd8,0x73,0xa6,0x78,0xcf,0x5d,0x76,0x75,0xb1,0xc5,0x66,0x39,0x35,0x39,0xd3 };

OpenSSLWrapper::OpenSSLWrapper()
{
}

Platform::String^ OpenSSLWinRTComponent::OpenSSLWrapper::Entry_AES_Encrypt(Platform::String^ strPwd)
{
	Platform::String^ strEncoded = "";
	int nTmplen;
	EVP_CIPHER_CTX ctx;
	int nOutputSize;
	unsigned char iv[16], key[16];
	unsigned char output[512] = { 0 };

	const wchar_t* cWideData = strPwd->Data();
	const unsigned int iLen = strPwd->Length();
	unsigned char * input = new unsigned char[iLen + 1];
	input[iLen] = 0;
	for (int i = 0; i < iLen; i++)
		input[i] = (char)cWideData[i];

	if (NULL == input)
	{
		return strEncoded;
	}

	int iInput_length = 0;
	iInput_length = strlen((const char *)input);

	if (NULL == iInput_length)
	{
		return strEncoded;
	}


	memset(iv, 0, sizeof(iv));
	memset(key, 0, sizeof(key));

	//For Debugging purpose get the key from File and use for encryption
	//bool bRet = FileKeyRead(cbc_debug_key, cbc_debug_iv);
	/*if (TRUE == bRet)
	{
		memcpy(iv, cbc_debug_iv, AES_BLOCK_SIZE);
		memcpy(key, cbc_debug_key, AES_BLOCK_SIZE);
	}
	else*/
	//{
	memcpy(iv, cbc_iv, 16);
	memcpy(key, cbc_key, 16);
	//}

	EVP_CIPHER_CTX_init(&ctx);
	EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv);
	if (!EVP_EncryptUpdate(&ctx, output, &nOutputSize, input, strlen((const char *)input) + 1))
	{
		return strEncoded;
	}
	/* Buffer passed to EVP_EncryptFinal() must be after data just
			* encrypted to avoid overwriting it.
			*/
	if (!EVP_EncryptFinal_ex(&ctx, output + nOutputSize, &nTmplen))
	{
		return strEncoded;
	}
	nOutputSize += nTmplen;
	EVP_CIPHER_CTX_cleanup(&ctx);

	//Copy the output size to the out parameter
	//dInputOutputSize = nOutputSize;

	std::string str;
	str.append(reinterpret_cast<const char*>(output));
	std::wstring widstr = std::wstring(str.begin(), str.end());
	const wchar_t* wData = widstr.c_str();
	strEncoded = ref new String(wData);
	return strEncoded;
}