#pragma once

namespace OpenSSLWinRTComponent
{
    public ref class OpenSSLWrapper sealed
    {
    public:
        OpenSSLWrapper();
		Platform::String^ Entry_AES_Encrypt(Platform::String^ strPwd);
    };
}
