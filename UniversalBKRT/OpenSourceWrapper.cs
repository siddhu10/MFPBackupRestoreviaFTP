using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Threading.Tasks;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;
using OpenSSLWinRTComponent;

namespace UniversalBKRT
{
    class OpenSourceWrapper
    {
        private static readonly byte[] KEY = { 0x5e, 0x71, 0xd9, 0xb8, 0xc2, 0xd8, 0x37, 0xb8, 0x2a, 0x74, 0x62, 0x30, 0x68, 0x24, 0x6b, 0x32 };
        private static readonly byte[] INIT_VECTOR = { 0x43, 0xd8, 0x73, 0xa6, 0x78, 0xcf, 0x5d, 0x76, 0x75, 0xb1, 0xc5, 0x66, 0x39, 0x35, 0x39, 0xd3 };

        public static string EncryptPassword(string strPassword, EAlgo algoName)
        {
            string strEncPwd = strPassword;
            string strTemp = string.Empty;
            byte[] bTemp = null;

            try
            {
                OpenSSLWrapper openSSLWrapper = new OpenSSLWrapper();

                if (algoName == EAlgo.FromAES)
                {
                    strTemp = openSSLWrapper.Entry_AES_Encrypt(strPassword);

                    byte[] bEnc = Encoding.Unicode.GetBytes(strTemp);
                    strTemp = string.Empty;
                    bTemp = new byte[16];
                    for (int i = 0; i < bEnc.Length; i = i + 2)
                        bTemp[i / 2] = bEnc[i];
                }
                else
                {
                    IBuffer input = CryptographicBuffer.ConvertStringToBinary(strPassword, BinaryStringEncoding.Utf8);
                    HashAlgorithmProvider hashAlg = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha256);
                    IBuffer hashData = hashAlg.HashData(input);
                    bTemp = hashData.ToArray();
                }

                strTemp = Convert.ToBase64String(bTemp);
                strTemp = AddPrefixSuffix(strTemp, algoName);
                strEncPwd = Convert.ToBase64String(Encoding.ASCII.GetBytes(strTemp));
            }
            catch (Exception ex)
            {
                Debug.WriteLine("OpenSourceWrapper :: EncryptPassword() :: Exception Handled: " + ex);
            }
            return strEncPwd;
        }

        public static string AddPrefixSuffix(string strEncContent, EAlgo algoName)
        {
            string strResult = strEncContent;
            try
            {
                string strTemp = string.Empty;
                if (algoName == EAlgo.FromAES)
                    strTemp = "#10#";
                else if (algoName == EAlgo.FromSHA)
                    strTemp = "%3%";

                strResult = strTemp + strEncContent + strTemp;
            }
            catch (Exception ex)
            {
                Debug.WriteLine("OpenSourceWrapper :: AddPrefixSuffix() :: Exception Handled: " + ex);
            }
            return strResult;
        }

        public async static Task<IBuffer> AESEncryptWithPwd(IBuffer iOrigData)
        {
            IBuffer encOutput = null;
            CryptographicKey key = null;
            string strPassword = "EFB@arc_ext#pass";
            try
            {
                SymmetricKeyAlgorithmProvider objAlg = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);

                IBuffer keyMaterial = CryptographicBuffer.ConvertStringToBinary(strPassword, BinaryStringEncoding.Utf8);
                key = objAlg.CreateSymmetricKey(keyMaterial);

                encOutput = CryptographicEngine.Encrypt(key, iOrigData, null);
            }
            catch (Exception ex)
            {
                Debug.WriteLine("OpenSourceWrapper :: AESEncryptWithPwd() :: Exception Handled: " + ex);
            }
            return encOutput;
        }

        //static string PadInput(string strPassword)
        //{
        //    int index = 1;
        //    int iPad = (16 - strPassword.Length);
        //    string strPaddedInput = string.Empty;
        //    //byte[] bConv = new byte[16];

        //    //foreach (char ch in strPassword.ToCharArray())
        //    //{
        //    //    bConv[index++] = (byte)ch;
        //    //}
        //    foreach (char ch in strPassword)
        //    {
        //        strPaddedInput += ((int)ch).ToString("X2");
        //    }

        //    for (index = 1; index <= iPad; index++)
        //    {
        //        strPaddedInput += iPad.ToString("X2");
        //    }
        //    return strPaddedInput;
        //}
    }
}
