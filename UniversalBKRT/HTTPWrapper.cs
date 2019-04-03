using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Windows.Web.Http;
using Windows.Web.Http.Filters;
using Windows.Security.Cryptography.Certificates;

namespace UniversalBKRT
{
    public class HTTPWrapper
    {
        const string HTTP_PREFIX = "http://";
        const string HTTPS_PREFIX = "https://";
        const string IP_PORT_SEPARATOR = ":";

        private static HttpClient httpClient = new HttpClient();
        private static HttpBaseProtocolFilter filter = new HttpBaseProtocolFilter();
        private static HttpClient httpsClient = null;

        //filter.IgnorableServerCertificateErrors.Add(Windows.Security.Cryptography.Certificates.ChainValidationResult.Expired);
        //filter.IgnorableServerCertificateErrors.Add(Windows.Security.Cryptography.Certificates.ChainValidationResult.Untrusted);
        //filter.IgnorableServerCertificateErrors.Add(Windows.Security.Cryptography.Certificates.ChainValidationResult.InvalidName);

        static HTTPWrapper()
        {
            foreach (ChainValidationResult result in Enum.GetValues(typeof(ChainValidationResult))) {
                if (result != ChainValidationResult.Success) {
                    try {
                        filter.IgnorableServerCertificateErrors.Add(result);
                    }
                    catch (Exception ex) { }
                }
            }

            httpsClient = new HttpClient(filter);
        }

        public async static Task<HttpResponseMessage> GetRequest(EBMFPSession eBMFPSession, string strURL, string strParams)
        {
            HttpResponseMessage responseMessage = null;
            try
            {
                string strHttpPrefix = HTTP_PREFIX;
                if (eBMFPSession.HTTPSSLEnabled == EState.ENABLED)
                    strHttpPrefix = HTTPS_PREFIX;

                string stURL = strHttpPrefix + eBMFPSession.ServerName + IP_PORT_SEPARATOR + eBMFPSession.ServerPort + strURL + strParams;
                Uri reqURI = new Uri(stURL);

                responseMessage = new HttpResponseMessage();

                if (eBMFPSession.HTTPSSLEnabled == EState.ENABLED)
                    responseMessage = await httpsClient.GetAsync(reqURI);
                else
                    responseMessage = await httpClient.GetAsync(reqURI);
                responseMessage.EnsureSuccessStatusCode();
            }
            catch (Exception ex)
            {
                Debug.WriteLine("HTTPWrapper :: GetRequest() :: Exception Handled: " + ex);
            }
            return responseMessage;
        }

        public async static Task<HttpResponseMessage> PostRequest(EBMFPSession eBMFPSession, string strURL, string strParams)
        {
            HttpResponseMessage responseMessage = null;
            try
            {
                string strHttpPrefix = HTTP_PREFIX;
                if (eBMFPSession.HTTPSSLEnabled == EState.ENABLED)
                    strHttpPrefix = HTTPS_PREFIX;

                string stURL = strHttpPrefix + eBMFPSession.ServerName + IP_PORT_SEPARATOR + eBMFPSession.ServerPort + strURL;
                Uri reqURI = new Uri(stURL);

                responseMessage = new HttpResponseMessage();

                if (eBMFPSession.HTTPSSLEnabled == EState.ENABLED)
                    responseMessage = await httpsClient.PostAsync(reqURI, new HttpStringContent(strParams));
                else
                    responseMessage = await httpClient.PostAsync(reqURI, new HttpStringContent(strParams));
                responseMessage.EnsureSuccessStatusCode();
            }
            catch (Exception ex)
            {
                Debug.WriteLine("HTTPWrapper :: PostRequest() :: Exception Handled: " + ex);
            }
            return responseMessage;
        }
    }
}
