using System;
using System.Collections.Specialized;
using System.IO;
using System.Net;
#if WINRT
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
#endif

namespace SteamAuth
{
    public class SteamWeb
    {
#if WINRT
        /// <summary>
        /// Perform a mobile login request
        /// </summary>
        /// <param name="url">API url</param>
        /// <param name="method">GET or POST</param>
        /// <param name="data">Name-data pairs</param>
        /// <param name="cookies">current cookie container</param>
        /// <returns>response body</returns>
        public static Task<string> MobileLoginRequestAsync(string url, string method, List<KeyValuePair<string, string>> data = null, CookieContainer cookies = null, List<KeyValuePair<string, string>> headers = null)
        {
            return RequestAsync(url, method, data, cookies, headers, APIEndpoints.COMMUNITY_BASE + "/mobilelogin?oauth_client_id=DE45CD61&oauth_scope=read_profile%20write_profile%20read_client%20write_client");
        }

        public static async Task<string> RequestAsync(string url, string method, List<KeyValuePair<string, string>> data = null, CookieContainer cookies = null, List<KeyValuePair<string, string>> headers = null, string referer = APIEndpoints.COMMUNITY_BASE)
        {
            string query = data == null
                ? string.Empty
                : string.Join("&", data.Select(d => String.Format("{0}={1}", WebUtility.UrlEncode(d.Key), WebUtility.UrlEncode(d.Value))));
            if (method == "GET")
            {
                url += (url.Contains("?") ? "&" : "?") + query;
            }

            HttpClientHandler clientHandler = new HttpClientHandler();

            if (cookies != null)
            {
                clientHandler.CookieContainer = cookies;
            }

            HttpClient request = new HttpClient(clientHandler);
            request.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("text/javascript"));
            request.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("text/html"));
            request.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/xml"));
            request.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("text/xml"));
            request.DefaultRequestHeaders.UserAgent.Add(new System.Net.Http.Headers.ProductInfoHeaderValue("Mozilla/5.0 (Linux; U; Android 4.1.1; en-us; Google Nexus 4 - 4.1.1 - API 16 - 768x1280 Build/JRO03S) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30"));
            request.DefaultRequestHeaders.Referrer = new Uri(referer);
            // request.Method = method;
            // TODO: compression support
            // request.AutomaticDecompression = DecompressionMethods.Deflate | DecompressionMethods.GZip;

            if (headers != null)
            {
                foreach (var header in headers)
                {
                    // TODO: check for duplicate headers?
                    request.DefaultRequestHeaders.Add(header.Key, header.Value);
                }
            }

            try
            {
                if (method == "POST")
                {
                    var postContent = new FormUrlEncodedContent(data);
                    var result = await request.PostAsync(url, postContent);

                    return await result.Content.ReadAsStringAsync();
                }
                else
                {
                    var result = await request.GetAsync(url);

                    return await result.Content.ReadAsStringAsync();
                }
            }
            catch (Exception ex)
            {
                throw;
            }
        }
#else
        /// <summary>
        /// Perform a mobile login request
        /// </summary>
        /// <param name="url">API url</param>
        /// <param name="method">GET or POST</param>
        /// <param name="data">Name-data pairs</param>
        /// <param name="cookies">current cookie container</param>
        /// <returns>response body</returns>
        public static string MobileLoginRequest(string url, string method, NameValueCollection data = null, CookieContainer cookies = null, NameValueCollection headers = null)
        {
            return Request(url, method, data, cookies, headers, APIEndpoints.COMMUNITY_BASE + "/mobilelogin?oauth_client_id=DE45CD61&oauth_scope=read_profile%20write_profile%20read_client%20write_client");
        }

        public static string Request(string url, string method, NameValueCollection data = null, CookieContainer cookies = null, NameValueCollection headers = null, string referer = APIEndpoints.COMMUNITY_BASE)
        {
            string query = (data == null ? string.Empty : string.Join("&", Array.ConvertAll(data.AllKeys, key => String.Format("{0}={1}", WebUtility.UrlEncode(key), WebUtility.UrlEncode(data[key])))));
            if (method == "GET")
            {
                url += (url.Contains("?") ? "&" : "?") + query;
            }

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = method;
            request.Accept = "text/javascript, text/html, application/xml, text/xml, */*";
            request.UserAgent = "Mozilla/5.0 (Linux; U; Android 4.1.1; en-us; Google Nexus 4 - 4.1.1 - API 16 - 768x1280 Build/JRO03S) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30";
            request.AutomaticDecompression = DecompressionMethods.Deflate | DecompressionMethods.GZip;
            request.Referer = referer;

            if (headers != null)
            {
                request.Headers.Add(headers);
            }

            if (cookies != null)
            {
                request.CookieContainer = cookies;
            }

            if (method == "POST")
            {
                request.ContentType = "application/x-www-form-urlencoded; charset=UTF-8";
                request.ContentLength = query.Length;

                StreamWriter requestStream = new StreamWriter(request.GetRequestStream());
                requestStream.Write(query);
                requestStream.Close();
            }

            try
            {
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    if (response.StatusCode != HttpStatusCode.OK)
                    {
                        return null;
                    }

                    using (StreamReader responseStream = new StreamReader(response.GetResponseStream()))
                    {
                        string responseData = responseStream.ReadToEnd();

                        return responseData;
                    }
                }
            }
            catch (Exception ex)
            {
                throw;
            }
        }
#endif
    }
}
