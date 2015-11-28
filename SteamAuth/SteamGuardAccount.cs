using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
#if WINRT
using System.Threading.Tasks;
using Windows.Security.Cryptography.Core;
using System.Runtime.InteropServices.WindowsRuntime;
#else
using System.Security.Cryptography;
using System.Collections.Specialized;
#endif

namespace SteamAuth
{
    public class SteamGuardAccount
    {
        [JsonProperty("shared_secret")]
        public string SharedSecret { get; set; }

        [JsonProperty("serial_number")]
        public string SerialNumber { get; set; }

        [JsonProperty("revocation_code")]
        public string RevocationCode { get; set; }

        [JsonProperty("uri")]
        public string URI { get; set; }

        [JsonProperty("server_time")]
        public long ServerTime { get; set; }

        [JsonProperty("account_name")]
        public string AccountName { get; set; }

        [JsonProperty("token_gid")]
        public string TokenGID { get; set; }

        [JsonProperty("identity_secret")]
        public string IdentitySecret { get; set; }

        [JsonProperty("secret_1")]
        public string Secret1 { get; set; }

        [JsonProperty("status")]
        public int Status { get; set; }

        [JsonProperty("device_id")]
        public string DeviceID { get; set; }

        /// <summary>
        /// Set to true if the authenticator has actually been applied to the account.
        /// </summary>
        [JsonProperty("fully_enrolled")]
        public bool FullyEnrolled { get; set; }

        public SessionData Session { get; set; }

        private static byte[] steamGuardCodeTranslations = new byte[] { 50, 51, 52, 53, 54, 55, 56, 57, 66, 67, 68, 70, 71, 72, 74, 75, 77, 78, 80, 81, 82, 84, 86, 87, 88, 89 };

#if WINRT
        public async Task<bool> DeactivateAuthenticatorAsync()
#else
        public bool DeactivateAuthenticator()
#endif
        {
#if WINRT
            var postData = new List<KeyValuePair<string, string>>();
            postData.Add(new KeyValuePair<string, string>("steamid", this.Session.SteamID.ToString()));
            postData.Add(new KeyValuePair<string, string>("steamguard_scheme", "2"));
            postData.Add(new KeyValuePair<string, string>("revocation_code", this.RevocationCode));
            postData.Add(new KeyValuePair<string, string>("access_token", this.Session.OAuthToken));

            try
            {
                string response = await SteamWeb.MobileLoginRequestAsync(APIEndpoints.STEAMAPI_BASE + "/ITwoFactorService/RemoveAuthenticator/v0001", "POST", postData);
                var removeResponse = JsonConvert.DeserializeObject<RemoveAuthenticatorResponse>(response);

                if (removeResponse == null || removeResponse.Response == null || !removeResponse.Response.Success) return false;
                return true;
            }
            catch (Exception e)
            {
                return false;
            }
#else
            var postData = new NameValueCollection();
            postData.Add("steamid", this.Session.SteamID.ToString());
            postData.Add("steamguard_scheme", "2");
            postData.Add("revocation_code", this.RevocationCode);
            postData.Add("access_token", this.Session.OAuthToken);

            try
            {
                string response = SteamWeb.MobileLoginRequest(APIEndpoints.STEAMAPI_BASE + "/ITwoFactorService/RemoveAuthenticator/v0001", "POST", postData);
                var removeResponse = JsonConvert.DeserializeObject<RemoveAuthenticatorResponse>(response);

                if (removeResponse == null || removeResponse.Response == null || !removeResponse.Response.Success) return false;
                return true;
            }
            catch (Exception e)
            {
                return false;
            }
#endif
        }

#if WINRT
        public async Task<string> GenerateSteamGuardCodeAsync()
#else
        public string GenerateSteamGuardCode()
#endif
        {
#if WINRT
            return GenerateSteamGuardCodeForTime(await TimeAligner.GetSteamTimeAsync());
#else
            return GenerateSteamGuardCodeForTime(TimeAligner.GetSteamTime());
#endif
        }

        public string GenerateSteamGuardCodeForTime(long time)
        {
            if (this.SharedSecret == null || this.SharedSecret.Length == 0)
            {
                return "";
            }

            byte[] sharedSecretArray = Convert.FromBase64String(this.SharedSecret);
            byte[] timeArray = new byte[8];

            time /= 30L;

            for (int i = 8; i > 0; i--)
            {
                timeArray[i - 1] = (byte)time;
                time >>= 8;
            }

#if WINRT
            MacAlgorithmProvider provider = MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.HmacSha1);
            var keyBuffer = sharedSecretArray.AsBuffer();
            provider.CreateKey(keyBuffer);
            var timeBuffer = timeArray.AsBuffer();
            var hash = provider.CreateHash(timeBuffer);
            var hashBuffer = hash.GetValueAndReset();
            byte[] hashedData = hashBuffer.ToArray();
#else
            HMACSHA1 hmacGenerator = new HMACSHA1();
            hmacGenerator.Key = sharedSecretArray;
            byte[] hashedData = hmacGenerator.ComputeHash(timeArray);
#endif
            byte[] codeArray = new byte[5];
            try
            {
                byte b = (byte)(hashedData[19] & 0xF);
                int codePoint = (hashedData[b] & 0x7F) << 24 | (hashedData[b + 1] & 0xFF) << 16 | (hashedData[b + 2] & 0xFF) << 8 | (hashedData[b + 3] & 0xFF);

                for (int i = 0; i < 5; ++i)
                {
                    codeArray[i] = steamGuardCodeTranslations[codePoint % steamGuardCodeTranslations.Length];
                    codePoint /= steamGuardCodeTranslations.Length;
                }
            }
            catch (Exception e)
            {
                return null; //Change later, catch-alls are bad!
            }

#if WINRT
            return Encoding.UTF8.GetString(codeArray, 0, codeArray.Length);
#else
            return Encoding.UTF8.GetString(codeArray);
#endif
        }

#if WINRT
        public async Task<List<Confirmation>> FetchConfirmationsAsync()
#else
        public List<Confirmation> FetchConfirmations()
#endif
        {
#if WINRT
            string url = await this._generateConfirmationURLAsync();
#else
            string url = this._generateConfirmationURL();
#endif

            CookieContainer cookies = new CookieContainer();
            this.Session.AddCookies(cookies);

#if WINRT
            string response = await SteamWeb.RequestAsync(url, "GET", null, cookies);
#else
            string response = SteamWeb.Request(url, "GET", null, cookies);
#endif

            /*So you're going to see this abomination and you're going to be upset.
              It's understandable. But the thing is, regex for HTML -- while awful -- makes this way faster than parsing a DOM, plus we don't need another library.
              And because the data is always in the same place and same format... It's not as if we're trying to naturally understand HTML here. Just extract strings.
              I'm sorry. */

            Regex confIDRegex = new Regex("data-confid=\"(\\d+)\"");
            Regex confKeyRegex = new Regex("data-key=\"(\\d+)\"");
            Regex confDescRegex = new Regex("<div>((Confirm|Trade with) .+)</div>");

            if (!(confIDRegex.IsMatch(response) && confKeyRegex.IsMatch(response) && confDescRegex.IsMatch(response)))
            {
                return new List<Confirmation>();
            }

            MatchCollection confIDs = confIDRegex.Matches(response);
            MatchCollection confKeys = confKeyRegex.Matches(response);
            MatchCollection confDescs = confDescRegex.Matches(response);

            List<Confirmation> ret = new List<Confirmation>();
            for (int i = 0; i < confIDs.Count; i++)
            {
                string confID = confIDs[i].Groups[1].Value;
                string confKey = confKeys[i].Groups[1].Value;
                string confDesc = confDescs[i].Groups[1].Value;
                Confirmation conf = new Confirmation(confID, confKey, confDesc);
                ret.Add(conf);
            }

            return ret;
        }

#if WINRT
        public Task<bool> AcceptConfirmationAsync(Confirmation conf)
        {
            return _sendConfirmationAjaxAsync(conf, "allow");
        }
#else
        public bool AcceptConfirmation(Confirmation conf)
        {
            return _sendConfirmationAjax(conf, "allow");
        }
#endif

#if WINRT
        public Task<bool> DenyConfirmationAsync(Confirmation conf)
        {
            return _sendConfirmationAjaxAsync(conf, "cancel");
        }
#else
        public bool DenyConfirmation(Confirmation conf)
        {
            return _sendConfirmationAjax(conf, "cancel");
        }
#endif

#if WINRT
        private async Task<bool> _sendConfirmationAjaxAsync(Confirmation conf, string op)
#else
        private bool _sendConfirmationAjax(Confirmation conf, string op)
#endif
        {
            string url = APIEndpoints.COMMUNITY_BASE + "/mobileconf/ajaxop";
            string queryString = "?op=" + op + "&";
#if WINRT
            queryString += await _generateConfirmationQueryParamsAsync(op);
#else
            queryString += _generateConfirmationQueryParams(op);
#endif
            queryString += "&cid=" + conf.ConfirmationID + "&ck=" + conf.ConfirmationKey;
            url += queryString;

            CookieContainer cookies = new CookieContainer();
            this.Session.AddCookies(cookies);
#if WINRT
            string referer = await _generateConfirmationURLAsync();
#else
            string referer = _generateConfirmationURL();
#endif

#if WINRT
            string response = await SteamWeb.RequestAsync(url + queryString, "GET", null, cookies, null);
#else
            string response = SteamWeb.Request(url + queryString, "GET", null, cookies, null);
#endif
            if (response == null) return false;

            SendConfirmationResponse confResponse = JsonConvert.DeserializeObject<SendConfirmationResponse>(response);
            return confResponse.Success;
        }

#if WINRT
        private async Task<string> _generateConfirmationURLAsync(string tag = "conf")
#else
        private string _generateConfirmationURL(string tag = "conf")
#endif
        {
            string endpoint = APIEndpoints.COMMUNITY_BASE + "/mobileconf/conf?";
#if WINRT
            string queryString = await _generateConfirmationQueryParamsAsync(tag);
#else
            string queryString = _generateConfirmationQueryParams(tag);
#endif
            return endpoint + queryString;
        }

#if WINRT
        private async Task<string> _generateConfirmationQueryParamsAsync(string tag)
#else
        private string _generateConfirmationQueryParams(string tag)
#endif
        {
#if WINRT
            long time = await TimeAligner.GetSteamTimeAsync();
#else
            long time = TimeAligner.GetSteamTime();
#endif
            return "p=" + this.DeviceID + "&a=" + this.Session.SteamID.ToString() + "&k=" + _generateConfirmationHashForTime(time, tag) + "&t=" + time + "&m=android&tag=" + tag;
        }

        private string _generateConfirmationHashForTime(long time, string tag) {
            byte[] decode = Convert.FromBase64String(this.IdentitySecret);
            int n2 = 8;
            if (tag != null)
            {
                if (tag.Length > 32)
                {
                    n2 = 8 + 32;
                }
                else
                {
                    n2 = 8 + tag.Length;
                }
            }
            byte[] array = new byte[n2];
            int n3 = 8;
            while (true)
            {
                int n4 = n3 - 1;
                if (n3 <= 0)
                {
                    break;
                }
                array[n4] = (byte)time;
                time >>= 8;
                n3 = n4;
            }
            if (tag != null)
            {
                Array.Copy(Encoding.UTF8.GetBytes(tag), 0, array, 8, n2 - 8);
            }

            try
            {
#if WINRT
                MacAlgorithmProvider provider = MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.HmacSha1);
                var keyBuffer = decode.AsBuffer();
                provider.CreateKey(keyBuffer);
                var timeBuffer = array.AsBuffer();
                var timeHash = provider.CreateHash(timeBuffer);
                var hashBuffer = timeHash.GetValueAndReset();
                byte[] hashedData = hashBuffer.ToArray();
                string encodedData = Convert.ToBase64String(hashedData);
#else
                HMACSHA1 hmacGenerator = new HMACSHA1();
                hmacGenerator.Key = decode;
                byte[] hashedData = hmacGenerator.ComputeHash(array);
                string encodedData = Convert.ToBase64String(hashedData, Base64FormattingOptions.None);
#endif
                string hash = WebUtility.UrlEncode(encodedData);
                return hash;
            }
            catch (Exception e)
            {
                return null; //Fix soon: catch-all is BAD!
            }
        }

        private class RemoveAuthenticatorResponse
        {
            [JsonProperty("response")]
            public RemoveAuthenticatorInternalResponse Response { get; set; }

            internal class RemoveAuthenticatorInternalResponse
            {
                [JsonProperty("success")]
                public bool Success { get; set; }
            }
        }

        private class SendConfirmationResponse
        {
            [JsonProperty("success")]
            public bool Success { get; set; }
        }
    }
}
