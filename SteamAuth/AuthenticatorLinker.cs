using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
#if WINRT
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using System.Runtime.InteropServices.WindowsRuntime;
#else
using System.Security.Cryptography;
#endif

namespace SteamAuth
{
    /// <summary>
    /// Handles the linking process for a new mobile authenticator.
    /// </summary>
    public class AuthenticatorLinker
    {


        /// <summary>
        /// Set to register a new phone number when linking. If a phone number is not set on the account, this must be set. If a phone number is set on the account, this must be null.
        /// </summary>
        public string PhoneNumber = null;

        /// <summary>
        /// Randomly-generated device ID. Should only be generated once per linker.
        /// </summary>
        public string DeviceID { get; private set; }

        /// <summary>
        /// After the initial link step, if successful, this will be the SteamGuard data for the account. PLEASE save this somewhere after generating it; it's vital data.
        /// </summary>
        public SteamGuardAccount LinkedAccount { get; private set; }

        /// <summary>
        /// True if the authenticator has been fully finalized.
        /// </summary>
        public bool Finalized = false;

        private SessionData _session;
        private CookieContainer _cookies;

        public AuthenticatorLinker(SessionData session)
        {
            this._session = session;
            this.DeviceID = _generateDeviceID();

            this._cookies = new CookieContainer();
#if WINRT
            _cookies.Add(new Uri(APIEndpoints.COMMUNITY_BASE), new Cookie("mobileClientVersion", "0 (2.1.3)", "/", ".steamcommunity.com"));
            _cookies.Add(new Uri(APIEndpoints.COMMUNITY_BASE), new Cookie("mobileClient", "android", "/", ".steamcommunity.com"));

            _cookies.Add(new Uri(APIEndpoints.COMMUNITY_BASE), new Cookie("steamid", session.SteamID.ToString(), "/", ".steamcommunity.com"));
            _cookies.Add(new Uri(APIEndpoints.COMMUNITY_BASE), new Cookie("steamLogin", session.SteamLogin, "/", ".steamcommunity.com")
            {
                HttpOnly = true
            });

            _cookies.Add(new Uri(APIEndpoints.COMMUNITY_BASE), new Cookie("steamLoginSecure", session.SteamLoginSecure, "/", ".steamcommunity.com")
            {
                HttpOnly = true,
                Secure = true
            });
            _cookies.Add(new Uri(APIEndpoints.COMMUNITY_BASE), new Cookie("Steam_Language", "english", "/", ".steamcommunity.com"));
            _cookies.Add(new Uri(APIEndpoints.COMMUNITY_BASE), new Cookie("dob", "", "/", ".steamcommunity.com"));
#else
            _cookies.Add(new Cookie("mobileClientVersion", "0 (2.1.3)", "/", ".steamcommunity.com"));
            _cookies.Add(new Cookie("mobileClient", "android", "/", ".steamcommunity.com"));

            _cookies.Add(new Cookie("steamid", session.SteamID.ToString(), "/", ".steamcommunity.com"));
            _cookies.Add(new Cookie("steamLogin", session.SteamLogin, "/", ".steamcommunity.com")
            {
                HttpOnly = true
            });

            _cookies.Add(new Cookie("steamLoginSecure", session.SteamLoginSecure, "/", ".steamcommunity.com")
            {
                HttpOnly = true,
                Secure = true
            });
            _cookies.Add(new Cookie("Steam_Language", "english", "/", ".steamcommunity.com"));
            _cookies.Add(new Cookie("dob", "", "/", ".steamcommunity.com"));
#endif
        }

#if WINRT
        public async Task<LinkResult> AddAuthenticatorAsync()
#else
        public LinkResult AddAuthenticator()
#endif
        {
#if WINRT
            bool hasPhone = await _hasPhoneAttachedAsync();
#else
            bool hasPhone = _hasPhoneAttached();
#endif
            if (hasPhone && PhoneNumber != null)
                return LinkResult.MustRemovePhoneNumber;
            if (!hasPhone && PhoneNumber == null)
                return LinkResult.MustProvidePhoneNumber;

            if (!hasPhone)
            {
#if WINRT
                if (!await _addPhoneNumberAsync())
#else
                if (!_addPhoneNumber())
#endif
                {
                    return LinkResult.GeneralFailure;
                }
            }

#if WINRT
            var postData = new List<KeyValuePair<string, string>>();
            postData.Add(new KeyValuePair<string, string>("access_token", _session.OAuthToken));
            postData.Add(new KeyValuePair<string, string>("steamid", _session.SteamID.ToString()));
            postData.Add(new KeyValuePair<string, string>("authenticator_type", "1"));
            postData.Add(new KeyValuePair<string, string>("device_identifier", this.DeviceID));
            postData.Add(new KeyValuePair<string, string>("sms_phone_id", "1"));

            string response = await SteamWeb.MobileLoginRequestAsync(APIEndpoints.STEAMAPI_BASE + "/ITwoFactorService/AddAuthenticator/v0001", "POST", postData);
#else
            var postData = new NameValueCollection();
            postData.Add("access_token", _session.OAuthToken);
            postData.Add("steamid", _session.SteamID.ToString());
            postData.Add("authenticator_type", "1");
            postData.Add("device_identifier", this.DeviceID);
            postData.Add("sms_phone_id", "1");

            string response = SteamWeb.MobileLoginRequest(APIEndpoints.STEAMAPI_BASE + "/ITwoFactorService/AddAuthenticator/v0001", "POST", postData);
#endif
            var addAuthenticatorResponse = JsonConvert.DeserializeObject<AddAuthenticatorResponse>(response);
            if (addAuthenticatorResponse == null || addAuthenticatorResponse.Response == null || addAuthenticatorResponse.Response.Status != 1)
            {
                return LinkResult.GeneralFailure;
            }

            this.LinkedAccount = addAuthenticatorResponse.Response;
            LinkedAccount.Session = this._session;
            LinkedAccount.DeviceID = this.DeviceID;

            return LinkResult.AwaitingFinalization;
        }

#if WINRT
        public async Task<FinalizeResult> FinalizeAddAuthenticatorAsync(string smsCode)
#else
        public FinalizeResult FinalizeAddAuthenticator(string smsCode)
#endif
        {
            bool smsCodeGood = false;

#if WINRT
            var postData = new List<KeyValuePair<string, string>>();
            postData.Add(new KeyValuePair<string, string>("steamid", _session.SteamID.ToString()));
            postData.Add(new KeyValuePair<string, string>("access_token", _session.OAuthToken));
#else
            var postData = new NameValueCollection();
            postData.Add("steamid", _session.SteamID.ToString());
            postData.Add("access_token", _session.OAuthToken);
            postData.Add("activation_code", smsCode);
            postData.Add("authenticator_code", "");
#endif
            int tries = 0;
            while (tries <= 30)
            {
#if WINRT
                var postData2 = new List<KeyValuePair<string, string>>(postData);
                postData.Add(new KeyValuePair<string, string>("authenticator_code", tries == 0 ? "" : await LinkedAccount.GenerateSteamGuardCodeAsync()));
                postData.Add(new KeyValuePair<string, string>("authenticator_time", TimeAligner.GetSteamTimeAsync().ToString()));

                if (smsCodeGood)
                {
                    postData.Add(new KeyValuePair<string, string>("activation_code", ""));
                }
                else
                {
                    postData.Add(new KeyValuePair<string, string>("activation_code", smsCode));
                }

                string response = await SteamWeb.MobileLoginRequestAsync(APIEndpoints.STEAMAPI_BASE + "/ITwoFactorService/FinalizeAddAuthenticator/v0001", "POST", postData);
#else
                postData.Set("authenticator_code", tries == 0 ? "" : LinkedAccount.GenerateSteamGuardCode());
                postData.Add("authenticator_time", TimeAligner.GetSteamTime().ToString());

                if(smsCodeGood)
                    postData.Set("activation_code", "");

                string response = SteamWeb.MobileLoginRequest(APIEndpoints.STEAMAPI_BASE + "/ITwoFactorService/FinalizeAddAuthenticator/v0001", "POST", postData);
#endif
                var finalizeResponse = JsonConvert.DeserializeObject<FinalizeAuthenticatorResponse>(response);

                if (finalizeResponse == null || finalizeResponse.Response == null)
                {
                    return FinalizeResult.GeneralFailure;
                }

                if (finalizeResponse.Response.Status == 89)
                {
                    return FinalizeResult.BadSMSCode;
                }

                if (finalizeResponse.Response.Status == 88)
                {
                    if (tries >= 30)
                    {
                        return FinalizeResult.UnableToGenerateCorrectCodes;
                    }
                }

                if (!finalizeResponse.Response.Success)
                {
                    return FinalizeResult.GeneralFailure;
                }

                if (finalizeResponse.Response.WantMore)
                {
                    smsCodeGood = true;
                    tries++;
                    continue;
                }

                return FinalizeResult.Success;
            }

            return FinalizeResult.GeneralFailure;
        }

#if WINRT
        private async Task<bool> _addPhoneNumberAsync()
#else
        private bool _addPhoneNumber()
#endif
        {
#if WINRT
            string response = await SteamWeb.RequestAsync(APIEndpoints.COMMUNITY_BASE + "/steamguard/phoneajax?op=add_phone_number&arg=" + WebUtility.UrlEncode(PhoneNumber), "GET", null, _cookies);
#else
            string response = SteamWeb.Request(APIEndpoints.COMMUNITY_BASE + "/steamguard/phoneajax?op=add_phone_number&arg=" + WebUtility.UrlEncode(PhoneNumber), "GET", null, _cookies);
#endif
            var addPhoneNumberResponse = JsonConvert.DeserializeObject<AddPhoneResponse>(response);
            return addPhoneNumberResponse.Success;
        }

#if WINRT
        private async Task<bool> _hasPhoneAttachedAsync()
#else
        private bool _hasPhoneAttached()
#endif
        {
#if WINRT
            var postData = new List<KeyValuePair<string, string>>();
            postData.Add(new KeyValuePair<string, string>("op", "has_phone"));
            postData.Add(new KeyValuePair<string, string>("arg", "null"));
            string response = await SteamWeb.MobileLoginRequestAsync(APIEndpoints.COMMUNITY_BASE + "/steamguard/phoneajax", "GET", postData, _cookies);
#else
            var postData = new NameValueCollection();
            postData.Add("op", "has_phone");
            postData.Add("arg", "null");
            string response = SteamWeb.MobileLoginRequest(APIEndpoints.COMMUNITY_BASE + "/steamguard/phoneajax", "GET", postData, _cookies);
#endif
            var hasPhoneResponse = JsonConvert.DeserializeObject<HasPhoneResponse>(response);
            return hasPhoneResponse.HasPhone;
        }

        public enum LinkResult
        {
            MustProvidePhoneNumber, //No phone number on the account
            MustRemovePhoneNumber, //A phone number is already on the account
            AwaitingFinalization, //Must provide an SMS code
            GeneralFailure //General failure (really now!)
        }

        public enum FinalizeResult
        {
            BadSMSCode,
            UnableToGenerateCorrectCodes,
            Success,
            GeneralFailure
        }

        private class AddAuthenticatorResponse
        {
            [JsonProperty("response")]
            public SteamGuardAccount Response { get; set; }
        }

        private class FinalizeAuthenticatorResponse
        {
            [JsonProperty("response")]
            public FinalizeAuthenticatorInternalResponse Response { get; set; }

            internal class FinalizeAuthenticatorInternalResponse
            {
                [JsonProperty("status")]
                public int Status { get; set; }

                [JsonProperty("server_time")]
                public long ServerTime { get; set; }

                [JsonProperty("want_more")]
                public bool WantMore { get; set; }

                [JsonProperty("success")]
                public bool Success { get; set; }
            }
        }

        private class HasPhoneResponse
        {
            [JsonProperty("has_phone")]
            public bool HasPhone { get; set; }
        }

        private class AddPhoneResponse
        {
            [JsonProperty("success")]
            public bool Success { get; set; }
        }

        private string _generateDeviceID()
        {
#if WINRT
            var sha1 = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha1);
            var randomBuffer= CryptographicBuffer.GenerateRandom(8);
            var hashedBuffer = sha1.HashData(randomBuffer);

            byte[] hashedBytes = hashedBuffer.ToArray();
            return "android:" + BitConverter.ToString(hashedBytes).Replace("-", "");
#else
            using (var sha1 = new SHA1Managed())
            {
                RNGCryptoServiceProvider secureRandom = new RNGCryptoServiceProvider();
                byte[] randomBytes = new byte[8];
                secureRandom.GetBytes(randomBytes);

                byte[] hashedBytes = sha1.ComputeHash(randomBytes);
                return "android:" + BitConverter.ToString(hashedBytes).Replace("-", "");
            }
#endif
        }
    }
}
