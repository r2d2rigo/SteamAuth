using Newtonsoft.Json;
using System;
using System.Collections.Specialized;
using System.Net;
using System.Text;
#if WINRT
using System.Collections.Generic;
using System.Threading.Tasks;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
#else
using System.Security.Cryptography;
#endif

namespace SteamAuth
{
    /// <summary>
    /// Handles logging the user into the mobile Steam website. Necessary to generate OAuth token and session cookies.
    /// </summary>
    public class UserLogin
    {
        public string Username;
        public string Password;
        public ulong SteamID;

        public bool RequiresCaptcha;
        public string CaptchaGID = null;
        public string CaptchaText = null;

        public bool RequiresEmail;
        public string EmailDomain = null;
        public string EmailCode = null;

        public bool Requires2FA;
        public string TwoFactorCode = null;

        public SessionData Session = null;
        public bool LoggedIn = false;

        private CookieContainer _cookies = new CookieContainer();

        public UserLogin(string username, string password)
        {
            this.Username = username;
            this.Password = password;
        }

#if WINRT
        public async Task<LoginResult> DoLoginAsync()
#else
        public LoginResult DoLogin()
#endif
        {
#if WINRT
            var postData = new List<KeyValuePair<string, string>>();
#else
            var postData = new NameValueCollection();
#endif
            var cookies = _cookies;
            string response = null;

            if (cookies.Count == 0)
            {
                //Generate a SessionID
#if WINRT
                cookies.Add(new Uri(APIEndpoints.COMMUNITY_BASE), new Cookie("mobileClientVersion", "0 (2.1.3)", "/", ".steamcommunity.com"));
                cookies.Add(new Uri(APIEndpoints.COMMUNITY_BASE), new Cookie("mobileClient", "android", "/", ".steamcommunity.com"));
                cookies.Add(new Uri(APIEndpoints.COMMUNITY_BASE), new Cookie("Steam_Language", "english", "/", ".steamcommunity.com"));

                List<KeyValuePair<string, string>> headers = new List<KeyValuePair<string, string>>();
                headers.Add(new KeyValuePair<string, string>("X-Requested-With", "com.valvesoftware.android.steam.community"));

                await SteamWeb.MobileLoginRequestAsync("https://steamcommunity.com/login?oauth_client_id=DE45CD61&oauth_scope=read_profile%20write_profile%20read_client%20write_client", "GET", null, cookies, headers);
#else
                cookies.Add(new Cookie("mobileClientVersion", "0 (2.1.3)", "/", ".steamcommunity.com"));
                cookies.Add(new Cookie("mobileClient", "android", "/", ".steamcommunity.com"));
                cookies.Add(new Cookie("Steam_Language", "english", "/", ".steamcommunity.com"));

                NameValueCollection headers = new NameValueCollection();
                headers.Add("X-Requested-With", "com.valvesoftware.android.steam.community");

                SteamWeb.MobileLoginRequest("https://steamcommunity.com/login?oauth_client_id=DE45CD61&oauth_scope=read_profile%20write_profile%20read_client%20write_client", "GET", null, cookies, headers);
#endif
            }

#if WINRT
            postData.Add(new KeyValuePair<string, string>("username", this.Username));

            response = await SteamWeb.MobileLoginRequestAsync(APIEndpoints.COMMUNITY_BASE + "/login/getrsakey", "POST", postData, cookies);
#else
            postData.Add("username", this.Username);

            response = SteamWeb.MobileLoginRequest(APIEndpoints.COMMUNITY_BASE + "/login/getrsakey", "POST", postData, cookies);
#endif

            var rsaResponse = JsonConvert.DeserializeObject<RSAResponse>(response);

            if (!rsaResponse.Success)
            {
                return LoginResult.BadRSA;
            }

#if WINRT
            byte[] encryptedPasswordBytes;

            Org.BouncyCastle.Crypto.Engines.RsaEngine rsaEncryptor = new Org.BouncyCastle.Crypto.Engines.RsaEngine();
            rsaEncryptor.Init(true, new Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters(false,
                new Org.BouncyCastle.Math.BigInteger(Util.HexStringToByteArray(rsaResponse.Modulus)),
                new Org.BouncyCastle.Math.BigInteger(Util.HexStringToByteArray(rsaResponse.Exponent))));

            var passwordBytes = Encoding.UTF8.GetBytes(this.Password);
            encryptedPasswordBytes = rsaEncryptor.ProcessBlock(passwordBytes, 0, passwordBytes.Length);
#else
            RNGCryptoServiceProvider secureRandom = new RNGCryptoServiceProvider();
            byte[] encryptedPasswordBytes;
            using (var rsaEncryptor = new RSACryptoServiceProvider())
            {
                var passwordBytes = Encoding.ASCII.GetBytes(this.Password);
                var rsaParameters = rsaEncryptor.ExportParameters(false);
                rsaParameters.Exponent = Util.HexStringToByteArray(rsaResponse.Exponent);
                rsaParameters.Modulus = Util.HexStringToByteArray(rsaResponse.Modulus);
                rsaEncryptor.ImportParameters(rsaParameters);
                encryptedPasswordBytes = rsaEncryptor.Encrypt(passwordBytes, false);
            }
#endif

            string encryptedPassword = Convert.ToBase64String(encryptedPasswordBytes);

            postData.Clear();

#if WINRT
            postData.Add(new KeyValuePair<string, string>("username", this.Username));
            postData.Add(new KeyValuePair<string, string>("password", encryptedPassword));

            postData.Add(new KeyValuePair<string, string>("twofactorcode", this.Requires2FA ? this.TwoFactorCode : ""));

            postData.Add(new KeyValuePair<string, string>("captchagid", this.RequiresCaptcha ? this.CaptchaGID : "-1"));
            postData.Add(new KeyValuePair<string, string>("captcha_text", this.RequiresCaptcha ? this.CaptchaText : ""));

            postData.Add(new KeyValuePair<string, string>("emailsteamid", this.RequiresEmail ? this.SteamID.ToString() : ""));
            postData.Add(new KeyValuePair<string, string>("emailauth", this.RequiresEmail ? this.EmailCode : ""));

            postData.Add(new KeyValuePair<string, string>("rsatimestamp", rsaResponse.Timestamp));
            postData.Add(new KeyValuePair<string, string>("remember_login", "false"));
            postData.Add(new KeyValuePair<string, string>("oauth_client_id", "DE45CD61"));
            postData.Add(new KeyValuePair<string, string>("oauth_scope", "read_profile write_profile read_client write_client"));
            postData.Add(new KeyValuePair<string, string>("loginfriendlyname", "#login_emailauth_friendlyname_mobile"));

            response = await SteamWeb.MobileLoginRequestAsync(APIEndpoints.COMMUNITY_BASE + "/login/dologin", "POST", postData, cookies);
#else
            postData.Add("username", this.Username);
            postData.Add("password", encryptedPassword);

            postData.Add("twofactorcode", this.Requires2FA ? this.TwoFactorCode : "");

            postData.Add("captchagid", this.RequiresCaptcha ? this.CaptchaGID : "-1");
            postData.Add("captcha_text", this.RequiresCaptcha ? this.CaptchaText : "");

            postData.Add("emailsteamid", this.RequiresEmail ? this.SteamID.ToString() : "");
            postData.Add("emailauth", this.RequiresEmail ? this.EmailCode : "");

            postData.Add("rsatimestamp", rsaResponse.Timestamp);
            postData.Add("remember_login", "false");
            postData.Add("oauth_client_id", "DE45CD61");
            postData.Add("oauth_scope", "read_profile write_profile read_client write_client");
            postData.Add("loginfriendlyname", "#login_emailauth_friendlyname_mobile");

            response = SteamWeb.MobileLoginRequest(APIEndpoints.COMMUNITY_BASE + "/login/dologin", "POST", postData, cookies);
#endif

            var loginResponse = JsonConvert.DeserializeObject<LoginResponse>(response);

            if (loginResponse.CaptchaNeeded)
            {
                this.RequiresCaptcha = true;
                this.CaptchaGID = loginResponse.CaptchaGID;
                return LoginResult.NeedCaptcha;
            }

            if (loginResponse.EmailAuthNeeded)
            {
                this.RequiresEmail = true;
                this.SteamID = loginResponse.EmailSteamID;
                return LoginResult.NeedEmail;
            }

            if (loginResponse.TwoFactorNeeded)
            {
                this.Requires2FA = true;
                return LoginResult.Need2FA;
            }

            if (loginResponse.OAuthData == null || loginResponse.OAuthData.OAuthToken == null || loginResponse.OAuthData.OAuthToken.Length == 0)
            {
                return LoginResult.GeneralFailure;
            }

            if (!loginResponse.LoginComplete)
            {
                return LoginResult.BadCredentials;
            }
            else
            {
                var readableCookies = cookies.GetCookies(new Uri("https://steamcommunity.com"));
                var oAuthData = loginResponse.OAuthData;

                SessionData session = new SessionData();
                session.OAuthToken = oAuthData.OAuthToken;
                session.SteamID = oAuthData.SteamID;
                session.SteamLogin = session.SteamID + "%7C%7C" + oAuthData.SteamLogin;
                session.SteamLoginSecure = session.SteamID + "%7C%7C" + oAuthData.SteamLoginSecure;
                session.WebCookie = oAuthData.Webcookie;
                session.SessionID = readableCookies["sessionid"].Value;
                this.Session = session;
                this.LoggedIn = true;
                return LoginResult.LoginOkay;
            }

            return LoginResult.GeneralFailure;
        }

        private class LoginResponse
        {
            [JsonProperty("login_complete")]
            public bool LoginComplete { get; set; }

            [JsonProperty("oauth")]
            public string OAuthDataString { get; set; }

            public OAuth OAuthData
            {
                get
                {
                    return OAuthDataString != null ? JsonConvert.DeserializeObject<OAuth>(OAuthDataString) : null;
                }
            }

            [JsonProperty("captcha_needed")]
            public bool CaptchaNeeded { get; set; }

            [JsonProperty("captcha_gid")]
            public string CaptchaGID { get; set; }

            [JsonProperty("emailsteamid")]
            public ulong EmailSteamID { get; set; }

            [JsonProperty("emailauth_needed")]
            public bool EmailAuthNeeded { get; set; }

            [JsonProperty("requires_twofactor")]
            public bool TwoFactorNeeded { get; set; }

            internal class OAuth
            {
                [JsonProperty("steamid")]
                public ulong SteamID { get; set; }

                [JsonProperty("oauth_token")]
                public string OAuthToken { get; set; }

                [JsonProperty("wgtoken")]
                public string SteamLogin { get; set; }

                [JsonProperty("wgtoken_secure")]
                public string SteamLoginSecure { get; set; }

                [JsonProperty("webcookie")]
                public string Webcookie { get; set; }
            }
        }

        private class RSAResponse
        {
            [JsonProperty("success")]
            public bool Success { get; set; }

            [JsonProperty("publickey_exp")]
            public string Exponent { get; set; }

            [JsonProperty("publickey_mod")]
            public string Modulus { get; set; }

            [JsonProperty("timestamp")]
            public string Timestamp { get; set; }

            [JsonProperty("steamid")]
            public ulong SteamID { get; set; }
        }
    }

    public enum LoginResult
    {
        LoginOkay,
        GeneralFailure,
        BadRSA,
        BadCredentials,
        NeedCaptcha,
        Need2FA,
        NeedEmail,
    }
}
