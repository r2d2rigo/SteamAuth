using System;
using System.Net;

namespace SteamAuth
{
    public class SessionData
    {
        public string SessionID { get; set; }

        public string SteamLogin { get; set; }

        public string SteamLoginSecure { get; set; }

        public string WebCookie { get; set; }

        public string OAuthToken { get; set; }

        public ulong SteamID { get; set; }

        public void AddCookies(CookieContainer cookies)
        {
#if WINRT
            cookies.Add(new Uri(APIEndpoints.COMMUNITY_BASE), new Cookie("mobileClientVersion", "0 (2.1.3)", "/", ".steamcommunity.com"));
            cookies.Add(new Uri(APIEndpoints.COMMUNITY_BASE), new Cookie("mobileClient", "android", "/", ".steamcommunity.com"));

            cookies.Add(new Uri(APIEndpoints.COMMUNITY_BASE), new Cookie("steamid", SteamID.ToString(), "/", ".steamcommunity.com"));
            cookies.Add(new Uri(APIEndpoints.COMMUNITY_BASE), new Cookie("steamLogin", SteamLogin, "/", ".steamcommunity.com")
            {
                HttpOnly = true
            });

            cookies.Add(new Uri(APIEndpoints.COMMUNITY_BASE), new Cookie("steamLoginSecure", SteamLoginSecure, "/", ".steamcommunity.com")
            {
                HttpOnly = true,
                Secure = true
            });
            cookies.Add(new Uri(APIEndpoints.COMMUNITY_BASE), new Cookie("Steam_Language", "english", "/", ".steamcommunity.com"));
            cookies.Add(new Uri(APIEndpoints.COMMUNITY_BASE), new Cookie("dob", "", "/", ".steamcommunity.com"));
#else
            cookies.Add(new Cookie("mobileClientVersion", "0 (2.1.3)", "/", ".steamcommunity.com"));
            cookies.Add(new Cookie("mobileClient", "android", "/", ".steamcommunity.com"));

            cookies.Add(new Cookie("steamid", SteamID.ToString(), "/", ".steamcommunity.com"));
            cookies.Add(new Cookie("steamLogin", SteamLogin, "/", ".steamcommunity.com")
            {
                HttpOnly = true
            });

            cookies.Add(new Cookie("steamLoginSecure", SteamLoginSecure, "/", ".steamcommunity.com")
            {
                HttpOnly = true,
                Secure = true
            });
            cookies.Add(new Cookie("Steam_Language", "english", "/", ".steamcommunity.com"));
            cookies.Add(new Cookie("dob", "", "/", ".steamcommunity.com"));
#endif

        }
    }
}
