using System.Net;
using Newtonsoft.Json;
#if WINRT
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Windows.Web.Http;
#endif

namespace SteamAuth
{
    /// <summary>
    /// Class to help align system time with the Steam server time. Not super advanced; probably not taking some things into account that it should.
    /// Necessary to generate up-to-date codes. In general, this will have an error of less than a second, assuming Steam is operational.
    /// </summary>
    public class TimeAligner
    {
        private static bool _aligned = false;
        private static int _timeDifference = 0;

#if WINRT
        public static async Task<long> GetSteamTimeAsync()
        {
            if (!TimeAligner._aligned)
            {
                await TimeAligner.AlignTimeAsync();
            }
            return Util.GetSystemUnixTime() + _timeDifference;
        }

        public static async Task AlignTimeAsync()
        {
            long currentTime = Util.GetSystemUnixTime();
            using (HttpClient client = new HttpClient())
            {
                try
                {
                    var result = await client.PostAsync(new System.Uri(APIEndpoints.TWO_FACTOR_TIME_QUERY), new HttpFormUrlEncodedContent(new List<KeyValuePair<string, string>>()
                    {
                        new KeyValuePair<string, string>("steamid", "0"),
                    }));

                    var response = await result.Content.ReadAsStringAsync();

                    TimeQuery query = JsonConvert.DeserializeObject<TimeQuery>(response);
                    TimeAligner._timeDifference = (int)(query.Response.ServerTime - currentTime);
                    TimeAligner._aligned = true;
                }
                catch (Exception e)
                {
                    return;
                }
            }
        }
#else
        public static long GetSteamTime()
        {
            if (!TimeAligner._aligned)
            {
                TimeAligner.AlignTime();
            }
            return Util.GetSystemUnixTime() + _timeDifference;
        }

        public static void AlignTime()
        {
            long currentTime = Util.GetSystemUnixTime();
            using (WebClient client = new WebClient())
            {
                try
                {
                    string response = client.UploadString(APIEndpoints.TWO_FACTOR_TIME_QUERY, "steamid=0");
                    TimeQuery query = JsonConvert.DeserializeObject<TimeQuery>(response);
                    TimeAligner._timeDifference = (int)(query.Response.ServerTime - currentTime);
                    TimeAligner._aligned = true;
                }
                catch (WebException e)
                {
                    return;
                }
            }
        }
#endif

        internal class TimeQuery
        {
            [JsonProperty("response")]
            internal TimeQueryResponse Response { get; set; }

            internal class TimeQueryResponse
            {
                [JsonProperty("server_time")]
                public long ServerTime { get; set; }
            }

        }
    }
}
