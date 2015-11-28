using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SteamAuth
{
    public class Confirmation
    {
        public string ConfirmationID
        {
            get;
            private set;
        }

        public string ConfirmationKey
        {
            get;
            private set;
        }

        public string ConfirmationDescription
        {
            get;
            private set;
        }

        public Confirmation(string id, string key, string description)
        {
            ConfirmationID = id;
            ConfirmationKey = key;
            ConfirmationDescription = description;
        }
    }
}
