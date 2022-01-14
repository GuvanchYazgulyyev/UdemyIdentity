using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace UdemyIdentity.TwoFService
{

    // appsettings.json Kısmında E Posta Onaylama Kısmı

    public class TwoFactorOptions
    {
        public string SendGrid_ApiKey { get; set; }
        public int CodeTimeExpire { get; set; }
    }
}
