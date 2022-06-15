using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace UdemyIdentity.TwoFService
{
    public class TwoFactorService
    {
        private readonly UrlEncoder _urlEncoder;
        private readonly TwoFactorOptions _twoFactorOptions;


        public TwoFactorService(UrlEncoder urlEncoder,IOptions<TwoFactorOptions> options)
        {
            _urlEncoder = urlEncoder;
            _twoFactorOptions = options.Value;
        }

        // Random 4 haneli Kod Üretme E Posta Onay için
        public int GetCodeVerification()
        {
            Random rn = new Random();
            return rn.Next(1000, 9999);
        }

        // Mesajı Ömrü
        public int TimeLeft(HttpContext context)
        {
            if (context.Session.GetString("currentTime")==null)
            {
                context.Session.SetString("currentTime", DateTime.Now.AddSeconds(_twoFactorOptions.CodeTimeExpire).ToString());


            }
            DateTime currentTime = DateTime.Parse(context.Session.GetString("currentTime").ToString());

            // Güncel Zamanda şu anki zamanı çıkartıyorum.
            // işlem double oldugu için int (caste) ediyoruz
            int timeLeft = (int)(currentTime - DateTime.Now).TotalSeconds;


            // Elimde kalan Saniye 0 veya eksi bir deger ise 
            // Session u siliyoruz tekrardan oluşturmamız gerekiyor.
            if (timeLeft<=0)
            {
                context.Session.Remove("currentTime");
                return 0;
            }
            else
            {
                return timeLeft;
            }
        }










        public string GenerateQrCodeUri(string email,string unformattedKey)
        {
            const string format = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";
            return string.Format(format, _urlEncoder.Encode("www.webigem.com"), _urlEncoder.Encode(email), unformattedKey);

        }
    }
}
