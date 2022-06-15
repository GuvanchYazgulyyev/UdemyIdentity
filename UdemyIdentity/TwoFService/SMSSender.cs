using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace UdemyIdentity.TwoFService
{
    public class SMSSender
    {
        // Startup daki serviseki 2 klası çagırıyoruz

        // Butası AppJson dan Sms veya e posta almak için kullandıgımız yol
        private readonly TwoFactorOptions _twoFactorOptions;

        // Burası ise Random kod üretmek için kullanılan yol
        private readonly TwoFactorService _twoFactorService;

        public SMSSender(IOptions<TwoFactorOptions> options, TwoFactorService twoFactorService)
        {
            _twoFactorOptions = options.Value;
            _twoFactorService = twoFactorService;
        }

        public string Send(string phone)
        {
            string code = _twoFactorService.GetCodeVerification().ToString();
            // Burada ise hangi sms provider kullanıyorsak onu ekliyecez. SMS Provider Code





            //return code;
            return "5555";
        }
    }
}
