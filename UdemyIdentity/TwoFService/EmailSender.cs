using Microsoft.Extensions.Options;
using SendGrid;
using SendGrid.Helpers.Mail;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace UdemyIdentity.TwoFService
{
    public class EmailSender
    {
        // Startup daki serviseki 2 klası çagırıyoruz

        private readonly TwoFactorOptions _twoFactorOptions;
        private readonly TwoFactorService _twoFactorService;

        public EmailSender(IOptions<TwoFactorOptions>options,TwoFactorService twoFactorService)
        {
            _twoFactorOptions = options.Value;
            _twoFactorService = twoFactorService;
        }


        // E Posta Gondereme
        public string Send(string emailAdress)
        {
            // Önce Kod Üretmeliyiz
            string code = _twoFactorService.GetCodeVerification().ToString();
            Execute(emailAdress, code).Wait();
            return code;
        }




        // Entegrasyon Kodu

       private async Task Execute(string email, string code)
        {
            var client = new SendGridClient(_twoFactorOptions.SendGrid_ApiKey);
            var from = new EmailAddress("mr.yazgulyyew@outlook.com");
            var subject = "Kimlik Doğrulama Kodunuz!";
            var to = new EmailAddress(email);
           // var plainTextContent = "and easy to do anywhere, even with C#";
            var htmlContent = $"<h2>Siteye Giriş Yapabilmek için Doğrulama Kodunu Kullanın! </h2> <h3> Kodunuz: {code}</h3>";
            var msg = MailHelper.CreateSingleEmail(from, to, subject, null, htmlContent);
            var response = await client.SendEmailAsync(msg);
        }
    }
}
