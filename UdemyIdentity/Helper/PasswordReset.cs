using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;

namespace UdemyIdentity.Helper
{
    // Şifremi Unuttum Yardımcı Method
    public static class PasswordReset
    {
        public static void PasswordResetSendEmail(string link)
        {
            MailMessage mail = new MailMessage();

            SmtpClient smtpClient = new SmtpClient();

            mail.From = new MailAddress("kivancturkmenn@gmail.com");
            mail.To.Add("mr.yazgulyyew@gmail.com");

            mail.Subject = $"www.bıdıbı.com::Şifre sıfırlama";
            mail.Body = "<h2>Şifrenizi yenilemek için lütfen aşağıdaki linke tıklayınız.</h2><hr/>";
            mail.Body += $"<a href='{link}'>şifre yenileme linki</a>";
            mail.IsBodyHtml = true;
            smtpClient.Port = 587;
            smtpClient.Host = "smtp.gmail.com";
            smtpClient.EnableSsl = true;

            smtpClient.Credentials = new System.Net.NetworkCredential("kivancturkmenn@gmail.com", "Guga100997");

            smtpClient.Send(mail);
            //mail.From = new MailAddress("kivancturkmenn@gmail.com");
            //mail.To.Add("mr.yazgulyyew@gmail.com");

            //mail.Subject = $"www.guga.com: Şifre Sıfırlama";
            //mail.Body = "<h2>Şifrenizi yenilemek için lütfen aşağıdaki linke tıklayınız.</h2><hr/>";
            //mail.Body += $"<a href='{link}'> şifre yenileme linki</a>";
            //mail.IsBodyHtml = true;
            //client.Port = 587;
            //NetworkCredential info = new NetworkCredential("kivancturkmenn@gmail.com", "Guga100997");
            //client.Credentials = info;
            //client.Send(mail);
        }
    }
}
