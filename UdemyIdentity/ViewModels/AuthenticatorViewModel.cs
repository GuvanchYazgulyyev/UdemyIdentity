using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using UdemyIdentity.Enums;

namespace UdemyIdentity.ViewModels
{
    public class AuthenticatorViewModel
    {
        public string SharedKey { get; set; }
        public string AuthenticatorUri { get; set; }

        [Display(Name ="Doğrulama Kodunuz")]
        [Required(ErrorMessage ="Doğrulama Kodu Zorunludur!")]
        public string VerificationCode { get; set; }

        [Display(Name = "Kimlik Doğrulama Tipi")]
        public TwoFactor TwoFactorType { get; set; }
    }
}
