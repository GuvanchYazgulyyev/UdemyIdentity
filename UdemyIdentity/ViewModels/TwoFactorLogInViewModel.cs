using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using UdemyIdentity.Enums;

namespace UdemyIdentity.ViewModels
{
    public class TwoFactorLogInViewModel
    {
        [Display(Name ="Doğrulama Kodunuz!")]
        [Required(ErrorMessage ="Doğrulama Kodunuz Eksiksiz Giriniz!")]
        [StringLength(8,ErrorMessage ="Kodunuz En Az 8 Haneli Olmalıdır!")]

        public string VerificationCode { get; set; }

        public bool isRememberMe { get; set; }
        public bool isRecoverCode { get; set; }

        public TwoFactor TwoFactorType { get; set; }
    }
}
