using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace UdemyIdentity.Enums
{
    public enum TwoFactor
    {
        [Display(Name = "Hiç biri")]
        None = 0,

        [Display(Name = "Telefon ile kimlik dğrulama")]
        Phone = 1,

        [Display(Name = "E Posta ile kimlik dğrulama")]
        Email = 2,

        [Display(Name = "Microsoft/Google ile kimlik dğrulama")]
        MicrosoftGoogle = 3
    }
}
