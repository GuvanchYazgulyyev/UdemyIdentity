using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace UdemyIdentity.ViewModels
{
    // Giriş yapmak için kullanılır

    public class LoginViewModel
    {

        [Required(ErrorMessage = "E-Posta Adresi Gereklidir!")]
        [Display(Name = "E-Posta...")]
        [EmailAddress]
        public string Email { get; set; }

        [Required(ErrorMessage = "Şifreniz Gereklidir!")]
        [Display(Name = "Şifre...")]
        [DataType(DataType.Password)]
        [MinLength(4,ErrorMessage ="Şifreniz en az 4 karakter olmalıdır!")]
        public string Password { get; set; }

        // beni hatırla 

        public bool RememberMe { get; set; }
    }
}
