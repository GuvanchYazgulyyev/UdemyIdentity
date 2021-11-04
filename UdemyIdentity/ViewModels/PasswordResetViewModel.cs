using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace UdemyIdentity.ViewModels
{
    // Şifre Sıfırlamak için Kullanılır
    public class PasswordResetViewModel
    {
        [Required(ErrorMessage = "E-Posta Adresi Gereklidir!")]
        [Display(Name = "E-Posta...")]
        [EmailAddress]
        public string Email { get; set; }






        // Yeni şifre için (Şidremi Unuttum)

        [Required(ErrorMessage = "Şifreniz Gereklidir!")]
        [Display(Name = "Yeni Şifre...")]
        [DataType(DataType.Password)]
        [MinLength(4, ErrorMessage = "Şifreniz en az 4 karakter olmalıdır!")]
        public string PasswordNew { get; set; }
    }
}
