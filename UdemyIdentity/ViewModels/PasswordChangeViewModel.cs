using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace UdemyIdentity.ViewModels
{
    // Kullanıcı şifre degiştirme (Member)
    public class PasswordChangeViewModel
    {
        [Display(Name ="Eski Şifrenizi Giriniz!")]
        [Required(ErrorMessage ="Eski Şifreniz Gereklidir!!!")]
        [DataType(DataType.Password)]
        [MinLength(4,ErrorMessage ="Şifreniz En Az 4 Karakter Olmalıdır!!!")]
        public string PasswordOld { get; set; }


        [Display(Name = "Yeni Şifrenizi Giriniz!")]
        [Required(ErrorMessage = "Yeni Şifreniz Gereklidir!!!")]
        [DataType(DataType.Password)]
        [MinLength(4, ErrorMessage = "Şifreniz En Az 4 Karakter Olmalıdır!!!")]
        public string PasswordNew { get; set; }

        [Display(Name = "Onay Şifrenizi Giriniz!")]
        [Required(ErrorMessage = "Onay Şifreniz Gereklidir!!!")]
        [DataType(DataType.Password)]
        [MinLength(4, ErrorMessage = "Şifreniz En Az 4 Karakter Olmalıdır!!!")]
        // Karşilaştırmak için compare kullanmalıdır
        [Compare("PasswordNew",ErrorMessage ="Yeni Şifreniz ve Onay Şifreniz birbirinden farklıdır!!!")]
        public string PasswordConfirm { get; set; }
    }
}
