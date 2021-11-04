using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using UdemyIdentity.Enums;

namespace UdemyIdentity.ViewModels
{

    // Burası Kullanıcının Kayıt olma işlemini gerçekleştirecek
    public class UserViewModel
    {
        [Required(ErrorMessage ="Kullanıcı İsimi Gereklidir!")]
        [Display(Name ="Kullanıcı Adı...")]
        public string UserName { get; set; }

        [Display(Name = "Telefon No...")]
        public string PhoneNumber { get; set; }

        [Required(ErrorMessage = "E-Posta Adresi Gereklidir!")]
        [Display(Name = "E-Posta...")]
        [EmailAddress(ErrorMessage ="E-Posta Adresiniz Doğru Formatta Değil!")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Şifreniz Gereklidir!")]
        [Display(Name = "Şifre...")]
        [DataType(DataType.Password)]
        public string Password { get; set; }


        [DataType(DataType.Date)]
        public DateTime? BirthDay { get; set; }

        public string Picture { get; set; }

        public string City { get; set; }

        public string Meslek { get; set; }

        public Gender Gender { get; set; }


    }
}
