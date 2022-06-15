using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace UdemyIdentity.ViewModels
{
    // Kullanıcıya şifre verme Kısmı
    public class PasswordResetByAdminViewModel
    {
        public string UserId { get; set; }
        [Display(Name ="Yeni Şifre")]
        public string NewPassword { get; set; }
    }
}
