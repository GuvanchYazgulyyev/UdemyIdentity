using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace UdemyIdentity.CustomValidation
{

    // Bu Klas ise validation (Türkçeleştirmek için kullanılır) // IdentityErrorDescriber miras almakta

    public class CustomIdentityErrorDescriber : IdentityErrorDescriber
    {

        // Kullanıcı adı
        public override IdentityError InvalidUserName(string userName)
        {
            return new IdentityError()
            {
                Code = "InvalidUserName",
                Description = $"Bu {userName} geçersizdir!!!"
            };
        }

        //

        public override IdentityError DuplicateUserName(string userName)
        {
            return new IdentityError()
            {
                Code = "DuplicateUserName",
                Description = $"Bu Kullanıcı adı ({userName}) zaten kullanılmaktadır!!!"
            };
        }

        // E Posta
        public override IdentityError DuplicateEmail(string email)
        {
            return new IdentityError()
            {
                Code = "DuplicateEmail",
                Description = $"Bu E-Posta ({email}) kullanılmaktadır!!!"
            };
        }

        // Şife için

        public override IdentityError PasswordTooShort(int length)
        {
            return new IdentityError()
            {
                Code = "PasswordTooShort",
                Description = $"Şifreniz en az {length} karakterli olmalıdır!!!"
            };
        }

    }
}
