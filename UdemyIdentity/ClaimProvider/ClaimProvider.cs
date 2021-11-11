using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using UdemyIdentity.Models;

namespace UdemyIdentity.ClaimProvider
{
    // Claimler burada yer alacak (IClaimsTransformation) interface alacak ve sonrada implement ediyoruz
    public class ClaimProvider : IClaimsTransformation
    {
        // Kullanıcıyı bulabilmem için ihtiyacım olan 
        public UserManager<AppUser> userManager { get; set; }

        public ClaimProvider(UserManager<AppUser> userManager)
        {
            this.userManager = userManager;
        }

        public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
        {
            // ilk kontrol kullanıcı var mı
            if(principal!=null && principal.Identity.IsAuthenticated)
            {
                ClaimsIdentity identity = principal.Identity as ClaimsIdentity;
                AppUser user = await userManager.FindByNameAsync(identity.Name);

                // Kullanıcı varsa 
                if (user != null)
                {

                    // 18 yaş altı sınırlama
                    if (user.BirthDay != null)
                    {
                        var today = DateTime.Today;
                        var age = today.Year - user.BirthDay?.Year;

                        if (age > 18)
                        {
                            Claim AgeClaim = new Claim("violence", true.ToString(), ClaimValueTypes.String, "Internal");
                            identity.AddClaim(AgeClaim);
                        }
                    }

                    if (user.City != null)
                    {
                        if (!principal.HasClaim(k => k.Type == "city"))
                        {
                            Claim CityClaim = new Claim("city", user.City, ClaimValueTypes.String, "Internal");
                            identity.AddClaim(CityClaim);
                        }
                    }
                }
            }

            return principal;
        }
    }
}
