using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using UdemyIdentity.Models;

namespace UdemyIdentity.Controllers
{
    public class BaseController : Controller
    {
        // Tekrar edilen kodları buraya topluyoruz

        // Controller Seviyesinde UserManager Elde edeiyoruz

        protected UserManager<AppUser> userManager { get; }
        protected SignInManager<AppUser> signInManager { get; }

        // Roller için 
        protected RoleManager<AppRole> roleManager { get; }

        protected AppUser CurrentUser => userManager.FindByNameAsync(User.Identity.Name).Result;

        public BaseController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager,RoleManager
            <AppRole>roleManager=null)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.roleManager = roleManager;

        }

        public void AddModelError(IdentityResult result)
        {
            foreach (var item in result.Errors)
            {
                ModelState.AddModelError("", item.Description);
            }
        }









    }
}
