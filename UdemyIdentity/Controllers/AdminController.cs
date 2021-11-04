using Mapster;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using UdemyIdentity.Models;
using UdemyIdentity.ViewModels;
using Mapster;
using Microsoft.AspNetCore.Authorization;

namespace UdemyIdentity.Controllers
{
    [Authorize(Roles = "admin")]
    public class AdminController : BaseController
    {
        //private UserManager<AppUser> userManager { get; }// Base Controllerde 

        public AdminController(UserManager<AppUser> userManager, RoleManager<AppRole> roleManager) :
            base(userManager, null, roleManager)
        {
            // this.userManager = userManager;// Base Controllerde 
        }

        public IActionResult Index()
        {
            return View();
        }


        // Admin kullanıcıları çagırma
        public IActionResult Users()
        {
            return View(userManager.Users.ToList());

        }



        // Roller oluşturma

        public IActionResult RoleCreat()
        {
            return View();
        }

        [HttpPost]
        public IActionResult RoleCreat(RoleViewModel roleViewModel)
        {
            // Rolun geldigi yer
            AppRole role = new AppRole();
            role.Name = roleViewModel.Name;
            IdentityResult result = roleManager.CreateAsync(role).Result;

            if (result.Succeeded)
            {
                return RedirectToAction("Roles");
            }
            else
            {
                AddModelError(result);
            }


            return View(roleViewModel);
        }


        public IActionResult Roles()
        {
            return View(roleManager.Roles.ToList());
        }



        // Rol Silme

        public IActionResult RoleDelete(string id)
        {
            // Böyle bir rol var mı

            AppRole role = roleManager.FindByIdAsync(id).Result;

            if (role != null)
            {
                IdentityResult result = roleManager.DeleteAsync(role).Result;
            }
            return RedirectToAction("Roles");

        }

        // Rol Güncelle
        public IActionResult RoleUpdate(string id)
        {
            // ilk kontrol
            AppRole role = roleManager.FindByIdAsync(id).Result;

            if (role != null)
            {
                return View(role.Adapt<RoleViewModel>());
            }
            // Eşleştirme yapıyoruz
            return RedirectToAction("Roles");
        }
        // Rol Güncelleme
        [HttpPost]
        public IActionResult RoleUpdate(RoleViewModel roleViewModel)
        {
            // ilk kontrol
            AppRole role = roleManager.FindByIdAsync(roleViewModel.Id).Result;
            if (role != null)
            {
                role.Name = roleViewModel.Name;
                IdentityResult result = roleManager.UpdateAsync(role).Result;

                if (result.Succeeded)
                {
                    return RedirectToAction("Roles");
                }
                else
                {
                    AddModelError(result);
                }
            }

            else
            {
                ModelState.AddModelError("", "Güncelleme işlemi başarısız oldu!!!");
            }
            return View(roleViewModel);
        }


        // Rol Atama işlemi----------------------
        public IActionResult RoleAssign(string id)
        {
            TempData["userId"] = id;
            // Önce buluyoruz
            AppUser user = userManager.FindByIdAsync(id).Result;

            ViewBag.userName = user.UserName;

            // Var olan Rolleri çekiyoruz
            IQueryable<AppRole> roles = roleManager.Roles;

            List<string> userRoles = userManager.GetRolesAsync(user).Result as List<string>;

            // CheckBox ta gösterebilmem için 
            List<RoleAssignViewModel> roleAssignViewModels = new List<RoleAssignViewModel>();

            // Sonra yukardaki var olan rollerle dönüyoruz
            foreach (var x in roles)
            {
                // Nesne örnegi
                RoleAssignViewModel r = new RoleAssignViewModel();

                r.RoleId = x.Id;
                r.RoleName = x.Name;


                if (userRoles.Contains(x.Name))
                {
                    r.Exist = true;
                }
                else
                {
                    r.Exist = false;
                }

                // Kontrolden sonra sonucu listeye ekliyoruz
                roleAssignViewModels.Add(r);
            }
            return View(roleAssignViewModels);
        }


        [HttpPost]
        public async Task<IActionResult> RoleAssign(List<RoleAssignViewModel> roleAssignViewModels)
        {
            AppUser user = userManager.FindByIdAsync(TempData["userId"].ToString()).Result;

            foreach (var x in roleAssignViewModels)
            {
                // checkbox isaretli ise
                if (x.Exist)
                {
                    await userManager.AddToRoleAsync(user, x.RoleName);
                }

                // isaretli degilse
                else
                {
                    await userManager.RemoveFromRoleAsync(user, x.RoleName);
                }
            }
            
            return RedirectToAction("Users");
        }
    }
}
