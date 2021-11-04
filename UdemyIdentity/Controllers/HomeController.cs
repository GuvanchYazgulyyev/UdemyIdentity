using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using UdemyIdentity.Models;
using UdemyIdentity.ViewModels;

namespace UdemyIdentity.Controllers
{
    public class HomeController : BaseController

    {   // Controller Seviyesinde UserManager Elde edeiyoruz

        //Burayı Base Controllere gönderiyoruz

        //public  UserManager<AppUser> userManager { get; }
        //public SignInManager<AppUser> signInManager { get; }
        public HomeController(UserManager<AppUser>userManager, SignInManager<AppUser> signInManager):base(userManager,signInManager)
        {
            //this.userManager = userManager;
            //this.signInManager = signInManager;

        }


        public IActionResult Index()
        {
            // Burada direk Member sayfasına gider
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Member");
            }

            return View();
        }


        public IActionResult Login(string ReturnUrl)
        {
            TempData["ReturnUrl"] = ReturnUrl;
            return View();
        }

        // Giriş Sayfası
        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel userlogin)
        {

            // Kullanıcı var mı yokmu kontrol ediyoruz

            //if (ModelState.IsValid)
            //{
            //    // maile gore kontrol ediyoruz
            //    AppUser user = await userManager.FindByIdAsync(userlogin.Email);

            //    // kullanıcı varsa
            //    if (user != null)
            //    {

            //        // Kullanıcı Kitlimi
            //        if(await userManager.IsLockedOutAsync(user))
            //        {
            //            ModelState.AddModelError("", "Hesabınız bir süreligini kilitlenmiştir! " +
            //                "Lütfen daha sonra tekrar deneyin!");
            //            return View(userlogin);
            //        }


            //        // ilk olarak cookiden çıkış yaptırıyoruz (yeni kullanıcı adı ile giriyoruz)
            //        await signInManager.SignOutAsync();

            //        Microsoft.AspNetCore.Identity.SignInResult result = await signInManager.PasswordSignInAsync(user, userlogin.Password, userlogin.RememberMe, false);

            //        // Başarılı ise
            //        if (result.Succeeded)
            //        {
            //            // Kullanıcının giriş sayısını sıfırlar
            //            await userManager.ResetAccessFailedCountAsync(user);

            //            // beni hatırla için
            //            if (TempData["ReturnUrl"] != null)
            //            {
            //                return Redirect(TempData["ReturnUrl"].ToString());
            //            }

            //            return RedirectToAction("Index", "Member");
            //        }

            //        // eger kullanıcı başarılı giriş yapamadıysa sayıyı arttırmamız lazım
            //        else
            //        {
            //            // Kullanıcının başarısız sayısını 1 arıttırır
            //            await userManager.AccessFailedAsync(user);

            //            // başarısı sayısını saydırdık
            //            int fail = await userManager.GetAccessFailedCountAsync(user);

            //            // Kaç kere başarısız giriş yaptıgını gösterir
            //            ModelState.AddModelError("", $"{fail} kez başarısız giriş!");

            //            // eger 3 başarızı giriş olursa 20 dk sistemi kilitle
            //            if (fail == 3)
            //            {
            //                await userManager.SetLockoutEndDateAsync(user, new System.DateTimeOffset(DateTime.Now.AddMinutes(20)));
            //                // Hata Mesajı
            //                ModelState.AddModelError("", "Hesabınız 3 başarı girişten dolayı 20 dakika " +
            //                    "süreyle kilitlenmiştir! Lütfen daha sonra tekrar deneyin");
            //            }
            //            else
            //            {
            //                ModelState.AddModelError("", "E-Posta adresiniz veya şifreniz yalnış!");
            //            }
            //        }
            //    }
            //    // Hataları gösteriyoruz
            //    else
            //    {
            //        ModelState.AddModelError("", "Bu email adresine kayıtlı kullanıcı bulunamamıştır!");
            //    }
            //}
            //return View(userlogin);

            if (ModelState.IsValid)
            {
                AppUser user = await userManager.FindByEmailAsync(userlogin.Email);

                if (user != null)
                {
                    if (await userManager.IsLockedOutAsync(user))
                    {
                        ModelState.AddModelError("", "Hesabınız bir süreliğine kilitlenmiştir. Lütfen daha sonra tekrar deneyiniz.");

                        return View(userlogin);
                    }

                    if (userManager.IsEmailConfirmedAsync(user).Result == false)
                    {
                        ModelState.AddModelError("", "Email adresiniz onaylanmamıştır. Lütfen  epostanızı kontrol ediniz.");
                        return View(userlogin);
                    }

                    await signInManager.SignOutAsync();

                    Microsoft.AspNetCore.Identity.SignInResult result = await signInManager.PasswordSignInAsync(user, userlogin.Password, userlogin.RememberMe, false);

                    if (result.Succeeded)
                    {
                        await userManager.ResetAccessFailedCountAsync(user);

                        if (TempData["ReturnUrl"] != null)
                        {
                            return Redirect(TempData["ReturnUrl"].ToString());
                        }

                        return RedirectToAction("Index", "Member");
                    }
                    else
                    {
                        await userManager.AccessFailedAsync(user);

                        int fail = await userManager.GetAccessFailedCountAsync(user);
                        ModelState.AddModelError("", $" {fail} kez başarısız giriş.");
                        if (fail == 3)
                        {
                            await userManager.SetLockoutEndDateAsync(user, new System.DateTimeOffset(DateTime.Now.AddMinutes(20)));

                            ModelState.AddModelError("", "Hesabınız 3 başarısız girişten dolayı 20 dakika süreyle kitlenmiştir. Lütfen daha sonra tekrar deneyiniz.");
                        }
                        else
                        {
                            ModelState.AddModelError("", "Email adresiniz veya şifreniz yanlış.");
                        }
                    }
                }
                else
                {
                    ModelState.AddModelError("", "Bu email adresine kayıtlı kullanıcı bulunamamıştır.");
                }
            }

            return View(userlogin);
        }


        // Kayıt Olmak
        public IActionResult SignUp()
        {
            return View();
        }
        
        [HttpPost]
        public async Task< IActionResult> SignUp(UserViewModel userViewModel)
        {

            // verinin olup olmadıgını kontrol ediyoruz
            if (ModelState.IsValid)
            {
                AppUser user = new AppUser();
                user.UserName = userViewModel.UserName;
                user.Email = userViewModel.Email;
                user.PhoneNumber = userViewModel.PhoneNumber;

                // IdentityResult Buna atamamızın sebebi bize extra bilbiler saglayacak
                IdentityResult result = await userManager.CreateAsync(user, userViewModel.Password);

                if (result.Succeeded)
                {
                    return RedirectToAction("Login");
                }

                else
                {
                    // Base Controllere Gönderildi
                    //foreach (IdentityError item in result.Errors)
                    //{
                    //    ModelState.AddModelError("", item.Description);
                    //}
                    AddModelError(result);
                }

            }
            return View(userViewModel);
        }









        // Şifre sıfırlama

        public IActionResult ResetPassword()
        {
            return View();
        }

        [HttpPost]
         public IActionResult ResetPassword(PasswordResetViewModel passwordResetViewModel)
        {
            // Böyle bir kullanıcı var mı? Test edelim
            AppUser user = userManager.FindByEmailAsync(passwordResetViewModel.Email).Result;
            // böyle bir kullanıcı varsa 
            if (user != null)
            {
                // Token Oluşturuyoruz
                string passwordResetToken = userManager.GeneratePasswordResetTokenAsync(user).Result;
                // Linki Burada gönderiyoruz
                string passworResetLink = Url.Action("ResetPasswordConfirm", "Home", new
                {
                    userId = user.Id,
                    token = passwordResetToken
                }, HttpContext.Request.Scheme);

                // deneme.com/Home/ResetPasswordConfirm?userId=jdkjasbhdtoken=kdlksamdl

                Helper.PasswordReset.PasswordResetSendEmail(passworResetLink);
                ViewBag.status = "success";

            }
            // hata varsa
            else
            {
                ModelState.AddModelError("", "Sistemde kayıtlı email adresi bulunamamıştır!!!");
            }


            return View(passwordResetViewModel);
        }


        //
        // Yeni şifre isteme

        public IActionResult ResetPasswordConfirm(string userId, string token)
        {
            TempData["userId"] = userId;
            TempData["token"] = token;

            return View();
        }


        // Yeni şifre isteme
        // Bind sadece modelin içindeki istedigimiz yeri alır
        [HttpPost]
        public async Task< IActionResult> ResetPasswordConfirm([Bind("PasswordNew")] PasswordResetViewModel passwordResetViewModel)
        {
            // Tempdata sayfalar arasında veri taşımak için kullanılır
            string token = TempData["token"].ToString();
            string userId = TempData["userId"].ToString();

            // Böyle bir kullanıcı varmı
            AppUser user = await userManager.FindByIdAsync(userId);

            // Kullanıcı boş degilse
            if (user !=null)
            {
                IdentityResult result = await userManager.ResetPasswordAsync(user, token, 
                    passwordResetViewModel.PasswordNew);
                // Eğer başarılı ise
                if (result.Succeeded)
                {
                    // öncelik ile veritabanı tablosundaki securyty sistemi dediştirmemiz gerekiyor
                    // aksi halde kullanıcı eski şifresi ile gezebilir
                    await userManager.UpdateSecurityStampAsync(user);
                    //TempData["passwordResultInfo"] = "Şifreniz başarılı bir şekilde yenilenmiştir! Yeni" +
                    //    "şifreniz ile giriş yapabilirsiniz!";
                    ViewBag.status = "success";
                }

                // hatalı ise
                else
                {
                    //foreach (var item in result.Errors)
                    //{
                    //    ModelState.AddModelError("", item.Description);
                    //}
                    AddModelError(result);
                } 
            }
            else
            {
                ModelState.AddModelError("", "Hata meydana geldi! Lütfen daha sonra tekrar deneyin!!!");
            }

            return View(passwordResetViewModel);

        }
    }
}