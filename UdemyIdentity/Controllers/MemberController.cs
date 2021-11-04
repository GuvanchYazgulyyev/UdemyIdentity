using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using UdemyIdentity.Models;
//nesne karşılaştırma kütüphanesi
using Mapster;
using UdemyIdentity.ViewModels;
using Microsoft.AspNetCore.Mvc.Rendering;
using UdemyIdentity.Enums;
using Microsoft.AspNetCore.Http;
using System.IO;

namespace UdemyIdentity.Controllers
{
    [Authorize]
    public class MemberController : BaseController
    {


        // Controller Seviyesinde UserManager Elde edeiyoruz

        //Burayı Base Controllere gönderiyoruz
        //public UserManager<AppUser> userManager { get; }
        //public SignInManager<AppUser> signInManager { get; }

        public MemberController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager):base(userManager,signInManager)
        {
            //this.userManager = userManager;
            //this.signInManager = signInManager;

        }




        // Kullanıcını bulmamız gerekiyor
        public IActionResult Index()
        {
            // Önce kullanıcını buluyoruz
            //AppUser user = userManager.FindByNameAsync(User.Identity.Name).Result;
            AppUser user = CurrentUser;

            //nesne karşılaştırma kütüphanesi
            // using Mapster; // burada kullanıldı eşleştirmek için
            UserViewModel userViewModel = user.Adapt<UserViewModel>();
            return View(userViewModel);
        }


        // Kullanıcı Bilgilerini Güncellemesi için

        public IActionResult UserEdit()
        {

            //AppUser user = userManager.FindByNameAsync(User.Identity.Name).Result;
            AppUser user = CurrentUser;

            // Degişiklik yapacagımız ViewModeli çagırıyoruz
            UserViewModel userViewModel = user.Adapt<UserViewModel>();

            // Cinsiyet alabilmek için istenilen komut
            ViewBag.Gender = new SelectList(Enum.GetNames(typeof(Gender)));

            return View(userViewModel);
        }

        [HttpPost]
        // resim için IFROMFİLE kullanıldı
        public async Task<IActionResult> UserEdit(UserViewModel userViewModel, IFormFile userPicture)
        {
            // Bunu çıkarmazdak hata verir
            ModelState.Remove("Password");

            // Cinsiyet alabilmek için istenilen komut
            ViewBag.Gender = new SelectList(Enum.GetNames(typeof(Gender)));

            if (ModelState.IsValid)
            {
                // Kullancıyı buluyoruz
                //AppUser user = await userManager.FindByNameAsync(User.Identity.Name);
                AppUser user = CurrentUser;



                // Resim Kaydetme----------------------------------------------
                if (userPicture != null && userPicture.Length > 0)
                {
                    // Resim Yolunu buluyor
                    var fileName = Guid.NewGuid().ToString() + Path.GetExtension(userPicture.FileName);
                    // Veri tabanı yolunu buluyor
                    var path = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/UserPicture/", fileName);

                    // Kaydetmek için
                    using (var stream = new FileStream(path, FileMode.Create))
                    {
                        await userPicture.CopyToAsync(stream);
                        user.Picture = "/UserPicture/" + fileName;
                    }
                }


               


                // Güncelliyoruz
                user.UserName = userViewModel.UserName;
                user.Email = userViewModel.Email;
                user.PhoneNumber = userViewModel.PhoneNumber;
                user.City = userViewModel.City;
                user.Meslek = userViewModel.Meslek;
                user.BirthDay = userViewModel.BirthDay;
                user.Gender = (int) userViewModel.Gender;

                // Karşılaştırma yapıyoruz Ornk Mail adresi başka kullanınıcı ile aynı olamaz
                IdentityResult result = await userManager.UpdateAsync(user); // Bura WebConfige den çekiyor

                if (result.Succeeded)
                {
                    // Security Stamp Onemli Bilgi

                    // Burası Önemli Otomatik Çıkış Yaptırır
                    await userManager.UpdateSecurityStampAsync(user);


                    // Eğer Kullanıcı şifre bilgisini degiştirmişse
                    await signInManager.SignOutAsync();// Çıkış Yaptırır
                    await signInManager.SignInAsync(user, true);// Burada kullanıcı çıkış yapmadan 
                                                                // Normal sayfada devam edebilir
                    ViewBag.success = "true";

                }
                else
                {
                    //foreach (var item in result.Errors)
                    //{
                    //    ModelState.AddModelError("", item.Description);
                    //}
                    AddModelError(result);
                }


            }
            return View(userViewModel);
        }


        // Şifre degiştirme 

        public IActionResult PasswordChange()
        {
            return View();
        }



        [HttpPost]
        public IActionResult PasswordChange(PasswordChangeViewModel passwordChangeViewModel)
        {


            if (ModelState.IsValid)
            {
                // Kullanıcıyı buluyoruz

                //AppUser user = userManager.FindByNameAsync(User.Identity.Name).Result;
                AppUser user = CurrentUser;

                //if (user != null)
                //{
                // Kullanıcı eski şifreyidoğru girdi mi
                bool exist = userManager.CheckPasswordAsync(user, passwordChangeViewModel.PasswordOld).Result;

                if (exist)
                {
                    IdentityResult result = userManager.ChangePasswordAsync(user, passwordChangeViewModel.PasswordOld,
                        passwordChangeViewModel.PasswordNew).Result;

                    if (result.Succeeded)
                    {
                        // Burası Önemli Otomatik Çıkış Yaptırır
                        userManager.UpdateSecurityStampAsync(user);


                        // Eğer Kullanıcı şifre bilgisini degiştirmişse
                        signInManager.SignOutAsync();// Çıkış Yaptırır
                        signInManager.PasswordSignInAsync(user, passwordChangeViewModel.PasswordNew, true, false);// Burada kullanıcı çıkış yapmadan 
                        // Normal sayfada devam edebilir

                        ViewBag.success = "true";
                    }

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
                    ModelState.AddModelError("", "Eski Şifreniz Yanlış!!!");
                }
            }
            //}




            return View(passwordChangeViewModel);
        }



        /// Çıkış
        /// Geri donuşu olmayacak Void
        public void LogOut()
        {
            signInManager.SignOutAsync();
            //return RedirectToAction("Index", "Home");
        }

        // Role yetkisi olmayan kişiler için 
        public IActionResult AccessDenied()
        {
            return View();
        }

        // Sayfaları Yetkilendirme

        [Authorize(Roles = "Editör")]
        public IActionResult Editor()
        {
            return View();
        } 
        
        [Authorize(Roles = "Yönetici")]
        public IActionResult Yonetici()
        {
            return View();
        }
    }
}
