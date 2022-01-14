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
using System.Security.Claims;
using UdemyIdentity.TwoFService;

namespace UdemyIdentity.Controllers
{
    [Authorize]
    public class MemberController : BaseController
    {
        private readonly TwoFactorService _twoFactorService;

        // Controller Seviyesinde UserManager Elde edeiyoruz

        //Burayı Base Controllere gönderiyoruz
        //public UserManager<AppUser> userManager { get; }
        //public SignInManager<AppUser> signInManager { get; }

        public MemberController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager,TwoFactorService twoFactorService):base(userManager,signInManager)
        {
            _twoFactorService = twoFactorService;
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


                // Tellefonu Kontrol ediyoruz
                string phone = userManager.GetPhoneNumberAsync(user).Result;

                // Kullanıcı dan gelen tel no lie Texbox Tel no Karşılaşdırıyoruz.(Yani Yukardan gelen)
                // Telefon No Farklı ise Buradaki kod çalışacak Aynı ise bu kod işleme girmeyecek
                if (phone != userViewModel.PhoneNumber)
                {
                    if (userManager.Users.Any(k => k.PhoneNumber == userViewModel.PhoneNumber))
                    {
                        ModelState.AddModelError("", "Bu Telefon Numarası Zaten Kayıtlıdır!");
                        return View(userViewModel);
                    }
                }



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
        public IActionResult AccessDenied(string ReturnUrl)
        {

            if (ReturnUrl.Contains("AgePage"))
            {
                ViewBag.message = "Yaşınız 15 yaş altı oldugundan dolayı bu sayfaya erişme hakkınız yoktur!";
            }
            else if (ReturnUrl.Contains("AnkaraPage"))
            {
                ViewBag.message = "Bu sayfaya sadece Şehiri Ankara olan kullancılar erişebilir!";
            } 
            else if (ReturnUrl.Contains("Exchange"))
            {
                ViewBag.message = "30 günlük deneme süreciniz sona ermiştir!";
            }
            else
            {
                ViewBag.message = "Bu sayfaya maalesef erişim izininiz yoktur. Erişim" +
                    " izni almak için site yöneticisi ile görüşünüz!";
            }


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

        // Claim bazlı yetkilendirme Şehire göre giriş yapsın
        [Authorize(Policy = "AnkaraPolicy")]
        public IActionResult AnkaraPage()
        {
            return View();
        }

        // Claim bazlı yetkilendirme Yaşa göre giriş yapsın
        [Authorize(Policy = "AgePolicy")]
        public IActionResult AgePage()
        {
            return View();
        }




        
        // Ücretli sayfa
         public async Task<IActionResult> ExchangeRedirect()
        {

            // Böyle bir Claim Var mı
            bool result = User.HasClaim(k => k.Type == "ExpireDateExchange");

            // Böyle bir kullanıcı yoksa ekleme yapıyoruz
            if (!result)
            {
                Claim ExpireDateExchange = new Claim("ExpireDateExchange", DateTime.Now.AddDays
                    (30).Date.ToShortDateString(), ClaimValueTypes.String, "Internal");

                // işlem bittikten sonra siteye giriş çıkış yapar
                await userManager.AddClaimAsync(CurrentUser, ExpireDateExchange);
                await signInManager.SignOutAsync();
                await signInManager.SignInAsync(CurrentUser,true);
            }

            return RedirectToAction("Exchange");
        }




        // İzin verildikten sonra bu sayfaya gidiyor

        [Authorize(Policy = "ExchangePolicy")]
        public IActionResult Exchange()
        {
            return View();
        }




        // Ders 2

        public async Task<IActionResult> TwoFactorWithAuthenticator()
        {
            // Öncelikle AspNetUserTokens tablosunda  Value var mı (unformattedKey).
            // Eger var ise Bu kodla devam et
            string unformattedKey = await userManager.GetAuthenticatorKeyAsync(CurrentUser);

            // Eğer Yok ise
            // Bu kodla devam et
            if (string.IsNullOrEmpty(unformattedKey))
            {
                await userManager.ResetAuthenticatorKeyAsync(CurrentUser);
                unformattedKey = await userManager.GetAuthenticatorKeyAsync(CurrentUser);
            }

            AuthenticatorViewModel authenticatorViewModel = new AuthenticatorViewModel();
            authenticatorViewModel.SharedKey = unformattedKey;
            authenticatorViewModel.AuthenticatorUri = _twoFactorService.GenerateQrCodeUri(CurrentUser.Email, unformattedKey);
            return View (authenticatorViewModel);
        }

        [HttpPost]
        public async Task<IActionResult> TwoFactorWithAuthenticator(AuthenticatorViewModel authenticatorViewModel)
        {
            // Kullanıcıya gelen kodları düzenler, boşlukları çıkarır
            var verificationCode = authenticatorViewModel.VerificationCode.Replace(" ", string.Empty).Replace("-", string.Empty);

            var is2FaTokenValid = await userManager.VerifyTwoFactorTokenAsync(CurrentUser, userManager.Options.Tokens.
                AuthenticatorTokenProvider, verificationCode);

            // Kod dogrulandıgında Veri tabanında TwoFactorEnabled durumunu True yapar
            if (is2FaTokenValid)
            {
                CurrentUser.TwoFactorEnabled = true;
                CurrentUser.TwoFactor = (sbyte)TwoFactor.MicrosoftGoogle;

                // 8 Tane Kurtarma Kodu Oluşturuyoruz
                var recoveryCodes = await userManager.GenerateNewTwoFactorRecoveryCodesAsync(CurrentUser, 8);
                TempData["recoveryCodes"] = recoveryCodes;
                TempData["message"] = "Kimlik Doğrulama Tipiniz Googele/Microsoft Olarak Belirlenmiştir!";
                return RedirectToAction("TwoFactorAut");
            }
            // Kullanıcının girdigi dogrulama kodu yalnış ise
            else
            {
                ModelState.AddModelError("", "Girdiginiz Doğrulama Kodu Yalnıştır!");
                return View(authenticatorViewModel);
            }
        
        }






        // Burası Two Factor Auth DropDown Seçme yeridir
        public IActionResult TwoFactorAut()
        {
            return View(new AuthenticatorViewModel() { TwoFactorType=(TwoFactor)CurrentUser.TwoFactor});
        }

        [HttpPost]
        public async Task< IActionResult> TwoFactorAut(AuthenticatorViewModel authenticatorViewModel)
        {
            switch (authenticatorViewModel.TwoFactorType)
            {
                case TwoFactor.None:
                    CurrentUser.TwoFactorEnabled = false;
                    CurrentUser.TwoFactor = (sbyte)TwoFactor.None;
                    TempData["message"] = "Kimlik Doğrulama Tipiniz Hiçbir Olarak Belirlenmiştir!";
                    break;
                case TwoFactor.Phone:
                    // Eger Tel No yok ise Uyarı ver
                    if (string.IsNullOrEmpty(CurrentUser.PhoneNumber))
                    {
                        ViewBag.warning = "Telefon Numaranız Belirtilmemiş. Lütfen Kullanıcı Güncelleme Sayfasından " +
                            "telefon numaranızı belirtiniz! ";
                    }

                    // 
                    CurrentUser.TwoFactorEnabled = true;
                    CurrentUser.TwoFactor = (sbyte)TwoFactor.Phone;
                    TempData["message"] = "Kimlik Doğrulama Tipiniz Telefon Doğrulama Olarak Belirlenmiştir!";

                    break;
                case TwoFactor.Email:
                    CurrentUser.TwoFactorEnabled = true;
                    CurrentUser.TwoFactor = (sbyte)TwoFactor.Email;
                    TempData["message"] = "Kimlik Doğrulama Tipiniz E Posta Olarak Belirlenmiştir!";

                    break;
                case TwoFactor.MicrosoftGoogle:
                    return RedirectToAction("TwoFactorWithAuthenticator");
                  
                default:
                    break;
            }
            await userManager.UpdateAsync(CurrentUser);
            return View(authenticatorViewModel);
        }
    }
}
