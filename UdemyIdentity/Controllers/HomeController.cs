using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using UdemyIdentity.Enums;
using UdemyIdentity.Models;
using UdemyIdentity.TwoFService;
using UdemyIdentity.ViewModels;

namespace UdemyIdentity.Controllers
{
    public class HomeController : BaseController

    {

        private readonly TwoFactorService _twoFactorService;

        private readonly EmailSender _emailSender;

        private readonly SMSSender _sMSSender;
        // Controller Seviyesinde UserManager Elde edeiyoruz

        //Burayı Base Controllere gönderiyoruz

        //public  UserManager<AppUser> userManager { get; }
        //public SignInManager<AppUser> signInManager { get; }
        public HomeController(UserManager<AppUser> userManager, SignInManager<AppUser> 
            signInManager,TwoFactorService twoFactorService,EmailSender emailSender,SMSSender sMSSender) : base(userManager, signInManager)
        {
            //this.userManager = userManager;
            //this.signInManager = signInManager;
            _twoFactorService = twoFactorService;
            _emailSender = emailSender;
            _sMSSender = sMSSender;

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


        public IActionResult Login(string ReturnUrl = "/")
        {
            TempData["ReturnUrl"] = ReturnUrl;
            return View();
        }

        // Giriş Sayfası
        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel userlogin)
        {

           

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


                    // Burası E posta onaynı gösterir

                    if (userManager.IsEmailConfirmedAsync(user).Result == false)
                    {
                        ModelState.AddModelError("", "Email adresiniz onaylanmamıştır. Lütfen  epostanızı kontrol ediniz.");
                        return View(userlogin);
                    }

                    //İki adımlı Kimlik dogrulamadan dolayı burası çalışmıyor

                    // await signInManager.SignOutAsync();

                    //Microsoft.AspNetCore.Identity.SignInResult result = await signInManager.PasswordSignInAsync(user, userlogin.Password, userlogin.RememberMe, false);

                    // Kullanıcının girmiş oldugu E posta ve şifreyi kontrol ettiriyoruz
                    bool userCheck = await userManager.CheckPasswordAsync(user, userlogin.Password);

                    // Eger Dogrıysa

                    if (userCheck)
                    {
                        // Dogru giriş yaptırsa başarısız giriş sayısını Resetliyoruz.
                        await userManager.ResetAccessFailedCountAsync(user);
                        await signInManager.SignOutAsync();

                        var result = await signInManager.PasswordSignInAsync(user, userlogin.Password,
                            userlogin.RememberMe, false);

                        if (result.RequiresTwoFactor)
                        {
                            // Eğer bir session varsa bunu silelim
                            // E Mail ve SMS için geçerlidir
                            // Burası Yeni eklendi
                            if (user.TwoFactor==(int)TwoFactor.Email||user.TwoFactor==(int)TwoFactor.Phone)
                            {
                                HttpContext.Session.Remove("currentTime");
                            }   // Burası Yeni eklendi

                            return RedirectToAction("TwoFactorLoIn","Home",new { ReturnUrl=TempData["ReturnUrl"].ToString() });
                        }
                        else
                        {
                            return Redirect(TempData["ReturnUrl"].ToString());
                        }
                    }

                    //if (result.Succeeded)
                    //{
                    //    //await userManager.ResetAccessFailedCountAsync(user);

                    //    if (TempData["ReturnUrl"] != null)
                    //    {
                    //        return Redirect(TempData["ReturnUrl"].ToString());
                    //    }

                    //    return RedirectToAction("Index", "Member");
                    //}
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



        // İkinic Adımda Kimlik Dogrulama Giriş Kısmı

        public async Task< IActionResult> TwoFactorLoIn(string ReturnUrl = "/")
        {

            // Burada UserId alarak Kullanıcı bilgilerini elde etmem gerekiyor
            var user = await signInManager.GetTwoFactorAuthenticationUserAsync();
            TempData["ReturnUrl"] = ReturnUrl;
            switch ((TwoFactor)user.TwoFactor)
            {
                case TwoFactor.MicrosoftGoogle:
                   
                    break;
                case TwoFactor.Phone:
                    // Eger Zaman bittiyse Ana sayfaya yönlendir
                    if (_twoFactorService.TimeLeft(HttpContext) == 0)
                    {
                        return RedirectToAction("LogIn");
                    }
                    ViewBag.timeLeft = _twoFactorService.TimeLeft(HttpContext);
                    HttpContext.Session.SetString("codeverification", _sMSSender.Send(user.PhoneNumber));


                    break;
                case TwoFactor.Email:
                    // Eger Zaman bittiyse Ana sayfaya yönlendir
                    if (_twoFactorService.TimeLeft(HttpContext)==0)
                    {
                        return RedirectToAction("LogIn");
                    }
                    ViewBag.timeLeft = _twoFactorService.TimeLeft(HttpContext);
                    // Gelen Kodu Sesion da kaydediyoruz
                    HttpContext.Session.SetString("codeverification", _emailSender.Send(user.Email));
                    break;
            }

            return View(new TwoFactorLogInViewModel() { TwoFactorType=(TwoFactor)
                user.TwoFactor/*,isRecoverCode=false,isRememberMe=false,VerificationCode=string.Empty*/});
        }

        [HttpPost]
        public async Task<IActionResult> TwoFactorLoIn(TwoFactorLogInViewModel twoFactorLogInViewModel)
        {
            // Kullanıcıyı Yakalıyoruz
            var user = await signInManager.GetTwoFactorAuthenticationUserAsync();
            //Hataları Sıfırlıyoruz
            ModelState.Clear();
            bool isSuccessAuth = false;

            if ((TwoFactor) user.TwoFactor==TwoFactor.MicrosoftGoogle)
            {


                Microsoft.AspNetCore.Identity.SignInResult result;
                // Kullancıya verilmiş 8 adet kod için burası çalışmaktadır
                if (twoFactorLogInViewModel.isRecoverCode)
                {
                    result = await signInManager.TwoFactorRecoveryCodeSignInAsync(twoFactorLogInViewModel.VerificationCode);
                }
                // Uygulamadan gelen kod için burası çalışmaktadır
                else
                {
                    result = await signInManager.TwoFactorAuthenticatorSignInAsync(twoFactorLogInViewModel.VerificationCode,twoFactorLogInViewModel.isRememberMe, false);
                }

                if (result.Succeeded)
                {
                    isSuccessAuth = true;
                }
                else
                {
                    ModelState.AddModelError("", "Doğrulama Kodu Yanlış!");
                }
            }


            // E posta ve SMS için
            // iki durunu burada kontrol ediyoruz    codeverification
            else if (user.TwoFactor==(sbyte)TwoFactor.Email||user.TwoFactor==(int)TwoFactor.Phone)
            {
                // Bu komut Pos olduktan sonra Time durdurur
                ViewBag.timeLeft = _twoFactorService.TimeLeft(HttpContext);


                if (twoFactorLogInViewModel.VerificationCode==HttpContext.Session.GetString("codeverification"))
                {
                    await signInManager.SignOutAsync();
                    await signInManager.SignInAsync(user, twoFactorLogInViewModel.isRememberMe);
                    HttpContext.Session.Remove("currentTime");
                    HttpContext.Session.Remove("codeverification");
                    isSuccessAuth = true;

                }
                else
                {
                    ModelState.AddModelError("", "Doğrulama Kodu Yanlış");
                }
                
            }



            if (isSuccessAuth)
            {
                return Redirect(TempData["ReturnUrl"].ToString());
            }
            twoFactorLogInViewModel.TwoFactorType = (TwoFactor)user.TwoFactor;
            return View(twoFactorLogInViewModel);


        }


        // E Posta Dogrulandıktan sonra yönlendirilecek sayfa

        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            var user = await userManager.FindByIdAsync(userId);
            IdentityResult result = await userManager.ConfirmEmailAsync(user, token);

            if (result.Succeeded)
            {
                ViewBag.status = "E Posta adresiniz onaylanmıştır. Sisteme giriş yapabilirsiniz.";
            }
            else
            {
                ViewBag.status = "Bir hata meydana geldi, lütfen daha sonra tekrar deneyin.";
            }
            return View();
        }







        // Kayıt Olmak
        public IActionResult SignUp()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> SignUp(UserViewModel userViewModel)
        {

            // verinin olup olmadıgını kontrol ediyoruz
            if (ModelState.IsValid)
            {

                // Veri Tabanında böyle bir tel no var mı ?
                if (userManager.Users.Any(u => u.PhoneNumber == userViewModel.PhoneNumber))
                {
                    ModelState.AddModelError("", "Bu Telefon Numarası Zaten Kayıtlıdır!");
                    return View(userViewModel);
                }


                AppUser user = new AppUser();
                user.UserName = userViewModel.UserName;
                user.Email = userViewModel.Email;
                user.PhoneNumber = userViewModel.PhoneNumber;
                user.TwoFactor = 0;

                // IdentityResult Buna atamamızın sebebi bize extra bilbiler saglayacak
                IdentityResult result = await userManager.CreateAsync(user, userViewModel.Password);

                if (result.Succeeded)
                {
                    // E Posta dogrulamak için kullanılıyor 
                    // Öncelikle toke oluşturuyoruz
                    string confirmationToken = await userManager.GenerateEmailConfirmationTokenAsync(user);

                    string link = Url.Action("ConfirmEmail", "Home", new
                    {
                        userId = user.Id,
                        token = confirmationToken
                    }, protocol: HttpContext.Request.Scheme
                    );

                    // şimdi ise EmailConfirmation Clasa Send emaili gönderiyoruz
                    Helper.EmailConfirmation.SendEmail(link, user.Email);
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

                Helper.PasswordReset.PasswordResetSendEmail(passworResetLink, user.Email);
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
        public async Task<IActionResult> ResetPasswordConfirm([Bind("PasswordNew")] PasswordResetViewModel passwordResetViewModel)
        {
            // Tempdata sayfalar arasında veri taşımak için kullanılır
            string token = TempData["token"].ToString();
            string userId = TempData["userId"].ToString();

            // Böyle bir kullanıcı varmı
            AppUser user = await userManager.FindByIdAsync(userId);

            // Kullanıcı boş degilse
            if (user != null)
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



        // Facebook ile giri yap (FacebookLogin)

        public IActionResult FacebookLogin(string ReturnUrl)
        {
            string RedirectUrl = Url.Action("ExternalResponse", "Home", new { ReturnUrl = ReturnUrl });

            var properties = signInManager.ConfigureExternalAuthenticationProperties("Facebook", RedirectUrl);

            // içersine ne alırsa onu getirir
            return new ChallengeResult("Facebook", properties);
        }


        // Facebook donus sayfasi

        public async Task<IActionResult> ExternalResponse(string ReturnUrl = "/")
        {
            // Kullanıcı bilgilerini alıyoruz

            ExternalLoginInfo info = await signInManager.GetExternalLoginInfoAsync();

            if (info == null)
            {
                // eger bos gelirse login ekranına git
                return RedirectToAction("LogIn");
            }

            else
            {
                // Doluysa
                Microsoft.AspNetCore.Identity.SignInResult result = await signInManager.ExternalLoginSignInAsync(info.LoginProvider,
                    info.ProviderKey, true);

                if (result.Succeeded)
                {
                    return Redirect(ReturnUrl);
                }
                // eger kullanıcı ilk kez Facebook butonuna basıyorsa
                else
                {
                    AppUser user = new AppUser();

                    user.Email = info.Principal.FindFirst(ClaimTypes.Email).Value;

                    string ExternalUserId = info.Principal.FindFirst(ClaimTypes.NameIdentifier).Value;

                    if (info.Principal.HasClaim(x => x.Type == ClaimTypes.Name))
                    {
                        string userName = info.Principal.FindFirst(ClaimTypes.Name).Value;


                        userName = userName.Replace(' ', '_').ToLower() + ExternalUserId.Substring(0, 6).ToString();

                        user.UserName = userName;
                    }

                    // Eger Kullanıcı adı yoksa direk mail girebilir
                    else
                    {
                        user.UserName = info.Principal.FindFirst(ClaimTypes.Email).Value;
                    }

                    // Kaydetme işlemi

                    // Böyle bir kullanıcı var mı 
                    AppUser user2 = await userManager.FindByEmailAsync(user.Email);

                    if (user2 == null)
                    {
                        IdentityResult createResult = await userManager.CreateAsync(user);

                        if (createResult.Succeeded)
                        {
                            IdentityResult loginResult = await userManager.AddLoginAsync(user, info);

                            if (loginResult.Succeeded)
                            {
                                //await signInManager.SignInAsync(user, true);
                                await signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, true);
                                return Redirect(ReturnUrl);
                            }
                            // Hatalar

                            else
                            {
                                AddModelError(loginResult);
                            }
                        }

                        // Hatalar

                        else
                        {
                            AddModelError(createResult);
                        }

                    }

                    else
                    {
                        IdentityResult loginResult = await userManager.AddLoginAsync(user2, info);
                        await signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, true);
                        return Redirect(ReturnUrl);

                    }






                }
            }
            // Hataları alabilmek için burada string bir şekilde alıyoruz
            List<string> errors = ModelState.Values.SelectMany(k => k.Errors).Select(l => l.ErrorMessage).ToList();


            return View("Error", errors);
        }




        // MicrosoftLogin Giriş Kısmı


        public IActionResult MicrosoftLogin(string ReturnUrl)
        {
            string RedirectUrl = Url.Action("ExternalResponse", "Home", new { ReturnUrl = ReturnUrl });

            var properties = signInManager.ConfigureExternalAuthenticationProperties("Microsoft", RedirectUrl);

            // içersine ne alırsa onu getirir
            return new ChallengeResult("Microsoft", properties);
        }



        // Hata sayfaları

        public ActionResult Error()
        {
            return View();
        }


        [HttpGet]
        public JsonResult AgainSendEmail()
        {
            try
            {
                var user = signInManager.GetTwoFactorAuthenticationUserAsync().Result;
                HttpContext.Session.SetString("codeverification", _emailSender.Send(user.Email));
                return Json(true);
            }
            catch (Exception)
            {
                // Loglama Yap
                return Json(false);
            }
        }



        // E Posta Dogrulama API
        //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

    }
}