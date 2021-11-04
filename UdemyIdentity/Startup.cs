using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using UdemyIdentity.CustomValidation;
using UdemyIdentity.Models;

namespace UdemyIdentity
{
    public class Startup
    {
        public IConfiguration configuration { get; }

        public Startup(IConfiguration configuration)
        {
            this.configuration = configuration;
        }

        // Appsetting.json dosyası ile ilişkili veri tabanını kaydeder
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<AppIdentityDbContext>(opts =>
            {
                //opts.UseSqlServer(configuration["DefaultConnectionString"]);
                opts.UseSqlServer(configuration["ConnectionStrings:DefaultConnectionString"]);
            });

         

            // Burada ise nasıl kayt edecegimiz belirtiriz
            services.AddIdentity<AppUser, AppRole>(opts=> {

                // Kullanıcı Üzerine
                opts.User.RequireUniqueEmail = true;
                opts.User.AllowedUserNameCharacters = "abcçdefgğhıijklmnoçpqrsştuüvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._";





                // Şifre Şartları
                opts.Password.RequiredLength = 3;
                opts.Password.RequireNonAlphanumeric = false;
                opts.Password.RequireUppercase = false;
                opts.Password.RequireLowercase = false;
                opts.Password.RequireDigit = false;
                // CustomValidator Dosyasındaki (CustomPasswordValidator)
                // (CustomUserValidator) (CustomIdentityErrorDescriber) sınıfını buraya ekledik
                //// Şifremi unuttum servisi burada (AddDefaultTokenProviders)

            }).AddPasswordValidator<CustomPasswordValidator>()
            .AddUserValidator<CustomUserValidator>()
            .AddErrorDescriber<CustomIdentityErrorDescriber>()
            .AddEntityFrameworkStores<AppIdentityDbContext>().AddDefaultTokenProviders();










            // Cookie bazlı kimlik dogrulama ayarları

            //CookieBuilder cookieBuilder = new CookieBuilder(); // Cookie çagırdık
            //cookieBuilder.Name = "MyBlog";      // isim belirledik
            //cookieBuilder.HttpOnly = false;       // özelligini false yaptık  
            //cookieBuilder.Expiration = System.TimeSpan.FromDays(60);    // zaman sınırı koyduk
            //cookieBuilder.SameSite = SameSiteMode.Lax; // Site güvenligi kritik sitelerde  (Strict) methodu kullanır
            //cookieBuilder.SecurePolicy = CookieSecurePolicy.SameAsRequest; //  Site güvenligi genelde (always) method kullanılır
            //                                                               //  çünkü sadece https// çalışır

            //services.ConfigureApplicationCookie(opts =>
            //{
            //    opts.LoginPath = new PathString("/Home/Login"); // gidecegi sayfatı belirtiyoruz
            //    opts.Cookie = cookieBuilder;
            //    opts.SlidingExpiration = true; // yukarıda koydugumuz zaman sınırının yarısını geldiginde kullanıcı tekrar sisteme giriş yapars
            //                                   // mesela 32. günde siteye girerse tekrar 60 gün daha cookie izin veriyor


            //});

            CookieBuilder cookieBuilder = new CookieBuilder();
            cookieBuilder.Name = "MyBlog";
            cookieBuilder.HttpOnly = false;
            cookieBuilder.SameSite = SameSiteMode.Lax;
            cookieBuilder.SecurePolicy = CookieSecurePolicy.SameAsRequest;
            services.ConfigureApplicationCookie(opts =>

            {
                opts.LoginPath = new PathString("/Home/Login");// Üye olan kullanıcılar için
                opts.LogoutPath = new PathString("/Member/LogOut");
                opts.Cookie = cookieBuilder;
                opts.SlidingExpiration = true;
                opts.ExpireTimeSpan = System.TimeSpan.FromDays(60);
                opts.AccessDeniedPath = new PathString("/Member/AccessDenied");// Rol kullanıldıgında 
                //yönlendirmek için kullanılır veya uyarı verir// üye olup ta yetkisi olmayan kullanıcılar için
            });


            services.AddMvc();
            //services.AddScoped<IClaimsTransformation, ClaimProvider.ClaimProvider>();

            //services.AddControllersWithViews(); +++++++++
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseDeveloperExceptionPage();
            app.UseStatusCodePages();// Sitedeki hataları söyler Ornk(404, 500 hataları)
            app.UseStaticFiles();

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });

            //{ controller}/{ action}/ id
        }
    }
}