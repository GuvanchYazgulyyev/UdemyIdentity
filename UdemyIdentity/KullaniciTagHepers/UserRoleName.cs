using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Razor.TagHelpers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using UdemyIdentity.Models;

namespace UdemyIdentity.KullaniciTagHepers
{
    // Rolleri göstermek için kullanılır
    // Burada TagHelperin Namespace ini ViewImportta belirtmemiz Lazım
    [HtmlTargetElement("td", Attributes = "user-roles")]
    public class UserRoleName : TagHelper
    {
        public UserManager<AppUser> UserManager { get; set; }

        public UserRoleName(UserManager<AppUser> userManager)
        {
            this.UserManager = userManager;
        }
        [HtmlAttributeName("user-roles")]
        public string UserId { get; set; }

        public override async Task ProcessAsync(TagHelperContext context, TagHelperOutput output)
        {
            // Rolleri alabilmek için
            AppUser user = await UserManager.FindByIdAsync(UserId);
            IList<string> roles = await UserManager.GetRolesAsync(user);

            string html = string.Empty;

            roles.ToList().ForEach(x =>
            {
                html += $"<span class='badge badge-info'> {x} </span>";
            });
            output.Content.SetHtmlContent(html);
        }
    }
}
