using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
namespace UdemyIdentity
{
    // 30 günlül kısıtlama için kullanılmaktadır

    public class ExpireDateExchangeRequirement : IAuthorizationRequirement
    {
        // Burayı boş bırakıyoruz StartUp tarafında kısıtlama ismi olarak veriyoruz (ExpireDateExchangeRequirement)
    }

    public class ExpireDateExchangeHandler : AuthorizationHandler<ExpireDateExchangeRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context,
            ExpireDateExchangeRequirement requirement)
        {
            if (context.User != null & context.User.Identity != null)
            {
                var claim = context.User.Claims.Where(l => l.Type == "ExpireDateExchange" && l.Value == null).FirstOrDefault();


                if (claim != null)
                {
                    if (DateTime.Now < Convert.ToDateTime(claim.Value))
                    {
                        context.Succeed(requirement);
                    }
                    else
                    {
                        context.Fail();
                    }
                }
            }
            return Task.CompletedTask;
        }
    }
}
