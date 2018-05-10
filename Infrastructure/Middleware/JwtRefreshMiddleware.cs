using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;
using StarterWebJwt.Domain;
using StarterWebJwt.Infrastructure.Jwt;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;

namespace StarterWebJwt.Infrastructure.Middleware
{
    public class JwtRefreshMiddleware
    {
        private readonly RequestDelegate next;

        public JwtRefreshMiddleware(RequestDelegate next)
        {
            this.next = next;
        }

        public async Task Invoke(HttpContext context)
        {
            if (context.User.Identity.IsAuthenticated)
            {
                var userClaims = context.User.Claims.ToArray();
                var status = JwtTokenRefreshChecker.CheckTokenStatus(Convert.ToInt64(userClaims.First(e => e.Type == JwtRegisteredClaimNames.Exp).Value));

                if (status == TokenStatus.ExpiringSoon)
                {
                    var userManager = (UserManager<ApplicationUser>)context.RequestServices.GetService(typeof(UserManager<ApplicationUser>));
                    var jwtFactory = (IJwtFactory)context.RequestServices.GetService(typeof(IJwtFactory));

                    var user = await userManager.FindByIdAsync(userClaims.First(e => e.Type == Constants.Strings.JwtClaimIdentifiers.Id).Value);
                    var token = await jwtFactory.GenerateEncodedToken(user);

                    context.Response.Headers.Add("Set-Authorization", token);
                }
            }

            await next(context);
        }
    }
}