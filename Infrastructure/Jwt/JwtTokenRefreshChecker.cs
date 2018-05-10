using System;
using System.Threading.Tasks;
using StarterWebJwt.Domain;
using Microsoft.AspNetCore.Identity;

namespace StarterWebJwt.Infrastructure.Jwt
{
    public static class JwtTokenRefreshChecker
    {
        public static TokenStatus CheckTokenStatus(long tokenExpiry)
        {
            var startDate = new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero);
            var expiryDate = new DateTime(startDate.Ticks + TimeSpan.FromSeconds(tokenExpiry).Ticks);

            return ((expiryDate - DateTime.UtcNow).TotalSeconds < 600)
                        ? TokenStatus.ExpiringSoon
                        : TokenStatus.DoesntRequireRefresh;
        }
    }
}