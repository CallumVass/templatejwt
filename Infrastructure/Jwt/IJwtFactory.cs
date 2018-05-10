using System.Security.Claims;
using System.Threading.Tasks;
using StarterWebJwt.Domain;

namespace StarterWebJwt.Infrastructure.Jwt
{
    public interface IJwtFactory
    {
        Task<string> GenerateEncodedToken(ApplicationUser user);
    }
}