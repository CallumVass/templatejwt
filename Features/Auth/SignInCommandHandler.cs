using System.Threading;
using System.Threading.Tasks;
using StarterWebJwt.Domain;
using StarterWebJwt.Infrastructure.Jwt;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace StarterWebJwt.Features.Auth
{
    public class SignInCommandHandler : IRequestHandler<SignInCommand, string>
    {
        private readonly IJwtFactory jwtFactory;

        private readonly UserManager<ApplicationUser> userManager;

        public SignInCommandHandler(IJwtFactory jwtFactory, UserManager<ApplicationUser> userManager)
        {
            this.userManager = userManager;
            this.jwtFactory = jwtFactory;
        }

        public async Task<string> Handle(SignInCommand request, CancellationToken cancellationToken)
        {
            var user = await this.userManager.FindByEmailAsync(request.Username);

            return await this.jwtFactory.GenerateEncodedToken(user);
        }
    }
}