using MediatR;

namespace StarterWebJwt.Features.Auth
{
    public class SignInCommand : IRequest<string>
    {
        public string Username { get; set; }

        public string Password { get; set; }
    }
}