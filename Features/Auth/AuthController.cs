using System.Threading.Tasks;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace StarterWebJwt.Features.Auth
{
    public class AuthController : ApiController
    {
        private readonly IMediator mediator;

        public AuthController(IMediator mediator)
        {
            this.mediator = mediator;
        }

        [HttpPost("sign-in")]
        [AllowAnonymous]
        public async Task<IActionResult> SignIn(SignInCommand signInCommand)
        {
            return Ok(new { token = await this.mediator.Send(signInCommand) });
        }
    }
}