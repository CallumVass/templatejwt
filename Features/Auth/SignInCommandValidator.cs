using System.Threading.Tasks;
using FluentValidation;
using StarterWebJwt.Domain;
using Microsoft.AspNetCore.Identity;

namespace StarterWebJwt.Features.Auth
{
    public class SignInCommandValidator : AbstractValidator<SignInCommand>
    {
        private readonly UserManager<ApplicationUser> userManager;

        private readonly SignInManager<ApplicationUser> signInManager;

        public SignInCommandValidator(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;

            RuleFor(vm => vm.Username).NotEmpty().WithMessage("Please ensure a username has been entered");
            RuleFor(vm => vm.Password).NotEmpty().WithMessage("Please ensure a password has been entered");
            RuleFor(e => e)
                .MustAsync((c, u) => ExistAndHaveAValidPassword(c))
                .OverridePropertyName("Username")
                .WithMessage("Invalid login attempt");
        }
        private async Task<bool> ExistAndHaveAValidPassword(SignInCommand c)
        {
            var user = await this.userManager.FindByNameAsync(c.Username);

            if (user == null)
            {
                return false;
            }

            var result = await this.signInManager.CheckPasswordSignInAsync(user, c.Password, user.AccessFailedCount >= this.signInManager.Options.Lockout.MaxFailedAccessAttempts);

            if (result != SignInResult.Success)
            {
                await this.userManager.AccessFailedAsync(user);
                return false;
            }

            await this.userManager.ResetAccessFailedCountAsync(user);

            return true;
        }
    }
}