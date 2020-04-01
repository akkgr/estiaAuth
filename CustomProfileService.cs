using System.Security.Claims;
using System.Threading.Tasks;
using IdentityServer4.Models;
using IdentityServer4.Services;

namespace estiaAuth
{
    public class CustomProfileService : IProfileService
    {
        private readonly UserStore _users;

        public CustomProfileService(
            UserStore users)
        {

            _users = users;

        }

        public async Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            var name = context.Subject.Identity.Name;
            var user = await _users.FindByUsername(name);
            context.IssuedClaims.Add(new Claim(ClaimTypes.Name, user.Username));
        }

        public Task IsActiveAsync(IsActiveContext context)
        {
            context.IsActive = true;
            return Task.FromResult(true);
        }
    }
}