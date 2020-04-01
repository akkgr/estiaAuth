using IdentityModel;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System;
using MongoDB.Driver;
using System.Threading.Tasks;
using System.Threading;
using Microsoft.AspNetCore.Identity;
using MongoDB.Bson;

namespace estiaAuth
{
    public class UserStore
    {
        private readonly IMongoCollection<User> _users;

        public UserStore(IAuthDatabaseSettings settings)
        {
            var client = new MongoClient(settings.ConnectionString);
            var database = client.GetDatabase(settings.DatabaseName);

            _users = database.GetCollection<User>(settings.UsersCollectionName);
        }

        public async Task<bool> ValidateCredentials(string username, string password, CancellationToken cancellationToken = default)
        {
            var user = await FindByUsername(username, cancellationToken);

            if (user != null)
            {
                if (string.IsNullOrWhiteSpace(user.Password) && string.IsNullOrWhiteSpace(password))
                {
                    return true;
                }
                var ph = new PasswordHasher<User>();
                var res = ph.VerifyHashedPassword(user, user.Password, password);
                return res == PasswordVerificationResult.Success;
            }

            return false;
        }

        public async Task<User> FindBySubjectId(string subjectId, CancellationToken cancellationToken = default)
        {
            return await _users.Find(x => x.Id == subjectId).FirstOrDefaultAsync(cancellationToken);
        }

        public async Task<User> FindByUsername(string username, CancellationToken cancellationToken = default)
        {
            return await _users.Find(new BsonDocument("username", "/^" + username + "$/i"))
                .FirstOrDefaultAsync(cancellationToken);
        }

        public async Task<User> FindByExternalProvider(string provider, string userId, CancellationToken cancellationToken = default)
        {
            return await _users.Find(x =>
                x.ProviderName == provider &&
                x.ProviderSubjectId == userId)
                .FirstOrDefaultAsync(cancellationToken);
        }

        public async Task<User> AutoProvisionUser(string provider, string userId, List<Claim> claims, CancellationToken cancellationToken = default)
        {
            // create a list of claims that we want to transfer into our store
            var filtered = new List<Claim>();

            foreach (var claim in claims)
            {
                // if the external system sends a display name - translate that to the standard OIDC name claim
                if (claim.Type == ClaimTypes.Name)
                {
                    filtered.Add(new Claim(JwtClaimTypes.Name, claim.Value));
                }
                // if the JWT handler has an outbound mapping to an OIDC claim use that
                else if (JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap.ContainsKey(claim.Type))
                {
                    filtered.Add(new Claim(JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap[claim.Type], claim.Value));
                }
                // copy the claim as-is
                else
                {
                    filtered.Add(claim);
                }
            }

            // if no display name was provided, try to construct by first and/or last name
            if (!filtered.Any(x => x.Type == JwtClaimTypes.Name))
            {
                var first = filtered.FirstOrDefault(x => x.Type == JwtClaimTypes.GivenName)?.Value;
                var last = filtered.FirstOrDefault(x => x.Type == JwtClaimTypes.FamilyName)?.Value;
                if (first != null && last != null)
                {
                    filtered.Add(new Claim(JwtClaimTypes.Name, first + " " + last));
                }
                else if (first != null)
                {
                    filtered.Add(new Claim(JwtClaimTypes.Name, first));
                }
                else if (last != null)
                {
                    filtered.Add(new Claim(JwtClaimTypes.Name, last));
                }
            }

            // check if a display name is available
            var name = filtered.FirstOrDefault(c => c.Type == JwtClaimTypes.Name)?.Value;

            // create new user
            var user = new User
            {
                Username = name,
                ProviderName = provider,
                ProviderSubjectId = userId,
                Claims = filtered
            };

            // add user to in-memory store
            await _users.InsertOneAsync(user);

            return user;
        }
    }
}