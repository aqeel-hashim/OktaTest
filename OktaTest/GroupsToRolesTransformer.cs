using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Okta.Sdk;
using Okta.Sdk.Configuration;
using System.Configuration;

namespace OktaTest
{
    public class GroupsToRolesTransformer : IClaimsTransformation
    {
        private OktaClient client;

        public GroupsToRolesTransformer()
        {
            client = new OktaClient(new OktaClientConfiguration
            {
                OktaDomain = ConfigurationManager.AppSettings["okta:OrgUri"],
                Token = "00fUVyCyWmPu1cAqhhuVUFZv5PhKrGL6vF151sgf22"
            });
        }

        public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal iprincipal)
        {
            var idClaim = iprincipal.FindFirst(x => x.Type == ClaimTypes.NameIdentifier);
            if (idClaim != null)
            {
                var user = await client.Users.GetUserAsync(idClaim.Value);
                if (user != null)
                {
                    var groups = user.Groups.ToEnumerable();
                    foreach (var group in groups)
                    {
                        ((ClaimsIdentity)iprincipal.Identity).AddClaim(new Claim(ClaimTypes.Role, group.Profile.Name));
                    }
                }
            }
            return iprincipal;
        }
    }
}