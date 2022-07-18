using MinimalJwt.Models;

namespace MinimalJwt.Repositories
{
    public class UserRepository
    {
        public static List<User> Users = new()
        {
            new() { UserName = "luke_admin", EmailAddress = "luke.admin@email.com", Password = "MyPass_w0rd", GivenName = "Luke", Surname = "Rogers", Role = "Administrator" },
            new() { UserName = "lydia_standard", EmailAddress = "lydia.standard@email.com", Password = "MyPass_w0rd", GivenName = "Elyse", Surname = "Burton", Role = "Standard" },
        };
    }
}
