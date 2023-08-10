using Microsoft.AspNetCore.Identity;

namespace Jwt.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
    }
}
