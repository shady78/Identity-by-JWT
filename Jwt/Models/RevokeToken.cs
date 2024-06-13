namespace JWTRefreshTokenInDotNet6.Models
{
    public class RevokeToken
    {
        // nullable =>  this token can get by cookies or body
        public string? Token { get; set; }
    }
}