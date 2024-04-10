using System.IdentityModel.Tokens.Jwt;

namespace Mbill.Core.Security
{
    public class JwtServiceCustom : IJwtService
    {
        private readonly IConfiguration _configuration;
        private readonly JwtSettings _jwtSettings;
        public JwtServiceCustom(IConfiguration configuration, JwtSettings jwtSettings)
        {
            _configuration = configuration;
            _jwtSettings = jwtSettings;
        }

        public Dictionary<string, object> Decode(string token) => new JwtSecurityTokenHandler().ReadJwtToken(token).Payload;

        public string Encode(IList<Claim> claims)
        {
            var key = Appsettings.JwtBearer.SecurityKey;

            var securityKey = new SymmetricSecurityKey(Convert.FromBase64String(key ?? throw new ArgumentNullException()))
            {
                KeyId = Convert.ToBase64String((Appsettings.JwtBearer.Audience + Appsettings.JwtBearer.Issuer).ToByteArray()),
            };
            var token = new JwtSecurityToken
            (
                _jwtSettings.Issuer,
                _jwtSettings.Audience,
                claims ?? new List<Claim>(),
                DateTime.UtcNow,
                DateTime.UtcNow.Add(_jwtSettings.Expires),
                new SigningCredentials(_jwtSettings.SecurityKey, SecurityAlgorithms.HmacSha256)
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public string Encode(string sub, string[] roles)
        {
            var claims = new List<Claim> { new("sub", sub) };

            roles.ToList().ForEach(role => claims.Add(new Claim("role", role)));

            return Encode(claims);
        }
    }
}
