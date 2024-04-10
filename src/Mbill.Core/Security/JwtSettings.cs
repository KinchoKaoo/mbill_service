namespace Mbill.Core.Security
{
    public class JwtSettings(string key, TimeSpan expires)
    {
        public JwtSettings(string key, TimeSpan expires, string audience, string issuer)
            : this(key, expires)
        {
            this.Audience = audience;
            this.Issuer = issuer;
        }

        public string Audience { get; }

        public TimeSpan Expires { get; } = expires;

        public string Issuer { get; }

        public SecurityKey SecurityKey { get; } = new SymmetricSecurityKey(Encoding.Default.GetBytes(key))
        {
            KeyId = Convert.ToBase64String((Appsettings.JwtBearer.Audience + Appsettings.JwtBearer.Issuer).ToByteArray())
        };

        public TokenValidationParameters TokenValidationParameters => new ()
        {
            IssuerSigningKey = this.SecurityKey,
            ValidAudience = this.Audience,
            ValidIssuer = this.Issuer,
            ValidateAudience = !string.IsNullOrEmpty(this.Audience),
            ValidateIssuer = !string.IsNullOrEmpty(this.Issuer),
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        };

        //new TokenValidationParameters
        //{
        //    // 密钥必须匹配
        //    ValidateIssuerSigningKey = true,
        //    IssuerSigningKey = jsonWebTokenSetting.SecurityKey,

        //    // 验证Issuer
        //    ValidateIssuer = true,
        //    ValidIssuer = jsonWebTokenSetting.Issuer,

        //    // 验证Audience
        //    ValidateAudience = true,
        //    ValidAudience = jsonWebTokenSetting.Audience,

        //    //偏移设置为了0s,用于测试过期策略,完全按照access_token的过期时间策略，默认原本为5分钟
        //    ClockSkew = TimeSpan.Zero
        //};
}
}
