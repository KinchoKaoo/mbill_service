namespace Mbill.Core.Extensions
{
    public  static class JwtServiceCustomExtensions
    {
        public static void AddCustomJwtService(this IServiceCollection services) => services.AddSingleton<IJwtService, JwtServiceCustom>();
    }
}
