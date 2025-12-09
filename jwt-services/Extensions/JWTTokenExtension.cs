namespace jwt_services.Extensions;

using jwt_services.TokenService;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Text;

/// <summary>
/// Adds JWT authentication services to the IServiceCollection, configures token validation
/// and registers the JWT service.
/// </summary>
public static class JwtTokenExtension
{
    /// <summary>
    /// Registers essential JWT token services to IServiceCollection.
    /// </summary>
    /// <param name="services">The service collection to which JWT services will be added</param>
    /// <param name="configuration">The configuration used to get JWT settings (Key, Issuer, Audience)</param>
    public static IServiceCollection AddJwtTokenExtension(this IServiceCollection services, IConfiguration configuration)
    {
        // Get JWT key from configuration or throw an exception if not found.
        string jwtKey = configuration["Jwt:Key"]
            ?? throw new InvalidOperationException("JWT key not found in configuration!");

        string jwtIssuer = configuration["Jwt:Issuer"]
            ?? throw new InvalidOperationException("JWT issuer not found in configuration!");

        string jwtAudience = configuration["Jwt:Audience"]
            ?? throw new InvalidOperationException("JWT audience not found in configuration!");

        // Configure authentication services.
        services.AddAuthentication(options =>
        {
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options =>
        {
            byte[] key = Encoding.UTF8.GetBytes(jwtKey);

            options.TokenValidationParameters = new()
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero,
                ValidIssuer = jwtIssuer,
                ValidAudience = jwtAudience,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key)
            };
        });

        // Register token service.
        services.AddSingleton<ITokenService, TokenService>();

        return services;
    }
}