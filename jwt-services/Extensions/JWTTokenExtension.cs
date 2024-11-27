namespace jwt_services.Extensions;

using jwt_services.TokenService;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Text;

public static class JWTTokenExtension
{
	/// <summary>
	///	Registers essential JWT token services to IServiceCollection.
	/// </summary>
	/// <param name="services">Services</param>
	/// <param name="configuration">Configuration</param>
	public static IServiceCollection AddJWTTokenExtension(this IServiceCollection services, IConfiguration configuration)
	{
		// Get JWT key from configuration or throw an exception if not found.
		string jwtKey = configuration["Jwt:Key"]
			?? throw new Exception("JWT key configuration not found!");

		// Configure authentication services.
		services.AddAuthentication(options =>
		{
			options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
			options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
		})
		.AddJwtBearer(options =>
		{
			byte[] key = Encoding.UTF8.GetBytes(jwtKey);

			options.TokenValidationParameters = new TokenValidationParameters
			{
				ValidateIssuer = true,
				ValidateAudience = true,
				ValidateLifetime = true,
				ValidateIssuerSigningKey = true,
				ValidIssuer = configuration["Jwt:Issuer"],
				ValidAudience = configuration["Jwt:Audience"],
				IssuerSigningKey = new SymmetricSecurityKey(key)
			};
		});

		// Register token service.
		services.AddSingleton<ITokenService, TokenService>();

		return services;
	}
}