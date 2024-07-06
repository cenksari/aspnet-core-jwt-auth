namespace jwt_services;

using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

/// <summary>
/// Token service.
/// </summary>
/// <param name="configuration">IConfiguration</param>
public class TokenService(IConfiguration configuration) : ITokenService
{
	private readonly IConfiguration _configuration = configuration;

	/// <summary>
	/// Generate token.
	/// </summary>
	/// <param name="username">Username</param>
	public string GenerateToken(string username)
	{
		string jwtKey = _configuration["Jwt:Key"] ?? throw new SecurityTokenException("Jwt:Key not found");

		SymmetricSecurityKey key = new(Encoding.UTF8.GetBytes(jwtKey));

		SigningCredentials credentials = new(key, SecurityAlgorithms.HmacSha256);

		DateTime expiration = DateTime.Now.AddMinutes(Convert.ToDouble(_configuration["Jwt:ExpiryMinutes"]));

		JwtSecurityToken token = new(
			issuer: _configuration["Jwt:Issuer"],
			audience: _configuration["Jwt:Audience"],
			claims: [
				// sub is who is the user subject of the JWT. Ex: ID, E-mail address etc.
				new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Sub, username),
					// jti is which individual JWT is this
					new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
					// custom claim type for role. Ex: User, Admin etc.
					// but validate issuer is the solution for access
					// different locations.
					new Claim(ClaimTypes.Role, "Admin")
			],
			expires: expiration,
			signingCredentials: credentials
		);

		return new JwtSecurityTokenHandler().WriteToken(token);
	}

	/// <summary>
	/// Validate token.
	/// </summary>
	/// <param name="token">JWT Token</param>
	public async Task<IDictionary<string, object>> ValidateToken(string token)
	{
		string jwtKey = _configuration["Jwt:Key"] ?? throw new SecurityTokenException("Jwt:Key not found");

		byte[] key = Encoding.UTF8.GetBytes(jwtKey);

		TokenValidationParameters validationParameters = new()
		{
			ValidateIssuer = true,
			ValidateAudience = true,
			ValidateLifetime = true,
			ValidateIssuerSigningKey = true,
			ValidIssuer = _configuration["Jwt:Issuer"],
			ValidAudience = _configuration["Jwt:Audience"],
			IssuerSigningKey = new SymmetricSecurityKey(key)
		};

		JsonWebTokenHandler tokenHandler = new();

		var result = await tokenHandler.ValidateTokenAsync(token, validationParameters);

		if (result.IsValid)
			return result.Claims;
		else
			throw new SecurityTokenException("Invalid token");
	}
}