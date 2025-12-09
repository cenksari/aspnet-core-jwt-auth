namespace jwt_services.TokenService;

using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

/// <summary>
/// Service responsible for generating JWT tokens for authentication, including user ID and role claims.
/// </summary>
/// <param name="configuration">Injected configuration to read JWT settings</param>
public class TokenService(IConfiguration configuration) : ITokenService
{
    /// <summary>
    /// Provides the secret key for signing the JWT.
    /// </summary>
    private readonly string jwtKey = configuration["Jwt:Key"]
           ?? throw new InvalidOperationException("JWT key configuration not found!");

    /// <summary>
    /// Provides the issuer of the JWT.
    /// </summary>
    private readonly string jwtIssuer = configuration["Jwt:Issuer"]
           ?? throw new InvalidOperationException("JWT issuer configuration not found!");

    /// <summary>
    /// Provides the audience for the JWT.
    /// </summary>
    private readonly string jwtAudience = configuration["Jwt:Audience"]
           ?? throw new InvalidOperationException("JWT audience configuration not found!");

    /// <summary>
    /// Provides the expiration time (in days) for the JWT.
    /// </summary>
    private readonly string jwtExpiryDays = configuration["Jwt:ExpiryDays"]
            ?? throw new InvalidOperationException("JWT expiration configuration not found!");

    /// <summary>
    ///	Generates JWT token.
    /// </summary>
    /// <param name="memberId">User ID</param>
    /// <param name="memberRole">User role</param>
    public string GenerateToken(string memberId, string memberRole = "User")
    {
        // Create security key.
        SymmetricSecurityKey key = new(Encoding.UTF8.GetBytes(jwtKey));

        // Create signing credentials.
        SigningCredentials credentials = new(key, SecurityAlgorithms.HmacSha256);

        // Set token expiration.
        DateTime expiration = DateTime.UtcNow.AddDays(Convert.ToDouble(jwtExpiryDays));

        // Define token claims.
        List<Claim> claims =
        [
            new Claim(ClaimTypes.Role, memberRole),
            new Claim(ClaimTypes.NameIdentifier, memberId),
        ];

        // Create token descriptor.
        SecurityTokenDescriptor tokenDescriptor = new()
        {
            Issuer = jwtIssuer,
            Subject = new(claims),
            Expires = expiration,
            Audience = jwtAudience,
            SigningCredentials = credentials
        };

        // Create token handler.
        JwtSecurityTokenHandler tokenHandler = new()
        {
            SetDefaultTimesOnTokenCreation = false
        };

        // Create token.
        SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);

        // return token.
        return tokenHandler.WriteToken(token);
    }

    /// <summary>
    /// Validates JWT token.
    /// </summary>
    /// <param name="token">JWT token</param>
    public async Task<IDictionary<string, object>> ValidateToken(string token)
    {
        byte[] key = Encoding.UTF8.GetBytes(jwtKey);

        // Create security key.
        SymmetricSecurityKey securityKey = new(key);

        // Set validation parameters.
        TokenValidationParameters validationParameters = new()
        {
            ValidIssuer = jwtIssuer,
            ValidAudience = jwtAudience,
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            IssuerSigningKey = securityKey,
            ValidateIssuerSigningKey = true
        };

        // Create token handler.
        JwtSecurityTokenHandler tokenHandler = new();

        // Validate token.
        TokenValidationResult result = await tokenHandler.ValidateTokenAsync(token, validationParameters);

        // If not result is valid.
        if (!result.IsValid)
            throw new SecurityTokenException("Invalid token.");

        return result.Claims;
    }
}