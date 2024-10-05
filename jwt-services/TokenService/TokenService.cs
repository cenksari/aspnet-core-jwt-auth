namespace jwt_services.TokenService;

using Microsoft.Extensions.Configuration;
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
    private readonly string _jwtKey = configuration["Jwt:Key"]
           ?? throw new Exception("JWT key configuration not found!");

    private readonly string _jwtIssuer = configuration["Jwt:Issuer"]
           ?? throw new Exception("JWT issuer configuration not found!");

    private readonly string _jwtAudience = configuration["Jwt:Audience"]
           ?? throw new Exception("JWT audience configuration not found!");

    private readonly string _jwtExpiryDays = configuration["Jwt:ExpiryDays"]
            ?? throw new Exception("JWT expiration configuration not found!");

    /// <summary>
    ///	Generates JWT token.
    /// </summary>
    /// <param name="memberId">User ID</param>
    /// <param name="memberRole">User role</param>
    public string GenerateToken(string memberId, string memberRole = "Member")
    {
        // Create security key.
        SymmetricSecurityKey key = new(Encoding.UTF8.GetBytes(_jwtKey));

        // Create signing credentials.
        SigningCredentials credentials = new(key, SecurityAlgorithms.HmacSha256);

        // Set token expiration.
        DateTime expiration = DateTime.UtcNow.AddDays(Convert.ToDouble(_jwtExpiryDays));

        // Define token claims.
        Dictionary<string, object> claims = new()
        {
            [ClaimTypes.Role] = memberRole,
            [ClaimTypes.NameIdentifier] = memberId,
        };

        // Create token descriptor.
        SecurityTokenDescriptor tokenDescriptor = new()
        {
            Claims = claims,
            Issuer = _jwtIssuer,
            Expires = expiration,
            Audience = _jwtAudience,
            SigningCredentials = credentials,
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
        byte[] key = Encoding.UTF8.GetBytes(_jwtKey);

        // Create security key.
        SymmetricSecurityKey securityKey = new(key);

        // Set validation parameters.
        TokenValidationParameters validationParameters = new()
        {
            ValidIssuer = _jwtIssuer,
            ValidAudience = _jwtAudience,
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