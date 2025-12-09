namespace jwt_services.TokenService;

public interface ITokenService
{
    Task<IDictionary<string, object>> ValidateToken(string token);

    string GenerateToken(string memberId, string memberRole = "User");
}