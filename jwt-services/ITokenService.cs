namespace jwt_services;

public interface ITokenService
{
	string GenerateToken(string username);

	Task<IDictionary<string, object>> ValidateToken(string token);
}