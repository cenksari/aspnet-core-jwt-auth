namespace jwt_models;

public record User
{
	public string? Username { get; init; }
	public string? Password { get; init; }
}