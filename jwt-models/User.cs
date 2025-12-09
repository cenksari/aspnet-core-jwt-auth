namespace jwt_models;

using System.Text.Json.Serialization;

public record User
{
    [JsonPropertyName("username")]
    public string? Username { get; init; }

    [JsonPropertyName("password")]
    public string? Password { get; init; }
}