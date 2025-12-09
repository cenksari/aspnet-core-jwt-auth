namespace jwt_api.Controllers;

using jwt_models;
using jwt_services.TokenService;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController, Route("api/[controller]")]
public class AuthController(TokenService tokenService) : ControllerBase
{
    /// <summary>
    /// Login action to generate JWT token.
    /// </summary>
    /// <param name="user">User credentials</param>
    [HttpPost("login")]
    public IActionResult Login([FromBody] User user)
    {
        if (user?.Username == null || user?.Password == null)
            return BadRequest(new { Title = "Please enter your credentials" });

        var token = tokenService.GenerateToken(user.Username, "User");

        return Ok(new { Token = token });
    }

    /// <summary>
    /// Standard protected action.
    /// </summary>
    [HttpGet("protecteduser"), Authorize]
    public IActionResult ProtectedUser() => Ok("Protected user action");

    /// <summary>
    /// Admin protected action.
    /// </summary>
    [HttpGet("protectedadmin"), Authorize(Roles = "Admin")]
    public IActionResult ProtectedAdmin() => Ok("Protected admin action");

    /// <summary>
    /// SuperUser protected action.
    /// </summary>
    [HttpGet("protectedsuperuser"), Authorize(Roles = "SuperUser")]
    public IActionResult ProtectedSuperUser() => Ok("Protected superuser action");
}