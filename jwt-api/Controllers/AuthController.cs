namespace jwt_api.Controllers;

using jwt_models;
using jwt_services.TokenService;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController, Route("api/[controller]")]
public class AuthController(TokenService tokenService) : ControllerBase
{
	/// <summary>
	/// Login.
	/// </summary>
	/// <param name="user">User</param>
	[HttpPost("login")]
	public IActionResult Login([FromBody] User user)
	{
		if (user?.Username == null || user?.Password == null)
			return BadRequest(new { Title = "Please enter your credentials" });

		var token = tokenService.GenerateToken(user.Username, "Member");

		return Ok(new { Token = token });
	}

	/// <summary>
	/// Standard protected action.
	/// </summary>
	[HttpGet("protecteduser"), Authorize]
	public IActionResult ProtectedUser()
	{
		return Ok("protected user action");
	}

	/// <summary>
	/// Admin protected action.
	/// </summary>
	[HttpGet("protectedadmin"), Authorize(Roles = "Admin")]
	public IActionResult ProtectedAdmin()
	{
		return Ok("protected admin action");
	}

	/// <summary>
	/// SuperUser protected action.
	/// </summary>
	[HttpGet("protectedsuperuser"), Authorize(Roles = "SuperUser")]
	public IActionResult ProtectedSuperUser()
	{
		return Ok("protected superuser action");
	}
}