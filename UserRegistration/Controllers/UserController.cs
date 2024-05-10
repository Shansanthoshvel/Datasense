using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using UserRegistration.Models;

namespace UserRegistration.Controllers
{
    [Route("api/user")]
    [ApiController]
    public class UserController : BaseController
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;

        public UserController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        [HttpGet]
        public async Task<ActionResult> GetUser()
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(UserId);
                return Ok(user);
            }
            catch (Exception ex)
            {
                var message = ex.InnerException == null ? ex.Message : ex.InnerException.Message;
                return BadRequest(message);
            }
        }

        [HttpPost("register")]
        public async Task<ActionResult> CreateUser([FromForm] CreateUserDto createUser, [FromForm] IFormFile image)
        {
            try
            {
                var errorMessages = string.Empty;

                var user = new ApplicationUser { FullName = createUser.Name, UserName = createUser.Email, Email = createUser.Email, DateOfBirth = createUser.DateOfBirth, Gender = createUser.Gender, MaritalStatus = createUser.MaritalStatus };
                var userCreationResult = await _userManager.CreateAsync(user, createUser.Password);

                if (!userCreationResult.Succeeded)
                {
                    foreach (var error in userCreationResult.Errors)
                    {
                        errorMessages = errorMessages + ", " + error;
                    }

                    if (!string.IsNullOrEmpty(errorMessages))
                    {
                        throw new Exception(errorMessages);
                    }
                }

                if (image != null && image.Length > 0)
                {
                    var fileName = Guid.NewGuid().ToString() + Path.GetExtension(image.FileName);

                    var rootDirectory = Path.Combine(Directory.GetCurrentDirectory(), "UserImages");

                    if (!Directory.Exists(rootDirectory))
                    {
                        Directory.CreateDirectory(rootDirectory);
                    }

                    var filePath = Path.Combine(rootDirectory, fileName);

                    using (var stream = new FileStream(filePath, FileMode.Create))
                    {
                        await image.CopyToAsync(stream);
                    }

                    user.ImageUrl = filePath;
                    await _userManager.UpdateAsync(user);
                }

                if (userCreationResult.Succeeded)
                {
                    await _signInManager.SignInAsync(user, isPersistent: false);

                    user = await _userManager.FindByEmailAsync(createUser.Email);

                    await _userManager.AddToRoleAsync(user, "User");
                }

                return Ok(userCreationResult);
            }
            catch (Exception ex)
            {
                var message = ex.InnerException == null ? ex.Message : ex.InnerException.Message;
                return BadRequest(message);
            }
        }


        [HttpPut]
        public async Task<IActionResult> UpdateUserInfo([FromForm] UpdateUserDto model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    return NotFound();
                }

                user.FullName = model.Name;
                user.Gender = model.Gender;
                user.MaritalStatus = model.MaritalStatus;
                user.DateOfBirth = model.DateOfBirth;

                if (model.Image != null)
                {
                    var fileName = Guid.NewGuid().ToString() + Path.GetExtension(model.Image.FileName);

                    var rootDirectory = Path.Combine(Directory.GetCurrentDirectory(), "UserImages");

                    if (!Directory.Exists(rootDirectory))
                    {
                        Directory.CreateDirectory(rootDirectory);
                    }

                    var filePath = Path.Combine(rootDirectory, fileName);

                    using (var stream = new FileStream(filePath, FileMode.Create))
                    {
                        await model.Image.CopyToAsync(stream);
                    }

                    user.ImageUrl = filePath;
                }

                var result = await _userManager.UpdateAsync(user);
                if (result.Succeeded)
                {
                    return Ok();
                }
                else
                {
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                }
            }

            return BadRequest();
        }

        [HttpDelete]
        public async Task<ActionResult> DeleteUser(string email)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(email);
                var result = await _userManager.DeleteAsync(user);
                return Ok(result);
            }
            catch (Exception ex)
            {
                var message = ex.InnerException == null ? ex.Message : ex.InnerException.Message;
                return BadRequest(message);
            }
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.UserName);
            if (user != null && _userManager.CheckPasswordAsync(user, model.Password).Result)
            {
                var claims = new[]
                {
            new Claim(ClaimTypes.Name, user.UserName),
             new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.Role, "User")
        };

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("5897279b-5248-40a0-814c-fa855ab1895d"));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                var token = new JwtSecurityToken("test",
                "test",
                    claims,
                    expires: DateTime.Now.AddMinutes(30),
                    signingCredentials: creds);

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo
                });
            }

            return Unauthorized("Invalid username or password.");
        }

        [Authorize(Roles = "Admin")]
        [HttpGet("all")]
        public IActionResult GetAllUsers()
        {
            var users = _userManager.Users.ToList();
            return Ok(users);
        }
    }
}
