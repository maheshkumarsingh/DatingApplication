using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;

namespace API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly DataContext _dataContext;
        private readonly ILogger<AccountController> _logger;
        private readonly ITokenService _tokenService;

        public AccountController(DataContext dataContext, ILogger<AccountController> logger, ITokenService tokenService)
        {
            _dataContext = dataContext;
            _logger = logger;
            _tokenService = tokenService;
        }

        [HttpPost("register")] //api/account/register?userName=sam&password=password
        public async Task<ActionResult<UserDTO>> Register(RegisterDTO registerDTO)
        {
            if (await UserExists(registerDTO.UserName))
                return BadRequest("UserName already exists");

            using var hmac = new HMACSHA512();
            var user = new AppUser
            {
                UserName = registerDTO.UserName,
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDTO.Password)),
                PasswordSalt = hmac.Key
            };
            _dataContext.Add(user);
            await _dataContext.SaveChangesAsync();
            return new UserDTO
            {
                UserName = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
        }
        [HttpDelete("delete/{id}")] //api/account/delete/2
        public async Task<IActionResult> Delete(int id)
        {
            var user = await _dataContext.Users.FindAsync(id);
            if(user != null)
            {
                _dataContext.Users.Remove(user);
                await _dataContext.SaveChangesAsync();
                return Ok();
            }
            else
                return NotFound();
        }

        [HttpPost("login")]
        public async Task<ActionResult<UserDTO>> LoginUser(LoginDTO loginDTO)
        {
            var user = await _dataContext.Users.FirstOrDefaultAsync(x => x.UserName == loginDTO.UserName);
            if (user == null)
                return BadRequest("User doesnot exists");
            using var hmac = new HMACSHA512(user.PasswordSalt);
            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDTO.Password));

            for (int i = 0; i < computedHash.Length; i++)
            {
                if (computedHash[i] != user.PasswordHash[i]) return Unauthorized("incorrect password");
            }
            return new UserDTO
            {
                UserName = user.UserName,
                Token = _tokenService.CreateToken(user),
            };
        }
        public async Task<bool> UserExists(string userName)
        {
            return await _dataContext.Users.AnyAsync(x => x.UserName.ToLower() == userName.ToLower());
        }
    }
}
