using API.Data;
using Microsoft.AspNetCore.Mvc;
using API.Entities;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using API.DTOs;
using API.Interfaces;

namespace API.Controllers
{
    public class AccountController : BaseApiController // hertitage from BaseApiController
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenService;
        public AccountController(DataContext context, ITokenService tokenService)
        {
            _context = context;
            _tokenService = tokenService;
            
        }

        [HttpPost("register")] // POST: api / account (bo w nazwie kontrolera jest acount / register - ta nazwa tutaj)
        
        public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto)
        {
            if (await UserExist(registerDto.Username)) return BadRequest ("Username is taken"); // sprawdzenie czy taki user juz jest
            
            using var hmac = new HMACSHA512(); // specialna funckcja dostarczona przez dotnet framework

            var user = new AppUser
            {
                UserName = registerDto.Username.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
                PasswordSalt = hmac.Key

            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return new UserDto
             {
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)

             };
        }

        [HttpPost("login")]
        public async Task<ActionResult<UserDto>>Login(LoginDto loginDto)
        {
            var user = await _context.Users.SingleOrDefaultAsync(x => 
            x.UserName == loginDto.Username);

            if(user == null) return Unauthorized("invalid username");

             using var hmac = new HMACSHA512(user.PasswordSalt);

             var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

             for (int i=0; i < computedHash.Length; i++)
             {
                if (computedHash[i] != user.PasswordHash[i]) return Unauthorized("invalid password");

             }

            return new UserDto
             {
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)

             };
        }



        private async Task<bool> UserExist(string username)
        {
            return await _context.Users.AnyAsync(x=>x.UserName == username.ToLower());  //sprwadzenie czy taki uzytkowik juz istnieje w bazie dancyh
        }

        
    }
}