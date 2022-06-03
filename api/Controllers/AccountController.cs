using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using api.Data;
using api.DTOs;
using api.Entities;
using api.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace api.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;

        private readonly ITokenService _tokenService;
        public AccountController(DataContext context, ITokenService tokenService)
        {
            _context = context;
            _tokenService = tokenService;
        }

        [HttpPost("register")]
        public async Task<ActionResult<AppUser>> Register(RegisterDto registerDto){
            if(await UserExists(registerDto.UserName)) return BadRequest("Username Already Exists");

            using var hmac = new HMACSHA512();

            var user = new AppUser
            {
                UserName = registerDto.UserName.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
                PasswordSalt = hmac.Key
            };

            _context.Users.Add(user);

            await _context.SaveChangesAsync();

            return user;
        }

        [HttpPost("login")]
        public async Task<ActionResult<AppUser>> Login(LoginDto loginDto){
            var user = await _context.Users.SingleOrDefaultAsync(x => String.Equals(x.UserName, loginDto.UserName.ToLower()));

            if(user == null) return Unauthorized("Invalid Username");

            using var hmac = new HMACSHA512(user.PasswordSalt);

            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

            for(int i = 0; i < computedHash.Length; i++){
                if(computedHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid Password");
            }
        
            return user;
        }
               
        [HttpDelete("delete/{id}")]
        public async Task<ActionResult<AppUser>> DeleteUser(int id){
            var user = await _context.Users.FindAsync(id);
            if(user == null) return BadRequest("User does not exist");
            _context.Attach(user);
           _context.Users.Remove(user);
            await _context.SaveChangesAsync();
            return user;
        }

        [HttpDelete("fastdelete/{id}")]
        public async Task<ActionResult<bool>> FastDelete(int id){
            var user = new AppUser{Id = id};
            //_context.Attach(user);
           _context.Users.Remove(user);
            await _context.SaveChangesAsync();
            return true;
        }

        private async Task<bool> UserExists(string username){
            return await _context.Users.AnyAsync(x => String.Equals(x.UserName,
                                                                    username.ToLower()));
        }
    }
}