﻿using API.Data;
using API.Entities;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    [Route("api/[controller]")] // api/users
    [ApiController]
    public class UsersController: ControllerBase
    {
        private readonly DataContext _dataContext;
        public UsersController(DataContext dataContext)
        {
            _dataContext = dataContext;
        }
        [HttpGet]
        public async Task<ActionResult<IEnumerable<AppUser>>> GetAllUsers()
        {
            var users = await _dataContext.Users.ToListAsync();
            return users;
        }
        [HttpGet("{id:int}")] // api/users/3
        public async Task<ActionResult<AppUser>> GetUser(int id)
        {
            var user = await _dataContext.Users.FindAsync(id);
            return user;
        }
    }
}
