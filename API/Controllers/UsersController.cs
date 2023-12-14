using System.Collections;
using API.Data;
using API.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers;
[Authorize]
public class UsersController : BaseApiController
{
  private readonly DataContext _context;

  public UsersController(DataContext context)
  {
    _context = context;
  }

  // Just an example to show how you can allow access to select methods
  [HttpGet]
  public async Task<ActionResult<IEnumerable>> GetUsers()
  {
    return await _context.Users.ToListAsync();
  }

  [HttpGet("{id}")]
  public async Task<ActionResult<AppUser>> GetUser(int id)
  {
    return await _context.Users.FindAsync(id);
  }

  [AllowAnonymous]
  [HttpGet("allowAnonymous")]
  public string AllowAnonymous()
  {
    return "I allow anonymous access";
  }
}
