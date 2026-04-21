using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using System.Security.Claims;
using System.Text.Json;
using TeduBlog.Api.Extensions;
using TeduBlog.Api.Services;
using TeduBlog.Core.Domain.Identity;
using TeduBlog.Core.Models.Auth;
using TeduBlog.Core.Models.System;
using TeduBlog.Core.SeedWorks.Constants;

namespace TeduBlog.Api.Controllers.AdminApi
{
    [Route("api/admin/auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly ITokenService _tokenService;
        private readonly RoleManager<AppRole> _roleManager;
        public AuthController(UserManager<AppUser> userManager,
            SignInManager<AppUser> signInManager,
            ITokenService tokenService,
            RoleManager<AppRole> roleManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _tokenService = tokenService;
            _roleManager = roleManager;
        }

        [HttpPost("login")]
        public async Task<ActionResult<AuthenticatedResult>> Login([FromBody] LoginRequest request)
        {
            if (request == null) return BadRequest("Invalid request");

            var user = await _userManager.FindByNameAsync(request.UserName);

            // 1. Kiểm tra user tồn tại và trạng thái
            if (user == null || !user.IsActive || user.LockoutEnabled)
            {
                return BadRequest("Đăng nhập không đúng");
            }

            // 2. CHỈ KIỂM TRA MẬT KHẨU (Không dùng SignInManager để tạo Cookie)
            var isPasswordValid = await _userManager.CheckPasswordAsync(user, request.Password);
            if (!isPasswordValid)
            {
                // Bạn có thể xử lý tăng AccessFailedCount ở đây nếu muốn Lockout
                await _userManager.AccessFailedAsync(user);
                return BadRequest("Đăng nhập không đúng");
            }

            // 3. Reset số lần đăng nhập sai nếu thành công
            await _userManager.ResetAccessFailedCountAsync(user);

            //Authorization
            var roles = await _userManager.GetRolesAsync(user);
            var permissions = await this.GetPermissionsByUserIdAsync(user.Id.ToString());

            var claimsList = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(UserClaims.Id, user.Id.ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.UserName),
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(UserClaims.FirstName, user.FirstName),
                new Claim(UserClaims.Roles, string.Join(";", roles)),
                new Claim(UserClaims.Permissions, JsonSerializer.Serialize(permissions)),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            // Add individual permission claims for authorization handler
            foreach (var permission in permissions)
            {
                claimsList.Add(new Claim("Permission", permission, ClaimValueTypes.String, "LOCAL AUTHORITY"));
            }

            var claims = claimsList.ToArray();
            var accessToken = _tokenService.GenerateAccessToken(claims);
            var refreshToken = _tokenService.GenerateRefreshToken();

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(30);
            await _userManager.UpdateAsync(user);

            return Ok(new AuthenticatedResult()
            {
                Token = accessToken,
                RefreshToken = refreshToken
            });
        }

        [HttpPost("register")]
        public async Task<ActionResult> Register([FromBody] RegisterRequest request)
        {
            //Authentication
            if(request == null)
            {
                return BadRequest("Invalid request");
            }

            var user = await _userManager.FindByNameAsync(request.Username);
            if (user != null && (user.IsActive == true || !user.LockoutEnabled))
            {
                return BadRequest("Người dùng đã tồn tại");
            }

            var newUser = new AppUser(){ 
                Id = Guid.NewGuid(),
                FirstName = request.FirstName,
                LastName = request.LastName,
                UserName = request.Username,
                IsActive = true,
                DateCreated = DateTime.Now,
                Balance = 0,
                Email = request.Email,
                EmailConfirmed = false,
                PhoneNumberConfirmed = false,
                TwoFactorEnabled = false,
                LockoutEnabled = false,
                AccessFailedCount = 0,
                RoyaltyAmountPerPost = 0,
                PasswordHash = _userManager.PasswordHasher.HashPassword(null, request.Password),
            };

            var result = await _userManager.CreateAsync(newUser);
            return Ok(result);
        }

        private async Task<List<string>> GetPermissionsByUserIdAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            var roles = await _userManager.GetRolesAsync(user);
            var permissions = new List<string>();

            var allPermissions = new List<RoleClaimsDto>();
            if (roles.Contains(Roles.Admin))
            {
                var types = typeof(Permissions).GetTypeInfo().DeclaredNestedTypes;
                foreach (var type in types)
                {
                    allPermissions.GetPermissions(type);
                }
                permissions.AddRange(allPermissions.Select(x => x.Value));
            }
            else
            {
                foreach(var roleName in roles)
                {
                    var role = await _roleManager.FindByNameAsync(roleName);
                    var claims = await _roleManager.GetClaimsAsync(role);
                    var roleClaimValues = claims.Select(x => x.Value).ToList();
                    permissions.AddRange(roleClaimValues);
                }
            }
            return permissions.Distinct().ToList();
        }
    }
}
