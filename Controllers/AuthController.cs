using DemoJWT.Data;
using DemoJWT.Dtos;
using DemoJWT.Models;
using DemoJWT.Service;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace TodoApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly EmailService _emailService;
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly IMemoryCache _memoryCache;
      

        public AuthController(UserManager<IdentityUser> userManager, ApplicationDbContext context, EmailService emailService, IConfiguration configuration, IMemoryCache memoryCache)
        {
            _emailService = emailService;
            _userManager = userManager;
            _context = context;
            _configuration = configuration;
            _memoryCache = memoryCache;
        }

        /// <summary>
        /// Đăng ký tài khoản mới
        /// </summary>
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromQuery] string username, [FromQuery] string password)
        {
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
                return BadRequest("Username và password không được để trống");

            var user = new IdentityUser { UserName = username, Email = username + "@example.com" };
            var result = await _userManager.CreateAsync(user, password);
            if (result.Succeeded)
                return Ok("Đăng ký thành công");
            return BadRequest(result.Errors);
        }

        /// <summary>
        /// Đăng nhập bằng Google
        /// </summary>
        [HttpPost("google-login")]
        public async Task<IActionResult> GoogleLogin([FromBody] GoogleLoginModel model)
        {
            try
            {
                // Xác thực Google ID Token
                var settings = new GoogleJsonWebSignature.ValidationSettings
                {
                    Audience = new[] { _configuration["Google:ClientId"] }
                };
                var payload = await GoogleJsonWebSignature.ValidateAsync(model.IdToken, settings);

                // Tìm hoặc tạo người dùng trong AspNetUsers
                var user = await _userManager.FindByEmailAsync(payload.Email);
                if (user == null)
                {
                    user = new IdentityUser
                    {
                        UserName = payload.Email, // Dùng email làm username mặc định
                        Email = payload.Email,
                        EmailConfirmed = true
                    };
                    var result = await _userManager.CreateAsync(user);
                    if (!result.Succeeded)
                        return BadRequest(result.Errors);

                    // Thêm thông tin đăng nhập Google vào AspNetUserLogins
                    await _userManager.AddLoginAsync(user, new UserLoginInfo("Google", payload.Subject, "Google"));
                }

                // Tạo Access Token và Refresh Token
                var authClaims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.UserName),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };

                var accessToken = GenerateAccessToken(authClaims);
                var refreshToken = await GenerateRefreshToken(user.Id);

                // Lấy username để trả về
                // Username có thể là payload.Name (tên người dùng từ Google) hoặc user.UserName (email nếu không có tên)
                var username = payload.Name ?? user.UserName;

                return Ok(new
                {
                    AccessToken = accessToken,
                    RefreshToken = refreshToken.Token,
                    Username = username // Thêm username vào response
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = "Token Google không hợp lệ: " + ex.Message });
            }
        }

        /// <summary>
        /// Đăng nhập bằng username và password
        /// </summary>
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromQuery] string username, [FromQuery] string password)
        {
            var user = await _userManager.FindByNameAsync(username);
            if (user != null && await _userManager.CheckPasswordAsync(user, password))
            {
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

                var accessToken = GenerateAccessToken(authClaims);
                var refreshToken = await GenerateRefreshToken(user.Id);

                return Ok(new { AccessToken = accessToken, RefreshToken = refreshToken.Token });
            }
            return Unauthorized("Tên đăng nhập hoặc mật khẩu không đúng");
        }

        /// <summary>
        /// Làm mới Access Token bằng Refresh Token
        /// </summary>
        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromQuery] string refreshToken)
        {
            var token = _context.RefreshTokens.FirstOrDefault(t => t.Token == refreshToken && !t.IsRevoked);
            if (token == null || token.ExpiryDate < DateTime.UtcNow)
                return Unauthorized("Refresh token không hợp lệ hoặc đã hết hạn");

            var user = await _userManager.FindByIdAsync(token.UserId);
            if (user == null)
                return Unauthorized("Không tìm thấy người dùng");

            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            };

            var newAccessToken = GenerateAccessToken(authClaims);
            var newRefreshToken = await GenerateRefreshToken(user.Id);

            // Đánh dấu refresh token cũ đã được sử dụng
            token.IsRevoked = true;
            _context.RefreshTokens.Update(token);
            await _context.SaveChangesAsync();

            return Ok(new { AccessToken = newAccessToken, RefreshToken = newRefreshToken.Token });
        }

        /// <summary>
        /// Tạo Access Token mới
        /// </summary>
        private string GenerateAccessToken(IEnumerable<Claim> claims)
        {
            var jwtSettings = _configuration.GetSection("Jwt");
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["Key"]));
            var token = new JwtSecurityToken(
                issuer: jwtSettings["Issuer"],
                audience: jwtSettings["Audience"],
                expires: DateTime.UtcNow.AddMinutes(int.Parse(jwtSettings["AccessTokenExpirationMinutes"])),
                claims: claims,
                signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
            );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        /// <summary>
        /// Tạo Refresh Token mới
        /// </summary>
        private async Task<RefreshToken> GenerateRefreshToken(string userId)
        {
            var refreshToken = new RefreshToken
            {
                UserId = userId,
                Token = Guid.NewGuid().ToString(),
                ExpiryDate = DateTime.UtcNow.AddDays(int.Parse(_configuration["Jwt:RefreshTokenExpirationDays"])),
                IsRevoked = false
            };
            _context.RefreshTokens.Add(refreshToken);
            await _context.SaveChangesAsync();
            return refreshToken;
        }


        [HttpPost("send-otp")]
        public async Task<IActionResult> SendOtp([FromBody] OtpRequest model)
        {
            if (string.IsNullOrEmpty(model.Email))
                return BadRequest("Email is required");

            // Kiểm tra email có tồn tại không (tùy chọn)
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
                return BadRequest("Email not found");

            // Tạo mã OTP ngẫu nhiên (6 chữ số)
            string otp = GenerateOtp();
            DateTime expiryTime = DateTime.UtcNow.AddMinutes(5); // OTP hết hạn sau 5 phút

            // Gửi email chứa OTP
            try
            {
                await _emailService.SendOtpEmailAsync(model.Email, otp);
                // Lưu OTP vào bộ nhớ hoặc DB (tùy chọn)
                // Ví dụ: Sử dụng MemoryCache
                // MemoryCache.Set(model.Email, new OtpModel { Otp = otp, ExpiryTime = expiryTime }, TimeSpan.FromMinutes(5));

                _memoryCache.Set(model.Email, new OtpModel { Otp = otp, ExpiryTime = expiryTime }, TimeSpan.FromMinutes(5));
                return Ok(new { message = "OTP sent successfully", otpExpiry = expiryTime });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Failed to send OTP: {ex.Message}");
            }
        }
        [HttpPost("verify-otp")]
        public IActionResult VerifyOtp([FromBody] VerifyOtpRequest model)
        {
            if (_memoryCache.TryGetValue(model.Email, out OtpModel otpModel) && otpModel.ExpiryTime > DateTime.UtcNow)
            {
                if (otpModel.Otp == model.Otp)
                {
                    _memoryCache.Remove(model.Email); // Xóa OTP sau khi xác minh thành công
                    return Ok(new { message = "OTP verified successfully" });
                }
                return BadRequest("Invalid OTP");
            }
            return BadRequest("OTP expired or not found");
        }
        private string GenerateOtp()
        {
            Random random = new Random();
            return random.Next(100000, 999999).ToString(); // Tạo mã 6 chữ số
        }
    
      
    }


    public class VerifyOtpRequest
    {
        public string Email { get; set; }
        public string Otp { get; set; }
    }
    /// <summary>
    /// Model cho đăng nhập thông thường
    /// </summary>
    public class LoginModel
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }

    /// <summary>
    /// Model cho đăng nhập bằng Google
    /// </summary>
    public class GoogleLoginModel
    {
        public string IdToken { get; set; }
    }

    /// <summary>
    /// Model cho refresh token
    /// </summary>
    public class RefreshTokenModel
    {
        public string RefreshToken { get; set; }
    }

    public class OtpRequest
    {
        public string Email { get; set; }
    }
}