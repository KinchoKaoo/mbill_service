﻿using EasyCaching.Core;
using Mbill.Core.Security.Dto;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace Mbill.Service.Core.Auth;

public class JwtTokenSvc : IJwtTokenSvc
{
    private readonly ILogger<JwtTokenSvc> _logger;
    private readonly IUserRepo _userRepo;
    private readonly IUserRoleRepo _userRoleRepo;
    private readonly IUserIdentitySvc _userIdentityService;
    private readonly IJwtService _jsonWebTokenService;
    private readonly IEasyCachingProvider _cachingProvider;
    private readonly IConfiguration _configuration;

    public JwtTokenSvc(
        ILogger<JwtTokenSvc> logger,
        IUserRepo userRepo,
        IUserRoleRepo userRoleRepo,
        IUserIdentitySvc userIdentityService,
        IJwtService jsonWebTokenService,
        IEasyCachingProvider cachingProvider, IConfiguration configuration)
    {
        _logger = logger;
        _userRepo = userRepo;
        _userRoleRepo = userRoleRepo;
        _userIdentityService = userIdentityService;
        _jsonWebTokenService = jsonWebTokenService;
        _cachingProvider = cachingProvider;
        _configuration = configuration;
    }

    public async Task<TokenDto> RefreshTokenAsync(string refreshToken)
    {
        var user = await _userRepo.GetUserAsync(r => r.RefreshToken == refreshToken);//获取用户信息记录的refreshToken

        if (user.IsNull())
        {
            throw new KnownException("该refreshToken无效!");
        }

        if (DateTime.Compare(user.LastLoginTime, DateTime.Now) > TimeSpan.FromSeconds(Appsettings.JwtBearer.Expires).Ticks)//如果登陆时长已超过Token过期时间，则直接返回异常重新登陆
        {
            throw new KnownException("请重新登录", ServiceResultCode.RefreshTokenError);
        }

        TokenDto tokens = await CreateTokenAsync(user);
        _logger.LogInformation($"用户{user.Username},Jwt RefreshToken 刷新-登录成功");

        return tokens;
    }

    public async Task<TokenDto> CreateTokenAsync(UserEntity user)
    {
        List<Claim> claims = new List<Claim>()
            {
                new Claim (ClaimTypes.NameIdentifier, user.BId.ToString()),
                new Claim (ClaimTypes.Email, user.Email?? ""),
                new Claim (ClaimTypes.GivenName, user.Nickname?? ""),
                new Claim (ClaimTypes.Name, user.Username?? ""),
            };

        var userRoles = await _userRoleRepo.Where(r => r.UserBId == user.BId).Include(r => r.Role).ToListAsync() ?? new List<UserRoleEntity>();
        var userRoleCaches = userRoles.Select(ur => new UserRoleCacheDto
        {
            RoleBId = ur.RoleBId,
            RoleType = ur.Role.Type,
        }).ToList();

        await _cachingProvider.SetAsync(CacheKeyConst.UserRole(user.BId), userRoleCaches, TimeSpan.FromHours(6));
        string token = _jsonWebTokenService.Encode(claims);

        string refreshToken = GenerateToken();
        user.ChangeLoginStatus(refreshToken);
        await _userRepo.UpdateAsync(user);

        return new TokenDto(token, refreshToken);
    }

    /// <summary>
    /// 生成RefreshToken
    /// </summary>
    /// <param name="size">长度</param>
    /// <returns></returns>
    private string GenerateToken(int size = 32)
    {
        var randomNumber = new byte[size];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }
    }
}
