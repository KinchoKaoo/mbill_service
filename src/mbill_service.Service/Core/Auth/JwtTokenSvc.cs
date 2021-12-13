﻿using mbill_service.Core.Common.Configs;
using mbill_service.Core.Domains.Common.Consts;
using mbill_service.Core.Domains.Common.Enums.Base;
using mbill_service.Core.Domains.Entities.User;
using mbill_service.Core.Exceptions;
using mbill_service.Core.Interface.IRepositories.Core;
using mbill_service.Service.Core.Auth.Input;
using mbill_service.Service.Core.User;
using DotNetCore.Security;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace mbill_service.Service.Core.Auth
{
    public class JwtTokenSvc : IJwtTokenSvc
    {
        private readonly ILogger<JwtTokenSvc> _logger;
        private readonly IUserRepo _userRepo;
        private readonly IUserIdentitySvc _userIdentityService;
        private readonly IJsonWebTokenService _jsonWebTokenService;
        public JwtTokenSvc(ILogger<JwtTokenSvc> logger, IUserRepo userRepo, IUserIdentitySvc userIdentityService, IJsonWebTokenService jsonWebTokenService)
        {
            _logger = logger;
            _userRepo = userRepo;
            _userIdentityService = userIdentityService;
            _jsonWebTokenService = jsonWebTokenService;
        }

        public async Task<TokenDto> RefreshTokenAsync(string refreshToken)
        {
            UserEntity user = await _userRepo.GetUserAsync(r => r.RefreshToken == refreshToken);//获取用户信息记录的refreshToken

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
                new Claim (ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim (ClaimTypes.Email, user.Email?? ""),
                new Claim (ClaimTypes.GivenName, user.Nickname?? ""),
                new Claim (ClaimTypes.Name, user.Username?? ""),
            };
            user.Roles?.ForEach(r =>
            {
                claims.Add(new Claim(ClaimTypes.Role, r.Name));
                claims.Add(new Claim(CoreClaimTypes.Roles, r.Id.ToString()));
            });

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
}