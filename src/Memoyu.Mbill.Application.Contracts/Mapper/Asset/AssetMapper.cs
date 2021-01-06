﻿/**************************************************************************  
*   =================================
*   CLR版本  ：4.0.30319.42000
*   命名空间 ：Memoyu.Mbill.Application.Contracts.Mapper.Asset
*   文件名称 ：AssetMapper.cs
*   =================================
*   创 建 者 ：Memoyu
*   创建日期 ：2021-01-07 0:18:30
*   邮箱     ：mmy6076@outlook.com
*   功能描述 ：
***************************************************************************/
using AutoMapper;
using Memoyu.Mbill.Application.Contracts.Dtos.Asset;
using Memoyu.Mbill.Domain.Entities.Asset;

namespace Memoyu.Mbill.Application.Contracts.Mapper.Asset
{
    public class AssetMapper : Profile
    {
        public AssetMapper()
        {
            CreateMap<ModifyAssetDto, AssetEntity>();
            CreateMap<AssetEntity, AssetDto>();
        }
    }
}
