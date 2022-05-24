﻿namespace mbill.Core.Domains.Entities.Bill;

/// <summary>
/// 流水记录实体
/// </summary>
[Table(Name = SystemConst.DbTablePrefix + "_bill")]
[Index("index_bill_on_type", "Type", false)]
[Index("index_bill_on_create_user_id_and_type", "Sort,CreateUserId", false)]
[Index("index_bill_on_create_user_id_and_category_id", "CategoryId,CreateUserId", false)]
[Index("index_bill_on_create_user_id_and_asset_id", "AssetId,CreateUserId", false)]
[Index("index_bill_on_year_and_month_and_day_and_time", "Year,Month,Day,Time", false)]
public class BillEntity : FullAduitEntity
{
    /// <summary>
    /// 分类Id
    /// </summary>
    public long? CategoryId { get; set; }

    /// <summary>
    /// 资产Id
    /// </summary>
    public long AssetId { get; set; }

    /// <summary>
    /// 目标资产Id
    /// </summary>
    public long? TargetAssetId { get; set; }

    /// <summary>
    /// 金额
    /// </summary>
    [Column(Precision = 12, Scale = 2)]
    public decimal Amount { get; set; }

    /// <summary>
    /// 账户余额
    /// </summary>
    [Column(Precision = 12, Scale = 2)]
    public decimal AssetResidue { get; set; }

    /// <summary>
    /// 记录类型：支出、收入、转账、还款
    /// </summary>
    [Column(StringLength = 10, IsNullable = false)]
    public string Type { get; set; }

    /// <summary>
    /// 说明
    /// </summary>
    [Column(StringLength = 200)]
    public string Description { get; set; }

    /// <summary>
    /// 地点
    /// </summary>
    [Column(StringLength = 200)]
    public string Address { get; set; }

    /// <summary>
    /// 地点:省
    /// </summary>
    [Column(StringLength = 50)]
    public string Province { get; set; }

    /// <summary>
    /// 地点:市
    /// </summary>
    [Column(StringLength = 50)]
    public string City { get; set; }

    /// <summary>
    /// 地点:区/县
    /// </summary>
    [Column(StringLength = 50)]
    public string District { get; set; }

    /// <summary>
    /// 地点:街道/镇
    /// </summary>
    [Column(StringLength = 70)]
    public string Street { get; set; }

    /// <summary>
    /// 记录日期：时间
    /// </summary>
    [Column(StringLength = 10)]
    public DateTime Time { get; set; }

}