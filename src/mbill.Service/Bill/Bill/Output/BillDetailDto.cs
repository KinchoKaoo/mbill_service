﻿namespace mbill.Service.Bill.Statement.Output;

public class BillDetailDto : BillDto
{
    public string categoryParentName { get; set; }

    public string assetParentName { get; set; }
}