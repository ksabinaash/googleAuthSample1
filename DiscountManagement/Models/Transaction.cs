using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace DiscountManagement.Models
{
    public class Transaction
    {
        public string CustomerName { get; set; }

        public string UserEmail { get; set; }

        public int MobileNumber { get; set; }
        
        public string ShopName { get; set; }

        public double BilledValue { get; set; }
        
        public double Discount { get; set; }

        public string DiscountReason { get; set; }

        public string OTP { get; set; }

        public string MessageTemplate { get; set; }

        public DateTime BilledDateTime { get; set; }
    }
}