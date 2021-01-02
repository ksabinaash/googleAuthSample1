using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace DiscountManagement.Controllers
{
    public class DataController : Controller
    {
        // GET: Data
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult SignOff()        
        {
            Session.Abandon();
            return RedirectToAction("Index", "Home", new { area = "" });
        }
    }
}