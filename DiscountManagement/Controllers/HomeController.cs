using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace DiscountManagement.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index(string message=null)
        {
            ViewBag.Title = "Login Page";
            ViewBag.Message = message;

            string[] myCookies = Request.Cookies.AllKeys;
            foreach (string cookie in myCookies)
            {
                Response.Cookies[cookie].Expires = DateTime.Now.AddDays(-1);
            }

            return View();
        }

        public ActionResult LogOff()
        {
            Session.Abandon();
            return RedirectToAction("Index", "Home", new { message = "You are logged off successfully!", area = "" });
        }
    }
}
