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
            ViewBag.Title = "Transactions Page";

            if (!string.IsNullOrEmpty(Session["userName"] as string))
            {
                ViewBag.User = Session["userName"].ToString();
            }
            else
            {
                ViewBag.User = String.Empty;
            }

            return View();
        }

        public ActionResult Reports()
        {
            ViewBag.Title = "Reports Page";

            if (!string.IsNullOrEmpty(Session["userName"] as string))
            {
                ViewBag.User = Session["userName"].ToString();
            }
            else
            {
                ViewBag.User = String.Empty;
            }

            return View();
        }
    }
}