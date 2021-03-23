using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using roleDemo.Data;
using roleDemo.Repositories;
using roleDemo.ViewModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace roleDemo.Controllers
{
    // This annotation can be used at the class or method level.
    // The annotation could include a comma separated list or different
    // roles.
    [Authorize(Roles = "Admin")]
    public class RoleController : Controller
    {
        ApplicationDbContext _context;

        public RoleController(ApplicationDbContext context)
        {
            _context = context;
        }

        // GET: Role
        public ActionResult Index()
        {
            RoleRepo roleRepo = new RoleRepo(_context);
            return View(roleRepo.GetAllRoles());
        }

        [HttpGet]
        public ActionResult Create()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Create(RoleVM roleVM)
        {
            if (ModelState.IsValid)
            {
                RoleRepo roleRepo = new RoleRepo(_context);
                var success = roleRepo.CreateRole(roleVM.RoleName);
                if (success)
                {
                    return RedirectToAction(nameof(Index));
                }
            }
            ViewBag.Error = "An error occurred while creating this role. Please try again.";
            return View();
        }

    }
}
