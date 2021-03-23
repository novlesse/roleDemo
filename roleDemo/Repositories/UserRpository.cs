using roleDemo.Data;
using roleDemo.ViewModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace roleDemo.Repositories
{
    public class UserRepo
    {
        ApplicationDbContext _context;

        public UserRepo(ApplicationDbContext context)
        {
            this._context = context;
        }

        // Get all users in the database.
        public IEnumerable<UserVM> All()
        {
            var users = _context.Users.Select(u => new UserVM()
            {
                Email = u.Email
            });
            return users;
        }

    }
}
