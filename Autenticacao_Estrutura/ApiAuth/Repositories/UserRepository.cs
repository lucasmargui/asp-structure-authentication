using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using ApiAuth.Models;

namespace ApiAuth.Repositories
{
	public static class UserRepository
	{
		public static User Get(string username, string password)
		{

			var users = new List<User>();
			users.Add(new User { Id = 1, Username = "Lucas", Password = "123", Role = "manager" });
			users.Add(new User { Id = 2, Username = "Martins", Password = "321", Role = "employee" });
			return users.Where(x => x.Username.ToLower() == username.ToLower() && x.Password == x.Password).FirstOrDefault();

		}
	}
}
