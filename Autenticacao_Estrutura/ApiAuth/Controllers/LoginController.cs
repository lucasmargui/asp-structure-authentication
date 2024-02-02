using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using ApiAuth.Models;
using ApiAuth.Repositories;
using ApiAuth.Services;
using System.Net;

namespace ApiAuth.Controllers
{

	[ApiController]
	[Route(template: "v1")]
	public class LoginController
	{
		[HttpPost]
		[Route("login")]
		public async Task<ActionResult<dynamic>> Authenticate([FromBody] User model)
		{
			// Recupera o usuário
			var user = UserRepository.Get(model.Username, model.Password);

			// Verifica se o usuário existe
			if (user == null)
				return HttpStatusCode.BadRequest;

			// Gera o Token
			var token = TokenService.GenerateToken(user);

			// Oculta a senha
			user.Password = "";

			// Retorna os dados
			return new
			{
				user = user,
				token = token
			};
		}


	}

}
