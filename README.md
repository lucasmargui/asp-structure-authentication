<H1 align="center">Api de Autenticação e Autorização</H1>
<p align="center">🚀 Projeto de criação de uma api de sistema de Autenticação e Autorização para referências futuras</p>



## Recursos Utilizados

* .NET 5.0
* Authentication – versão 2.2.0
* JwtBearer – versão 5.0.12

## Adicionando pacotes ao projeto

<details>
  <summary>Clique para mostrar conteúdo</summary>
  
Para instalação de pacotes com versões antigas utilize dotnet no Windows powershell

```
dotnet add package Microsoft.AspNetCore.Authentication --version 2.2.0
```
```
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer --version 5.0.12
```


</details>


## Criação de repositório

<details>
  <summary>Clique para mostrar conteúdo</summary>
  
 ```
 Repositories/UserRepository.cs
 ```

 Representará um banco de dados com usuários e suas roles
 
```
var users = new List<User>();
users.Add(new User { Id = 1, Username = "Lucas", Password = "123", Role = "manager" });
users.Add(new User { Id = 2, Username = "Martins", Password = "321", Role = "employee" });
return users.Where(x => x.Username.ToLower() == username.ToLower() && x.Password == x.Password).FirstOrDefault();

```

</details>



## Criação chave privada
<details>
  <summary>Clique para mostrar conteúdo</summary>
  
```
Settings.cs
```
Contém um chave privada para criação de tokens onde o servidor utiliza para descriptografar uma parte dos tokens recebidos 

```

public static class Settings
{
	public static string Secret = "fedaf7d8863b48e197b9287d492b708e";
}

```

</details>




## Criação do Service

<details>
  <summary>Clique para mostrar conteúdo</summary>
  
```
Services/TokenService.cs
```

Este service será responsável para criação de tokens, gerando um token JWT utilziando ASP.NET 5

```
public class TokenService
	{
	public static string GenerateToken(User user)
		{
			var tokenHandler = new JwtSecurityTokenHandler();
			var key = Encoding.ASCII.GetBytes(Settings.Secret);
			var tokenDescriptor = new SecurityTokenDescriptor
			{
				Subject = new ClaimsIdentity(new Claim[]
				{
					new Claim(ClaimTypes.Name, user.Username.ToString()), //User.Identity.name
					new Claim(ClaimTypes.Role, user.Role.ToString()) //User.isInRole()
				}),
				Expires = DateTime.UtcNow.AddHours(2),
				SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
			};
			var token = tokenHandler.CreateToken(tokenDescriptor);
			return tokenHandler.WriteToken(token);
		}
	}
}
```

</details>




## Adicionando autenticação e autorização


<details>
  <summary>Clique para mostrar conteúdo</summary>
  
### Configurando autenticação

Definindo quais perfis tem acesso a determinadas ações de controladores
```

var key = Encoding.ASCII.GetBytes(Settings.Secret);

			services.AddAuthentication(x =>
			{
				x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
				x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
			}).AddJwtBearer(x =>
			{
				x.RequireHttpsMetadata = false;
				x.SaveToken = true;
				x.TokenValidationParameters = new TokenValidationParameters
				{
					ValidateIssuerSigningKey = true,
					IssuerSigningKey = new SymmetricSecurityKey(key),
					ValidateIssuer = false,
					ValidateAudience = false
				};
			});

```




<div align="center">
<img src="https://github.com/lucasmargui/ASP_Autenticacao_Estrutura/assets/157809964/f3ad1ea9-b763-474b-918f-ddbb2241535a" style="width:45%">	
<img src="https://github.com/lucasmargui/ASP_Autenticacao_Estrutura/assets/157809964/4c403ed5-c1e9-4acf-87b0-842f090b15a0" style="width:45%">
</div>



</details>





## Autenticando

<details>
  <summary>Clique para mostrar conteúdo</summary>
  
```
    Controller/LoginController.cs

```

Explorando toda autenticação e autorização no Controller

```
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
```

</details>





## Controlador de Rotas

<details>
  <summary>Clique para mostrar conteúdo</summary>
  
```
Controller/HomeController.cs

```

Criação de 4 métodos explorando as autorizações e rotas

```
namespace ApiAuth.Controllers
{
	[ApiController]
	public class HomeController : ControllerBase
	{
		[HttpGet]
		[Route("anonymous")]
		[AllowAnonymous]
		public string Anonymous() => "Anônimo";

		[HttpGet]
		[Route("authenticated")]
		[Authorize]
		public string Authenticated() => String.Format("Autenticado - {0}", User.Identity.Name);

		[HttpGet]
		[Route("employee")]
		[Authorize(Roles = "employee")]
		public string Employee() => "Funcionário";

		[HttpGet]
		[Route("manager")]
		[Authorize(Roles = "manager")]
		public string Manager() => "Gerente";
	}
}

```

</details>



## Tipos de acesso

### Anônimo


<div align="center">
	<h3> </h3>
<img src="https://github.com/lucasmargui/ASP_Autenticacao_Estrutura/assets/157809964/f446f9e6-7059-4b14-af75-e964645f6e3a" style="width:100%">
</div>





### Não autenticado 


<div align="center">
	<h3> </h3>
<img src="https://github.com/lucasmargui/ASP_Autenticacao_Estrutura/assets/157809964/bb9c0a34-0c7b-485c-a26e-b40dfeb62ebc" style="width:100%">
</div>


### Autenticação





<div align="center">
	<h3> </h3>
<img src="https://github.com/lucasmargui/ASP_Autenticacao_Estrutura/assets/157809964/ef5c76b1-0c7b-4622-a306-e5d58efd67bf" style="width:100%">
</div>



### Autenticado


<div align="center">
	<h3> </h3>
<img src="https://github.com/lucasmargui/ASP_Autenticacao_Estrutura/assets/157809964/b951b882-d68f-433f-a39c-3b682b0ce6c1" style="width:100%">
</div>



### Autenticado porém sem acesso a Employee


<div align="center">
	<h3> </h3>
<img src="https://github.com/lucasmargui/ASP_Autenticacao_Estrutura/assets/157809964/9bcd7c40-6997-4d98-8736-f7310839738b" style="width:100%">
</div>


### Autenticado e com acesso a Manager


<div align="center">
<img src="https://github.com/lucasmargui/ASP_Autenticacao_Estrutura/assets/157809964/48dd5e40-450e-49db-999c-7fee52b08966" style="width:100%">
</div>


## Estrutura do Projeto

<div align="center">
	<h3> </h3>
<img src="" style="width:100%">
</div>



