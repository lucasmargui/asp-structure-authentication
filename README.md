<H1 align="center">Authentication and Authorization API</H1>
<p align="center">🚀 Project to create an Authentication and Authorization system api for future references</p>



## Resources Used

* .NET 5.0
* Authentication – version 2.2.0
* JwtBearer – version 5.0.12

## Types of access

<div align="center">
<h3> Anonymous </h3>
<img src="https://github.com/lucasmargui/ASP_Autenticacao_Estrutura/assets/157809964/f446f9e6-7059-4b14-af75-e964645f6e3a" style="width:70%">
</div>


<div align="center">
<h3> Not authenticated </h3>
<img src="https://github.com/lucasmargui/ASP_Autenticacao_Estrutura/assets/157809964/bb9c0a34-0c7b-485c-a26e-b40dfeb62ebc" style="width:70%">
</div>

<div align="center">
<h3> Authentication </h3>
<img src="https://github.com/lucasmargui/ASP_Autenticacao_Estrutura/assets/157809964/ef5c76b1-0c7b-4622-a306-e5d58efd67bf" style="width:70%">
</div>


<div align="center">
<h3> Authenticated </h3>
<img src="https://github.com/lucasmargui/ASP_Autenticacao_Estrutura/assets/157809964/b951b882-d68f-433f-a39c-3b682b0ce6c1" style="width:70%">
</div>


<div align="center">
<h3> Authenticated but without access to Employee </h3>
<img src="https://github.com/lucasmargui/ASP_Autenticacao_Estrutura/assets/157809964/9bcd7c40-6997-4d98-8736-f7310839738b" style="width:70%">
</div>


<div align="center">
<h3> Authenticated and with access to Manager </h3>	
<img src="https://github.com/lucasmargui/ASP_Autenticacao_Estrutura/assets/157809964/48dd5e40-450e-49db-999c-7fee52b08966" style="width:70%">
</div>


## Adding packages to the project

<details>
   <summary>Click to show content</summary>
  
To install packages with old versions, use dotnet in Windows powershell

```
dotnet add package Microsoft.AspNetCore.Authentication --version 2.2.0
```
```
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer --version 5.0.12
```


</details>


## Repository create

<details>
   <summary>Click to show content</summary>
  
  ```
  Repositories/UserRepository.cs
  ```

  It will represent a database with users and their roles
 
```
var users = new List<User>();
users.Add(new User { Id = 1, Username = "Lucas", Password = "123", Role = "manager" });
users.Add(new User { Id = 2, Username = "Martins", Password = "321", Role = "employee" });
return users.Where(x => x.Username.ToLower() == username.ToLower() && x.Password == x.Password).FirstOrDefault();

```

</details>



## Private key create
<details>
   <summary>Click to show content</summary>
  
```
Settings.cs
```
Contains a private key for creating tokens which the server uses to decrypt a portion of the tokens received

```

public static class Settings
{
public static string Secret = "fedaf7d8863b48e197b9287d492b708e";
}

```

</details>




## Service Create

<details>
   <summary>Click to show content</summary>
  
```
Services/TokenService.cs
```

This service will be responsible for creating tokens, generating a JWT token using ASP.NET 5

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




## Adding authentication and authorization


<details>
   <summary>Click to show content</summary>
  
### Configuring authentication

Defining which profiles have access to certain controller actions
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





## Authenticating

<details>
   <summary>Click to show content</summary>
  
```
     Controller/LoginController.cs

```

Exploring all authentication and authorization in the Controller

```
[ApiController]
[Route(template: "v1")]
public class LoginController
{
[HttpPost]
[Route("login")]
public async Task<ActionResult<dynamic>> Authenticate([FromBody] User model)
{
// Retrieves the user
var user = UserRepository.Get(model.Username, model.Password);

// Checks if the user exists
if (user == null)
return HttpStatusCode.BadRequest;

// Generate the Token
var token = TokenService.GenerateToken(user);

// Hide the password
user.Password = "";

// Returns the data
return new
{
user = user,
token = token
};
}


}
```

</details>

## Route Controller

<details>
   <summary>Click to show content</summary>
  
```
Controller/HomeController.cs

```

Creation of 4 methods exploring authorizations and routes

```
ApiAuth.Controllers namespace
{
[ApiController]
public class HomeController : ControllerBase
{
[HttpGet]
[Route("anonymous")]
[AllowAnonymous]
public string Anonymous() => "Anonymous";

[HttpGet]
[Route("authenticated")]
[Authorize]
public string Authenticated() => String.Format("Authenticated - {0}", User.Identity.Name);

[HttpGet]
[Route("employee")]
[Authorize(Roles = "employee")]
public string Employee() => "Employee";

[HttpGet]
[Route("manager")]
[Authorize(Roles = "manager")]
public string Manager() => "Manager";
}
}

```

</details>







