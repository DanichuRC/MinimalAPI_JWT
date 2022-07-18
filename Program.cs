using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using MinimalJwt.Models;
using MinimalJwt.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

//Activar Swagger en nuestra aplicaci�n
//Desde aqu� podemos configurar que a trav�s de swagger se valide el token generado al autenticarnos y darnos los privilegios seg�n el tipo de usuario

builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Name = "Authorization",
        Description = "Bearer Authentication with JWT Token",
        Type = SecuritySchemeType.Http
    });
    options.AddSecurityRequirement( new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Id = "Bearer",
                    Type = ReferenceType.SecurityScheme
                }
            },
            new List<string>()
        }
    });
});

//Declaraci�n del servicio de autenticaci�n de Jwt
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters()
    {
        ValidateActor = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        //validamos que la validaci�n est� encriptada
        ValidateIssuerSigningKey = true, 
        //datos recogidos de app.settings.json
        ValidIssuer = builder.Configuration["Jwt:Issuer"], 
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
    };
});

//Importante a�adir el servicio de autenticaci�n

builder.Services.AddAuthorization();

/**
 * Aqu� es donde registramos los servicios con inyecci�n de dependencias
 * Se�alamos que vamos a a�adir los endpoints ("/create", "/get", etc)
 * y a�adimos los servicios de usuarios y pel�culas declarando sus interfaces y qu� clase las implementan
 */

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSingleton<IMovieService, MovieService>();
builder.Services.AddSingleton<IUserService, UserService>();

var app = builder.Build();

//Importante usar Swagger justo despu�s de builder.Build();

app.UseSwagger();

//Importante activar la autorizaci�n y autenticaci�n

app.UseAuthorization();
app.UseAuthentication();

app.MapGet("/", () => "Hello World!").ExcludeFromDescription();

/**
 * Definici�n del endpoint de login con su m�todo local, definido m�s abajo
 * 
 * Importante situarlo despu�s de la declaraci�n de app y antes de app.Run();
 */

app.MapPost("/login", (UserLogin user, IUserService service) => Login(user, service)).Accepts<UserLogin>("application/json").Produces<String>();

/**
 * Aqu� se definen los endpoints de la API
 * 
 * Los m�todos CRUD son locales, est�n definidos debajo
 */

//Restringimos a que s�lo los administradores puedan crear pel�culas
//Retorna 401 si no est�s autenticado y forbidden si no eres administrador

app.MapPost("/create", [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "Administrator")]
    (Movie movie, IMovieService service) => Create(movie, service)).Accepts<Movie>("application/json").Produces<Movie>(statusCode: 200, contentType: "application/json"); 

//Get est� restringido a los usuarios que est�n autenticados, siendo indiferente su rol

app.MapGet("/get", [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "Standard, Administrator")]
(int id, IMovieService service) => Get(id, service)).Produces<Movie>();

//List no est� restringido; pueden acceder tanto personas autenticadas como las que no

app.MapGet("/list", (IMovieService service) => List(service)).Produces<List<Movie>>(statusCode: 200, contentType: "application/json");

app.MapPut("/update", [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "Administrator")]
(Movie newMovie, IMovieService service) => Update(newMovie, service)).Accepts<Movie>("application/json").Produces<Movie>(statusCode: 200, contentType: "application/json");

app.MapDelete("/delete", [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "Administrator")]
(int id, IMovieService service) => Delete(id, service)).Accepts<Movie>("application/json").Produces<bool>();

IResult Login(UserLogin user, IUserService service)
{
    if(!string.IsNullOrEmpty(user.UserName) && !string.IsNullOrEmpty(user.Password))
    {
        var loggedInUser = service.Get(user);
        if (loggedInUser is null) return Results.NotFound("User not found");

        //Claims contiene la informaci�n adicional del usuario que podemos codificar y unir con el token Jwt
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, loggedInUser.UserName),
            new Claim(ClaimTypes.Email, loggedInUser.EmailAddress),
            new Claim(ClaimTypes.GivenName, loggedInUser.GivenName),
            new Claim(ClaimTypes.Surname, loggedInUser.Surname),
            new Claim(ClaimTypes.Role, loggedInUser.Role),
        };

        var token = new JwtSecurityToken
        (
         issuer: builder.Configuration["Jwt:Issuer"],
         audience: builder.Configuration["Jwt:Audience"],
         claims: claims,
         expires: DateTime.UtcNow.AddDays(60),
         notBefore: DateTime.UtcNow,
         signingCredentials: new SigningCredentials(
             new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"])),
             SecurityAlgorithms.HmacSha256)
        );

        var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

        return Results.Ok(tokenString);
    }
    return Results.BadRequest("Invalid user credentials");
}

/**
 * Definici�n de los m�todos CRUD
 * 
 * Estos m�todos llaman al servicio para acceder al m�todo correspondiente para realizar la operaci�n.
 * Son de tipo IResult, en los cuales se retorna un objeto de la clase Result que incluye tanto el �xito o fracaso del proceso como el objeto devuelto.
 */

IResult Create(Movie movie, IMovieService service) 
{
    var result = service.Create(movie);
    return Results.Ok(result);
} 

IResult Get(int id, IMovieService service)
{
    var movie = service.Get(id);

    if (movie is null) return Results.NotFound("Movie not found");

    return Results.Ok(movie);
}

IResult List(IMovieService service)
{
    var movies = service.List();

    return Results.Ok(movies);
}

/**
 * En el if de este m�todo, podemos comprobar si es nulo ya que en el m�todo Update del servicio retornamos un null en caso de no encontrar el objeto a actualizar
 */

IResult Update(Movie newMovie, IMovieService service)
{
    var updatedMovie = service.Update(newMovie);

    if (updatedMovie is null) return Results.NotFound("Movie not found");

    return Results.Ok(updatedMovie);
}

IResult Delete(int id, IMovieService service)
{
    var result = service.Delete(id);

    if (!result) Results.BadRequest("Something went wrong");

    return Results.Ok(result);
}

//Importante usar SwaggerUI justo antes de app.Run();

app.UseSwaggerUI();

app.Run();
