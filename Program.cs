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

//Activar Swagger en nuestra aplicación
//Desde aquí podemos configurar que a través de swagger se valide el token generado al autenticarnos y darnos los privilegios según el tipo de usuario

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

//Declaración del servicio de autenticación de Jwt
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters()
    {
        ValidateActor = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        //validamos que la validación está encriptada
        ValidateIssuerSigningKey = true, 
        //datos recogidos de app.settings.json
        ValidIssuer = builder.Configuration["Jwt:Issuer"], 
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
    };
});

//Importante añadir el servicio de autenticación

builder.Services.AddAuthorization();

/**
 * Aquí es donde registramos los servicios con inyección de dependencias
 * Señalamos que vamos a añadir los endpoints ("/create", "/get", etc)
 * y añadimos los servicios de usuarios y películas declarando sus interfaces y qué clase las implementan
 */

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSingleton<IMovieService, MovieService>();
builder.Services.AddSingleton<IUserService, UserService>();

var app = builder.Build();

//Importante usar Swagger justo después de builder.Build();

app.UseSwagger();

//Importante activar la autorización y autenticación

app.UseAuthorization();
app.UseAuthentication();

app.MapGet("/", () => "Hello World!").ExcludeFromDescription();

/**
 * Definición del endpoint de login con su método local, definido más abajo
 * 
 * Importante situarlo después de la declaración de app y antes de app.Run();
 */

app.MapPost("/login", (UserLogin user, IUserService service) => Login(user, service)).Accepts<UserLogin>("application/json").Produces<String>();

/**
 * Aquí se definen los endpoints de la API
 * 
 * Los métodos CRUD son locales, están definidos debajo
 */

//Restringimos a que sólo los administradores puedan crear películas
//Retorna 401 si no estás autenticado y forbidden si no eres administrador

app.MapPost("/create", [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "Administrator")]
    (Movie movie, IMovieService service) => Create(movie, service)).Accepts<Movie>("application/json").Produces<Movie>(statusCode: 200, contentType: "application/json"); 

//Get está restringido a los usuarios que estén autenticados, siendo indiferente su rol

app.MapGet("/get", [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "Standard, Administrator")]
(int id, IMovieService service) => Get(id, service)).Produces<Movie>();

//List no está restringido; pueden acceder tanto personas autenticadas como las que no

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

        //Claims contiene la información adicional del usuario que podemos codificar y unir con el token Jwt
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
 * Definición de los métodos CRUD
 * 
 * Estos métodos llaman al servicio para acceder al método correspondiente para realizar la operación.
 * Son de tipo IResult, en los cuales se retorna un objeto de la clase Result que incluye tanto el éxito o fracaso del proceso como el objeto devuelto.
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
 * En el if de este método, podemos comprobar si es nulo ya que en el método Update del servicio retornamos un null en caso de no encontrar el objeto a actualizar
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
