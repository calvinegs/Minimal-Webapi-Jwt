using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

ConfigurationManager _configuration = builder.Configuration;
var secret = _configuration.GetValue<string>("JwtSettings:Secret");

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
// builder.Services.AddSwaggerGen();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "JwtDemo", Version = "v1" });
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description = "Please enter JWT with Bearer into field",
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
                {
                    Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "Bearer"}
                },
            new string[] {}
        }
    });
});

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        // 當驗證失敗時，回應標頭會包含 WWW-Authenticate 標頭，這裡會顯示失敗的詳細錯誤原因
        options.IncludeErrorDetails = true; // 預設值為 true，有時會特別關閉

        options.TokenValidationParameters = new TokenValidationParameters
        {
            // 透過這項宣告，就可以從 "NAME" 取值
            NameClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
            // 透過這項宣告，就可以從 "Role" 取值，並可讓 [Authorize] 判斷角色
            RoleClaimType = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",

            // 驗證 Issuer (一般都會)
            ValidateIssuer = true,
            ValidIssuer = _configuration.GetValue<string>("JwtSettings:Issuer"),

            // 驗證 Audience (通常不太需要)
            ValidateAudience = false,
            //ValidAudience = "JwtAuthDemo", // 不驗證就不需要填寫

            // 驗證 Token 的有效期間 (一般都會)
            ValidateLifetime = true,

            // 如果 Token 中包含 key 才需要驗證，一般都只有簽章而已
            ValidateIssuerSigningKey = false,

            // 應該從 IConfiguration 取得
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret))
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
};

app.MapGet("/weatherforecast", () =>
{
    var forecast =  Enumerable.Range(1, 5).Select(index =>
        new WeatherForecast
        (
            DateTime.Now.AddDays(index),
            Random.Shared.Next(-20, 55),
            summaries[Random.Shared.Next(summaries.Length)]
        ))
        .ToArray();
    return forecast;
})
.WithName("GetWeatherForecast").RequireAuthorization();

app.MapPost("/signin", (LoginViewModel login) =>
    {
        if (ValidateUser(login))
        {
            var token = CreateToken(login);
            return Results.Ok(new { token });
        }
        else
        {
            return Results.BadRequest();
        }
    }
).WithName("SignIn").AllowAnonymous();

string CreateToken(LoginViewModel user)
{
    List<Claim> claims = new List<Claim>
    {
        new Claim(ClaimTypes.Name, user.Username),
        new Claim(ClaimTypes.Role, "Admin"),
        new Claim(ClaimTypes.Role, "Users"),
        new Claim("ProjectType", "TTG"),
    };

    var secretkey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(secret));    
    // _configuration.GetSection("JwtSettings:Secret").Value)

    var credentials = new SigningCredentials(secretkey, SecurityAlgorithms.HmacSha512Signature);

    var token = new JwtSecurityToken(   // 亦可使用　SecurityTokenDescriptor　來産生 Token
        issuer: _configuration.GetValue<string>("JwtSettings:Issuer"),
        audience: _configuration.GetValue<string>("JwtSettings:Audience"),
        claims: claims,
        expires: DateTime.Now.AddDays(1),
        signingCredentials: credentials);

    var jwt = new JwtSecurityTokenHandler().WriteToken(token);

    return jwt;
}

bool ValidateUser(LoginViewModel login)
{
    return login.Username == "cal" ? true : false;
}

app.MapGet("/claims", (ClaimsPrincipal user) =>
    {
        return Results.Ok(user.Claims.Select(p => new { p.Type, p.Value }));
    })
    .WithName("Claims")
    .RequireAuthorization();

app.MapGet("/username", (ClaimsPrincipal user) =>
    {
        return Results.Ok(user.Claims.FirstOrDefault(p => p.Type == ClaimTypes.Name)?.Value);
    })
    .WithName("Username")
    .RequireAuthorization();

app.MapGet("/roles", (ClaimsPrincipal user) =>
    {
        return Results.Ok(user.Claims.Select(p => new { p.Type, p.Value }).Where( c=> c.Type == ClaimTypes.Role));
    })
    .WithName("Userrole")
    .RequireAuthorization();

app.MapGet("/issuer", (ClaimsPrincipal user) =>
    {
        return Results.Ok(user.Claims.FirstOrDefault(p => p.Type == "iss")?.Value);
    })
    .WithName("Issuer")
    .RequireAuthorization();

await app.RunAsync();

record WeatherForecast(DateTime Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}

record LoginViewModel(string Username, string Password);