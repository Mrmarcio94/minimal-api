using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using MinimalApi;
using MinimalApi.Dominio.Entidades;
using MinimalApi.Dominio.Enuns;
using MinimalApi.Dominio.Interfaces;
using MinimalApi.Dominio.ModelViews;
using MinimalApi.Dominio.Servicos;
using MinimalApi.DTOs;
using MinimalApi.Infraestrutura.Db;

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

public class Startup
{
    public IConfiguration Configuration { get; set; }
    private readonly byte[] _jwtKeyBytes;

    public Startup(IConfiguration configuration)
    {
        Configuration = configuration;
        
        // CORREÇÃO: Captura o valor real da string configurada no appsettings.json
        string jwtKey = Configuration.GetSection("Jwt").Value ?? string.Empty;
        _jwtKeyBytes = Encoding.UTF8.GetBytes(jwtKey);
    }

    public void ConfigureServices(IServiceCollection services)
    {
        services.AddAuthentication(options => {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        }).AddJwtBearer(options => {
            options.TokenValidationParameters = new TokenValidationParameters {
                ValidateLifetime = true,
                IssuerSigningKey = new SymmetricSecurityKey(_jwtKeyBytes),
                ValidateIssuer = false,
                ValidateAudience = false,
            };
        });

        services.AddAuthorization();

        // Injeção de Dependência
        services.AddScoped<IAdministradorServico, AdministradorServico>();
        services.AddScoped<IVeiculoServico, VeiculoServico>();

        // Configuração do Swagger
        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen(options => {
            options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme {
                Name = "Authorization",
                Type = SecuritySchemeType.Http,
                Scheme = "bearer",
                BearerFormat = "JWT",
                In = ParameterLocation.Header,
                Description = "Insira o token JWT aqui"
            });

            options.AddSecurityRequirement(new OpenApiSecurityRequirement {
                {
                    new OpenApiSecurityScheme {
                        Reference = new OpenApiReference {
                            Type = ReferenceType.SecurityScheme,
                            Id = "Bearer"
                        }
                    },
                    Array.Empty<string>()
                }
            });
        });

        // Banco de Dados
        string connectionString = Configuration.GetConnectionString("MySql") ?? string.Empty;
        services.AddDbContext<DbContexto>(options => {
            options.UseMySql(connectionString, ServerVersion.AutoDetect(connectionString));
        });

        // CORS
        services.AddCors(options => {
            options.AddDefaultPolicy(builder => {
                builder.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader();
            });
        });
    }

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        app.UseSwagger();
        app.UseSwaggerUI();

        app.UseRouting();

        app.UseCors();

        app.UseAuthentication();
        app.UseAuthorization();

        app.UseEndpoints(endpoints => {

            #region Home
            endpoints.MapGet("/", () => Results.Json(new Home()))
                .AllowAnonymous()
                .WithTags("Home");
            #endregion

            #region Administradores
            string GerarTokenJwt(Administrador administrador) {
                if (_jwtKeyBytes.Length == 0) return string.Empty;

                var securityKey = new SymmetricSecurityKey(_jwtKeyBytes);
                var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

                var claims = new List<Claim> {
                    new("Email", administrador.Email),
                    new("Perfil", administrador.Perfil),
                    new(ClaimTypes.Role, administrador.Perfil) // Simplificado com target-typed new
                };
                
                var token = new JwtSecurityToken(
                    claims: claims,
                    expires: DateTime.Now.AddDays(1),
                    signingCredentials: credentials
                );

                return new JwtSecurityTokenHandler().WriteToken(token);
            }

            endpoints.MapPost("/administradores/login", ([FromBody] LoginDTO loginDTO, IAdministradorServico administradorServico) => {
                var adm = administradorServico.Login(loginDTO);
                if (adm == null) return Results.Unauthorized();

                return Results.Ok(new AdministradorLogado {
                    Email = adm.Email,
                    Perfil = adm.Perfil,
                    Token = GerarTokenJwt(adm)
                });
            }).AllowAnonymous().WithTags("Administradores");

            endpoints.MapGet("/administradores", ([FromQuery] int? pagina, IAdministradorServico administradorServico) => {
                var administradores = administradorServico.Todos(pagina);
                
                // MELHORIA: Substituído o foreach manual por um Select do LINQ (Muito mais limpo)
                var adms = administradores.Select(adm => new AdministradorModelView {
                    Id = adm.Id,
                    Email = adm.Email,
                    Perfil = adm.Perfil
                }).ToList();

                return Results.Ok(adms);
            })
            .RequireAuthorization(new AuthorizeAttribute { Roles = "Adm" }) // MELHORIA: Removida a duplicação
            .WithTags("Administradores");

            endpoints.MapGet("/administradores/{id}", ([FromRoute] int id, IAdministradorServico administradorServico) => {
                var administrador = administradorServico.BuscaPorId(id);
                if (administrador == null) return Results.NotFound();

                return Results.Ok(new AdministradorModelView {
                    Id = administrador.Id,
                    Email = administrador.Email,
                    Perfil = administrador.Perfil
                });
            })
            .RequireAuthorization(new AuthorizeAttribute { Roles = "Adm" })
            .WithTags("Administradores");

            endpoints.MapPost("/administradores", ([FromBody] AdministradorDTO administradorDTO, IAdministradorServico administradorServico) => {
                var mensagensErro = new List<string>();

                if (string.IsNullOrEmpty(administradorDTO.Email)) mensagensErro.Add("Email não pode ser vazio");
                if (string.IsNullOrEmpty(administradorDTO.Senha)) mensagensErro.Add("Senha não pode ser vazia");
                if (administradorDTO.Perfil == null) mensagensErro.Add("Perfil não pode ser vazio");

                if (mensagensErro.Count > 0) 
                    return Results.BadRequest(new ErrosDeValidacao { Mensagens = mensagensErro });
                
                var administrador = new Administrador {
                    Email = administradorDTO.Email,
                    Senha = administradorDTO.Senha,
                    Perfil = administradorDTO.Perfil?.ToString() ?? Perfil.Editor.ToString()
                };

                administradorServico.Incluir(administrador);

                return Results.Created($"/administrador/{administrador.Id}", new AdministradorModelView {
                    Id = administrador.Id,
                    Email = administrador.Email,
                    Perfil = administrador.Perfil
                });
            })
            .RequireAuthorization(new AuthorizeAttribute { Roles = "Adm" })
            .WithTags("Administradores");
            #endregion

            #region Veiculos
            // Função local estática evita alocações desnecessárias de escopo externo
            static ErrosDeValidacao validaDTO(VeiculoDTO veiculoDTO) {
                var validacao = new ErrosDeValidacao { Mensagens = new List<string>() };

                if (string.IsNullOrEmpty(veiculoDTO.Nome)) validacao.Mensagens.Add("O nome não pode ser vazio");
                if (string.IsNullOrEmpty(veiculoDTO.Marca)) validacao.Mensagens.Add("A Marca não pode ficar em branco");
                if (veiculoDTO.Ano < 1950) validacao.Mensagens.Add("Veículo muito antigo, aceito somente anos superiores a 1950");

                return validacao;
            }

            endpoints.MapPost("/veiculos", ([FromBody] VeiculoDTO veiculoDTO, IVeiculoServico veiculoServico) => {
                var validacao = validaDTO(veiculoDTO);
                if (validacao.Mensagens.Count > 0) return Results.BadRequest(validacao);
                
                var veiculo = new Veiculo {
                    Nome = veiculoDTO.Nome,
                    Marca = veiculoDTO.Marca,
                    Ano = veiculoDTO.Ano
                };
                veiculoServico.Incluir(veiculo);

                return Results.Created($"/veiculo/{veiculo.Id}", veiculo);
            })
            .RequireAuthorization(new AuthorizeAttribute { Roles = "Adm,Editor" })
            .WithTags("Veiculos");

            endpoints.MapGet("/veiculos", ([FromQuery] int? pagina, IVeiculoServico veiculoServico) => {
                return Results.Ok(veiculoServico.Todos(pagina));
            })
            .RequireAuthorization() // Exige apenas autenticação geral
            .WithTags("Veiculos");

            endpoints.MapGet("/veiculos/{id}", ([FromRoute] int id, IVeiculoServico veiculoServico) => {
                var veiculo = veiculoServico.BuscaPorId(id);
                return veiculo == null ? Results.NotFound() : Results.Ok(veiculo);
            })
            .RequireAuthorization(new AuthorizeAttribute { Roles = "Adm,Editor" })
            .WithTags("Veiculos");

            endpoints.MapPut("/veiculos/{id}", ([FromRoute] int id, VeiculoDTO veiculoDTO, IVeiculoServico veiculoServico) => {
                var veiculo = veiculoServico.BuscaPorId(id);
                if (veiculo == null) return Results.NotFound();
                
                var validacao = validaDTO(veiculoDTO);
                if (validacao.Mensagens.Count > 0) return Results.BadRequest(validacao);
                
                veiculo.Nome = veiculoDTO.Nome;
                veiculo.Marca = veiculoDTO.Marca;
                veiculo.Ano = veiculoDTO.Ano;

                veiculoServico.Atualizar(veiculo);
                return Results.Ok(veiculo);
            })
            .RequireAuthorization(new AuthorizeAttribute { Roles = "Adm" })
            .WithTags("Veiculos");

            endpoints.MapDelete("/veiculos/{id}", ([FromRoute] int id, IVeiculoServico veiculoServico) => {
                var veiculo = veiculoServico.BuscaPorId(id);
                if (veiculo == null) return Results.NotFound();

                veiculoServico.Apagar(veiculo);
                return Results.NoContent();
            })
            .RequireAuthorization(new AuthorizeAttribute { Roles = "Adm" })
            .WithTags("Veiculos");
            #endregion
        });
    }
}