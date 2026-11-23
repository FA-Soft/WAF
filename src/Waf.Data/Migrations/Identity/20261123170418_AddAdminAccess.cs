using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace FASoft.Waf.Data.Migrations.Identity;

/// <inheritdoc />
public partial class _20261123170418_AddAdminAccess : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "AdminAccess",
            columns: table => new
            {
                Id = table.Column<int>(type: "INTEGER", nullable: false),
                RemoteUrl = table.Column<string>(type: "TEXT", maxLength: 300, nullable: true),
                AllowedNetworks = table.Column<string>(type: "TEXT", nullable: false),
                UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_AdminAccess", x => x.Id);
            });
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(
            name: "AdminAccess");
    }
}
