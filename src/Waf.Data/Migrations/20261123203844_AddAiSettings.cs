using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace FASoft.Waf.Data.Migrations;

/// <inheritdoc />
public partial class _20261123203844_AddAiSettings : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "AiSettings",
            columns: table => new
            {
                Id = table.Column<int>(type: "INTEGER", nullable: false),
                Provider = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                ProtectedApiKey = table.Column<byte[]>(type: "BLOB", nullable: false),
                KeyHint = table.Column<string>(type: "TEXT", maxLength: 8, nullable: false),
                UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                UpdatedBy = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_AiSettings", x => x.Id);
            });
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(
            name: "AiSettings");
    }
}
