using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Waf.Data.Migrations;

/// <inheritdoc />
public partial class _20261122141223_InitialCreate : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "ConfigurationVersions",
            columns: table => new
            {
                Id = table.Column<long>(type: "INTEGER", nullable: false)
                    .Annotation("Sqlite:Autoincrement", true),
                CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                Author = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                Comment = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                SchemaVersion = table.Column<int>(type: "INTEGER", nullable: false),
                Json = table.Column<string>(type: "TEXT", nullable: false),
                Sha256 = table.Column<string>(type: "TEXT", fixedLength: true, maxLength: 64, nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_ConfigurationVersions", x => x.Id);
            });

        migrationBuilder.CreateIndex(
            name: "IX_ConfigurationVersions_CreatedAtUtc",
            table: "ConfigurationVersions",
            column: "CreatedAtUtc");
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(
            name: "ConfigurationVersions");
    }
}
