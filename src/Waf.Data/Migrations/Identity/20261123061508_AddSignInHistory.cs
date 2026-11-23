using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Waf.Data.Migrations.Identity;

/// <inheritdoc />
public partial class _20261123061508_AddSignInHistory : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "SignInEvents",
            columns: table => new
            {
                Id = table.Column<long>(type: "INTEGER", nullable: false)
                    .Annotation("Sqlite:Autoincrement", true),
                TimestampMs = table.Column<long>(type: "INTEGER", nullable: false),
                UserId = table.Column<string>(type: "TEXT", maxLength: 450, nullable: true),
                UserName = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                ClientIp = table.Column<string>(type: "TEXT", maxLength: 45, nullable: false),
                UserAgent = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                Result = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_SignInEvents", x => x.Id);
            });

        migrationBuilder.CreateIndex(
            name: "IX_SignInEvents_TimestampMs",
            table: "SignInEvents",
            column: "TimestampMs");
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(
            name: "SignInEvents");
    }
}
