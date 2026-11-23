using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace FASoft.Waf.Data.Migrations.Events;

/// <inheritdoc />
public partial class _20261122210558_InitialEvents : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "RequestEvents",
            columns: table => new
            {
                Id = table.Column<long>(type: "INTEGER", nullable: false)
                    .Annotation("Sqlite:Autoincrement", true),
                TimestampMs = table.Column<long>(type: "INTEGER", nullable: false),
                ClientIp = table.Column<string>(type: "TEXT", maxLength: 45, nullable: false),
                Method = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                Host = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                Path = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: false),
                RouteName = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                Action = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                Event = table.Column<string>(type: "TEXT", maxLength: 32, nullable: true),
                RuleName = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                Detail = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                Destination = table.Column<string>(type: "TEXT", maxLength: 300, nullable: true),
                StatusCode = table.Column<int>(type: "INTEGER", nullable: false),
                LatencyMs = table.Column<double>(type: "REAL", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_RequestEvents", x => x.Id);
            });

        migrationBuilder.CreateIndex(
            name: "IX_RequestEvents_Action",
            table: "RequestEvents",
            column: "Action");

        migrationBuilder.CreateIndex(
            name: "IX_RequestEvents_ClientIp",
            table: "RequestEvents",
            column: "ClientIp");

        migrationBuilder.CreateIndex(
            name: "IX_RequestEvents_TimestampMs",
            table: "RequestEvents",
            column: "TimestampMs");
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(
            name: "RequestEvents");
    }
}
