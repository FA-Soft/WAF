using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace FASoft.Waf.Data.Migrations;

/// <inheritdoc />
public partial class _20261123155111_AddAuditLog : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "AuditEntries",
            columns: table => new
            {
                Id = table.Column<long>(type: "INTEGER", nullable: false)
                    .Annotation("Sqlite:Autoincrement", true),
                TimestampUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                Category = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                Action = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                UserName = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                ClientIp = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                Source = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                Summary = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                Details = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                ConfigurationVersionId = table.Column<long>(type: "INTEGER", nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_AuditEntries", x => x.Id);
            });

        migrationBuilder.CreateIndex(
            name: "IX_AuditEntries_ConfigurationVersionId",
            table: "AuditEntries",
            column: "ConfigurationVersionId");

        migrationBuilder.CreateIndex(
            name: "IX_AuditEntries_TimestampUtc",
            table: "AuditEntries",
            column: "TimestampUtc");

        // Every configuration version links to an audit entry: record the versions stored before the audit log existed.
        migrationBuilder.Sql(
            """
            INSERT INTO AuditEntries (TimestampUtc, Category, Action, UserName, ClientIp, Source, Summary, Details, ConfigurationVersionId)
            SELECT CreatedAtUtc, 'Configuration', 'config.recorded', Author, NULL, 'before the audit log',
                   SUBSTR('Version ' || Id || ': ' || COALESCE(NULLIF(TRIM(Comment), ''), 'configuration changed.'), 1, 500),
                   'Stored before the audit log existed; only the author and comment are known.', Id
            FROM ConfigurationVersions
            ORDER BY Id;
            """);
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(
            name: "AuditEntries");
    }
}
