using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace FASoft.Waf.Data.Migrations;

/// <inheritdoc />
public partial class _20261123182948_AddAcme : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<string>(
            name: "AcmeDirectory",
            table: "StoredCertificates",
            type: "TEXT",
            maxLength: 500,
            nullable: true);

        migrationBuilder.AddColumn<string>(
            name: "AcmeHostName",
            table: "StoredCertificates",
            type: "TEXT",
            maxLength: 253,
            nullable: true);

        migrationBuilder.CreateTable(
            name: "AcmeAccounts",
            columns: table => new
            {
                DirectoryUrl = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                AccountUrl = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                Email = table.Column<string>(type: "TEXT", maxLength: 320, nullable: false),
                ProtectedKey = table.Column<byte[]>(type: "BLOB", nullable: false),
                CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_AcmeAccounts", x => x.DirectoryUrl);
            });

        migrationBuilder.CreateIndex(
            name: "IX_StoredCertificates_AcmeHostName",
            table: "StoredCertificates",
            column: "AcmeHostName");
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(
            name: "AcmeAccounts");

        migrationBuilder.DropIndex(
            name: "IX_StoredCertificates_AcmeHostName",
            table: "StoredCertificates");

        migrationBuilder.DropColumn(
            name: "AcmeDirectory",
            table: "StoredCertificates");

        migrationBuilder.DropColumn(
            name: "AcmeHostName",
            table: "StoredCertificates");
    }
}
