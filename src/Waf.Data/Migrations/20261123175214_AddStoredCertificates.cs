using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace FASoft.Waf.Data.Migrations;

/// <inheritdoc />
public partial class _20261123175214_AddStoredCertificates : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "StoredCertificates",
            columns: table => new
            {
                Thumbprint = table.Column<string>(type: "TEXT", fixedLength: true, maxLength: 64, nullable: false),
                Subject = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: false),
                Issuer = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: false),
                DnsNames = table.Column<string>(type: "TEXT", nullable: false),
                NotBeforeUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                NotAfterUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                ProtectedPfx = table.Column<byte[]>(type: "BLOB", nullable: false),
                UploadedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                UploadedBy = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_StoredCertificates", x => x.Thumbprint);
            });
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(
            name: "StoredCertificates");
    }
}
