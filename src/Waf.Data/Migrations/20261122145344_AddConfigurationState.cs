using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Waf.Data.Migrations;

/// <inheritdoc />
public partial class _20261122145344_AddConfigurationState : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "ConfigurationState",
            columns: table => new
            {
                Id = table.Column<int>(type: "INTEGER", nullable: false),
                LastKnownGoodVersionId = table.Column<long>(type: "INTEGER", nullable: true),
                ActivatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_ConfigurationState", x => x.Id);
                table.ForeignKey(
                    name: "FK_ConfigurationState_ConfigurationVersions_LastKnownGoodVersionId",
                    column: x => x.LastKnownGoodVersionId,
                    principalTable: "ConfigurationVersions",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Restrict);
            });

        migrationBuilder.CreateIndex(
            name: "IX_ConfigurationState_LastKnownGoodVersionId",
            table: "ConfigurationState",
            column: "LastKnownGoodVersionId");
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(
            name: "ConfigurationState");
    }
}
