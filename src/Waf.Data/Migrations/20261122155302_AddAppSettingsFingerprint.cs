using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Waf.Data.Migrations;

/// <inheritdoc />
public partial class _20261122155302_AddAppSettingsFingerprint : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<string>(
            name: "AppSettingsFingerprint",
            table: "ConfigurationState",
            type: "TEXT",
            maxLength: 64,
            nullable: true);
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropColumn(
            name: "AppSettingsFingerprint",
            table: "ConfigurationState");
    }
}
