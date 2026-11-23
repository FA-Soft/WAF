using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace FASoft.Waf.Data.Migrations;

/// <inheritdoc />
public partial class _20261123212341_AddAiProposals : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "AiProposals",
            columns: table => new
            {
                Id = table.Column<long>(type: "INTEGER", nullable: false)
                    .Annotation("Sqlite:Autoincrement", true),
                CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                UserName = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                Prompt = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: false),
                Summary = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: false),
                ProposalJson = table.Column<string>(type: "TEXT", nullable: true),
                Errors = table.Column<string>(type: "TEXT", nullable: true),
                Status = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                BaseVersion = table.Column<long>(type: "INTEGER", nullable: false),
                AppliedVersion = table.Column<long>(type: "INTEGER", nullable: true),
                UndoneVersion = table.Column<long>(type: "INTEGER", nullable: true),
                DecidedBy = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                DecidedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                Model = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                InputTokens = table.Column<long>(type: "INTEGER", nullable: false),
                OutputTokens = table.Column<long>(type: "INTEGER", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_AiProposals", x => x.Id);
            });
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(
            name: "AiProposals");
    }
}
