using Microsoft.EntityFrameworkCore.Migrations;

namespace UdemyIdentity.Migrations
{
    public partial class Meslek : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Meslek",
                table: "AspNetUsers",
                nullable: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Meslek",
                table: "AspNetUsers");
        }
    }
}
