using System.ComponentModel.DataAnnotations;

namespace API.Entities
{
    public class AppUser
    {
        [Key]
        public int ID { get; set; }

        [Required]
        public string? UserName { get; set; }
    }
}
