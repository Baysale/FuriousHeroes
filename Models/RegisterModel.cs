using System.ComponentModel.DataAnnotations;

namespace FuriousHeroes.Models
{
    public class RegisterModel
    {
        [Required]
        [DataType(DataType.Text)]
        public string Email { get; set; }
        [Required]
        [DataType(DataType.Text)]
        public string UserName { get; set; }
        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }
        [Required]
        [DataType(DataType.Password)]
        [Compare(nameof(Password))]
        public string ConfirmPassword { get; set; }
    }
}
