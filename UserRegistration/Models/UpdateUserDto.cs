namespace UserRegistration.Models
{
    public class UpdateUserDto
    {
        public string Email { get; set; }
        public string Name { get; set; }
        public IFormFile Image { get; set; }
        public string Gender { get; set; }
        public string MaritalStatus { get; set; }
        public DateTime DateOfBirth { get; set; }
    }
}
