namespace DemoJWT.Dtos
{
    public class EmailSettings
    {
        public string SmtpServer { get; set; }
        public int Port { get; set; }
        public string SenderEmail { get; set; }
        public string SenderName { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public class OtpModel
    {
        public string Email { get; set; }
        public string Otp { get; set; }
        public DateTime ExpiryTime { get; set; }
    }
}
