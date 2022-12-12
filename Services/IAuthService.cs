namespace VictorTest.Services
{
    public interface IAuthService
    {
        string GenerateJwtToken(string userId, string username, string secret);
    }
}
