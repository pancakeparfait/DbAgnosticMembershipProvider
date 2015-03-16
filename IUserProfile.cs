namespace Pancake.MembershipProviders
{
    public interface IUserProfile
    {
        int Id { get; set; }
        string Username { get; set; }
    }
}
