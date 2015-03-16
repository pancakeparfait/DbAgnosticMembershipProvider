using System;
using System.Collections.Generic;

namespace Pancake.MembershipProviders
{
    /// <summary>
    /// DbAgnosticMembershipProvider depends on an implementation of IMembershipService
    /// to handle entities or queries in the data layer. IMembershipService depends on an
    /// entity to implement IUserProfile.
    /// </summary>
    public interface IMembershipService<TUserEntity>
        where TUserEntity : IUserProfile
    {
        bool ConfirmAccount(string accountConfirmationToken);
        bool ConfirmAccount(string accountConfirmationToken, int userId);
        void CreateAccountForUser(int userId, string hashedPassword, string token, bool requireConfirmationToken);
        void CreateOrUpdateOAuthAccountForUser(TUserEntity userProfile, string provider, string providerUserId);
        /// <summary>
        /// Create a user with only a username.
        /// </summary>
        void CreateUser(string username);
        void DeleteOAuthAccount(string provider, string providerUserId);
        DateTime GetCreateDate(string userName);
        int GetMembershipCountByUserId(int userId);
        int GetMembershipCountByUserId(int userId, bool requireConfirm);
        /// <summary>
        /// Get the OAuth data associated with the user id passed in.
        /// </summary>
        /// <returns>A collection of tuples in the format [Provider, ProviderUserId].</returns>
        ICollection<Tuple<string, string>> GetOAuthAccountDataByUserId(int userId);
        /// <summary>
        /// Get the hashed password stored in the database by user id.
        /// </summary>
        /// <returns>A hashed password.</returns>
        string GetHashedPassword(int userId);
        string GetPasswordVerificationTokenByUserId(int userId);
        TUserEntity GetUserById(int id);
        TUserEntity GetUserByName(string username);
        TUserEntity GetUserByOAuth(string provider, string providerUserId);
        TUserEntity GetUserByPasswordVerificationToken(string token);
        bool RemovePasswordVerificationTokenForUserId(int userId);
        bool SetPasswordForUserId(int userId, string hashedPassword);
        bool SetPasswordVerificationTokenAndDateForUserId(int userId, string token, DateTime expiresOn);
    }
}
