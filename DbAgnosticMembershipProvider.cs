using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration.Provider;
using System.Linq;
using System.Security.Cryptography;
using System.Web;
using System.Web.Helpers;
using System.Web.Mvc;
using System.Web.Security;
using WebMatrix.WebData;

namespace Pancake.MembershipProviders
{
    /// <summary>
    /// Modeled after the SimpleMembershipProvider in WebMatrix.WebData, this
    /// implementation of ExtendedMembershipProvider allows you to implement
    /// IMembershipService with any database access you like. IMembershipService
    /// depends on an entity that implements IUserProfile.
    /// </summary>
    public class DbAgnosticMembershipProvider : ExtendedMembershipProvider
    {
        #region [Properties]

        private const int TOKEN_SIZE_IN_BYTES = 16;

        /// <summary>
        /// Use SetMembershipService to override Dependency Resolver for unit testing.
        /// </summary>
        protected IMembershipService<IUserProfile> MembershipService
        {
            get { return _membershipService ?? DependencyResolver.Current.GetService<IMembershipService<IUserProfile>>(); }
        }
        private IMembershipService<IUserProfile> _membershipService;

        private static string ProviderName
        {
            get { return typeof(DbAgnosticMembershipProvider).Name; }
        }

        public override bool EnablePasswordRetrieval
        {
            get { return false; }
        }

        public override bool EnablePasswordReset
        {
            get { return false; }
        }

        public override bool RequiresQuestionAndAnswer
        {
            get { return false; }
        }

        public override bool RequiresUniqueEmail
        {
            get { return false; }
        }

        public override MembershipPasswordFormat PasswordFormat
        {
            get { return MembershipPasswordFormat.Hashed; }
        }

        public override int MaxInvalidPasswordAttempts
        {
            get { return Int32.MaxValue; }
        }

        public override int PasswordAttemptWindow
        {
            get { return Int32.MaxValue; }
        }

        public override int MinRequiredPasswordLength
        {
            get { return 0; }
        }

        public override int MinRequiredNonAlphanumericCharacters
        {
            get { return 0; }
        }

        public override string PasswordStrengthRegularExpression
        {
            get { return String.Empty; }
        }

        public override string ApplicationName
        {
            get { throw new NotSupportedException(); }
            set { throw new NotSupportedException(); }
        }

        #endregion

        #region [Supported Membership Provider Methods]

        public override void Initialize(string name, NameValueCollection config)
        {
            if (config == null)
            {
                throw new ArgumentNullException("config");
            }
            if (String.IsNullOrEmpty(name))
            {
                name = "DbAgnosticMembershipProvider";
            }
            if (String.IsNullOrEmpty(config["description"]))
            {
                config.Remove("description");
                config.Add("description", "DB Agnostic Membership Provider");
            }
            base.Initialize(name, config);

            config.Remove("connectionStringName");
            config.Remove("enablePasswordRetrieval");
            config.Remove("enablePasswordReset");
            config.Remove("requiresQuestionAndAnswer");
            config.Remove("applicationName");
            config.Remove("requiresUniqueEmail");
            config.Remove("maxInvalidPasswordAttempts");
            config.Remove("passwordAttemptWindow");
            config.Remove("passwordFormat");
            config.Remove("name");
            config.Remove("description");
            config.Remove("minRequiredPasswordLength");
            config.Remove("minRequiredNonalphanumericCharacters");
            config.Remove("passwordStrengthRegularExpression");
            config.Remove("hashAlgorithmType");
        }

        public override bool ChangePassword(string username, string oldPassword, string newPassword)
        {
            Ensure.ArgumentNotNull(username, "username");
            Ensure.ArgumentNotNull(oldPassword, "oldPassword");
            Ensure.ArgumentNotNull(newPassword, "newPassword");

            var membershipService = MembershipService;
            var userId = GetUserId(membershipService, username);
            if (userId == -1) return false;

            if (!CheckPassword(membershipService, userId, oldPassword)) return false;

            return SetPassword(membershipService, userId, newPassword);
        }

        public override bool ValidateUser(string username, string password)
        {
            var membershipService = MembershipService;
            var userId = VerifyUserNameHasConfirmedAccount(membershipService, username);
            if (userId == -1) return false;

            return CheckPassword(membershipService, userId, password);
        }

        public override MembershipUser GetUser(string username, bool userIsOnline)
        {
            var membershipService = MembershipService;
            var userId = GetUserId(membershipService, username);
            return userId == -1
                ? null
                : new MembershipUser(ProviderName, username, userId, null, null, null, true, false,
                    DateTime.MinValue, DateTime.MinValue, DateTime.MinValue, DateTime.MinValue, DateTime.MinValue);
        }

        public override string GetUserNameByEmail(string email)
        {
            throw new NotImplementedException();
        }

        public override bool DeleteUser(string username, bool deleteAllRelatedData)
        {
            throw new NotImplementedException();
        }

        public override ICollection<OAuthAccountData> GetAccountsForUser(string userName)
        {
            var membershipService = MembershipService;
            var userId = GetUserId(membershipService, userName);
            if (userId != -1)
            {
                return membershipService.GetOAuthAccountDataByUserId(userId)
                    .Select(x => new OAuthAccountData(x.Item1, x.Item2))
                    .ToArray();
            }

            return new OAuthAccountData[0];
        }

        public override string CreateUserAndAccount(string userName, string password, bool requireConfirmation, IDictionary<string, object> values)
        {
            CreateUserProfile(MembershipService, userName);
            return CreateAccount(userName, password, requireConfirmation);
        }

        public override string CreateAccount(string userName, string password, bool requireConfirmationToken)
        {
            var hashedPassword = Crypto.HashPassword(password);
            if (hashedPassword.Length > 128) throw new MembershipCreateUserException(MembershipCreateStatus.InvalidPassword);

            // Step 1: Check if the user exists in the Users table
            var membershipService = MembershipService;
            var userId = GetUserId(membershipService, userName);
            if (userId == -1) throw new MembershipCreateUserException(MembershipCreateStatus.ProviderError); // User not found

            // Step 2: Check if the user exists in the Membership table: Error if yes.
            if (membershipService.GetMembershipCountByUserId(userId) > 0)
                throw new MembershipCreateUserException(MembershipCreateStatus.DuplicateUserName);

            // Step 3: Create user in Membership table
            string token = null;
            if (requireConfirmationToken)
            {
                token = GenerateToken();
            }

            membershipService.CreateAccountForUser(userId, hashedPassword, token, requireConfirmationToken);

            return token;
        }

        public override void CreateOrUpdateOAuthAccount(string provider, string providerUserId, string userName)
        {
            var membershipService = MembershipService;

            var user = membershipService.GetUserByName(userName);
            if (user == null) throw new MembershipCreateUserException(MembershipCreateStatus.InvalidUserName);

            membershipService.CreateOrUpdateOAuthAccountForUser(user, provider, providerUserId);
        }

        public override bool ConfirmAccount(string userName, string accountConfirmationToken)
        {
            var membershipService = MembershipService;
            var userId = GetUserId(membershipService, userName);

            if (userId == -1) return false;

            return membershipService.ConfirmAccount(accountConfirmationToken, userId);
        }

        public override bool ConfirmAccount(string accountConfirmationToken)
        {
            return MembershipService.ConfirmAccount(accountConfirmationToken);
        }

        public override bool DeleteAccount(string userName)
        {
            throw new NotImplementedException();
        }

        public override void DeleteOAuthAccount(string provider, string providerUserId)
        {
            Ensure.ArgumentNotNullOrBlank(provider, "provider");
            Ensure.ArgumentNotNullOrBlank(providerUserId, "providerUserId");

            MembershipService.DeleteOAuthAccount(provider, providerUserId);
        }

        public override string GeneratePasswordResetToken(string userName, int tokenExpirationInMinutesFromNow)
        {
            Ensure.ArgumentNotNullOrBlank(userName, "userName");

            var userId = VerifyUserNameHasConfirmedAccount(MembershipService, userName, throwException: true);

            var token = MembershipService.GetPasswordVerificationTokenByUserId(userId);
            if (token == null)
            {
                token = GenerateToken();

                if (!MembershipService.SetPasswordVerificationTokenAndDateForUserId(userId, token, DateTime.UtcNow.AddMinutes(tokenExpirationInMinutesFromNow)))
                    throw new ProviderException(string.Format("Unable to set password verification token for user {0}", userName));
            }
            return token;
        }

        public override int GetUserIdFromOAuth(string provider, string providerUserId)
        {
            var user = MembershipService.GetUserByOAuth(provider, providerUserId);
            return user == null ? -1 : user.Id;
        }

        public override string GetUserNameFromId(int userId)
        {
            return MembershipService.GetUserById(userId).Username;
        }

        public override int GetUserIdFromPasswordResetToken(string token)
        {
            var user = MembershipService.GetUserByPasswordVerificationToken(token);
            return user == null ? -1 : user.Id;
        }

        public override bool IsConfirmed(string userName)
        {
            var userId = VerifyUserNameHasConfirmedAccount(MembershipService, userName);
            return userId != -1;
        }

        public override bool ResetPasswordWithToken(string token, string newPassword)
        {
            Ensure.ArgumentNotNullOrBlank(newPassword, "newPassword");
            var userId = GetUserIdFromPasswordResetToken(token);

            if (userId == -1) return false;

            var success = SetPassword(MembershipService, userId, newPassword);
            if (success)
            {
                if (!MembershipService.RemovePasswordVerificationTokenForUserId(userId))
                    throw new ProviderException("An error occurred while clearing password verification token for user.");
            }
            return success;
        }

        public override DateTime GetCreateDate(string userName)
        {
            return MembershipService.GetCreateDate(userName);
        }

        public override bool HasLocalAccount(int userId)
        {
            return MembershipService.GetMembershipCountByUserId(userId) > 0;
        }

        #endregion

        #region [Helper Methods]

        private static bool CheckPassword(IMembershipService<IUserProfile> membershipService, int userId, string password)
        {
            var hashedPassword = GetHashedPassword(membershipService, userId);
            return hashedPassword != null && Crypto.VerifyHashedPassword(hashedPassword, password);
        }

        private static void CreateUserProfile(IMembershipService<IUserProfile> membershipService, string userName)
        {
            var userId = GetUserId(membershipService, userName);
            if (userId != -1) throw new MembershipCreateUserException(MembershipCreateStatus.DuplicateUserName);

            membershipService.CreateUser(userName);
        }

        private static string GenerateToken()
        {
            using (var prng = new RNGCryptoServiceProvider())
            {
                return GenerateToken(prng);
            }
        }

        internal static string GenerateToken(RandomNumberGenerator generator)
        {
            var tokenBytes = new byte[TOKEN_SIZE_IN_BYTES];
            generator.GetBytes(tokenBytes);
            return HttpServerUtility.UrlTokenEncode(tokenBytes);
        }

        private static string GetHashedPassword(IMembershipService<IUserProfile> membershipService, int userId)
        {
            return membershipService.GetHashedPassword(userId);
        }

        /// <summary>
        /// Get user id by username
        /// </summary>
        private static int GetUserId(IMembershipService<IUserProfile> membershipService, string username)
        {
            var user = membershipService.GetUserByName(username);
            return user == null ? -1 : user.Id;
        }

        /// <summary>
        /// Use this method to provide an IMembershipService for unit testing that overrides Dependency Resolver.
        /// </summary>
        public void SetMembershipService(IMembershipService<IUserProfile> membershipService)
        {
            _membershipService = membershipService;
        }

        private static bool SetPassword(IMembershipService<IUserProfile> membershipService, int userId, string newPassword)
        {
            var hashedPassword = Crypto.HashPassword(newPassword);
            Ensure.ArgumentFollowsRule(x => x.Length <= 128, hashedPassword, "Password is too long.");

            // Update new password
            return membershipService.SetPasswordForUserId(userId, hashedPassword);
        }

        /// <summary>
        /// Ensures the user exists in the accounts table
        /// </summary>
        private static int VerifyUserNameHasConfirmedAccount(IMembershipService<IUserProfile> membershipService, string username, bool throwException = false)
        {
            var userId = GetUserId(membershipService, username);
            if (userId == -1)
            {
                if (throwException)
                    throw new InvalidOperationException(string.Format("Did not find user {0}", username));
                return -1;
            }

            var result = membershipService.GetMembershipCountByUserId(userId, true);
            if (result == 0)
            {
                if (throwException)
                    throw new InvalidOperationException(string.Format("Did not find membership for user {0}", username));
                return -1;
            }

            return userId;
        }

        #endregion

        #region [Unsupported Membership Provider Methods]

        public override bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer)
        {
            throw new NotSupportedException();
        }

        public override MembershipUser CreateUser(string username, string password, string email, string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey, out MembershipCreateStatus status)
        {
            throw new NotSupportedException();
        }

        public override MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            throw new NotSupportedException();
        }

        public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            throw new NotSupportedException();
        }

        public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
        {
            throw new NotSupportedException();
        }

        public override DateTime GetLastPasswordFailureDate(string userName)
        {
            throw new NotSupportedException();
        }

        public override int GetNumberOfUsersOnline()
        {
            throw new NotSupportedException();
        }

        public override string GetPassword(string username, string answer)
        {
            throw new NotSupportedException();
        }

        public override DateTime GetPasswordChangedDate(string userName)
        {
            throw new NotSupportedException();
        }

        public override int GetPasswordFailuresSinceLastSuccess(string userName)
        {
            throw new NotSupportedException();
        }

        public override MembershipUser GetUser(object providerUserKey, bool userIsOnline)
        {
            throw new NotSupportedException();
        }

        public override string ResetPassword(string username, string answer)
        {
            throw new NotSupportedException();
        }

        public override bool UnlockUser(string userName)
        {
            throw new NotSupportedException();
        }

        public override void UpdateUser(MembershipUser user)
        {
            throw new NotSupportedException();
        }

        #endregion
    }
}
