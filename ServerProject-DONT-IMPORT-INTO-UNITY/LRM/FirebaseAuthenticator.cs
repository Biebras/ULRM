using System;
using System.Threading.Tasks;
using FirebaseAdmin.Auth;
using FirebaseAdmin;
using Google.Apis.Auth.OAuth2;
using LightReflectiveMirror;

namespace LRM
{
    public class FirebaseAuthenticator
    {
        private static bool _firebaseAppInitialized = false;

        public FirebaseAuthenticator()
        {
            if (!_firebaseAppInitialized)
            {
                FirebaseApp.Create(new AppOptions()
                {
                    Credential = GoogleCredential.GetApplicationDefault()
                });
                _firebaseAppInitialized = true;

                Program.WriteLogMessage("FirebaseApp initialized!");
            }
        }

        public async Task<bool> AuthenticateClient(string token)
        {
            try
            {
                await VerifyTokenGetUid(token);
                return true;
            }
            catch (FirebaseAuthException e)
            {
                switch (e.AuthErrorCode)
                {
                    case AuthErrorCode.ExpiredIdToken:
                        Program.WriteLogMessage("Expired token!");
                        break;
                    case AuthErrorCode.InvalidIdToken:
                    case AuthErrorCode.RevokedIdToken:
                        Program.WriteLogMessage("Invalid token!");
                        break;
                    case AuthErrorCode.UserNotFound:
                        Program.WriteLogMessage("User not found!");
                        break;
                    default:
                        Program.WriteLogMessage("Unknown Firebase authentication error!");
                        break;
                }
            }
            catch (ArgumentException)
            {
                Program.WriteLogMessage("Invalid token!");
            }

            return false;
        }

        private async Task<string> VerifyTokenGetUid(string token)
        {
            FirebaseToken decodedToken = await FirebaseAuth.DefaultInstance.VerifyIdTokenAsync(token);
            // Console.WriteLine(decodedToken.Uid);
            return decodedToken.Uid;
        }
    }
}
