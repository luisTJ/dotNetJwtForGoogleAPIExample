using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using Newtonsoft.Json;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Net;
using System.Web;
using Newtonsoft.Json.Linq;

namespace jwtExample
{
    class Program
    {
        /// <summary>
        /// Demonstrate how to create JWT for google api Authentication
        /// This example depends on 2 external libraries 
        /// - bouncy castle
        /// - json.net
        /// Read more https://developers.google.com/identity/protocols/OAuth2ServiceAccount#creatingjwt
        /// </summary>
        /// <param name="args"></param>
        static void Main(string[] args)
        {
            //RS256 is specified by google
            var header = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
            var header64 = getUrlSafeBase64(header); // base64 will be used in creating signature 

            //makeing a claim body in json format
            StringBuilder sb = new StringBuilder();
            using (StringWriter sw = new StringWriter(sb))
            {
                using (JsonWriter writer = new JsonTextWriter(sw))
                {
                    writer.Formatting = Formatting.None;
                    writer.WriteStartObject();

                    writer.WritePropertyName("iss");
                    writer.WriteValue("my-service@my-application.iam.gserviceaccount.com");

                    writer.WritePropertyName("scope");
                    writer.WriteValue("https://www.googleapis.com/auth/drive.file");

                    writer.WritePropertyName("aud");
                    writer.WriteValue("https://www.googleapis.com/oauth2/v4/token");

                    DateTime now = DateTime.Now;
                    var exp = ConvertToUnixTimestamp(now.AddHours(1));
                    writer.WritePropertyName("exp"); //expiry max 1hr (told by google)
                    writer.WriteValue(exp);

                    var iat = ConvertToUnixTimestamp(now); //issue time
                    writer.WritePropertyName("iat");
                    writer.WriteValue(iat);

                    writer.WriteEndObject();
                }
            }

            var claim_set = sb.ToString();
            var claim_set_64 = getUrlSafeBase64(claim_set);// base64 will be used in creating signature

            String signature = computeSignature(header64, claim_set_64);
            String jwt = String.Format("{0}.{1}.{2}", header64, claim_set_64, signature); // put information together in format of header.claim.signature

            System.Net.ServicePointManager.Expect100Continue = false;
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create("https://www.googleapis.com/oauth2/v4/token");
            req.Method = "POST";

            string post_params = string.Format("grant_type={0}&assertion={1}", HttpUtility.UrlEncode("urn:ietf:params:oauth:grant-type:jwt-bearer"), HttpUtility.UrlEncode(jwt));
            req.ContentType = "application/x-www-form-urlencoded";
            CookieContainer cookiejar = new CookieContainer();
            req.CookieContainer = cookiejar;

            if (post_params.Length > 0)
            {
                byte[] buffer = Encoding.UTF8.GetBytes(post_params);
                req.ContentLength = buffer.Length;

                using (var stream = req.GetRequestStream())
                {
                    stream.Write(buffer, 0, buffer.Length);
                }
            }

            String access_token = "";
            using (var res = req.GetResponse())
            {
                using (var stream = res.GetResponseStream())
                {
                    using (var reader = new StreamReader(stream))
                    {
                        var json = reader.ReadToEnd();
                        access_token = JObject.Parse(json)["access_token"].ToString();
                    }
                }
            }

        }

        /// <summary>
        /// Computing signature by SHA256(header+.+claim) then sign with private key
        /// </summary>
        /// <param name="base64_header">header in url-safe base64 encoding</param>
        /// <param name="base64_claim">claim body in url-safe base64 encoding</param>
        /// <returns>Url-safe base64 encoding of signature</returns>
        static String computeSignature(String base64_header, String base64_claim)
        {
            String body = String.Format("{0}.{1}",base64_header, base64_claim);

            var hashAlg = new SHA256CryptoServiceProvider();
            byte[] hash = hashAlg.ComputeHash(Encoding.ASCII.GetBytes(body));

            byte[] signature = sign(hash);

            return getUrlSafeBase64(signature);
        }

        static string PrivateKeyPrefix = "-----BEGIN PRIVATE KEY-----";
        static string PrivateKeySuffix = "-----END PRIVATE KEY-----";

        /// <summary>
        /// Signing process happen here. Basically it performs Sign(SHA256(header,body),private_key)
        /// </summary>
        /// <param name="input">hashed bytes of header.claim_body</param>
        /// <returns>signature byte</returns>
        private static byte[] sign(byte[] input)
        {

            /**
             * From: https://support.ssl.com/Knowledgebase/Article/View/19/0/der-vs-crt-vs-cer-vs-pem-certificates-and-how-to-convert-them
             * Encodings (also used as extensions)
             * .DER = The DER extension is used for binary DER encoded certificates. These files may also bear the CER or the CRT extension.   Proper English usage would be “I have a DER encoded certificate” not “I have a DER certificate”.
             * .PEM = The PEM extension is used for different types of X.509v3 files which contain ASCII (Base64) armored data prefixed with a “—– BEGIN …” line.
             * 
             * Common Extensions
             * .CRT = The CRT extension is used for certificates. The certificates may be encoded as binary DER or as ASCII PEM. The CER and CRT extensions are nearly synonymous.  Most common among *nix systems
             * .CER = alternate form of .crt (Microsoft Convention) You can use MS to convert .crt to .cer (.both DER encoded .cer, or base64[PEM] encoded .cer)  The .cer file extension is also recognized by IE as a command to run a MS cryptoAPI command (specifically rundll32.exe cryptext.dll,CryptExtOpenCER) which displays a dialogue for importing and/or viewing certificate contents.
             * .KEY = The KEY extension is used both for public and private PKCS#8 keys. The keys may be encoded as binary DER or as ASCII PEM.
             * */

            String private_key = "-----BEGIN PRIVATE KEY-----\nMITEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAaoIBAQC85PTbj3Yn+Js+\nkywHHnW48uEiwkBNMLecvX/li86j0WXwjhl2g0EA9Lt1W5JZTh4i8WsSPcXBdpsh\n4jX5/CxJACYS8ewU2TAIirxdGgCVNTW0xKndvbFlkX3BJjDDi2e+cwXufFMddx9b\nr4FsCokYw8h3Uv2TioXvsnbB7JDE3oaHdtqRFn5EI+le5QDh2TG3woQFlP0qBEQZ\nNiM3z7iVL8wzi5gewEgSSnoRF/2KgV9+wL+1IGZJtkWnDjmHra62lIhBgG1+l8U5\nHlHfGo/mDZ8b/4UhtIYL3P+zjZUpRtszn3+DohBYOmsw1HatC459ghRvxWPiePbM\n/9f1IHdTAgMBAAECggEAaaYpKXBI5rxOoCYSdvzbXRFDSHybGFFKMPlwQkP61Hc2\n69+ecEGjJtS60D3iUd62Tlb2yuIP7E/ZHo92Hxai8kWKBgiXQWXkTrLB/dSgRNPY\n8P0aAPKq+KLyUgh5N7WN1eBhjeytVAqfWFmGKpaN7XL7eXnKaC4PEWygrYARzHmv\nZJlATnyWPsb2Qi3ZeJFbFiCT0rn5M1tntwQbLFlqdte6REX2u5ASszim7Pue8Cah\nnX3rkDjlPAnOOYtsR2iMOvu/NMHzoSqVETwYuwBNeZpkvAkIuQNyWsEK2PmyCeZ2\n+Ai1Eu+lgGxXyVQWXed39FI+BtusoxMvBZyklTWpQQKBgQDjms9wy5hqeHQ0QZCS\njnoyVhJKJoGsEjQEYI+wFsuNxD7h+iGh3ZBBVGMxfKVJI2ToeMErCZmDNb1p5o4i\nlQN3Dj9Sc3TB4E/6Og9IOdt4f36jhgXe+1sgK9dkjiTYxkl/icPIXwl0p2pFPuMo\nbJE/rq7Q9iUk0a8Lv+9iu2D4MwKBgQDUddKv2654u8Lkc4+dvMaCrZ0+aK0rMDYj\neZJTzzGykCt0U6FhWB/iZtvgpyXDF4DMnnTLIzdXtHjYmYZemS37GGDCrSnjOzs2\ni3qM3Gf6yaRbybqCDIj2s6R9HyI3yl70NmEhejq5w3KU4cLvC6UHu5jIpWWjyomb\nwz0DxVfkYQKBgQDfaphTxVZQtPqETROn+PmULY74gIHrMVckMND67fVTrJ55Xfnj\nlMTEjBxueEca2wZzeA1NvLeW54qNyIYfBh0HodGgkrq6kQCQxKs5n6mCx8u8opNi\nxWM22jItf6ZFr6Z37fhj2H5Epw2W+Vsr1B5j34m0jtn5IWbtZrOKPBq8pwKBgQCf\n4lb9/n0q4GnHD+wJEXH2D38g4xdGRA7J3Ygvx+GndfUtom302qOL9koLot25FivY\nUHqmEEdqmibDIa3L7Mx8hJj0h+nY1c82ufosnQUm5q3oYUQY8CP2O7RScKaIg6O3\ndmDcF6av+xR0U/0ldYbo7dUJUebOPvIVpPR6rPz6oQKBgQCkrt8KKtvj/vYoCMVf\nD19zv/xd21UUsmg6gnbjFP/kMQBgYrPoIVONE6Zn8V/o2kfZktLD+G2K1eCZ0GnW\nxg5m+VdfButrRAa5oKi7tHMplffkTJvicPHvLAby13FV+EsmzB4pyff97VbXq6hU\npYRwySAD8EPuQm5zV+p/9GwhhA==\n-----END PRIVATE KEY-----\n";
            String base64PrivateKey = private_key.Replace(PrivateKeyPrefix, "").Replace("\n", "").Replace(PrivateKeySuffix, "");
            byte[] privateKeyBytes = Convert.FromBase64String(base64PrivateKey); //private key is here
            RsaPrivateCrtKeyParameters crtParameters = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(privateKeyBytes);//read params 
            RSAParameters rsa_params = DotNetUtilities.ToRSAParameters(crtParameters);// parse rsa param https://msdn.microsoft.com/en-us/library/system.security.cryptography.rsaparameters(v=vs.110).aspx

            RSACryptoServiceProvider key = new RSACryptoServiceProvider();
            key.ImportParameters(rsa_params);

            String sha256_OID = CryptoConfig.MapNameToOID("SHA256");
            byte[] signature = key.SignHash(input,sha256_OID); 
            return signature;
        }

        /// <summary>
        /// A variant of base64 use in authentication
        /// </summary>
        /// <param name="data">input data</param>
        /// <returns></returns>
        static String getUrlSafeBase64(byte[] data)
        {
            return Convert.ToBase64String(data).Replace("=", String.Empty).Replace('+', '-').Replace('/', '_'); ;
        }


        /// <summary>
        /// A variant of base64 use in authentication
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        static String getUrlSafeBase64(String input)
        {
            byte[] tmp = Encoding.UTF8.GetBytes(input);
            return getUrlSafeBase64(tmp);
        }


        public static long ConvertToUnixTimestamp(DateTime date)
        {
            DateTime origin = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            TimeSpan diff = date.ToUniversalTime() - origin;
            return (long)Math.Floor(diff.TotalSeconds);
        }
    }
}
