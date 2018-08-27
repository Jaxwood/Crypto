using System;
using System.Security.Cryptography;
using System.Xml;

namespace Jaxwood.Crypto
{
    /// <summary>
    /// Extensions for <see cref="System.Security.Cryptography.RSA"/> as dotnet Core2.1 does not support <see cref="System.Security.Cryptography.RSA.ToXmlString(bool)"/> and <see cref="RSA.FromXmlString(string)"/>
    /// </summary>
    public static class RSAExtensions
    {
        /// <summary>
        /// Deserialize string representation into <see cref="System.Security.Cryptography.RSAParameters"/>
        /// <para>see more <a href="https://github.com/dotnet/core/issues/874#issuecomment-323894072">here</a></para>
        /// </summary>
        /// <param name="rsa"><see cref="System.Security.Cryptography.RSA"/></param>
        /// <param name="xmlString"><see cref="System.String"/></param>
        public static void XFromXmlString(this RSA rsa, string xmlString)
        {
            RSAParameters parameters = new RSAParameters();

            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(xmlString);

            if (xmlDoc.DocumentElement.Name.Equals("RSAKeyValue"))
            {
                foreach (XmlNode node in xmlDoc.DocumentElement.ChildNodes)
                {
                    switch (node.Name)
                    {
                        case "Modulus": parameters.Modulus = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "Exponent": parameters.Exponent = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "P": parameters.P = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "Q": parameters.Q = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "DP": parameters.DP = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "DQ": parameters.DQ = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "InverseQ": parameters.InverseQ = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "D": parameters.D = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                    }
                }
            }
            else
            {
                throw new Exception("Invalid XML RSA key.");
            }

            rsa.ImportParameters(parameters);
        }

        /// <summary>
        /// Generate XML representation of a RSA key
        /// <para>see more <a href="https://github.com/dotnet/core/issues/874#issuecomment-323894072">here</a></para>
        /// </summary>
        /// <param name="rsa"><see cref="System.Security.Cryptography.RSA"/></param>
        /// <param name="parameters"><see cref="System.Security.Cryptography.RSAParameters"/></param>
        /// <returns><see cref="System.String"/></returns>
        public static string XToXmlString(this RSA rsa, RSAParameters parameters)
        {
            return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent><P>{2}</P><Q>{3}</Q><DP>{4}</DP><DQ>{5}</DQ><InverseQ>{6}</InverseQ><D>{7}</D></RSAKeyValue>",
                  parameters.Modulus != null ? Convert.ToBase64String(parameters.Modulus) : null,
                  parameters.Exponent != null ? Convert.ToBase64String(parameters.Exponent) : null,
                  parameters.P != null ? Convert.ToBase64String(parameters.P) : null,
                  parameters.Q != null ? Convert.ToBase64String(parameters.Q) : null,
                  parameters.DP != null ? Convert.ToBase64String(parameters.DP) : null,
                  parameters.DQ != null ? Convert.ToBase64String(parameters.DQ) : null,
                  parameters.InverseQ != null ? Convert.ToBase64String(parameters.InverseQ) : null,
                  parameters.D != null ? Convert.ToBase64String(parameters.D) : null);
        }
    }
}
