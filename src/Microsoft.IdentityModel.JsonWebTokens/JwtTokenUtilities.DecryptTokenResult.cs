﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

namespace Microsoft.IdentityModel.JsonWebTokens
{
    public partial class JwtTokenUtilities
    {
        /// <summary>
        /// Decrypts a JWT token.
        /// </summary>
        /// <param name="jsonWebToken">The JWT token to decrypt.</param>
        /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
        /// <param name="decryptionParameters">The decryption parameters container.</param>
        /// <param name="callContext">The call context used for logging.</param>
        /// <returns>The decrypted, and if the 'zip' claim is set, decompressed string representation of the token.</returns>
        internal static ValidationResult<string> DecryptJwtToken(
            JsonWebToken jsonWebToken,
            ValidationParameters validationParameters,
            JwtTokenDecryptionParameters decryptionParameters,
            CallContext callContext)
        {
            if (validationParameters == null)
                return ValidationError.NullParameter(
                    nameof(validationParameters),
                    ValidationError.GetCurrentStackFrame());

            if (decryptionParameters == null)
                return ValidationError.NullParameter(
                    nameof(decryptionParameters),
                    ValidationError.GetCurrentStackFrame());

            bool decryptionSucceeded = false;
            bool algorithmNotSupportedByCryptoProvider = false;
            byte[] decryptedTokenBytes = null;

            // keep track of exceptions thrown, keys that were tried
            StringBuilder exceptionStrings = null;
            StringBuilder keysAttempted = null;
            string zipAlgorithm = null;
            foreach (SecurityKey key in decryptionParameters.Keys)
            {
                var cryptoProviderFactory = validationParameters.CryptoProviderFactory ?? key.CryptoProviderFactory;
                if (cryptoProviderFactory == null)
                {
                    // TODO: Move to CallContext
                    //if (LogHelper.IsEnabled(EventLogLevel.Warning))
                    //    LogHelper.LogWarning(TokenLogMessages.IDX10607, key);

                    continue;
                }

                try
                {
                    if (!cryptoProviderFactory.IsSupportedAlgorithm(jsonWebToken.Enc, key))
                    {
                        //TODO: Move to CallContext
                        //if (LogHelper.IsEnabled(EventLogLevel.Warning))
                        //    LogHelper.LogWarning(TokenLogMessages.IDX10611, LogHelper.MarkAsNonPII(decryptionParameters.Enc), key);

                        algorithmNotSupportedByCryptoProvider = true;
                        continue;
                    }

                    ValidationResult<string> result = validationParameters.AlgorithmValidator(zipAlgorithm, key, jsonWebToken, validationParameters, callContext);
                    if (!result.IsValid)
                    {
                        (exceptionStrings ??= new StringBuilder()).AppendLine(result.UnwrapError().MessageDetail.Message);
                        continue;
                    }

                    decryptedTokenBytes = DecryptToken(
                        cryptoProviderFactory,
                        key,
                        jsonWebToken.Enc,
                        jsonWebToken.CipherTextBytes,
                        jsonWebToken.HeaderAsciiBytes,
                        jsonWebToken.InitializationVectorBytes,
                        jsonWebToken.AuthenticationTagBytes);

                    zipAlgorithm = jsonWebToken.Zip;
                    decryptionSucceeded = true;
                    break;
                }
#pragma warning disable CA1031 // Do not catch general exception types
                catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
                {
                    (exceptionStrings ??= new StringBuilder()).AppendLine(ex.ToString());
                }

                if (key != null)
                    (keysAttempted ??= new StringBuilder()).AppendLine(key.KeyId);
            }

            if (!decryptionSucceeded)
                return GetDecryptionError(
                    decryptionParameters,
                    algorithmNotSupportedByCryptoProvider,
                    exceptionStrings,
                    keysAttempted,
                    callContext);

            try
            {
                string decodedString;
                if (string.IsNullOrEmpty(zipAlgorithm))
                    decodedString = Encoding.UTF8.GetString(decryptedTokenBytes);
                else
                    decodedString = decryptionParameters.DecompressionFunction(decryptedTokenBytes, zipAlgorithm, decryptionParameters.MaximumDeflateSize);

                return decodedString;
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                return new ValidationError(
                    new MessageDetail(TokenLogMessages.IDX10679, zipAlgorithm),
                    ValidationFailureType.TokenDecryptionFailed,
                    typeof(SecurityTokenDecompressionFailedException),
                    ValidationError.GetCurrentStackFrame(),
                    ex);
            }
        }
    }
}
