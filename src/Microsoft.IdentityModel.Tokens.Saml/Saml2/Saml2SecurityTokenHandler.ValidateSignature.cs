﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens.Saml;
using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Saml2
{
    public partial class Saml2SecurityTokenHandler : SecurityTokenHandler
    {
        internal static ValidationResult<SecurityKey> ValidateSignature(
            Saml2SecurityToken samlToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            if (samlToken is null)
            {
                return SignatureValidationError.NullParameter(
                    nameof(samlToken),
                    ValidationError.GetCurrentStackFrame());
            }

            if (validationParameters is null)
            {
                return SignatureValidationError.NullParameter(
                    nameof(validationParameters),
                    ValidationError.GetCurrentStackFrame());
            }

            // Delegate is set by the user, we call it and return the result.
            if (validationParameters.SignatureValidator is not null)
            {
                try
                {
                    ValidationResult<SecurityKey> signatureValidationResult = validationParameters.SignatureValidator(
                        samlToken,
                        validationParameters,
                        null, // configuration
                        callContext);

                    if (!signatureValidationResult.IsValid)
                        return signatureValidationResult.UnwrapError().AddCurrentStackFrame();

                    return signatureValidationResult;
                }
#pragma warning disable CA1031 // Do not catch general exception types
                catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
                {
                    return new SignatureValidationError(
                        new MessageDetail(TokenLogMessages.IDX10272),
                        ValidationFailureType.SignatureValidatorThrew,
                        typeof(SecurityTokenInvalidSignatureException),
                        ValidationError.GetCurrentStackFrame(),
                        innerException: ex);
                }
            }

            // If the user wants to accept unsigned tokens, they must set validationParameters.SignatureValidator
            if (samlToken.Assertion.Signature is null)
                return new SignatureValidationError(
                    new MessageDetail(
                        TokenLogMessages.IDX10504,
                        samlToken.Assertion.CanonicalString),
                    ValidationFailureType.TokenIsNotSigned,
                    typeof(SecurityTokenValidationException),
                    ValidationError.GetCurrentStackFrame());

            SecurityKey? resolvedKey = null;
            bool keyMatched = false;

            if (validationParameters.IssuerSigningKeyResolver is not null)
            {
                resolvedKey = validationParameters.IssuerSigningKeyResolver(
                    samlToken.Assertion.CanonicalString,
                    samlToken,
                    samlToken.Assertion.Signature.KeyInfo?.Id,
                    validationParameters,
                    null,
                    callContext);
            }
            else
            {
                resolvedKey = SamlTokenUtilities.ResolveTokenSigningKey(samlToken.Assertion.Signature.KeyInfo, validationParameters);
            }

            if (resolvedKey is not null)
            {
                keyMatched = true;
                var result = ValidateSignatureUsingKey(resolvedKey, samlToken, validationParameters, callContext);
                if (!result.IsValid)
                    return result.UnwrapError().AddCurrentStackFrame();

                return result;
            }

            bool canMatchKey = samlToken.Assertion.Signature.KeyInfo != null;
            List<ValidationError>? errors = null;
            StringBuilder? keysAttempted = null;

            if (!keyMatched && validationParameters.TryAllIssuerSigningKeys && validationParameters.IssuerSigningKeys is not null)
            {
                // Control reaches here only if the key could not be resolved and TryAllIssuerSigningKeys is set to true.
                // We try all the keys in the list and return the first valid key. This is the degenerate case.
                for (int i = 0; i < validationParameters.IssuerSigningKeys.Count; i++)
                {
                    SecurityKey key = validationParameters.IssuerSigningKeys[i];
                    if (key is null)
                        continue;

                    var result = ValidateSignatureUsingKey(key, samlToken, validationParameters, callContext);
                    if (result.IsValid)
                        return result;

                    (errors ??= new()).Add(result.UnwrapError());

                    (keysAttempted ??= new()).Append(key.KeyId);
                    if (canMatchKey && !keyMatched && key.KeyId is not null && samlToken.Assertion.Signature.KeyInfo is not null)
                        keyMatched = samlToken.Assertion.Signature.KeyInfo.MatchesKey(key);
                }
            }

            if (canMatchKey && keyMatched)
                return new SignatureValidationError(
                    new MessageDetail(
                        TokenLogMessages.IDX10514,
                        LogHelper.MarkAsNonPII(keysAttempted?.ToString()),
                        samlToken.Assertion.Signature.KeyInfo,
                        GetErrorStrings(errors),
                        samlToken),
                    ValidationFailureType.SignatureValidationFailed,
                    typeof(SecurityTokenInvalidSignatureException),
                    ValidationError.GetCurrentStackFrame());

            string? keysAttemptedString = null;
            if (resolvedKey is not null)
                keysAttemptedString = resolvedKey.KeyId;
            else if ((keysAttempted?.Length ?? 0) > 0)
                keysAttemptedString = keysAttempted!.ToString();

            if (keysAttemptedString is not null)
                return new SignatureValidationError(
                    new MessageDetail(
                        TokenLogMessages.IDX10512,
                        LogHelper.MarkAsNonPII(keysAttemptedString),
                        GetErrorStrings(errors),
                        samlToken),
                    ValidationFailureType.SignatureValidationFailed,
                    typeof(SecurityTokenSignatureKeyNotFoundException),
                    ValidationError.GetCurrentStackFrame());

            return new SignatureValidationError(
                new MessageDetail(TokenLogMessages.IDX10500),
                ValidationFailureType.SignatureValidationFailed,
                typeof(SecurityTokenSignatureKeyNotFoundException),
                ValidationError.GetCurrentStackFrame());
        }

        private static ValidationResult<SecurityKey> ValidateSignatureUsingKey(SecurityKey key, Saml2SecurityToken samlToken, ValidationParameters validationParameters, CallContext callContext)
        {
            try
            {
                ValidationResult<string> algorithmValidationResult = validationParameters.AlgorithmValidator(
                    samlToken.Assertion.Signature.SignedInfo.SignatureMethod,
                    key,
                    samlToken,
                    validationParameters,
                    callContext);

                if (!algorithmValidationResult.IsValid)
                {
                    var algorithmValidationError = algorithmValidationResult.UnwrapError().AddCurrentStackFrame();
                    return new SignatureValidationError(
                        new MessageDetail(
                            TokenLogMessages.IDX10518,
                            algorithmValidationError.MessageDetail.Message),
                        algorithmValidationError.FailureType, // Surface the algorithm validation error's failure type.
                        typeof(SecurityTokenInvalidSignatureException),
                        SignatureValidationError.GetCurrentStackFrame(),
                        algorithmValidationError); // Pass the algorithm validation error as the inner validation error.
                }
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                return new SignatureValidationError(
                    new MessageDetail(TokenLogMessages.IDX10273),
                    ValidationFailureType.AlgorithmValidatorThrew,
                    typeof(SecurityTokenInvalidSignatureException),
                    ValidationError.GetCurrentStackFrame(),
                    null, // No need to create an AlgorithmValidationError for this case.
                    ex);
            }

            var validationError = samlToken.Assertion.Signature.Verify(
                key,
                validationParameters.CryptoProviderFactory ?? key.CryptoProviderFactory,
                callContext);

            if (validationError is null)
            {
                samlToken.SigningKey = key;

                return key;
            }
            else
            {
                return validationError.AddCurrentStackFrame();
            }
        }

        private static string GetErrorStrings(List<ValidationError>? errors)
        {
            // This method is called if there are errors in the signature validation process.

            if (errors is null)
                return string.Empty;

            if (errors.Count == 1)
                return errors[0].MessageDetail.Message;

            StringBuilder sb = new();
            for (int i = 0; i < errors.Count; i++)
            {
                sb.AppendLine(errors[i].MessageDetail.Message);
            }

            return sb.ToString();
        }
    }
}
#nullable restore
