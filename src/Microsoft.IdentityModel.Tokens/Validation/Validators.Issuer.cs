// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Logging;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Definition for delegate that will validate the issuer value in a token.
    /// </summary>
    /// <param name="issuer">The issuer to validate.</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> that is being validated.</param>
    /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
    /// <param name="callContext"></param>
    /// <param name="cancellationToken"></param>
    /// <returns>An <see cref="ValidationResult{TResult}"/>that contains the results of validating the issuer.</returns>
    /// <remarks>This delegate is not expected to throw.</remarks>
    internal delegate Task<ValidationResult<ValidatedIssuer>> IssuerValidationDelegateAsync(
        string issuer,
        SecurityToken securityToken,
        ValidationParameters validationParameters,
        CallContext callContext,
        CancellationToken cancellationToken);

    /// <summary>
    /// Partial class for Issuer Validation.
    /// </summary>
    public static partial class Validators
    {
        /// <summary>
        /// Determines if an issuer found in a <see cref="SecurityToken"/> is valid.
        /// </summary>
        /// <param name="issuer">The issuer to validate</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> that is being validated.</param>
        /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
        /// <param name="callContext"></param>
        /// <param name="cancellationToken"></param>
        /// <returns>An <see cref="ValidationResult{TResult}"/> that contains either the issuer that was validated or an error.</returns>
        /// <remarks>An EXACT match is required.</remarks>
        internal static async Task<ValidationResult<ValidatedIssuer>> ValidateIssuerAsync(
            string? issuer,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
#pragma warning disable CA1801 // Review unused parameters
            CallContext? callContext,
#pragma warning restore CA1801 // Review unused parameters
            CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(issuer))
            {
                return new IssuerValidationError(
                    new MessageDetail(LogMessages.IDX10211),
                    ValidationFailureType.IssuerValidationFailed,
                    typeof(SecurityTokenInvalidIssuerException),
                    ValidationError.GetCurrentStackFrame(),
                    issuer);
            }

            if (validationParameters == null)
                return ValidationError.NullParameter(
                    nameof(validationParameters),
                    ValidationError.GetCurrentStackFrame());

            if (securityToken == null)
                return ValidationError.NullParameter(
                    nameof(securityToken),
                    ValidationError.GetCurrentStackFrame());

            BaseConfiguration? configuration = null;
            if (validationParameters.ConfigurationManager != null)
                configuration = await validationParameters.ConfigurationManager.GetBaseConfigurationAsync(cancellationToken).ConfigureAwait(false);

            // Return failed IssuerValidationResult if all possible places to validate against are null or empty.
            if (validationParameters.ValidIssuers.Count == 0 && string.IsNullOrWhiteSpace(configuration?.Issuer))
                return new IssuerValidationError(
                    new MessageDetail(LogMessages.IDX10211),
                    ValidationFailureType.IssuerValidationFailed,
                    typeof(SecurityTokenInvalidIssuerException),
                    ValidationError.GetCurrentStackFrame(),
                    issuer);

            if (configuration != null)
            {
                if (string.Equals(configuration.Issuer, issuer))
                {
                    // TODO - how and when to log
                    // Logs will have to be passed back to Wilson
                    // so that they can be written to the correct place and in the correct format respecting PII.
                    // Add to CallContext
                    //if (LogHelper.IsEnabled(EventLogLevel.Informational))
                    //    LogHelper.LogInformation(LogMessages.IDX10236, LogHelper.MarkAsNonPII(issuer), callContext);


                    return new ValidatedIssuer(issuer!, IssuerValidationSource.IssuerMatchedConfiguration);
                }
            }

            if (validationParameters.ValidIssuers.Count != 0)
            {
                for (int i = 0; i < validationParameters.ValidIssuers.Count; i++)
                {
                    if (string.IsNullOrEmpty(validationParameters.ValidIssuers[i]))
                    {
                        // TODO: Add to CallContext
                        //if (LogHelper.IsEnabled(EventLogLevel.Informational))
                        //    LogHelper.LogInformation(LogMessages.IDX10262);

                        continue;
                    }

                    if (string.Equals(validationParameters.ValidIssuers[i], issuer))
                        return new ValidatedIssuer(issuer!, IssuerValidationSource.IssuerMatchedValidationParameters);
                }
            }

            return new IssuerValidationError(
                new MessageDetail(
                    LogMessages.IDX10212,
                    LogHelper.MarkAsNonPII(issuer),
                    LogHelper.MarkAsNonPII(Utility.SerializeAsSingleCommaDelimitedString(validationParameters.ValidIssuers)),
                    LogHelper.MarkAsNonPII(configuration?.Issuer)),
                ValidationFailureType.IssuerValidationFailed,
                typeof(SecurityTokenInvalidIssuerException),
                ValidationError.GetCurrentStackFrame(),
                issuer);
        }
    }
}
#nullable restore
