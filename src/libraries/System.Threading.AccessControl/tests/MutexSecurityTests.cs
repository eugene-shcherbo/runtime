// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Security.Principal;
using System;
using Xunit;
using System.Collections;
using System.Collections.Generic;

namespace System.Security.AccessControl
{
    public class MutexSecurityTests
    {
        [Theory]
        [InlineData(typeof(NTAccount))]
        [InlineData(typeof(SecurityIdentifier))]
        public void DefaultCtor_CreateObjectWithEmptyDACL(Type identityType)
        {
            // Act
            var ms = new MutexSecurity();

            // Assert
            string securityDescriptorSsdl = ms.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
            Assert.Contains("D:", securityDescriptorSsdl);
            Assert.Empty(ms.GetAccessRules(true, includeInherited: false, identityType));
        }

        [Theory]
        [MemberData(nameof(AccessRuleInvalidArguments))]
        public void AccessRuleFactory_ThrowsException_WhenInvalidMutexRights(IdentityReference identity, MutexRights rights, AccessControlType accessType, Type exceptionType)
        {
            // Arrange
            var ms = new MutexSecurity();

            // Act & Assert
            Assert.Throws(exceptionType,
                () => ms.AccessRuleFactory(identity, (int)rights, isInherited: false, InheritanceFlags.None, PropagationFlags.None, accessType));
        }

        [Theory]
        [MemberData(nameof(AccessRuleValidArguments))]
        public void AccessRuleFactory_CreatesMutexAccessRuleWithSpecifiedParameters(IdentityReference identity, MutexRights rights, AccessControlType accessType)
        {
            // Arrange
            var ms = new MutexSecurity();

            // Act
            AccessRule rule = ms.AccessRuleFactory(identity, (int)rights, isInherited: false, InheritanceFlags.None, PropagationFlags.None, accessType);

            // Assert
            var mutexRule = rule as MutexAccessRule;
            Assert.NotNull(mutexRule);
            Assert.Equal(mutexRule.IdentityReference, identity);
            Assert.Equal(mutexRule.AccessControlType, accessType);
            Assert.Equal(mutexRule.MutexRights, rights);
        }

        public static IEnumerable<object[]> AccessRuleValidArguments()
        {
            var user = new NTAccount($"{Environment.UserDomainName}//{Environment.UserName}");

            return new []
            {
                new object[] { user, MutexRights.ChangePermissions, AccessControlType.Allow },
                new object[] { user, MutexRights.ChangePermissions | MutexRights.Delete, AccessControlType.Deny },
                new object[] { user, MutexRights.FullControl, AccessControlType.Allow }
            };
        }

        public static IEnumerable<object[]> AccessRuleInvalidArguments()
        {
            var user = new NTAccount($"{Environment.UserDomainName}//{Environment.UserName}");

            return new[]
            {
                // Identity Reference is null
                new object[] { null, MutexRights.ChangePermissions, AccessControlType.Allow, typeof(ArgumentNullException) },

                // MutexRights = 0 which is not valid
                new object[] { user, 0, AccessControlType.Deny, typeof(ArgumentException) },

                // AccessControl is not valid enum value
                new object[] { user, MutexRights.FullControl, -1, typeof(ArgumentOutOfRangeException) }
            };
        }
    }
}
