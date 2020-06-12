# SecMgmtInsights.ConditionalAccessPolicies

## SYNOPSIS

Gets the configured conditional access policies from Azure Active Directory.

## SYNTAX

```powerquery-m
SecMgmtInsights.ConditionalAccessPolicies([customers])
```

## Examples

### Example 1

```powerquery-m
SecMgmtInsights.ConditionalAccessPolicies()
```

Gets the configured conditional access policies from Azure Active Directory for tenant associated with the authenticated account.

### Example 2

```powerquery-m
SecMgmtInsights.ConditionalAccessPolicies({"b7d6925d-7e34-435f-b8cf-86a5f4f71cca", "7fe734ec-7c01-4e17-8bc6-3cbb4597a37c"})
```

Gets the configured conditional access policies from Azure Active Directory for the specified tenants. The authenticate account will need privileges to access the information in the tenants.
