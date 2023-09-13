# One Identity Password Manager Compromised Credential Checker with Have I Been Pwned
[Read the One Identity Blog Post](https://www.oneidentity.com/community/blogs/b/one-identity/posts/eliminate-compromised-passwords-with-password-manager-and-have-i-been-pwned) for additional information. 

This repository contains a script for validating passwords set in One Identity Password Manager against the Have I Been Pwned PwnedPasswords database, using its completely free API. This allows you to ensure that your users are not setting passwords that are known to be compromised.

This solution is a replacement of the built-in compromised_password_checker.ps1 script that is used when you enable the "Credential Checker On" setting within One Identity Password Manager. This will ensure that all passwords reset through Password Manager do not exist in the PwnedPasswords list.

# Support
One Identity open source projects are supported through One Identity GitHub issues and the One Identity Community. This includes all scripts, plugins, SDKs, modules, code snippets or other solutions. For assistance with any One Identity GitHub project, please raise a new Issue on the One Identity GitHub project page. You may also visit the One Identity Community to ask questions. Requests for assistance made through official One Identity Support will be referred back to GitHub and the One Identity Community forums where those requests can benefit all users.

# Files
- Confirm-PwnedPassword.ps1
  - This is a standalone Powershell script that you can use to check passwords against the HaveIBeenPwned PwnedPasswords database. It can take either a pre-computed SHA-1 Hash, or a plaintext password. Be sure to refer to the [API Documentation](https://haveibeenpwned.com/API/v3#PwnedPasswords) to understand how this works. The included function is also copied in the primary `compromised_password_checker.ps1` replacement script.
- compromised_password_checker.ps1
  - This is a replacement for the default Password Manager script. It will provide the 5-character prefix of the pre-computed SHA1 hash, calculated by Password Manager, to the PwnedPasswords API.

# Requirements & Dependencies
* TLS 1.2 must be enabled on the Password Manager app server. This is enabled by default in Windows Server 2019.
* Powershell must be able to reach out to the https://api.pwnedpasswords.com API endpoint

# API Documentation, License, and Acceptable Use Policy
The Have I Been Pwned PwnedPasswords API has no licensing or attribution requirements. It is a completely free service, provided by [HaveIBeenPwned.com](https://HaveIBeenPwned.com), a [TroyHunt.com](https://www.troyhunt.com) project.

For additional information about this endpoint, including the Acceptable Use policy, please refer to the API documentation on HaveIBeenPwned.com:
[https://haveibeenpwned.com/API/v3#PwnedPasswords](https://haveibeenpwned.com/API/v3#PwnedPasswords).

# Quick Start Guide
1. Back up the original "compromised_password_checker.ps1" script located in the `\Service\Resources\CredentialChecker` folder in the Password Manager Install Directory. By default: `C:\Program Files\One Identity\Password Manager\Service\Resources\CredentialChecker`
2. Replace "compromised_password_checker.ps1" with the version from this repository.
3. Enable "Credential Checker on" in the General Settings section in the One Identity Password Manager Admin page.
