<#

    .NOTES
        One Identity Password Manager Compromised Password Checker Script
        https://www.oneidentity.com/products/password-manager/

        https://github.com/OneIdentity/OneIdentity-Password-Manager-PwnedPasswords-Checker

        Utilizing the HaveIBeenPwned Pwned Password API, V3:
        https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange

        Created by:
            AJ Lindner (AJ.Lindner@OneIdentity.com)

        Last Modified:
            October 28, 2022

        One Identity open source projects are supported through One Identity GitHub issues and the One Identity Community.
        This includes all scripts, plugins, SDKs, modules, code snippets or other solutions. For assistance with any One Identity GitHub project,
        please raise a new Issue on the One Identity GitHub project page. You may also visit the One Identity Community to ask questions.
        Requests for assistance made through official One Identity Support will be referred back to GitHub and the One Identity Community forums
        where those requests can benefit all users.

    .SYNOPSIS
        A functional version of the Compromised Password Checker script for Password Manager
        that uses the FREE HaveIBeenPwned API instead of the paid default CredVerify solution

    .DESCRIPTION
        Overwrite the original "compromised_password_checker.ps1" file in the
        Service\Resources\CredentialChecker directory of your Password Manager Installation
        The default location is:
        C:\Program Files\One Identity\Password Manager\Service\Resources\CredentialChecker

        A rewrite of the Password Manager compromised_password_checker.ps1 script to work
        properly with the "Credential Checker on" setting, but using the FREE API endpoint
        from HaveIBeenPwned.com instead of the paid default, Vericlouds CredVerify.

        The function names, parameters, and outputs are required by PWM and HIBP and should
        not be modified.

#>

function Get-HashAlgorithm
{   
    # Default function used by PWM on the backend. HIBP uses SHA-1.

    return "SHA1"

}

<#
    .SYNOPSIS
        Confirm-PwnedPassword
        
        Checks the HaveIBeenPwned Password Database to determine if a password has been pwned

    .DESCRIPTION
        If a password has been compromised according to the HaveIBeenPwned database, this
        function will return $true. Otherwise, $false.

        This function can either take a plaintext password, which it will hash automatically,
        or a pre-computed password hash. The HIBP API expects passwords hashed via SHA-1.

        When making the API request, this function sends only the first 5 characters of the hash,
        per the HIBP API guidelines to utilize its secure k-anonimity model.
#>
function Confirm-PwnedPassword {

    [cmdletbinding()]
    param(
        [parameter(position=1,mandatory,ParameterSetName="Plaintext")]
        [string]
        $PlaintextPassword,

        [parameter(position=1,mandatory,ParameterSetName="Hash")]
        [string]
        $HashedPassword
    )

    if ($PSCmdlet.ParameterSetName -eq "Plaintext") {
        # Get & Hash the entered password
        $PasswordStream = [IO.MemoryStream]::new([byte[]][char[]]$PlaintextPassword)
        $HashedPassword = (Get-FileHash -InputStream $PasswordStream -Algorithm SHA1).Hash
    }

    # HIBP uses the first 5 characters of the hash for its Range check
    # See details here: https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange
    $hashPrefix = $HashedPassword.Substring(0,5)
    $url = "https://api.pwnedpasswords.com/range/$hashPrefix"

    # Enable TLS 1.2 for the web call
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # The -UseBasicParsing parameter bypasses the need to setup IE's initial config
    $HIBP = Invoke-WebRequest -Uri $url -UseBasicParsing

    # The HIBP API returns a CRLF separated string with all matching hashes
    # but only includes the SUFFIX (all characters after the 5 we provide)
    # and also includes the count of compromises, separated by a colon
    # example ABCDEFGHIJKLMN: 24

    # Here we loop through that list, parse out the suffixes, and return an object
    # containing all the complete hashes (forced to lowercase)
    $HashMatches = ForEach ($result in $HIBP.Content.Split("`n")) {
        
        $hashSuffix = $Result.Split(":")[0].ToLower()
        "$hashPrefix$hashSuffix"

    }

    # If the original Hash is in our formatted HIBP list, fail the activity
    $PasswordLeaked = ($HashedPassword.ToLower() -in $HashMatches)

    Return $PasswordLeaked
}

function Test-IsCompromisedCredential
{

    # The other default function used on the backend. PWM hashes the password itself 
    # using the algorithm returned from the above Get-HashAlgorithm function above and
    # passes that in for the $passwordHash parameter.

    # username is in the OOTB function, so it was left as a non-mandatory
    # parameter, but is not needed for the HIBP API call. VeriClouds uses both the username
    # and the password to provide a full credentials check, while HaveIBeenPwned is only
    # checking if the password itself has been compromised

    param(

        [Parameter(Mandatory = $false)]        
        [string]
        $username,

        [Parameter(Mandatory = $true)]        
        [string]
        $passwordHash
        
    )

    Return Confirm-PwnedPassword -HashedPassword $passwordHash
}