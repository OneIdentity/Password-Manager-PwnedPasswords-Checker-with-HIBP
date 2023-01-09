<#
    .SYNOPSIS
        Confirm-PwnedPassword
        
        Determines if a password has been pwned utilizing the HaveIBeenPwned Pwned Password API, V3:
        https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange

        https://github.com/OneIdentity/OneIdentity-Password-Manager-PwnedPasswords-Checker

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
    $HIBP = Invoke-RestMethod -Uri $url -Method GET -UseBasicParsing

    # The HIBP API returns a newline separated string with all matching hashes
    # but only includes the SUFFIX (all characters after the 5 we provide)
    # and also includes the count of compromises, separated by a colon
    # example ABCDEFGHIJKLMN:24

    # Here we loop through that list, parse out the suffixes, and return an object
    # containing all the complete hashes (forced to lowercase)

    $HashMatches = ForEach ($result in $HIBP.Split("`n")) {
        
        $hashSuffix = $Result.Split(":")[0]
        "$hashPrefix$hashSuffix".ToUpper()

    }

    # If the original Hash is in our formatted HIBP list, return $true. Otherwise, $false.
    $PasswordLeaked = ($HashedPassword.ToUpper() -in $HashMatches)

    Return $PasswordLeaked
}