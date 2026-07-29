@{
    # Product lint settings for Hash.MassDownloader (scripts/ + src/).
    Severity = @('Error', 'Warning')

    ExcludeRules = @(
        'PSUseShouldProcessForStateChangingFunctions',
        'PSUseBOMForUnicodeEncodedFile'
    )
}
