[CmdletBinding()]
param(
    [switch]$SkipPdf,
    [switch]$SkipOdt
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$htmlPath = Join-Path $PSScriptRoot 'Rapport-de-projet-dev-web.html'
$pdfPath = Join-Path $PSScriptRoot 'Rapport-de-projet-dev-web.pdf'
$odtPath = Join-Path $PSScriptRoot 'Rapport-de-projet-dev-web.odt'
$homeImage = Join-Path $repoRoot 'assets\booktopia-home.png'
$detailsImage = Join-Path $repoRoot 'assets\booktopia-details.png'

foreach ($requiredFile in @($htmlPath, $homeImage, $detailsImage)) {
    if (!(Test-Path -LiteralPath $requiredFile)) {
        throw "Fichier requis introuvable : $requiredFile"
    }
}

if (!$SkipPdf) {
    $edgeCandidates = @(
        'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
        'C:\Program Files\Microsoft\Edge\Application\msedge.exe'
    )
    $edgePath = $edgeCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (!$edgePath) {
        throw 'Microsoft Edge est requis pour générer le PDF.'
    }

    $htmlUri = [System.Uri]::new((Resolve-Path $htmlPath).Path).AbsoluteUri
    & $edgePath --headless --disable-gpu --no-pdf-header-footer --print-to-pdf="$pdfPath" "$htmlUri"
    if (!(Test-Path -LiteralPath $pdfPath) -or (Get-Item $pdfPath).Length -lt 10000) {
        throw 'La génération du PDF a échoué.'
    }
}

if (!$SkipOdt) {
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    function ConvertTo-OdtText {
        param([AllowEmptyString()][string]$Value)

        $plain = $Value -replace '<br\s*/?>', "`n"
        $plain = $plain -replace '<[^>]+>', ' '
        $plain = [System.Net.WebUtility]::HtmlDecode($plain)
        $plain = $plain -replace '[\t ]+', ' '
        $plain = $plain -replace '\s*\r?\n\s*', ' '
        return $plain.Trim()
    }

    function ConvertTo-XmlText {
        param([AllowEmptyString()][string]$Value)
        return [System.Security.SecurityElement]::Escape($Value)
    }

    function Add-TextEntry {
        param(
            [System.IO.Compression.ZipArchive]$Archive,
            [string]$Name,
            [string]$Value,
            [System.IO.Compression.CompressionLevel]$Compression = [System.IO.Compression.CompressionLevel]::Optimal
        )

        $entry = $Archive.CreateEntry($Name, $Compression)
        $stream = $entry.Open()
        $writer = [System.IO.StreamWriter]::new($stream, [System.Text.UTF8Encoding]::new($false))
        try { $writer.Write($Value) } finally { $writer.Dispose(); $stream.Dispose() }
    }

    function Add-BinaryEntry {
        param(
            [System.IO.Compression.ZipArchive]$Archive,
            [string]$Name,
            [string]$Source
        )

        $entry = $Archive.CreateEntry($Name, [System.IO.Compression.CompressionLevel]::Optimal)
        $targetStream = $entry.Open()
        $sourceStream = [System.IO.File]::OpenRead($Source)
        try { $sourceStream.CopyTo($targetStream) } finally { $sourceStream.Dispose(); $targetStream.Dispose() }
    }

    $html = Get-Content -LiteralPath $htmlPath -Raw -Encoding UTF8
    $sections = [regex]::Matches($html, '<section\s+class="page(?:\s+cover)?"[^>]*>(?<body>.*?)</section>', [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if ($sections.Count -lt 10) {
        throw "Le rapport HTML ne contient que $($sections.Count) sections reconnues."
    }

    $bodyXml = [System.Text.StringBuilder]::new()
    $pageIndex = 0

    foreach ($section in $sections) {
        if ($pageIndex -gt 0) {
            [void]$bodyXml.Append('<text:p text:style-name="PageBreak"/>')
        }

        $sectionHtml = $section.Groups['body'].Value
        $sectionHtml = [regex]::Replace($sectionHtml, '<div\s+class="footer".*?</div>', '', [System.Text.RegularExpressions.RegexOptions]::Singleline)
        $sectionHtml = [regex]::Replace($sectionHtml, '<div\s+class="(?:metric|card|callout|flow|cover-meta)"[^>]*>(.*?)</div>', '<p>$1</p>', [System.Text.RegularExpressions.RegexOptions]::Singleline)

        $tokens = [regex]::Matches(
            $sectionHtml,
            '<table\b.*?</table>|<pre\b.*?</pre>|<img\b[^>]*>|<h[1-3]\b.*?</h[1-3]>|<p\b.*?</p>|<li\b.*?</li>',
            [System.Text.RegularExpressions.RegexOptions]::Singleline
        )

        foreach ($tokenMatch in $tokens) {
            $token = $tokenMatch.Value

            if ($token -match '^<img') {
                if ($token -match 'booktopia-home\.png') {
                    [void]$bodyXml.Append('<text:p text:style-name="Image"><draw:frame draw:name="Accueil BookTopia" text:anchor-type="as-char" svg:width="17cm" svg:height="9.19cm"><draw:image xlink:href="Pictures/booktopia-home.png" xlink:type="simple" xlink:show="embed" xlink:actuate="onLoad"/></draw:frame></text:p>')
                } elseif ($token -match 'booktopia-details\.png') {
                    [void]$bodyXml.Append('<text:p text:style-name="Image"><draw:frame draw:name="Fiche BookTopia" text:anchor-type="as-char" svg:width="17cm" svg:height="11.81cm"><draw:image xlink:href="Pictures/booktopia-details.png" xlink:type="simple" xlink:show="embed" xlink:actuate="onLoad"/></draw:frame></text:p>')
                }
                continue
            }

            if ($token -match '^<table') {
                $rows = [regex]::Matches($token, '<tr\b.*?</tr>', [System.Text.RegularExpressions.RegexOptions]::Singleline)
                $rowIndex = 0
                foreach ($row in $rows) {
                    $cells = [regex]::Matches($row.Value, '<t[hd]\b.*?</t[hd]>', [System.Text.RegularExpressions.RegexOptions]::Singleline)
                    $values = foreach ($cell in $cells) { ConvertTo-OdtText $cell.Value }
                    $rowText = ConvertTo-XmlText ($values -join '  |  ')
                    $styleName = if ($rowIndex -eq 0) { 'TableHeader' } else { 'TableLine' }
                    [void]$bodyXml.Append(('<text:p text:style-name="{0}">{1}</text:p>' -f $styleName, $rowText))
                    $rowIndex++
                }
                continue
            }

            $text = ConvertTo-OdtText $token
            if ([string]::IsNullOrWhiteSpace($text)) { continue }
            $escapedText = ConvertTo-XmlText $text

            if ($token -match '^<h1') {
                $styleName = if ($pageIndex -eq 0) { 'CoverTitle' } else { 'Heading1' }
                [void]$bodyXml.Append(('<text:h text:style-name="{0}" text:outline-level="1">{1}</text:h>' -f $styleName, $escapedText))
            } elseif ($token -match '^<h2') {
                [void]$bodyXml.Append(('<text:h text:style-name="Heading2" text:outline-level="2">{0}</text:h>' -f $escapedText))
            } elseif ($token -match '^<h3') {
                [void]$bodyXml.Append(('<text:h text:style-name="Heading3" text:outline-level="3">{0}</text:h>' -f $escapedText))
            } elseif ($token -match '^<li') {
                [void]$bodyXml.Append(('<text:p text:style-name="Bullet">- {0}</text:p>' -f $escapedText))
            } elseif ($token -match '^<pre') {
                [void]$bodyXml.Append(('<text:p text:style-name="Code">{0}</text:p>' -f $escapedText))
            } elseif ($token -match 'class="(?:eyebrow|section-kicker)"') {
                [void]$bodyXml.Append(('<text:p text:style-name="Kicker">{0}</text:p>' -f $escapedText))
            } elseif ($token -match 'class="caption"') {
                [void]$bodyXml.Append(('<text:p text:style-name="Caption">{0}</text:p>' -f $escapedText))
            } elseif ($token -match 'class="(?:lead|subtitle)"') {
                [void]$bodyXml.Append(('<text:p text:style-name="Lead">{0}</text:p>' -f $escapedText))
            } else {
                [void]$bodyXml.Append(('<text:p text:style-name="Body">{0}</text:p>' -f $escapedText))
            }
        }
        $pageIndex++
    }

    $contentXml = @"
<?xml version="1.0" encoding="UTF-8"?>
<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0" xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0" office:version="1.3">
  <office:automatic-styles>
    <style:style style:name="Body" style:family="paragraph"><style:paragraph-properties fo:margin-bottom="0.18cm" fo:line-height="150%"/><style:text-properties fo:font-family="Aptos" fo:font-size="10.5pt" fo:color="#24312d"/></style:style>
    <style:style style:name="Lead" style:family="paragraph"><style:paragraph-properties fo:margin-bottom="0.35cm" fo:line-height="155%"/><style:text-properties fo:font-family="Aptos" fo:font-size="12.5pt" fo:color="#42534d"/></style:style>
    <style:style style:name="CoverTitle" style:family="paragraph"><style:paragraph-properties fo:margin-top="5cm" fo:margin-bottom="0.5cm"/><style:text-properties fo:font-family="Georgia" fo:font-size="34pt" fo:font-weight="bold" fo:color="#19372f"/></style:style>
    <style:style style:name="Heading1" style:family="paragraph"><style:paragraph-properties fo:margin-top="0.35cm" fo:margin-bottom="0.5cm"/><style:text-properties fo:font-family="Georgia" fo:font-size="26pt" fo:font-weight="bold" fo:color="#19372f"/></style:style>
    <style:style style:name="Heading2" style:family="paragraph"><style:paragraph-properties fo:margin-top="0.25cm" fo:margin-bottom="0.4cm" fo:border-bottom="0.04cm solid #c96b3d" fo:padding-bottom="0.18cm"/><style:text-properties fo:font-family="Georgia" fo:font-size="19pt" fo:font-weight="bold" fo:color="#19372f"/></style:style>
    <style:style style:name="Heading3" style:family="paragraph"><style:paragraph-properties fo:margin-top="0.35cm" fo:margin-bottom="0.15cm"/><style:text-properties fo:font-family="Aptos" fo:font-size="12pt" fo:font-weight="bold" fo:color="#2f5d50"/></style:style>
    <style:style style:name="Kicker" style:family="paragraph"><style:paragraph-properties fo:margin-bottom="0.15cm"/><style:text-properties fo:font-family="Aptos" fo:font-size="9pt" fo:font-weight="bold" fo:color="#c96b3d" fo:letter-spacing="0.08cm"/></style:style>
    <style:style style:name="Bullet" style:family="paragraph"><style:paragraph-properties fo:margin-left="0.45cm" fo:text-indent="-0.35cm" fo:margin-bottom="0.1cm"/><style:text-properties fo:font-family="Aptos" fo:font-size="10.5pt" fo:color="#24312d"/></style:style>
    <style:style style:name="Code" style:family="paragraph"><style:paragraph-properties fo:background-color="#edf3f0" fo:padding="0.25cm" fo:margin-bottom="0.25cm"/><style:text-properties fo:font-family="Consolas" fo:font-size="8.5pt" fo:color="#19372f"/></style:style>
    <style:style style:name="TableHeader" style:family="paragraph"><style:paragraph-properties fo:background-color="#19372f" fo:padding="0.16cm" fo:margin-bottom="0cm"/><style:text-properties fo:font-family="Aptos" fo:font-size="9pt" fo:font-weight="bold" fo:color="#ffffff"/></style:style>
    <style:style style:name="TableLine" style:family="paragraph"><style:paragraph-properties fo:border-bottom="0.02cm solid #d9dfda" fo:padding="0.14cm" fo:margin-bottom="0cm"/><style:text-properties fo:font-family="Aptos" fo:font-size="9pt" fo:color="#24312d"/></style:style>
    <style:style style:name="Caption" style:family="paragraph"><style:paragraph-properties fo:text-align="center" fo:margin-bottom="0.3cm"/><style:text-properties fo:font-family="Aptos" fo:font-size="8.5pt" fo:font-style="italic" fo:color="#66736f"/></style:style>
    <style:style style:name="Image" style:family="paragraph"><style:paragraph-properties fo:text-align="center" fo:margin-top="0.2cm" fo:margin-bottom="0.2cm"/></style:style>
    <style:style style:name="PageBreak" style:family="paragraph"><style:paragraph-properties fo:break-before="page"/></style:style>
  </office:automatic-styles>
  <office:body><office:text>$bodyXml</office:text></office:body>
</office:document-content>
"@

    $stylesXml = @"
<?xml version="1.0" encoding="UTF-8"?>
<office:document-styles xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0" office:version="1.3">
  <office:styles><style:default-style style:family="paragraph"><style:text-properties fo:font-family="Aptos" fo:font-size="10.5pt"/></style:default-style></office:styles>
  <office:automatic-styles><style:page-layout style:name="A4"><style:page-layout-properties fo:page-width="21cm" fo:page-height="29.7cm" style:print-orientation="portrait" fo:margin-top="1.8cm" fo:margin-bottom="1.8cm" fo:margin-left="1.7cm" fo:margin-right="1.7cm"/></style:page-layout></office:automatic-styles>
  <office:master-styles><style:master-page style:name="Standard" style:page-layout-name="A4"/></office:master-styles>
</office:document-styles>
"@

    $metaXml = @"
<?xml version="1.0" encoding="UTF-8"?>
<office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0" xmlns:dc="http://purl.org/dc/elements/1.1/" office:version="1.3"><office:meta><dc:title>Rapport de projet — BookTopia</dc:title><dc:creator>Ayoub ABDELLI et Lounis BOUHADOUN</dc:creator><dc:description>Rapport technique et produit de BookTopia, édition 2026.</dc:description><meta:creation-date>2026-08-18T00:00:00</meta:creation-date></office:meta></office:document-meta>
"@

    $settingsXml = '<?xml version="1.0" encoding="UTF-8"?><office:document-settings xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" office:version="1.3"><office:settings/></office:document-settings>'
    $manifestXml = @"
<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.3">
  <manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.text"/>
  <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
  <manifest:file-entry manifest:full-path="styles.xml" manifest:media-type="text/xml"/>
  <manifest:file-entry manifest:full-path="meta.xml" manifest:media-type="text/xml"/>
  <manifest:file-entry manifest:full-path="settings.xml" manifest:media-type="text/xml"/>
  <manifest:file-entry manifest:full-path="Pictures/booktopia-home.png" manifest:media-type="image/png"/>
  <manifest:file-entry manifest:full-path="Pictures/booktopia-details.png" manifest:media-type="image/png"/>
</manifest:manifest>
"@

    [xml]$null = $contentXml
    [xml]$null = $stylesXml
    [xml]$null = $manifestXml

    if (Test-Path -LiteralPath $odtPath) {
        Remove-Item -LiteralPath $odtPath -Force
    }

    $fileStream = [System.IO.File]::Open($odtPath, [System.IO.FileMode]::CreateNew)
    $archive = [System.IO.Compression.ZipArchive]::new($fileStream, [System.IO.Compression.ZipArchiveMode]::Create, $false)
    try {
        Add-TextEntry $archive 'mimetype' 'application/vnd.oasis.opendocument.text' ([System.IO.Compression.CompressionLevel]::NoCompression)
        Add-TextEntry $archive 'content.xml' $contentXml
        Add-TextEntry $archive 'styles.xml' $stylesXml
        Add-TextEntry $archive 'meta.xml' $metaXml
        Add-TextEntry $archive 'settings.xml' $settingsXml
        Add-TextEntry $archive 'META-INF/manifest.xml' $manifestXml
        Add-BinaryEntry $archive 'Pictures/booktopia-home.png' $homeImage
        Add-BinaryEntry $archive 'Pictures/booktopia-details.png' $detailsImage
    } finally {
        $archive.Dispose()
        $fileStream.Dispose()
    }

    if ((Get-Item $odtPath).Length -lt 10000) {
        throw 'La génération du fichier ODT a échoué.'
    }
}

Get-Item @($htmlPath, $pdfPath, $odtPath) -ErrorAction SilentlyContinue |
    Select-Object Name, Length, LastWriteTime
