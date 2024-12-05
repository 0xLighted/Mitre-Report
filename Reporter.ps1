# Open shell for script
Start-Process cmd -ArgumentList "/k", "poetry shell"

# Get docx file path
$downloads = [Environment]::GetFolderPath("MyDocuments").Replace("Documents", "Downloads")
$date = Get-Date -Format "ddMMyyyy"
$filePath = "$downloads\MITRE ATT Report $date - yourname.docx"

# Create file if it doesnt exist
if (-not (Test-Path -Path $filePath)) {
    New-Item -Path $filePath -ItemType File
}

# Open the file after creation
Start-Process $filepath