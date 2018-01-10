## Lookup relevant account information based on username.
## Infile = a CSV file with a column named "name" that contains usernames in Last, First format.
##          Doesn't like middle initials.
## Outfile = path to an output CSV that will contain the AD info.

Param (
    [Parameter(mandatory = $true)]
    [String]$infile,
    [Parameter(mandatory = $true)]
    [String]$outfile
)
echo "Infile = $infile"
echo "Outfile = $outfile"
$userlist = import-csv $infile

echo "[*]     Lookup Employee ID# Based on *Name*"
foreach($user in $userlist) {
    $name = $user.name
    if ($name) {
        Get-ADUser -Filter "Name -Like '*$name*'" -Properties Name,SamAccountName,Department,Title | Select-Object -Property Name,SamAccountName,Department,Title | Export-Csv -Path $outfile -notype -append
    }
}
