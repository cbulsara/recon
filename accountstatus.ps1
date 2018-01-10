## Lookup account status based on employee ID # (SamAccountName).
## Infile = a CSV file with a column named "SamAccountName" that contains...SAM Account Names.
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

echo "[*]     By ID"
foreach($user in $userlist) {
    $id = $user.SamAccountName
    if ($id) {
        Get-ADUser $id -Properties Name,SamAccountName,Department,Title,Enabled | Select-Object -Property Name,SamAccountName,Department,Title,Enabled | Export-Csv -Path $outfile -notype -append
    }
}

#echo "[*]     ID *"
#foreach($user in $userlist) {
#    $id = $user.employee_id
#    if ($id) {
#        Get-ADUser -Filter "SamAccountName -Like '*$id*'" | Select-Object -Property Name,Enabled
#    }
#}

#echo "[*]    By Name"
#foreach($user in $userlist) {
#    $name = $user.name
#    if ($name) {
#        Get-ADUser -Filter {Name -Like $name} -Properties Name,Enabled
#    }
#}

