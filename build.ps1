$packageName = "snmpmod"
$spl = ".\build\$packageName.spl"
$tar = "$packageName.tar"

if(Test-Path $spl) {
	echo Deleting $spl
	rm $spl
}

cp README.md $packageName

mkdir -Force build

7z a -ttar $tar "@compressfiles.txt"
7z a -tgzip $spl $tar
rm $tar

rm $packageName/README.md
