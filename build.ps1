$packageName = "snmpmod"
$outputDir = "target"
$spl = ".\$outputDir\$packageName.spl"
$tar = "$packageName.tar"

if(Test-Path $spl) {
	echo Deleting $spl
	rm $spl
}

cp README.md $packageName

mkdir -Force $outputDir

7z a -ttar $tar "@compressfiles.txt"
7z a -tgzip $spl $tar
rm $tar

rm $packageName/README.md
