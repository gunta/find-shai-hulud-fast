# !!!注意!!!:
#   このスクリプトはCドライブ配下のファイル・フォルダを探索するため「システムに負荷がかかる場合があります」
#   実行は自己責任でお願いします。
# 使い方:
#   管理者権限でこのスクリプトを実行してください。


$bundle_js_sha256="46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09";

if ((Read-Host "Do you understand that this process may put load on the system?? (y/n)") -ne "y") {
    Write-Output "Aborted."
    exit
}

Write-Output "Searching for the node_modules folder......"
$node_modules_folders = Get-ChildItem -Path C:\ -Recurse -Directory -Filter "node_modules" -ErrorAction SilentlyContinue

Write-Output "Searching for the malicious bundle.js......"
foreach ($folder in $node_modules_folders) {
    $files = Get-ChildItem -Path $folder.FullName -Recurse -Filter "bundle.js" -File -ErrorAction SilentlyContinue
    foreach ($f in $files) {
        $sha256 = Get-FileHash -Algorithm SHA256 -Path $f.FullName
        if ($h.Hash -eq $bundle_js_sha256) {
            Write-Output "MATCH: $($h.Path)"
        }
    }
}
