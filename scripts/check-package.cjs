const fs=require('node:fs');
const crypto=require('node:crypto');
const path=require('node:path');
const yauzl=require('yauzl');
const assert=require('node:assert/strict');
const {version}=require('../package.json');
const file=path.resolve(__dirname,`../vscode-remote-prune-${version}.vsix`);
const names=['[Content_Types].xml','extension.vsixmanifest','GO-LICENSE','LICENSE.txt','NOTICE','PRIVACY.md','USAGE.md','icon/icon_2.png','changelog.md','package.json','readme.md','bin/linux-arm64/engine','bin/linux-arm64/inspector','bin/linux-x64/engine','bin/linux-x64/inspector','dist/extension.js','native/go.mod','native/cmd/engine/main.go','native/cmd/inspector/main.go','native/core/engine_linux.go','native/core/files_linux.go','native/core/inspect_linux.go','scripts/install-helper.sh'].map(n=>n.endsWith('.xml')||n==='extension.vsixmanifest'?n:'extension/'+n);
const expected=new Set(names),entries=[];
yauzl.open(file,{lazyEntries:true},(err,zip)=>{
 if(err)throw err;
 zip.on('entry',entry=>{
  assert(expected.delete(entry.fileName),'Unexpected or duplicate file: '+entry.fileName);
  zip.openReadStream(entry,(err,stream)=>{
   if(err)throw err;const hash=crypto.createHash('sha256');let size=0;
   stream.on('data',chunk=>{hash.update(chunk);size+=chunk.length});
   stream.on('end',()=>{assert.equal(size,entry.uncompressedSize);entries.push({path:entry.fileName,bytes:size,sha256:hash.digest('hex')});zip.readEntry()});
  });
 });
 zip.on('end',()=>{
  assert.equal(expected.size,0,'Missing package files');
  const manifest={vsix_sha256:crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'),entries};
  fs.mkdirSync(path.resolve(__dirname,'../.local'),{recursive:true});
  fs.writeFileSync(path.resolve(__dirname,`../.local/package-manifest-${version}.json`),JSON.stringify(manifest,null,2));
  console.log(JSON.stringify({files:entries.length,vsix_sha256:manifest.vsix_sha256,python_files:0,external_runtime_dependencies:0}));
 });
 zip.readEntry();
});
