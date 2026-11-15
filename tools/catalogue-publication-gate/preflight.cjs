// Synchronous first require for historical CommonJS entrypoints.
const {spawnSync}=require('node:child_process');
const {resolve,relative}=require('node:path');
const {realpathSync,existsSync}=require('node:fs');
const root=resolve(__dirname,'../..');
module.exports=function preflight(declared){
 if(!declared)throw Error('catalogue_entry_claim_required');
 if(!process.argv[1]||!existsSync(process.argv[1])||realpathSync(process.argv[1])!==realpathSync(declared))return;
 const result=spawnSync('python3',[resolve(__dirname,'guard.py'),'--root',root,'--registry','.catalogue-publication.json','--entry',relative(root,realpathSync(declared)).replaceAll('\\','/')],{stdio:['ignore','pipe','pipe']});
 if(result.error||result.status!==0){process.stderr.write(result.stderr?.length?result.stderr:'CATALOGUE: shared publication preflight unavailable\n');process.exit(78);}
};
