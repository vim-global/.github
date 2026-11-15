// VG-CATALOGUE-PUBLICATION-PREFLIGHT-1: must be the entrypoint's FIRST import.
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {relative,resolve} from 'node:path';
import {realpathSync,existsSync} from 'node:fs';
const root=fileURLToPath(new URL('../..',import.meta.url));
const declared=new URL(import.meta.url).searchParams.get('entry');
if(!declared)throw Error('catalogue_entry_claim_required');
// Library imports retain their existing behavior, like Python's __main__ guard.
// The query makes each declaring module a separate preload instance.
if(process.argv[1]&&existsSync(process.argv[1])&&realpathSync(process.argv[1])===realpathSync(resolve(root,declared))){
 const name=relative(root,realpathSync(process.argv[1])).replaceAll('\\','/');
 const result=spawnSync('python3',[fileURLToPath(new URL('./guard.py',import.meta.url)),'--root',root,'--registry','.catalogue-publication.json','--entry',name],{stdio:['ignore','pipe','pipe']});
 if(result.error||result.status!==0){process.stderr.write(result.stderr?.length?result.stderr:'CATALOGUE: shared publication preflight unavailable\n');process.exit(78);}
}
