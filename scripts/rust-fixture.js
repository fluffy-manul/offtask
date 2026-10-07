// Synthetic browser fixtures only. No application server runs in Node.
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createHash } from 'node:crypto';
export const credentialDigest = value => createHash('sha256').update(value).digest('hex');
export function createApp({mode,tokens}) {
  const dir=mkdtempSync(join(tmpdir(),'offtask-rust-browser-'));
  const database=mode==='public-preview'?':memory:':join(dir,'fixture.sqlite');
  let child,port;
  return {
    server: {
      listen(_port,_host,ready) {
        child=spawn(resolve('target/debug/examples/fixture'),[],{stdio:['pipe','pipe','pipe']});
        child.stdin.end(JSON.stringify({mode,tokens,database}));
        let output='';
        child.stdout.on('data',chunk=>{output+=chunk;if(!port&&output.includes('\n')){port=Number(output.trim());ready();}});
        child.stderr.on('data',chunk=>process.stderr.write(chunk));
        child.on('error',error=>{throw error;});
      },
      address(){return {port};},
    },
    administer(command,id,digest){
      return JSON.parse(execFileSync(resolve('target/debug/offtask-admin'),[command,...(id?[id]:[])],{env:{...process.env,OFFTASK_MODE:'local-auth',NODE_ENV:'test',OFFTASK_DATABASE:database},input:digest||'',encoding:'utf8'}));
    },
    async close(){if(child&&child.exitCode===null&&child.signalCode===null){child.kill();await new Promise(resolve=>child.once('exit',resolve));}rmSync(dir,{recursive:true,force:true});},
  };
}
