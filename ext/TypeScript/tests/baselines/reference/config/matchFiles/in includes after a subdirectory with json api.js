config:
{
 "include": [
  "**/y/../*"
 ]
}
Fs::
//// [c:/dev/a.d.ts]


//// [c:/dev/a.js]


//// [c:/dev/a.ts]


//// [c:/dev/b.js]


//// [c:/dev/b.ts]


//// [c:/dev/c.d.ts]


//// [c:/dev/js/a.js]


//// [c:/dev/js/ab.min.js]


//// [c:/dev/js/b.js]


//// [c:/dev/js/d.min.js]


//// [c:/dev/x/a.ts]


//// [c:/dev/x/aa.ts]


//// [c:/dev/x/b.ts]


//// [c:/dev/x/y/a.ts]


//// [c:/dev/x/y/b.ts]


//// [c:/dev/z/a.ts]


//// [c:/dev/z/aba.ts]


//// [c:/dev/z/abz.ts]


//// [c:/dev/z/b.ts]


//// [c:/dev/z/bba.ts]


//// [c:/dev/z/bbz.ts]


//// [c:/ext/b/a..b.ts]


//// [c:/ext/ext.ts]



configFileName:: c:/dev/tsconfig.json
Result
{
 "options": {
  "configFilePath": "c:/dev/tsconfig.json"
 },
 "fileNames": [],
 "typeAcquisition": {
  "enable": false,
  "include": [],
  "exclude": []
 },
 "raw": {
  "include": [
   "**/y/../*"
  ],
  "compileOnSave": false
 },
 "wildcardDirectories": {},
 "compileOnSave": false
}
Errors::
[91merror[0m[90m TS5065: [0mFile specification cannot contain a parent directory ('..') that appears after a recursive directory wildcard ('**'): '**/y/../*'.
[91merror[0m[90m TS18003: [0mNo inputs were found in config file 'c:/dev/tsconfig.json'. Specified 'include' paths were '["**/y/../*"]' and 'exclude' paths were '[]'.

