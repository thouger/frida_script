Fs::
//// [/dev/circular.json]
{"extends":"./circular2","compilerOptions":{"module":"amd"}}

//// [/dev/circular2.json]
{"extends":"./circular","compilerOptions":{"module":"commonjs"}}

//// [/dev/configs/base.json]
{"compilerOptions":{"allowJs":true,"noImplicitAny":true,"strictNullChecks":true}}

//// [/dev/configs/extendsArrayFifth.json]
{"extends":["./extendsArrayFirst","./extendsArraySecond","./extendsArrayThird","./extendsArrayFourth"],"files":[]}

//// [/dev/configs/extendsArrayFirst.json]
{"compilerOptions":{"allowJs":true,"noImplicitAny":true,"strictNullChecks":true}}

//// [/dev/configs/extendsArrayFourth.json]
{"compilerOptions":{"module":"system","strictNullChecks":false},"include":null,"files":["../main.ts"]}

//// [/dev/configs/extendsArraySecond.json]
{"compilerOptions":{"module":"amd"},"include":["../supplemental.*"]}

//// [/dev/configs/extendsArrayThird.json]
{"compilerOptions":{"module":null,"noImplicitAny":false},"extends":"./extendsArrayFirst","include":["../supplemental.*"]}

//// [/dev/configs/fifth.json]
{"extends":"./fourth","include":["../tests/utils.ts"],"files":[]}

//// [/dev/configs/first.json]
{"extends":"./base","compilerOptions":{"module":"commonjs"},"files":["../main.ts"]}

//// [/dev/configs/fourth.json]
{"extends":"./third","compilerOptions":{"module":"system"},"include":null,"files":["../main.ts"]}

//// [/dev/configs/second.json]
{"extends":"./base","compilerOptions":{"module":"amd"},"include":["../supplemental.*"]}

//// [/dev/configs/tests.json]
{"compilerOptions":{"preserveConstEnums":true,"removeComments":false,"sourceMap":true},"exclude":["../tests/baselines","../tests/scenarios"],"include":["../tests/**/*.ts"]}

//// [/dev/configs/third.json]
{"extends":"./second","compilerOptions":{"module":null},"include":["../supplemental.*"]}

//// [/dev/extends.json]
{"extends":42}

//// [/dev/extends2.json]
{"extends":"configs/base"}

//// [/dev/extends3.json]
{"extends":""}

//// [/dev/extends4.json]
{"extends":[""]}

//// [/dev/extendsArrayFails.json]
{"extends":["./missingFile"],"compilerOptions":{"types":[]}}

//// [/dev/extendsArrayFails2.json]
{"extends":[42]}

//// [/dev/failure.json]
{"extends":"./failure2.json","compilerOptions":{"typeRoots":[]}}

//// [/dev/failure2.json]
{"excludes":["*.js"]}

//// [/dev/main.ts]


//// [/dev/missing.json]
{"extends":"./missing2","compilerOptions":{"types":[]}}

//// [/dev/node_modules/@foo/tsconfig/package.json]
{"name":"@foo/tsconfig","version":"1.0.0","exports":{".":"./src/tsconfig.json"}}

//// [/dev/node_modules/@foo/tsconfig/src/tsconfig.json]
{"compilerOptions":{"strict":true}}

//// [/dev/node_modules/config-box/package.json]
{"name":"config-box","version":"1.0.0","tsconfig":"./strict.json"}

//// [/dev/node_modules/config-box/strict.json]
{"compilerOptions":{"strict":true}}

//// [/dev/node_modules/config-box/unstrict.json]
{"compilerOptions":{"strict":false}}

//// [/dev/node_modules/config-box-implied/package.json]
{"name":"config-box-implied","version":"1.0.0"}

//// [/dev/node_modules/config-box-implied/tsconfig.json]
{"compilerOptions":{"strict":true}}

//// [/dev/node_modules/config-box-implied/unstrict/tsconfig.json]
{"compilerOptions":{"strict":false}}

//// [/dev/supplemental.ts]


//// [/dev/tests/baselines/first/output.ts]


//// [/dev/tests/scenarios/first.json]


//// [/dev/tests/unit/spec.ts]


//// [/dev/tests/utils.ts]


//// [/dev/tsconfig.extendsBox.json]
{"extends":"config-box","files":["main.ts"]}

//// [/dev/tsconfig.extendsBoxImplied.json]
{"extends":"config-box-implied","files":["main.ts"]}

//// [/dev/tsconfig.extendsBoxImpliedPath.json]
{"extends":"config-box-implied/tsconfig.json","files":["main.ts"]}

//// [/dev/tsconfig.extendsBoxImpliedUnstrict.json]
{"extends":"config-box-implied/unstrict","files":["main.ts"]}

//// [/dev/tsconfig.extendsBoxImpliedUnstrictExtension.json]
{"extends":"config-box-implied/unstrict/tsconfig","files":["main.ts"]}

//// [/dev/tsconfig.extendsFoo.json]
{"extends":"@foo/tsconfig","files":["main.ts"]}

//// [/dev/tsconfig.extendsStrict.json]
{"extends":"config-box/strict","files":["main.ts"]}

//// [/dev/tsconfig.extendsStrictExtension.json]
{"extends":"config-box/strict.json","files":["main.ts"]}

//// [/dev/tsconfig.extendsUnStrict.json]
{"extends":"config-box/unstrict","files":["main.ts"]}

//// [/dev/tsconfig.json]
{"extends":"./configs/base","files":["main.ts","supplemental.ts"]}

//// [/dev/tsconfig.nostrictnull.json]
{"extends":"./tsconfig","compilerOptions":{"strictNullChecks":false}}


can resolve an extension with a base extension
configFileName:: tsconfig.json
CompilerOptions::
{
 "allowJs": true,
 "noImplicitAny": true,
 "strictNullChecks": true,
 "configFilePath": "tsconfig.json"
}
FileNames::
/dev/main.ts,/dev/supplemental.ts
Errors::


can resolve an extension with a base extension that overrides options
configFileName:: tsconfig.nostrictnull.json
CompilerOptions::
{
 "allowJs": true,
 "noImplicitAny": true,
 "strictNullChecks": false,
 "configFilePath": "tsconfig.nostrictnull.json"
}
FileNames::
/dev/main.ts,/dev/supplemental.ts
Errors::


can report errors on circular imports
configFileName:: circular.json
CompilerOptions::
{
 "module": 2,
 "configFilePath": "circular.json"
}
FileNames::
/dev/main.ts,/dev/supplemental.ts,/dev/tests/utils.ts,/dev/tests/baselines/first/output.ts,/dev/tests/unit/spec.ts
Errors::
[91merror[0m[90m TS18000: [0mCircularity detected while resolving configuration: /dev/circular.json -> /dev/circular2.json -> /dev/circular.json


can report missing configurations
configFileName:: missing.json
CompilerOptions::
{
 "types": [],
 "configFilePath": "missing.json"
}
FileNames::
/dev/main.ts,/dev/supplemental.ts,/dev/tests/utils.ts,/dev/tests/baselines/first/output.ts,/dev/tests/unit/spec.ts
Errors::
[91merror[0m[90m TS6053: [0mFile './missing2' not found.


can report errors in extended configs
configFileName:: failure.json
CompilerOptions::
{
 "typeRoots": [],
 "configFilePath": "failure.json"
}
FileNames::
/dev/main.ts,/dev/supplemental.ts,/dev/tests/utils.ts,/dev/tests/baselines/first/output.ts,/dev/tests/unit/spec.ts
Errors::
[96mfailure2.json[0m:[93m1[0m:[93m2[0m - [91merror[0m[90m TS6114: [0mUnknown option 'excludes'. Did you mean 'exclude'?

[7m1[0m {"excludes":["*.js"]}
[7m [0m [91m ~~~~~~~~~~[0m


can error when 'extends' is not a string or Array
configFileName:: extends.json
CompilerOptions::
{
 "configFilePath": "extends.json"
}
FileNames::
/dev/main.ts,/dev/supplemental.ts,/dev/tests/utils.ts,/dev/tests/baselines/first/output.ts,/dev/tests/unit/spec.ts
Errors::
[91merror[0m[90m TS5024: [0mCompiler option 'extends' requires a value of type string or Array.


can error when 'extends' is given an empty string
configFileName:: extends3.json
CompilerOptions::
{
 "configFilePath": "extends3.json"
}
FileNames::
/dev/main.ts,/dev/supplemental.ts,/dev/tests/utils.ts,/dev/tests/baselines/first/output.ts,/dev/tests/unit/spec.ts
Errors::
[91merror[0m[90m TS18051: [0mCompiler option 'extends' cannot be given an empty string.


can error when 'extends' is given an empty string in an array
configFileName:: extends4.json
CompilerOptions::
{
 "configFilePath": "extends4.json"
}
FileNames::
/dev/main.ts,/dev/supplemental.ts,/dev/tests/utils.ts,/dev/tests/baselines/first/output.ts,/dev/tests/unit/spec.ts
Errors::
[91merror[0m[90m TS18051: [0mCompiler option 'extends' cannot be given an empty string.


can overwrite compiler options using extended 'null'
configFileName:: configs/third.json
CompilerOptions::
{
 "allowJs": true,
 "noImplicitAny": true,
 "strictNullChecks": true,
 "configFilePath": "configs/third.json"
}
FileNames::
/dev/supplemental.ts
Errors::


can overwrite top-level options using extended 'null'
configFileName:: configs/fourth.json
CompilerOptions::
{
 "allowJs": true,
 "noImplicitAny": true,
 "strictNullChecks": true,
 "module": 4,
 "configFilePath": "configs/fourth.json"
}
FileNames::
/dev/main.ts
Errors::


can overwrite top-level files using extended []
configFileName:: configs/fifth.json
CompilerOptions::
{
 "allowJs": true,
 "noImplicitAny": true,
 "strictNullChecks": true,
 "module": 4,
 "configFilePath": "configs/fifth.json"
}
FileNames::
/dev/tests/utils.ts
Errors::


can lookup via tsconfig field
configFileName:: tsconfig.extendsBox.json
CompilerOptions::
{
 "strict": true,
 "configFilePath": "tsconfig.extendsBox.json"
}
FileNames::
/dev/main.ts
Errors::


can lookup via package-relative path
configFileName:: tsconfig.extendsStrict.json
CompilerOptions::
{
 "strict": true,
 "configFilePath": "tsconfig.extendsStrict.json"
}
FileNames::
/dev/main.ts
Errors::


can lookup via non-redirected-to package-relative path
configFileName:: tsconfig.extendsUnStrict.json
CompilerOptions::
{
 "strict": false,
 "configFilePath": "tsconfig.extendsUnStrict.json"
}
FileNames::
/dev/main.ts
Errors::


can lookup via package-relative path with extension
configFileName:: tsconfig.extendsStrictExtension.json
CompilerOptions::
{
 "strict": true,
 "configFilePath": "tsconfig.extendsStrictExtension.json"
}
FileNames::
/dev/main.ts
Errors::


can lookup via an implicit tsconfig
configFileName:: tsconfig.extendsBoxImplied.json
CompilerOptions::
{
 "strict": true,
 "configFilePath": "tsconfig.extendsBoxImplied.json"
}
FileNames::
/dev/main.ts
Errors::


can lookup via an implicit tsconfig in a package-relative directory
configFileName:: tsconfig.extendsBoxImpliedUnstrict.json
CompilerOptions::
{
 "strict": false,
 "configFilePath": "tsconfig.extendsBoxImpliedUnstrict.json"
}
FileNames::
/dev/main.ts
Errors::


can lookup via an implicit tsconfig in a package-relative directory with name
configFileName:: tsconfig.extendsBoxImpliedUnstrictExtension.json
CompilerOptions::
{
 "strict": false,
 "configFilePath": "tsconfig.extendsBoxImpliedUnstrictExtension.json"
}
FileNames::
/dev/main.ts
Errors::


can lookup via an implicit tsconfig in a package-relative directory with extension
configFileName:: tsconfig.extendsBoxImpliedPath.json
CompilerOptions::
{
 "strict": true,
 "configFilePath": "tsconfig.extendsBoxImpliedPath.json"
}
FileNames::
/dev/main.ts
Errors::


can lookup via an package.json exports
configFileName:: tsconfig.extendsFoo.json
CompilerOptions::
{
 "strict": true,
 "configFilePath": "tsconfig.extendsFoo.json"
}
FileNames::
/dev/main.ts
Errors::


can overwrite top-level compilerOptions
configFileName:: configs/extendsArrayFifth.json
CompilerOptions::
{
 "allowJs": true,
 "noImplicitAny": false,
 "strictNullChecks": false,
 "module": 4,
 "configFilePath": "configs/extendsArrayFifth.json"
}
FileNames::

Errors::


can report missing configurations
configFileName:: extendsArrayFails.json
CompilerOptions::
{
 "types": [],
 "configFilePath": "extendsArrayFails.json"
}
FileNames::
/dev/main.ts,/dev/supplemental.ts,/dev/tests/utils.ts,/dev/tests/baselines/first/output.ts,/dev/tests/unit/spec.ts
Errors::
[91merror[0m[90m TS6053: [0mFile './missingFile' not found.


can error when 'extends' is not a string or Array2
configFileName:: extendsArrayFails2.json
CompilerOptions::
{
 "configFilePath": "extendsArrayFails2.json"
}
FileNames::
/dev/main.ts,/dev/supplemental.ts,/dev/tests/utils.ts,/dev/tests/baselines/first/output.ts,/dev/tests/unit/spec.ts
Errors::
[91merror[0m[90m TS5024: [0mCompiler option 'extends' requires a value of type string.

