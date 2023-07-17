/// <reference path='fourslash.ts' />

// @noImplicitAny: true
////function existing<T>(value: T) {
////  added/*1*/(value);
////}

goTo.marker("1");
verify.codeFix({
  description: "Add missing function declaration 'added'",
  index: 0,
  newFileContent: `function existing<T>(value: T) {
  added(value);
}

function added<T>(value: T) {
    throw new Error("Function not implemented.");
}
`,
});
