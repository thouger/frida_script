/// <reference path="../fourslash.ts" />

// @Filename: /tsconfig.json
////{
////    "compilerOptions": {
////        "outDir": "./dist",
////        "inlineSourceMap": true,
////        "inlineSources": true,
////        "declaration": true,
////        "declarationMap": true,
////        "newLine": "lf",
////    },
////    "files": ["/index.ts"],
////}

// @Filename: /index.ts
// @emitThisFile: true
////export class Foo {
////    member: string;
////    /*2*/methodName(propName: SomeType): SomeType { return propName; }
////    otherMethod() {
////        if (Math.random() > 0.5) {
////            return {x: 42};
////        }
////        return {y: "yes"};
////    }
////}
////
////export interface /*SomeType*/SomeType {
////    member: number;
////}

// @Filename: /mymodule.ts
////import * as mod from "/dist/index";
////const instance = new mod.Foo();
////instance.[|/*1*/methodName|]({member: 12});

// @Filename: /dist/index.js
////"use strict";
////Object.defineProperty(exports, "__esModule", { value: true });
////exports.Foo = void 0;
////var Foo = /** @class */ (function () {
////    function Foo() {
////    }
////    Foo.prototype.methodName = function (propName) { return propName; };
////    Foo.prototype.otherMethod = function () {
////        if (Math.random() > 0.5) {
////            return { x: 42 };
////        }
////        return { y: "yes" };
////    };
////    return Foo;
////}());
////exports.Foo = Foo;
//////# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi9pbmRleC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFBQTtJQUFBO0lBU0EsQ0FBQztJQVBHLHdCQUFVLEdBQVYsVUFBVyxRQUFrQixJQUFjLE9BQU8sUUFBUSxDQUFDLENBQUMsQ0FBQztJQUM3RCx5QkFBVyxHQUFYO1FBQ0ksSUFBSSxJQUFJLENBQUMsTUFBTSxFQUFFLEdBQUcsR0FBRyxFQUFFO1lBQ3JCLE9BQU8sRUFBQyxDQUFDLEVBQUUsRUFBRSxFQUFDLENBQUM7U0FDbEI7UUFDRCxPQUFPLEVBQUMsQ0FBQyxFQUFFLEtBQUssRUFBQyxDQUFDO0lBQ3RCLENBQUM7SUFDTCxVQUFDO0FBQUQsQ0FBQyxBQVRELElBU0M7QUFUWSxrQkFBRyIsInNvdXJjZXNDb250ZW50IjpbImV4cG9ydCBjbGFzcyBGb28ge1xuICAgIG1lbWJlcjogc3RyaW5nO1xuICAgIG1ldGhvZE5hbWUocHJvcE5hbWU6IFNvbWVUeXBlKTogU29tZVR5cGUgeyByZXR1cm4gcHJvcE5hbWU7IH1cbiAgICBvdGhlck1ldGhvZCgpIHtcbiAgICAgICAgaWYgKE1hdGgucmFuZG9tKCkgPiAwLjUpIHtcbiAgICAgICAgICAgIHJldHVybiB7eDogNDJ9O1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiB7eTogXCJ5ZXNcIn07XG4gICAgfVxufVxuXG5leHBvcnQgaW50ZXJmYWNlIFNvbWVUeXBlIHtcbiAgICBtZW1iZXI6IG51bWJlcjtcbn0iXX0=

// @Filename: /dist/index.d.ts.map
////{"version":3,"file":"index.d.ts","sourceRoot":"","sources":["../index.ts"],"names":[],"mappings":"AAAA,qBAAa,GAAG;IACZ,MAAM,EAAE,MAAM,CAAC;IACf,UAAU,CAAC,QAAQ,EAAE,QAAQ,GAAG,QAAQ;IACxC,WAAW;;;;;;;CAMd;AAED,MAAM,WAAW,QAAQ;IACrB,MAAM,EAAE,MAAM,CAAC;CAClB"}

// @Filename: /dist/index.d.ts
////export declare class Foo {
////    member: string;
////    methodName(propName: SomeType): SomeType;
////    otherMethod(): {
////        x: number;
////        y?: undefined;
////    } | {
////        y: string;
////        x?: undefined;
////    };
////}
////export interface SomeType {
////    member: number;
////}
//////# sourceMappingURL=index.d.ts.map

goTo.file("/index.ts");
verify.getEmitOutput(["/dist/index.js", "/dist/index.d.ts.map", "/dist/index.d.ts"]);

verify.baselineCommands(
    { type: "goToImplementation", markerOrRange: "1" }, // getImplementationAtPosition
    { type: "goToType", markerOrRange: "1" }, // getTypeDefinitionAtPosition
    { type: "goToDefinition", markerOrRange: "1" }, // getDefinitionAndBoundSpan
    { type: "getDefinitionAtPosition", markerOrRange: "1" }, // getDefinitionAtPosition
);