//// [esDecorators-classDeclaration-methods-nonStaticPrivate.ts]
declare let dec: any;

class C {
    @dec #method1() {}
}


//// [esDecorators-classDeclaration-methods-nonStaticPrivate.js]
class C {
    @dec
    #method1() { }
}
